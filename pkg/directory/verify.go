package directory

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	torcrypto "rotten-onion-tor/pkg/crypto"
)

const minConsensusSignatures = 3

type consensusSignature struct {
	Algorithm        string
	IdentityFP       string
	SigningKeyDigest string
	Signature        []byte
}

type authorityKeyCertificate struct {
	IdentityFP             string
	SigningFP              string
	Published              time.Time
	Expires                time.Time
	IdentityKey            *rsa.PublicKey
	SigningKey             *rsa.PublicKey
	CrossCert              []byte
	CertificationSignature []byte
	CertificationSigned    []byte
}

var (
	keyCertCacheMu sync.Mutex
	keyCertCache   = make(map[string]*authorityKeyCertificate)
	keyCertsLoaded bool
)

func verifyConsensusDocument(body []byte) error {
	signedData, signatures, err := parseConsensusSignatures(body)
	if err != nil {
		return err
	}
	if len(signatures) == 0 {
		return fmt.Errorf("consensus contains no signatures")
	}

	trustedAuthorities := make(map[string]struct{}, len(DefaultAuthorities))
	for _, a := range DefaultAuthorities {
		trustedAuthorities[strings.ToUpper(a.Fingerprint)] = struct{}{}
	}

	valid := make(map[string]struct{})
	for _, sig := range signatures {
		if _, ok := trustedAuthorities[sig.IdentityFP]; !ok {
			continue
		}
		cert, err := fetchTrustedAuthorityKeyCert(sig.IdentityFP, sig.SigningKeyDigest)
		if err != nil {
			continue
		}

		var digest []byte
		var hashAlg crypto.Hash
		switch sig.Algorithm {
		case "sha1":
			h := sha1.Sum(signedData)
			digest = h[:]
			hashAlg = crypto.SHA1
		case "sha256":
			h := sha256.Sum256(signedData)
			digest = h[:]
			hashAlg = crypto.SHA256
		default:
			continue
		}

		if !verifyRSASignatureCompat(cert.SigningKey, hashAlg, digest, sig.Signature) {
			continue
		}
		valid[sig.IdentityFP] = struct{}{}
	}

	if len(valid) < minConsensusSignatures {
		return fmt.Errorf("consensus has %d valid trusted signatures, need at least %d", len(valid), minConsensusSignatures)
	}
	return nil
}

func parseConsensusSignatures(body []byte) ([]byte, []consensusSignature, error) {
	text := string(body)
	signedCut := strings.Index(text, "\ndirectory-signature ")
	if signedCut < 0 {
		if !strings.HasPrefix(text, "directory-signature ") {
			return nil, nil, fmt.Errorf("consensus missing directory-signature section")
		}
		signedCut = 0
	}

	var signedData []byte
	if signedCut == 0 {
		signedData = []byte("directory-signature ")
	} else {
		signedData = body[:signedCut+len("\ndirectory-signature ")]
	}

	lines := strings.Split(text, "\n")
	signatures := make([]consensusSignature, 0, 8)
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		if !strings.HasPrefix(line, "directory-signature ") {
			continue
		}

		fields := strings.Fields(line)
		var cs consensusSignature
		switch len(fields) {
		case 3:
			cs.Algorithm = "sha1"
			cs.IdentityFP = strings.ToUpper(fields[1])
			cs.SigningKeyDigest = strings.ToUpper(fields[2])
		case 4:
			cs.Algorithm = strings.ToLower(fields[1])
			cs.IdentityFP = strings.ToUpper(fields[2])
			cs.SigningKeyDigest = strings.ToUpper(fields[3])
		default:
			return nil, nil, fmt.Errorf("malformed directory-signature line: %q", line)
		}

		for i+1 < len(lines) && strings.TrimSpace(lines[i+1]) == "" {
			i++
		}
		i++
		if i >= len(lines) || strings.TrimSpace(strings.TrimRight(lines[i], "\r")) != "-----BEGIN SIGNATURE-----" {
			return nil, nil, fmt.Errorf("missing BEGIN SIGNATURE after directory-signature")
		}

		var sigB64 strings.Builder
		for i+1 < len(lines) {
			i++
			l := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
			if l == "-----END SIGNATURE-----" {
				break
			}
			if l != "" {
				sigB64.WriteString(l)
			}
		}
		sig, err := decodeB64Flexible(sigB64.String())
		if err != nil {
			return nil, nil, fmt.Errorf("decode consensus signature: %w", err)
		}
		cs.Signature = sig
		signatures = append(signatures, cs)
	}

	return signedData, signatures, nil
}

func fetchTrustedAuthorityKeyCert(identityFP, signingFP string) (*authorityKeyCertificate, error) {
	cacheKey := identityFP + ":" + signingFP
	keyCertCacheMu.Lock()
	if cert, ok := keyCertCache[cacheKey]; ok {
		keyCertCacheMu.Unlock()
		return cert, nil
	}
	keyCertCacheMu.Unlock()

	_ = loadAuthorityKeyCertCache()
	keyCertCacheMu.Lock()
	if cert, ok := keyCertCache[cacheKey]; ok {
		keyCertCacheMu.Unlock()
		return cert, nil
	}
	keyCertCacheMu.Unlock()

	urlPath := fmt.Sprintf("/tor/keys/fp-sk/%s-%s", identityFP, signingFP)
	var lastErr error
	for _, auth := range DefaultAuthorities {
		u := fmt.Sprintf("http://%s:%d%s", auth.Address, auth.DirPort, urlPath)
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(decompressBody(resp))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		certs, err := parseAuthorityKeyCertificates(body)
		if err != nil {
			lastErr = err
			continue
		}
		for _, cert := range certs {
			if cert.IdentityFP != identityFP || cert.SigningFP != signingFP {
				continue
			}
			if err := verifyAuthorityKeyCertificate(cert); err != nil {
				lastErr = err
				continue
			}
			keyCertCacheMu.Lock()
			keyCertCache[cacheKey] = cert
			keyCertCacheMu.Unlock()
			return cert, nil
		}
		lastErr = fmt.Errorf("matching key certificate not found")
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("unable to fetch key certificate")
	}
	return nil, lastErr
}

func loadAuthorityKeyCertCache() error {
	keyCertCacheMu.Lock()
	if keyCertsLoaded {
		keyCertCacheMu.Unlock()
		return nil
	}
	keyCertCacheMu.Unlock()

	trustedAuthorities := make(map[string]struct{}, len(DefaultAuthorities))
	for _, a := range DefaultAuthorities {
		trustedAuthorities[strings.ToUpper(a.Fingerprint)] = struct{}{}
	}

	var lastErr error
	for _, auth := range DefaultAuthorities {
		u := fmt.Sprintf("http://%s:%d/tor/keys/all", auth.Address, auth.DirPort)
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(decompressBody(resp))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		certs, err := parseAuthorityKeyCertificates(body)
		if err != nil {
			lastErr = err
			continue
		}

		added := 0
		keyCertCacheMu.Lock()
		for _, cert := range certs {
			if _, ok := trustedAuthorities[cert.IdentityFP]; !ok {
				continue
			}
			if err := verifyAuthorityKeyCertificate(cert); err != nil {
				continue
			}
			cacheKey := cert.IdentityFP + ":" + cert.SigningFP
			keyCertCache[cacheKey] = cert
			added++
		}
		if added > 0 {
			keyCertsLoaded = true
		}
		keyCertCacheMu.Unlock()

		if added > 0 {
			return nil
		}
		lastErr = fmt.Errorf("no usable trusted key certificates in /tor/keys/all")
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unable to load authority key certificates")
	}
	return lastErr
}

func parseAuthorityKeyCertificates(body []byte) ([]*authorityKeyCertificate, error) {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	parts := strings.Split(text, "dir-key-certificate-version")
	if len(parts) <= 1 {
		return nil, fmt.Errorf("no key certificates found")
	}

	out := make([]*authorityKeyCertificate, 0, len(parts)-1)
	for _, p := range parts[1:] {
		certText := "dir-key-certificate-version" + p
		cert, err := parseSingleAuthorityKeyCertificate(certText)
		if err != nil {
			continue
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no parseable key certificates")
	}
	return out, nil
}

func parseSingleAuthorityKeyCertificate(text string) (*authorityKeyCertificate, error) {
	lines := strings.Split(text, "\n")
	cert := &authorityKeyCertificate{}

	var signedPrefix strings.Builder
	prefixFrozen := false

	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		if !prefixFrozen {
			signedPrefix.WriteString(line)
			signedPrefix.WriteByte('\n')
		}

		switch {
		case strings.HasPrefix(line, "fingerprint "):
			fp := strings.ReplaceAll(line[len("fingerprint "):], " ", "")
			cert.IdentityFP = strings.ToUpper(fp)

		case strings.HasPrefix(line, "dir-key-published "):
			if t, err := time.Parse("2006-01-02 15:04:05", line[len("dir-key-published "):]); err == nil {
				cert.Published = t.UTC()
			}

		case strings.HasPrefix(line, "dir-key-expires "):
			if t, err := time.Parse("2006-01-02 15:04:05", line[len("dir-key-expires "):]); err == nil {
				cert.Expires = t.UTC()
			}

		case line == "dir-identity-key":
			key, next, err := parseRSAPublicKeyObject(lines, i+1)
			if err != nil {
				return nil, err
			}
			cert.IdentityKey = key
			i = next

		case line == "dir-signing-key":
			key, next, err := parseRSAPublicKeyObject(lines, i+1)
			if err != nil {
				return nil, err
			}
			cert.SigningKey = key
			i = next

		case line == "dir-key-crosscert":
			sig, next, err := parseSignatureObject(lines, i+1, "-----BEGIN ID SIGNATURE-----", "-----END ID SIGNATURE-----")
			if err != nil {
				return nil, err
			}
			cert.CrossCert = sig
			i = next

		case line == "dir-key-certification":
			cert.CertificationSigned = []byte(signedPrefix.String())
			prefixFrozen = true
			sig, next, err := parseSignatureObject(lines, i+1, "-----BEGIN SIGNATURE-----", "-----END SIGNATURE-----")
			if err != nil {
				return nil, err
			}
			cert.CertificationSignature = sig
			i = next
		}
	}

	if cert.IdentityKey == nil || cert.SigningKey == nil || len(cert.CrossCert) == 0 || len(cert.CertificationSignature) == 0 {
		return nil, fmt.Errorf("incomplete key certificate")
	}

	idDigest := sha1.Sum(x509.MarshalPKCS1PublicKey(cert.IdentityKey))
	signDigest := sha1.Sum(x509.MarshalPKCS1PublicKey(cert.SigningKey))
	computedID := strings.ToUpper(hex.EncodeToString(idDigest[:]))
	computedSigning := strings.ToUpper(hex.EncodeToString(signDigest[:]))
	if cert.IdentityFP == "" {
		cert.IdentityFP = computedID
	}
	cert.SigningFP = computedSigning
	return cert, nil
}

func verifyAuthorityKeyCertificate(cert *authorityKeyCertificate) error {
	now := time.Now().UTC()
	if cert.Published.IsZero() || cert.Expires.IsZero() {
		return fmt.Errorf("certificate missing validity interval")
	}
	if now.Before(cert.Published.Add(-2 * time.Hour)) {
		return fmt.Errorf("certificate not yet valid")
	}
	if now.After(cert.Expires) {
		return fmt.Errorf("certificate expired")
	}

	idDigest := sha1.Sum(x509.MarshalPKCS1PublicKey(cert.IdentityKey))
	if !verifyRSASHA1Compat(cert.SigningKey, idDigest[:], cert.CrossCert) {
		return fmt.Errorf("cross-cert invalid")
	}

	certDigest := sha1.Sum(cert.CertificationSigned)
	validCertification := verifyRSASHA1Compat(cert.IdentityKey, certDigest[:], cert.CertificationSignature)
	if !validCertification {
		trimmed := bytes.TrimSuffix(cert.CertificationSigned, []byte("\n"))
		if len(trimmed) != len(cert.CertificationSigned) {
			trimmedDigest := sha1.Sum(trimmed)
			validCertification = verifyRSASHA1Compat(cert.IdentityKey, trimmedDigest[:], cert.CertificationSignature)
		}
	}
	if !validCertification {
		return fmt.Errorf("key-certification signature invalid")
	}

	computedID := strings.ToUpper(hex.EncodeToString(idDigest[:]))
	if cert.IdentityFP != computedID {
		return fmt.Errorf("identity fingerprint mismatch")
	}
	return nil
}

func parseRSAPublicKeyObject(lines []string, start int) (*rsa.PublicKey, int, error) {
	if start >= len(lines) {
		return nil, start, fmt.Errorf("missing RSA public key object")
	}
	if strings.TrimSpace(lines[start]) != "-----BEGIN RSA PUBLIC KEY-----" {
		return nil, start, fmt.Errorf("missing BEGIN RSA PUBLIC KEY")
	}

	var b64 strings.Builder
	i := start + 1
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if l == "-----END RSA PUBLIC KEY-----" {
			break
		}
		if l != "" {
			b64.WriteString(l)
		}
	}
	if i >= len(lines) {
		return nil, start, fmt.Errorf("missing END RSA PUBLIC KEY")
	}
	der, err := decodeB64Flexible(b64.String())
	if err != nil {
		return nil, start, err
	}
	key, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, start, err
	}
	return key, i, nil
}

func parseSignatureObject(lines []string, start int, beginMarker, endMarker string) ([]byte, int, error) {
	if start >= len(lines) {
		return nil, start, fmt.Errorf("missing signature object")
	}
	if strings.TrimSpace(lines[start]) != beginMarker {
		return nil, start, fmt.Errorf("missing %s", beginMarker)
	}

	var b64 strings.Builder
	i := start + 1
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if l == endMarker {
			break
		}
		if l != "" {
			b64.WriteString(l)
		}
	}
	if i >= len(lines) {
		return nil, start, fmt.Errorf("missing %s", endMarker)
	}

	sig, err := decodeB64Flexible(b64.String())
	if err != nil {
		return nil, start, err
	}
	return sig, i, nil
}

func decodeB64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64 payload")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func verifyRSASignatureCompat(pub *rsa.PublicKey, hashAlg crypto.Hash, digest, sig []byte) bool {
	if err := torcrypto.VerifyRSAPKCS1v15NoOID(pub, digest, sig); err == nil {
		return true
	}
	if hashAlg.Available() {
		if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, sig); err == nil {
			return true
		}
	}
	return false
}

func verifyRSASHA1Compat(pub *rsa.PublicKey, digest, sig []byte) bool {
	if err := torcrypto.VerifyRSAPKCS1v15NoOID(pub, digest, sig); err == nil {
		return true
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest, sig); err == nil {
		return true
	}
	return false
}
