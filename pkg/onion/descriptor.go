package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	torcrypto "rotten-onion-tor/pkg/crypto"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// IntroPoint represents a parsed introduction point from an HS descriptor.
type IntroPoint struct {
	LinkSpecifiers []LinkSpecifier // For EXTEND2
	OnionKey       []byte          // curve25519 ntor key of intro point relay
	AuthKey        []byte          // ed25519 KP_hs_ipt_sid (from auth-key cert)
	EncKey         []byte          // curve25519 KP_hss_ntor (for hs-ntor)
	AuthKeyCert    []byte
	EncKeyCert     []byte
}

// LinkSpecifier represents a link specifier for EXTEND2.
type LinkSpecifier struct {
	Type byte
	Data []byte
}

// HSDescriptor holds the parsed outer layer of an HS descriptor.
type HSDescriptor struct {
	RevisionCounter     uint64
	Superencrypted      []byte // Raw superencrypted blob
	SigningKeyCert      []byte
	DescriptorSignature []byte
	SignedData          []byte
}

const (
	ed25519CertTypeHSDescSigning  = 8
	ed25519CertTypeHSIntroAuthKey = 9
	ed25519CertTypeHSEncKey       = 11
	ed25519CertKeyTypeEd25519     = 1
	descriptorSigPrefix           = "Tor onion service descriptor sig v3"
)

// ParseHSDescriptorOuter parses the outer wrapper of an HS descriptor.
func ParseHSDescriptorOuter(body string) (*HSDescriptor, error) {
	desc := &HSDescriptor{}
	lines := strings.Split(body, "\n")

	inSuperencrypted := false
	inSigningKeyCert := false
	var superencB64 strings.Builder
	var signingCertB64 strings.Builder

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		switch {
		case strings.HasPrefix(line, "revision-counter "):
			fmt.Sscanf(line, "revision-counter %d", &desc.RevisionCounter)

		case line == "descriptor-signing-key-cert":
			inSigningKeyCert = true
			signingCertB64.Reset()

		case line == "signature":
			// Ignore; signature is expected as "signature <b64>" below.

		case line == "-----BEGIN MESSAGE-----":
			inSuperencrypted = true

		case line == "-----END MESSAGE-----":
			inSuperencrypted = false
			decoded, err := base64DecodeFlexible(superencB64.String())
			if err != nil {
				return nil, fmt.Errorf("decode superencrypted: %w", err)
			}
			desc.Superencrypted = decoded

		case line == "-----BEGIN ED25519 CERT-----":
			// Marker line; content follows.

		case line == "-----END ED25519 CERT-----":
			if inSigningKeyCert {
				decoded, err := base64DecodeFlexible(signingCertB64.String())
				if err != nil {
					return nil, fmt.Errorf("decode descriptor signing cert: %w", err)
				}
				desc.SigningKeyCert = decoded
				inSigningKeyCert = false
			}

		case strings.HasPrefix(line, "signature "):
			sigB64 := strings.TrimSpace(line[len("signature "):])
			sig, err := base64DecodeFlexible(sigB64)
			if err != nil {
				return nil, fmt.Errorf("decode descriptor signature: %w", err)
			}
			desc.DescriptorSignature = sig

		default:
			if inSuperencrypted {
				superencB64.WriteString(strings.TrimSpace(line))
			}
			if inSigningKeyCert && len(strings.TrimSpace(line)) > 0 && !strings.HasPrefix(line, "-----") {
				signingCertB64.WriteString(strings.TrimSpace(line))
			}
		}
	}

	if desc.Superencrypted == nil {
		return nil, fmt.Errorf("no superencrypted data found")
	}
	if len(desc.SigningKeyCert) == 0 {
		return nil, fmt.Errorf("missing descriptor-signing-key-cert")
	}
	if len(desc.DescriptorSignature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid descriptor signature length: %d", len(desc.DescriptorSignature))
	}

	// Signed data is everything up to (but excluding) the "signature " line.
	sigLineIdx := strings.LastIndex(body, "\nsignature ")
	if sigLineIdx < 0 {
		if strings.HasPrefix(body, "signature ") {
			desc.SignedData = nil
		} else {
			return nil, fmt.Errorf("missing descriptor signature line")
		}
	} else {
		desc.SignedData = []byte(body[:sigLineIdx+1])
	}

	return desc, nil
}

// VerifyOuterDescriptor verifies the outer descriptor certificate and signature
// against the expected blinded key and returns the descriptor signing key.
func VerifyOuterDescriptor(desc *HSDescriptor, blindedKey []byte, now time.Time) ([]byte, error) {
	if desc == nil {
		return nil, fmt.Errorf("nil descriptor")
	}
	if len(blindedKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid blinded key length: %d", len(blindedKey))
	}
	cert, err := torcrypto.ParseEd25519Cert(desc.SigningKeyCert)
	if err != nil {
		return nil, fmt.Errorf("parse descriptor signing cert: %w", err)
	}
	if cert.CertType != ed25519CertTypeHSDescSigning {
		return nil, fmt.Errorf("unexpected descriptor cert type: %d", cert.CertType)
	}
	if cert.KeyType != ed25519CertKeyTypeEd25519 {
		return nil, fmt.Errorf("unexpected descriptor cert key type: %d", cert.KeyType)
	}
	if err := cert.Verify(blindedKey, now.UTC()); err != nil {
		return nil, fmt.Errorf("verify descriptor signing cert: %w", err)
	}

	descriptorSigningKey := make([]byte, ed25519.PublicKeySize)
	copy(descriptorSigningKey, cert.CertifiedKey[:])

	msg := make([]byte, 0, len(descriptorSigPrefix)+len(desc.SignedData))
	msg = append(msg, []byte(descriptorSigPrefix)...)
	msg = append(msg, desc.SignedData...)
	if !ed25519.Verify(ed25519.PublicKey(descriptorSigningKey), msg, desc.DescriptorSignature) {
		return nil, fmt.Errorf("descriptor signature verification failed")
	}
	return descriptorSigningKey, nil
}

// DecryptDescriptorLayer decrypts one layer of HS descriptor encryption.
// Per rend-spec-v3 section 2.5.1.1:
//
//	secret_input = SECRET_DATA || subcredential || INT_8(revision_counter)
//	keys = SHAKE256_KDF(secret_input || SALT || STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
//	SECRET_KEY = keys[0:32], SECRET_IV = keys[32:48], MAC_KEY = keys[48:80]
//
// The encrypted blob format is: SALT(16) || ENCRYPTED || MAC(32)
func DecryptDescriptorLayer(encrypted []byte, secretData, subcredential []byte, revisionCounter uint64, stringConstant string) ([]byte, error) {
	// encrypted = SALT(16) || ciphertext || MAC(32)
	if len(encrypted) < 48 { // 16 + 0 + 32 minimum
		return nil, fmt.Errorf("encrypted data too short: %d", len(encrypted))
	}

	salt := encrypted[:16]
	mac := encrypted[len(encrypted)-32:]
	ciphertext := encrypted[16 : len(encrypted)-32]

	// Build secret_input.
	revBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(revBuf, revisionCounter)

	secretInput := make([]byte, 0, len(secretData)+len(subcredential)+8)
	secretInput = append(secretInput, secretData...)
	secretInput = append(secretInput, subcredential...)
	secretInput = append(secretInput, revBuf...)

	// KDF input: secret_input || SALT || STRING_CONSTANT
	kdfInput := make([]byte, 0, len(secretInput)+len(salt)+len(stringConstant))
	kdfInput = append(kdfInput, secretInput...)
	kdfInput = append(kdfInput, salt...)
	kdfInput = append(kdfInput, []byte(stringConstant)...)

	// Derive keys: S_KEY_LEN(32) + S_IV_LEN(16) + MAC_KEY_LEN(32) = 80
	keys := torcrypto.SHAKE256KDF(kdfInput, 80)
	secretKey := keys[0:32]
	secretIV := keys[32:48]
	macKey := keys[48:80]

	// Verify MAC: MAC = SHA3_256(MAC_KEY_LEN_8bytes || MAC_KEY || SALT_LEN_8bytes || SALT || ENCRYPTED)
	macKeyLen := make([]byte, 8)
	binary.BigEndian.PutUint64(macKeyLen, uint64(len(macKey)))
	saltLen := make([]byte, 8)
	binary.BigEndian.PutUint64(saltLen, uint64(len(salt)))

	macInput := make([]byte, 0, 8+len(macKey)+8+len(salt)+len(ciphertext))
	macInput = append(macInput, macKeyLen...)
	macInput = append(macInput, macKey...)
	macInput = append(macInput, saltLen...)
	macInput = append(macInput, salt...)
	macInput = append(macInput, ciphertext...)

	expectedMAC := torcrypto.SHA3_256(macInput)
	if !bytesEqual(expectedMAC, mac) {
		return nil, fmt.Errorf("MAC verification failed")
	}

	// Decrypt: AES-256-CTR(SECRET_IV, SECRET_KEY) XOR ciphertext
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)
	aesCTRDecrypt(secretKey, secretIV, plaintext)

	return plaintext, nil
}

// aesCTRDecrypt decrypts data in-place using AES-256-CTR.
func aesCTRDecrypt(key, iv, data []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)
}

// DecryptSuperencrypted decrypts the first (superencrypted) layer.
func DecryptSuperencrypted(superencrypted []byte, blindedKey, subcredential []byte, revisionCounter uint64) ([]byte, error) {
	return DecryptDescriptorLayer(superencrypted, blindedKey, subcredential, revisionCounter, "hsdir-superencrypted-data")
}

// DecryptEncrypted decrypts the second (encrypted) layer.
// For non-restricted-discovery, SECRET_DATA = blinded_key (no descriptor_cookie).
func DecryptEncrypted(encrypted []byte, blindedKey, subcredential []byte, revisionCounter uint64) ([]byte, error) {
	return DecryptDescriptorLayer(encrypted, blindedKey, subcredential, revisionCounter, "hsdir-encrypted-data")
}

// ParseFirstLayerPlaintext extracts the encrypted blob from the first-layer plaintext.
func ParseFirstLayerPlaintext(plaintext []byte) ([]byte, error) {
	text := string(plaintext)

	// Find the last -----BEGIN MESSAGE----- / -----END MESSAGE----- block.
	// The first layer may have multiple sections; the encrypted blob is the last one.
	beginMarker := "-----BEGIN MESSAGE-----"
	endMarker := "-----END MESSAGE-----"

	beginIdx := strings.LastIndex(text, beginMarker)
	if beginIdx < 0 {
		return nil, fmt.Errorf("no encrypted data found in first layer")
	}
	endIdx := strings.Index(text[beginIdx:], endMarker)
	if endIdx < 0 {
		return nil, fmt.Errorf("no END MESSAGE marker found")
	}

	b64Data := text[beginIdx+len(beginMarker) : beginIdx+endIdx]

	decoded, err := base64DecodeFlexible(b64Data)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted blob: %w", err)
	}
	return decoded, nil
}

// ParseIntroPoints parses introduction points from the second-layer plaintext.
// It parses and validates auth-key/enc-key certificates against descriptorSigningKey.
func ParseIntroPoints(plaintext []byte, descriptorSigningKey []byte, now time.Time) ([]*IntroPoint, error) {
	text := string(plaintext)
	lines := strings.Split(text, "\n")

	var introPoints []*IntroPoint
	var current *IntroPoint
	certMode := ""
	inCert := false
	var certB64 strings.Builder

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		switch {
		case strings.HasPrefix(line, "introduction-point "):
			if current != nil {
				if isCompleteIntroPoint(current) {
					if err := validateAndFinalizeIntroPoint(current, descriptorSigningKey, now); err == nil {
						introPoints = append(introPoints, current)
					}
				}
			}
			current = &IntroPoint{}

			// Parse link specifiers from base64.
			lsB64 := strings.TrimSpace(line[len("introduction-point "):])
			lsBytes, err := base64.StdEncoding.DecodeString(lsB64)
			if err != nil {
				// Try raw.
				lsBytes, err = base64.RawStdEncoding.DecodeString(lsB64)
				if err != nil {
					return nil, fmt.Errorf("decode link specifiers: %w", err)
				}
			}
			ls, err := parseLinkSpecifiers(lsBytes)
			if err != nil {
				return nil, fmt.Errorf("parse link specifiers: %w", err)
			}
			current.LinkSpecifiers = ls

		case strings.HasPrefix(line, "onion-key ntor "):
			if current != nil {
				keyB64 := strings.TrimSpace(line[len("onion-key ntor "):])
				keyBytes, err := base64DecodeFlexible(keyB64)
				if err != nil {
					return nil, fmt.Errorf("decode onion-key: %w", err)
				}
				current.OnionKey = keyBytes
			}

		case strings.HasPrefix(line, "enc-key ntor "):
			if current != nil {
				keyB64 := strings.TrimSpace(line[len("enc-key ntor "):])
				keyBytes, err := base64DecodeFlexible(keyB64)
				if err != nil {
					return nil, fmt.Errorf("decode enc-key: %w", err)
				}
				current.EncKey = keyBytes
			}

		case line == "auth-key":
			certMode = "auth"
			inCert = false
			certB64.Reset()

		case line == "enc-key-cert":
			certMode = "enc"
			inCert = false
			certB64.Reset()

		case line == "-----BEGIN ED25519 CERT-----":
			if certMode != "" {
				inCert = true
			}

		case line == "-----END ED25519 CERT-----":
			if current != nil && inCert {
				certBytes, err := base64DecodeFlexible(certB64.String())
				if err != nil {
					return nil, fmt.Errorf("decode intro cert: %w", err)
				}
				if certMode == "auth" {
					current.AuthKeyCert = certBytes
				} else if certMode == "enc" {
					current.EncKeyCert = certBytes
				}
			}
			inCert = false
			certMode = ""

		default:
			if inCert && !strings.HasPrefix(line, "-----") && len(strings.TrimSpace(line)) > 0 {
				certB64.WriteString(strings.TrimSpace(line))
			}
		}
	}

	if current != nil {
		if isCompleteIntroPoint(current) {
			if err := validateAndFinalizeIntroPoint(current, descriptorSigningKey, now); err == nil {
				introPoints = append(introPoints, current)
			}
		}
	}

	return introPoints, nil
}

// parseLinkSpecifiers parses a link specifier block.
// Format: NSPEC(1) || [LSTYPE(1) LSLEN(1) LSPEC(LSLEN)] ...
func parseLinkSpecifiers(data []byte) ([]LinkSpecifier, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("link specifier data too short")
	}
	nspec := int(data[0])
	off := 1
	var specs []LinkSpecifier
	for i := 0; i < nspec; i++ {
		if off+2 > len(data) {
			return nil, fmt.Errorf("truncated link specifier %d", i)
		}
		lstype := data[off]
		lslen := int(data[off+1])
		off += 2
		if off+lslen > len(data) {
			return nil, fmt.Errorf("truncated link specifier data %d", i)
		}
		spec := LinkSpecifier{
			Type: lstype,
			Data: make([]byte, lslen),
		}
		copy(spec.Data, data[off:off+lslen])
		off += lslen
		specs = append(specs, spec)
	}
	if off != len(data) {
		return nil, fmt.Errorf("unexpected trailing bytes in link specifiers")
	}
	return specs, nil
}

// EncodeLinkSpecifiers encodes link specifiers for an EXTEND2 cell.
// Returns NSPEC(1) || [LSTYPE(1) LSLEN(1) LSPEC(LSLEN)] ...
func EncodeLinkSpecifiers(specs []LinkSpecifier) []byte {
	size := 1
	for _, s := range specs {
		size += 2 + len(s.Data)
	}
	buf := make([]byte, 0, size)
	buf = append(buf, byte(len(specs)))
	for _, s := range specs {
		buf = append(buf, s.Type, byte(len(s.Data)))
		buf = append(buf, s.Data...)
	}
	return buf
}

func base64DecodeFlexible(s string) ([]byte, error) {
	// Strip any remaining whitespace.
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	// Try standard (padded), then raw (unpadded).
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	return b, err
}

func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func isCompleteIntroPoint(ip *IntroPoint) bool {
	if ip == nil {
		return false
	}
	return len(ip.LinkSpecifiers) > 0 &&
		len(ip.OnionKey) == 32 &&
		len(ip.EncKey) == 32 &&
		len(ip.AuthKeyCert) > 0 &&
		len(ip.EncKeyCert) > 0
}

func validateAndFinalizeIntroPoint(ip *IntroPoint, descriptorSigningKey []byte, now time.Time) error {
	if len(descriptorSigningKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid descriptor signing key length: %d", len(descriptorSigningKey))
	}
	if err := validateLinkSpecifiers(ip.LinkSpecifiers); err != nil {
		return err
	}

	authCert, err := torcrypto.ParseEd25519Cert(ip.AuthKeyCert)
	if err != nil {
		return fmt.Errorf("parse auth-key cert: %w", err)
	}
	if authCert.CertType != ed25519CertTypeHSIntroAuthKey {
		return fmt.Errorf("unexpected auth-key cert type: %d", authCert.CertType)
	}
	if authCert.KeyType != ed25519CertKeyTypeEd25519 {
		return fmt.Errorf("unexpected auth-key cert key type: %d", authCert.KeyType)
	}
	if err := authCert.Verify(descriptorSigningKey, now.UTC()); err != nil {
		return fmt.Errorf("verify auth-key cert: %w", err)
	}

	encCert, err := torcrypto.ParseEd25519Cert(ip.EncKeyCert)
	if err != nil {
		return fmt.Errorf("parse enc-key cert: %w", err)
	}
	if encCert.CertType != ed25519CertTypeHSEncKey {
		return fmt.Errorf("unexpected enc-key cert type: %d", encCert.CertType)
	}
	if err := encCert.Verify(descriptorSigningKey, now.UTC()); err != nil {
		return fmt.Errorf("verify enc-key cert: %w", err)
	}
	equiv, err := x25519PublicToEd25519(ip.EncKey)
	if err != nil {
		return fmt.Errorf("convert enc-key to ed25519 form: %w", err)
	}
	if !bytesEqual(encCert.CertifiedKey[:], equiv) {
		return fmt.Errorf("enc-key cert does not match enc-key ntor")
	}

	ip.AuthKey = make([]byte, 32)
	copy(ip.AuthKey, authCert.CertifiedKey[:])
	return nil
}

func x25519PublicToEd25519(x25519Pub []byte) ([]byte, error) {
	if len(x25519Pub) != 32 {
		return nil, fmt.Errorf("x25519 public key length = %d, want 32", len(x25519Pub))
	}

	u := new(field.Element)
	if _, err := u.SetBytes(x25519Pub); err != nil {
		return nil, fmt.Errorf("parse x25519 u-coordinate: %w", err)
	}
	one := new(field.Element).One()

	num := new(field.Element).Subtract(u, one) // u - 1
	den := new(field.Element).Add(u, one)      // u + 1
	denInv := new(field.Element).Invert(den)
	y := new(field.Element).Multiply(num, denInv)

	enc := y.Bytes()
	enc[31] &= 0x7F // choose sign bit 0.

	p, err := new(edwards25519.Point).SetBytes(enc)
	if err != nil {
		return nil, fmt.Errorf("invalid converted ed25519 point: %w", err)
	}
	if !bytesEqual(p.BytesMontgomery(), x25519Pub) {
		return nil, fmt.Errorf("montgomery back-conversion mismatch")
	}

	return p.Bytes(), nil
}

func validateLinkSpecifiers(specs []LinkSpecifier) error {
	hasLegacy := false
	hasAddr := false
	for i, spec := range specs {
		switch spec.Type {
		case 0x00: // IPv4
			if len(spec.Data) != 6 {
				return fmt.Errorf("link spec %d has invalid IPv4 length %d", i, len(spec.Data))
			}
			hasAddr = true
		case 0x01: // IPv6
			if len(spec.Data) != 18 {
				return fmt.Errorf("link spec %d has invalid IPv6 length %d", i, len(spec.Data))
			}
			hasAddr = true
		case 0x02: // legacy identity
			if len(spec.Data) != 20 {
				return fmt.Errorf("link spec %d has invalid legacy identity length %d", i, len(spec.Data))
			}
			hasLegacy = true
		}
	}
	if !hasLegacy {
		return fmt.Errorf("intro point missing legacy identity link specifier")
	}
	if !hasAddr {
		return fmt.Errorf("intro point missing address link specifier")
	}
	return nil
}
