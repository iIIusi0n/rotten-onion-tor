package channel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"testing"
	"time"
)

func TestSelectVersion(t *testing.T) {
	tests := []struct {
		ours   []uint16
		theirs []uint16
		want   uint16
	}{
		{[]uint16{4, 5}, []uint16{3, 4, 5}, 5},
		{[]uint16{4, 5}, []uint16{3, 4}, 4},
		{[]uint16{4, 5}, []uint16{3}, 0},
		{[]uint16{4, 5}, []uint16{4, 5}, 5},
		{[]uint16{3, 4, 5}, []uint16{5}, 5},
		{[]uint16{}, []uint16{4, 5}, 0},
		{[]uint16{4}, []uint16{}, 0},
	}

	for _, tt := range tests {
		got := selectVersion(tt.ours, tt.theirs)
		if got != tt.want {
			t.Errorf("selectVersion(%v, %v) = %d, want %d", tt.ours, tt.theirs, got, tt.want)
		}
	}
}

func TestValidateCertsSuccess(t *testing.T) {
	linkDER, idDER, relayID, _, err := makeCertChain()
	if err != nil {
		t.Fatalf("make cert chain: %v", err)
	}

	ch := &Channel{
		peerCert:        linkDER,
		expectedRelayID: relayID,
	}

	if err := ch.validateCerts(buildCertsPayload(linkDER, idDER)); err != nil {
		t.Fatalf("validateCerts: %v", err)
	}
}

func TestValidateCertsRelayIdentityMismatch(t *testing.T) {
	linkDER, idDER, _, _, err := makeCertChain()
	if err != nil {
		t.Fatalf("make cert chain: %v", err)
	}

	ch := &Channel{
		peerCert:        linkDER,
		expectedRelayID: make([]byte, 20), // all-zero: guaranteed mismatch
	}

	if err := ch.validateCerts(buildCertsPayload(linkDER, idDER)); err == nil {
		t.Fatal("expected relay identity mismatch error")
	}
}

func TestValidateCertsModernEd25519Chain(t *testing.T) {
	linkDER, idDER, relayID, idKey, err := makeCertChain()
	if err != nil {
		t.Fatalf("make cert chain: %v", err)
	}

	edIdentityPub, edIdentityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed identity key: %v", err)
	}
	relaySigningPub, relaySigningPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate relay signing key: %v", err)
	}

	type7, err := buildRSAToEdCrossCert(idKey, edIdentityPub, time.Now().UTC().Add(6*time.Hour))
	if err != nil {
		t.Fatalf("build type7: %v", err)
	}
	type4 := mustBuildTorEdCert(t, certsTypeAuthEd, relaySigningPub, edIdentityPub, edIdentityPriv, time.Now().UTC().Add(6*time.Hour))

	linkDigest := sha256.Sum256(linkDER)
	type5 := mustBuildTorEdCert(t, certsTypeLinkEd, linkDigest[:], relaySigningPub, relaySigningPriv, time.Now().UTC().Add(6*time.Hour))

	payload := buildCertsPayloadExtended(map[byte][]byte{
		certsTypeLink:    linkDER,
		certsTypeID:      idDER,
		certsTypeAuthEd:  type4,
		certsTypeLinkEd:  type5,
		certsTypeRSAToEd: type7,
	})

	ch := &Channel{
		peerCert:        linkDER,
		expectedRelayID: relayID,
	}
	if err := ch.validateCerts(payload); err != nil {
		t.Fatalf("validateCerts modern chain: %v", err)
	}
}

func buildCertsPayload(linkDER, idDER []byte) []byte {
	return buildCertsPayloadExtended(map[byte][]byte{
		certsTypeLink: linkDER,
		certsTypeID:   idDER,
	})
}

func buildCertsPayloadExtended(entries map[byte][]byte) []byte {
	payload := make([]byte, 0, 256)
	payload = append(payload, byte(len(entries)))
	lenBuf := make([]byte, 2)
	for certType, certBody := range entries {
		payload = append(payload, certType)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(certBody)))
		payload = append(payload, lenBuf...)
		payload = append(payload, certBody...)
	}
	return payload
}

func makeCertChain() (linkDER []byte, idDER []byte, relayID []byte, idKey *rsa.PrivateKey, err error) {
	now := time.Now().UTC()

	idKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	idTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay-identity"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	idDER, err = x509.CreateCertificate(rand.Reader, idTemplate, idTemplate, &idKey.PublicKey, idKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	idCert, err := x509.ParseCertificate(idDER)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	linkKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	linkTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "relay-link"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	linkDER, err = x509.CreateCertificate(rand.Reader, linkTemplate, idCert, &linkKey.PublicKey, idKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sum := sha1.Sum(x509.MarshalPKCS1PublicKey(&idKey.PublicKey))
	relayID = make([]byte, len(sum))
	copy(relayID, sum[:])
	return linkDER, idDER, relayID, idKey, nil
}

func mustBuildTorEdCert(t *testing.T, certType byte, certifiedKey, signerPub []byte, signerPriv ed25519.PrivateKey, expiresAt time.Time) []byte {
	t.Helper()
	if len(certifiedKey) != 32 {
		t.Fatalf("certified key length = %d, want 32", len(certifiedKey))
	}
	body := make([]byte, 0, 1+1+4+1+32+1+2+1+1+32)
	body = append(body, 1)        // VERSION
	body = append(body, certType) // CERT_TYPE

	expBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(expBuf, uint32(expiresAt.Unix()/3600))
	body = append(body, expBuf...)
	body = append(body, 1) // KEY_TYPE=ed25519
	body = append(body, certifiedKey...)
	body = append(body, 1) // N_EXTENSIONS

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, 32)
	body = append(body, lenBuf...)
	body = append(body, 4) // EXT_TYPE signed-with-ed25519-key
	body = append(body, 0) // EXT_FLAGS
	body = append(body, signerPub...)

	sig := ed25519.Sign(signerPriv, body)
	return append(body, sig...)
}

func buildRSAToEdCrossCert(idKey *rsa.PrivateKey, edIdentityPub []byte, expiresAt time.Time) ([]byte, error) {
	if len(edIdentityPub) != 32 {
		return nil, errors.New("ed identity key must be 32 bytes")
	}
	body := make([]byte, 0, 32+4+1)
	body = append(body, edIdentityPub...)
	expBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(expBuf, uint32(expiresAt.Unix()/3600))
	body = append(body, expBuf...)

	// SIGLEN is part of signed fields.
	body = append(body, 0)

	msg := make([]byte, 0, len(rsaEdCrossCertMagic)+len(body))
	msg = append(msg, []byte(rsaEdCrossCertMagic)...)
	msg = append(msg, body...)
	digest := sha256.Sum256(msg)

	sig, err := signPKCS1v15NoOID(idKey, digest[:])
	if err != nil {
		return nil, err
	}
	if len(sig) > math.MaxUint8 {
		return nil, errors.New("cross-cert signature too long")
	}
	body[len(body)-1] = byte(len(sig))

	msg = msg[:0]
	msg = append(msg, []byte(rsaEdCrossCertMagic)...)
	msg = append(msg, body...)
	digest = sha256.Sum256(msg)

	sig, err = signPKCS1v15NoOID(idKey, digest[:])
	if err != nil {
		return nil, err
	}
	if len(sig) > math.MaxUint8 {
		return nil, errors.New("cross-cert signature too long")
	}
	body[len(body)-1] = byte(len(sig))
	return append(body, sig...), nil
}

func signPKCS1v15NoOID(priv *rsa.PrivateKey, digest []byte) ([]byte, error) {
	k := (priv.N.BitLen() + 7) / 8
	if len(digest) > k-11 {
		return nil, errors.New("digest too long")
	}
	em := make([]byte, k)
	em[0] = 0
	em[1] = 1
	for i := 2; i < k-len(digest)-1; i++ {
		em[i] = 0xFF
	}
	em[k-len(digest)-1] = 0
	copy(em[k-len(digest):], digest)

	m := new(big.Int).SetBytes(em)
	s := new(big.Int).Exp(m, priv.D, priv.N)
	return s.FillBytes(make([]byte, k)), nil
}
