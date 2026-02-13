package channel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	linkDER, idDER, relayID, err := makeCertChain()
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
	linkDER, idDER, _, err := makeCertChain()
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

func buildCertsPayload(linkDER, idDER []byte) []byte {
	payload := make([]byte, 0, 1+3+len(linkDER)+3+len(idDER))
	payload = append(payload, 2) // N_CERTS

	payload = append(payload, 1) // CERTS_TYPE_LINK
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(linkDER)))
	payload = append(payload, lenBuf...)
	payload = append(payload, linkDER...)

	payload = append(payload, 2) // CERTS_TYPE_ID
	binary.BigEndian.PutUint16(lenBuf, uint16(len(idDER)))
	payload = append(payload, lenBuf...)
	payload = append(payload, idDER...)

	return payload
}

func makeCertChain() (linkDER []byte, idDER []byte, relayID []byte, err error) {
	now := time.Now().UTC()

	idKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, err
	}
	idCert, err := x509.ParseCertificate(idDER)
	if err != nil {
		return nil, nil, nil, err
	}

	linkKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, err
	}

	sum := sha1.Sum(x509.MarshalPKCS1PublicKey(&idKey.PublicKey))
	relayID = make([]byte, len(sum))
	copy(relayID, sum[:])
	return linkDER, idDER, relayID, nil
}
