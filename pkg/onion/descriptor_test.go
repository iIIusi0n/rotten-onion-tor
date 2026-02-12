package onion

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseAuthKeyFromEd25519Cert(t *testing.T) {
	cert := make([]byte, 39)
	cert[0] = ed25519CertVersion
	cert[1] = ed25519CertTypeHSIntroAuthKey
	cert[6] = ed25519CertKeyTypeEd25519
	want := bytes.Repeat([]byte{0x42}, 32)
	copy(cert[7:39], want)

	key, err := parseAuthKeyFromEd25519Cert(base64.StdEncoding.EncodeToString(cert))
	if err != nil {
		t.Fatalf("parseAuthKeyFromEd25519Cert: %v", err)
	}
	if !bytes.Equal(key, want) {
		t.Fatalf("certified key mismatch: got %x want %x", key, want)
	}
}

func TestParseAuthKeyFromEd25519CertWrongType(t *testing.T) {
	cert := make([]byte, 39)
	cert[0] = ed25519CertVersion
	cert[1] = 0x08
	cert[6] = ed25519CertKeyTypeEd25519
	copy(cert[7:39], bytes.Repeat([]byte{0x11}, 32))

	if _, err := parseAuthKeyFromEd25519Cert(base64.StdEncoding.EncodeToString(cert)); err == nil {
		t.Fatal("expected cert type error")
	}
}

func TestParseIntroPointsCompleteOnly(t *testing.T) {
	linkSpecs := make([]byte, 1+2+20)
	linkSpecs[0] = 1  // NSPEC
	linkSpecs[1] = 2  // legacy identity
	linkSpecs[2] = 20 // length
	lsB64 := base64.StdEncoding.EncodeToString(linkSpecs)

	onionKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	encKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))

	cert := make([]byte, 39)
	cert[0] = ed25519CertVersion
	cert[1] = ed25519CertTypeHSIntroAuthKey
	cert[6] = ed25519CertKeyTypeEd25519
	authKey := bytes.Repeat([]byte{0x44}, 32)
	copy(cert[7:39], authKey)
	certB64 := base64.StdEncoding.EncodeToString(cert)

	plaintext := strings.Join([]string{
		"introduction-point " + lsB64,
		"onion-key ntor " + onionKey,
		"auth-key",
		"-----BEGIN ED25519 CERT-----",
		certB64,
		"-----END ED25519 CERT-----",
		"enc-key ntor " + encKey,
		"",
	}, "\n")

	points, err := ParseIntroPoints([]byte(plaintext))
	if err != nil {
		t.Fatalf("ParseIntroPoints: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1", len(points))
	}
	if !bytes.Equal(points[0].AuthKey, authKey) {
		t.Fatalf("auth key mismatch: got %x want %x", points[0].AuthKey, authKey)
	}
}
