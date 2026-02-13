package onion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestVerifyOuterDescriptor(t *testing.T) {
	now := time.Now().UTC()

	blindedPub, blindedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate blinded keypair: %v", err)
	}
	descSigningPub, descSigningPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate descriptor signing keypair: %v", err)
	}

	signingCert, err := buildTorEdCert(ed25519CertTypeHSDescSigning, descSigningPub, blindedPub, blindedPriv, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("build descriptor signing cert: %v", err)
	}

	superencrypted := make([]byte, 64)
	for i := range superencrypted {
		superencrypted[i] = byte(i + 1)
	}

	bodyNoSig := strings.Join([]string{
		"hs-descriptor 3",
		"revision-counter 42",
		"descriptor-signing-key-cert",
		"-----BEGIN ED25519 CERT-----",
		base64.StdEncoding.EncodeToString(signingCert),
		"-----END ED25519 CERT-----",
		"superencrypted",
		"-----BEGIN MESSAGE-----",
		base64.StdEncoding.EncodeToString(superencrypted),
		"-----END MESSAGE-----",
		"",
	}, "\n")

	msg := append([]byte(descriptorSigPrefix), []byte(bodyNoSig)...)
	signature := ed25519.Sign(descSigningPriv, msg)

	fullBody := bodyNoSig + "signature " + base64.StdEncoding.EncodeToString(signature) + "\n"
	desc, err := ParseHSDescriptorOuter(fullBody)
	if err != nil {
		t.Fatalf("ParseHSDescriptorOuter: %v", err)
	}

	gotSigningKey, err := VerifyOuterDescriptor(desc, blindedPub, now)
	if err != nil {
		t.Fatalf("VerifyOuterDescriptor: %v", err)
	}
	if !bytes.Equal(gotSigningKey, descSigningPub) {
		t.Fatalf("descriptor signing key mismatch\ngot  %x\nwant %x", gotSigningKey, descSigningPub)
	}
}

func TestParseIntroPointsValidated(t *testing.T) {
	now := time.Now().UTC()
	descSigningPub, descSigningPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate descriptor signing keypair: %v", err)
	}

	authPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate auth keypair: %v", err)
	}
	authCert, err := buildTorEdCert(ed25519CertTypeHSIntroAuthKey, authPub, descSigningPub, descSigningPriv, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("build auth cert: %v", err)
	}

	onionKey := make([]byte, 32)
	encKey := make([]byte, 32)
	var encPriv [32]byte
	if _, err := rand.Read(encPriv[:]); err != nil {
		t.Fatalf("generate enc-key ntor private: %v", err)
	}
	encPubMont, err := curve25519.X25519(encPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive enc-key ntor public: %v", err)
	}
	copy(encKey, encPubMont)
	encPub, err := x25519PublicToEd25519(encKey)
	if err != nil {
		t.Fatalf("convert enc-key ntor to ed form: %v", err)
	}
	encCert, err := buildTorEdCert(ed25519CertTypeHSEncKey, encPub, descSigningPub, descSigningPriv, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("build enc cert: %v", err)
	}

	for i := 0; i < 32; i++ {
		onionKey[i] = byte(i + 3)
	}

	linkSpecs := buildIntroLinkSpecs()
	plaintext := strings.Join([]string{
		"introduction-point " + base64.StdEncoding.EncodeToString(linkSpecs),
		"onion-key ntor " + base64.StdEncoding.EncodeToString(onionKey),
		"auth-key",
		"-----BEGIN ED25519 CERT-----",
		base64.StdEncoding.EncodeToString(authCert),
		"-----END ED25519 CERT-----",
		"enc-key ntor " + base64.StdEncoding.EncodeToString(encKey),
		"enc-key-cert",
		"-----BEGIN ED25519 CERT-----",
		base64.StdEncoding.EncodeToString(encCert),
		"-----END ED25519 CERT-----",
		"",
	}, "\n")

	points, err := ParseIntroPoints([]byte(plaintext), descSigningPub, now)
	if err != nil {
		t.Fatalf("ParseIntroPoints: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("len(points) = %d, want 1", len(points))
	}
	if !bytes.Equal(points[0].AuthKey, authPub) {
		t.Fatalf("auth key mismatch\ngot  %x\nwant %x", points[0].AuthKey, authPub)
	}
}

func buildIntroLinkSpecs() []byte {
	// NSPEC=2, IPv4 spec, legacy identity spec.
	out := make([]byte, 0, 1+2+6+2+20)
	out = append(out, 2)

	out = append(out, 0x00, 6)                  // IPv4
	out = append(out, 127, 0, 0, 1, 0x1F, 0x90) // 8080

	out = append(out, 0x02, 20) // legacy identity
	for i := 0; i < 20; i++ {
		out = append(out, byte(i+1))
	}
	return out
}

func buildTorEdCert(certType byte, certifiedKey, signerPub []byte, signerPriv ed25519.PrivateKey, expiresAt time.Time) ([]byte, error) {
	if len(certifiedKey) != 32 {
		return nil, errLen("certified key", len(certifiedKey), 32)
	}
	if len(signerPub) != 32 {
		return nil, errLen("signer pubkey", len(signerPub), 32)
	}

	body := make([]byte, 0, 1+1+4+1+32+1+2+1+1+32)
	body = append(body, 1)        // VERSION
	body = append(body, certType) // CERT_TYPE

	expiresHours := uint32(expiresAt.Unix() / 3600)
	expBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(expBuf, expiresHours)
	body = append(body, expBuf...)

	body = append(body, ed25519CertKeyTypeEd25519) // KEY_TYPE
	body = append(body, certifiedKey...)           // CERTIFIED_KEY
	body = append(body, 1)                         // N_EXTENSIONS

	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, 32)
	body = append(body, extLen...)
	body = append(body, 4) // EXT_TYPE = signed-with-ed25519-key
	body = append(body, 0) // EXT_FLAGS
	body = append(body, signerPub...)

	sig := ed25519.Sign(signerPriv, body)
	return append(body, sig...), nil
}

func errLen(label string, got, want int) error {
	return &lenErr{label: label, got: got, want: want}
}

type lenErr struct {
	label string
	got   int
	want  int
}

func (e *lenErr) Error() string {
	return e.label + " length mismatch"
}
