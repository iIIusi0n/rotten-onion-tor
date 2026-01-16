package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestHmacSHA256(t *testing.T) {
	key := []byte("test-key")
	msg := []byte("test-message")
	result := hmacSHA256(key, msg)
	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}

	// Verify against standard library.
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	expected := mac.Sum(nil)
	if !bytes.Equal(result, expected) {
		t.Error("hmacSHA256 result doesn't match standard library")
	}
}

func TestIsZero(t *testing.T) {
	if !isZero(make([]byte, 32)) {
		t.Error("expected all-zeros to be zero")
	}
	nonzero := make([]byte, 32)
	nonzero[16] = 1
	if isZero(nonzero) {
		t.Error("expected non-zeros to not be zero")
	}
}

func TestGenerateNtorKeypair(t *testing.T) {
	kp, err := GenerateNtorKeypair()
	if err != nil {
		t.Fatalf("GenerateNtorKeypair: %v", err)
	}

	// Verify public key matches private key.
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("compute public key: %v", err)
	}
	if !bytes.Equal(pub, kp.Public[:]) {
		t.Error("public key doesn't match derived value")
	}
}

func TestNtorHandshakeSimulated(t *testing.T) {
	// Simulate a full ntor handshake between client and server.

	// Server's static keypair (b, B).
	serverKP, err := GenerateNtorKeypair()
	if err != nil {
		t.Fatalf("generate server keypair: %v", err)
	}

	// Server's identity (20-byte NodeID).
	var serverID NodeID
	copy(serverID[:], []byte("01234567890123456789"))

	// CLIENT SIDE: Create handshake.
	client, err := NewNtorClientHandshake(serverID, serverKP.Public)
	if err != nil {
		t.Fatalf("NewNtorClientHandshake: %v", err)
	}
	clientData := client.ClientHandshakeData()
	if len(clientData) != NodeIDLen+32+32 {
		t.Fatalf("client data len = %d, want %d", len(clientData), NodeIDLen+32+32)
	}

	// SERVER SIDE: Process client data and generate response.
	// Parse client data.
	recvID := clientData[:NodeIDLen]
	if !bytes.Equal(recvID, serverID[:]) {
		t.Fatal("server ID mismatch")
	}
	recvB := clientData[NodeIDLen : NodeIDLen+32]
	if !bytes.Equal(recvB, serverKP.Public[:]) {
		t.Fatal("server PK mismatch")
	}
	var X NtorPublicKey
	copy(X[:], clientData[NodeIDLen+32:])

	// Server generates ephemeral keypair (y, Y).
	serverEphKP, err := GenerateNtorKeypair()
	if err != nil {
		t.Fatalf("generate server ephemeral: %v", err)
	}

	// Server computes shared secrets.
	xy, err := curve25519.X25519(serverEphKP.Private[:], X[:])
	if err != nil {
		t.Fatalf("server EXP(X,y): %v", err)
	}
	xb, err := curve25519.X25519(serverKP.Private[:], X[:])
	if err != nil {
		t.Fatalf("server EXP(X,b): %v", err)
	}

	// secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
	secretInput := make([]byte, 0, 256)
	secretInput = append(secretInput, xy...)
	secretInput = append(secretInput, xb...)
	secretInput = append(secretInput, serverID[:]...)
	secretInput = append(secretInput, serverKP.Public[:]...)
	secretInput = append(secretInput, X[:]...)
	secretInput = append(secretInput, serverEphKP.Public[:]...)
	secretInput = append(secretInput, []byte(NtorProtoID)...)

	serverKeySeed := hmacSHA256([]byte(NtorTKey), secretInput)
	verify := hmacSHA256([]byte(NtorTVerify), secretInput)

	authInput := make([]byte, 0, 256)
	authInput = append(authInput, verify...)
	authInput = append(authInput, serverID[:]...)
	authInput = append(authInput, serverKP.Public[:]...)
	authInput = append(authInput, serverEphKP.Public[:]...)
	authInput = append(authInput, X[:]...)
	authInput = append(authInput, []byte(NtorProtoID)...)
	authInput = append(authInput, []byte("Server")...)

	auth := hmacSHA256([]byte(NtorTMAC), authInput)

	// Server response: Y | AUTH
	serverResponse := make([]byte, 64)
	copy(serverResponse[:32], serverEphKP.Public[:])
	copy(serverResponse[32:], auth)

	// CLIENT SIDE: Complete handshake.
	result, err := client.Complete(serverResponse)
	if err != nil {
		t.Fatalf("client Complete: %v", err)
	}

	// Verify key seeds match.
	if !bytes.Equal(result.KeySeed[:], serverKeySeed) {
		t.Error("key seeds don't match")
	}
}

func TestNtorHandshakeBadAuth(t *testing.T) {
	serverKP, _ := GenerateNtorKeypair()
	var serverID NodeID

	client, _ := NewNtorClientHandshake(serverID, serverKP.Public)

	// Bad server response (random bytes).
	badResponse := make([]byte, 64)
	_, err := client.Complete(badResponse)
	if err == nil {
		t.Error("expected error for bad auth")
	}
}

func TestKDFRFC5869(t *testing.T) {
	keySeed := bytes.Repeat([]byte{0x42}, 32)

	// Request different lengths.
	for _, length := range []int{16, 32, 64, 92, 128} {
		result := KDFRFC5869(keySeed, length)
		if len(result) != length {
			t.Errorf("KDFRFC5869(%d) returned %d bytes", length, len(result))
		}
	}

	// Same input should produce same output.
	r1 := KDFRFC5869(keySeed, 92)
	r2 := KDFRFC5869(keySeed, 92)
	if !bytes.Equal(r1, r2) {
		t.Error("KDFRFC5869 not deterministic")
	}

	// Different seeds should produce different output.
	keySeed2 := bytes.Repeat([]byte{0x43}, 32)
	r3 := KDFRFC5869(keySeed2, 92)
	if bytes.Equal(r1, r3) {
		t.Error("different seeds produced same output")
	}
}

func TestDeriveCircuitKeys(t *testing.T) {
	keySeed := bytes.Repeat([]byte{0xAB}, 32)
	keys := DeriveCircuitKeys(keySeed)

	if len(keys.ForwardDigest) != DigestLen {
		t.Errorf("ForwardDigest len = %d, want %d", len(keys.ForwardDigest), DigestLen)
	}
	if len(keys.BackwardDigest) != DigestLen {
		t.Errorf("BackwardDigest len = %d, want %d", len(keys.BackwardDigest), DigestLen)
	}
	if len(keys.ForwardKey) != KeyLen {
		t.Errorf("ForwardKey len = %d, want %d", len(keys.ForwardKey), KeyLen)
	}
	if len(keys.BackwardKey) != KeyLen {
		t.Errorf("BackwardKey len = %d, want %d", len(keys.BackwardKey), KeyLen)
	}
	if len(keys.KH) != DigestLen {
		t.Errorf("KH len = %d, want %d", len(keys.KH), DigestLen)
	}

	// Ensure all keys are non-zero.
	if isZero(keys.ForwardKey) {
		t.Error("ForwardKey is all zeros")
	}
	if isZero(keys.BackwardKey) {
		t.Error("BackwardKey is all zeros")
	}
}

func TestRelayCryptoEncryptDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	seed := bytes.Repeat([]byte{0x01}, 20)

	enc, err := NewRelayCrypto(key, seed)
	if err != nil {
		t.Fatalf("NewRelayCrypto (enc): %v", err)
	}
	dec, err := NewRelayCrypto(key, seed)
	if err != nil {
		t.Fatalf("NewRelayCrypto (dec): %v", err)
	}

	plaintext := []byte("Hello, Tor relay cell encryption!")
	original := make([]byte, len(plaintext))
	copy(original, plaintext)

	// Encrypt.
	enc.Encrypt(plaintext)
	if bytes.Equal(plaintext, original) {
		t.Error("encryption didn't change data")
	}

	// Decrypt.
	dec.Decrypt(plaintext)
	if !bytes.Equal(plaintext, original) {
		t.Error("decryption didn't restore original data")
	}
}

func TestRelayCryptoDigest(t *testing.T) {
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	seed := bytes.Repeat([]byte{0x01}, 20)

	rc, err := NewRelayCrypto(key, seed)
	if err != nil {
		t.Fatalf("NewRelayCrypto: %v", err)
	}

	// Digest should be deterministic.
	rc.UpdateDigest([]byte("test data"))
	d1 := rc.DigestValue()
	if len(d1) != 20 { // SHA-1 output
		t.Errorf("digest len = %d, want 20", len(d1))
	}

	// Adding more data should change digest.
	rc.UpdateDigest([]byte("more data"))
	d2 := rc.DigestValue()
	if bytes.Equal(d1, d2) {
		t.Error("digest didn't change after update")
	}
}

func TestRelayCryptoStreamContinuity(t *testing.T) {
	// Verify that successive encrypt/decrypt operations maintain CTR state.
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	seed := bytes.Repeat([]byte{0x00}, 20)

	enc, _ := NewRelayCrypto(key, seed)
	dec, _ := NewRelayCrypto(key, seed)

	for i := 0; i < 10; i++ {
		data := bytes.Repeat([]byte{byte(i)}, 509)
		original := make([]byte, len(data))
		copy(original, data)

		enc.Encrypt(data)
		dec.Decrypt(data)

		if !bytes.Equal(data, original) {
			t.Errorf("round %d: data mismatch after encrypt/decrypt", i)
		}
	}
}
