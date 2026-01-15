// Package crypto implements Tor's cryptographic operations including
// the ntor handshake, AES-CTR stream cipher, and key derivation functions.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// ntor handshake constants per tor-spec section 5.1.4.
const (
	NtorProtoID  = "ntor-curve25519-sha256-1"
	NtorTMAC     = NtorProtoID + ":mac"
	NtorTKey     = NtorProtoID + ":key_extract"
	NtorTVerify  = NtorProtoID + ":verify"
	NtorMExpand  = NtorProtoID + ":key_expand"

	KeyLen    = 16 // AES-128 key length
	DigestLen = 20 // SHA-1 digest length
	NodeIDLen = 20 // SHA-1 of DER-encoded RSA identity key
	KeySeedLen = 32 // HMAC-SHA256 output
)

// NtorPublicKey is a Curve25519 public key (32 bytes).
type NtorPublicKey [32]byte

// NtorSecretKey is a Curve25519 secret key (32 bytes).
type NtorSecretKey [32]byte

// NodeID is the SHA-1 hash of the DER-encoded RSA identity key (20 bytes).
type NodeID [NodeIDLen]byte

// NtorKeypair holds a curve25519 keypair.
type NtorKeypair struct {
	Public  NtorPublicKey
	Private NtorSecretKey
}

// GenerateNtorKeypair creates a new random curve25519 keypair.
func GenerateNtorKeypair() (*NtorKeypair, error) {
	var priv NtorSecretKey
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("generate ntor keypair: %w", err)
	}

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("compute public key: %w", err)
	}

	kp := &NtorKeypair{Private: priv}
	copy(kp.Public[:], pub)
	return kp, nil
}

// NtorClientHandshake holds the state of a client-side ntor handshake.
type NtorClientHandshake struct {
	keypair  *NtorKeypair
	serverID NodeID
	serverPK NtorPublicKey // B - server's ntor onion key
}

// NtorHandshakeResult holds the result of a completed ntor handshake.
type NtorHandshakeResult struct {
	KeySeed [KeySeedLen]byte
	AuthMAC [KeySeedLen]byte
}

// NewNtorClientHandshake creates a new client-side ntor handshake.
func NewNtorClientHandshake(serverID NodeID, serverPK NtorPublicKey) (*NtorClientHandshake, error) {
	kp, err := GenerateNtorKeypair()
	if err != nil {
		return nil, err
	}
	return &NtorClientHandshake{
		keypair:  kp,
		serverID: serverID,
		serverPK: serverPK,
	}, nil
}

// ClientHandshakeData returns the data to send in the CREATE2 cell.
// Format: NODEID (20) | KEYID(B) (32) | CLIENT_KP(X) (32) = 84 bytes
func (h *NtorClientHandshake) ClientHandshakeData() []byte {
	data := make([]byte, 0, NodeIDLen+32+32)
	data = append(data, h.serverID[:]...)
	data = append(data, h.serverPK[:]...)
	data = append(data, h.keypair.Public[:]...)
	return data
}

// Complete processes the server's response (Y + AUTH) and derives the shared keys.
// serverData is CREATED2 HDATA: Y (32 bytes) | AUTH (32 bytes) = 64 bytes.
func (h *NtorClientHandshake) Complete(serverData []byte) (*NtorHandshakeResult, error) {
	if len(serverData) < 64 {
		return nil, fmt.Errorf("server handshake data too short: %d", len(serverData))
	}

	var Y NtorPublicKey
	copy(Y[:], serverData[:32])
	serverAuth := serverData[32:64]

	// Compute EXP(Y, x) = shared secret with ephemeral key
	yx, err := curve25519.X25519(h.keypair.Private[:], Y[:])
	if err != nil {
		return nil, fmt.Errorf("ecdh Y*x: %w", err)
	}
	// Check for all-zeros (point at infinity)
	if isZero(yx) {
		return nil, errors.New("ntor: Y*x resulted in zero")
	}

	// Compute EXP(B, x) = shared secret with static key
	bx, err := curve25519.X25519(h.keypair.Private[:], h.serverPK[:])
	if err != nil {
		return nil, fmt.Errorf("ecdh B*x: %w", err)
	}
	if isZero(bx) {
		return nil, errors.New("ntor: B*x resulted in zero")
	}

	// secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
	secretInput := make([]byte, 0, 32+32+NodeIDLen+32+32+32+len(NtorProtoID))
	secretInput = append(secretInput, yx...)
	secretInput = append(secretInput, bx...)
	secretInput = append(secretInput, h.serverID[:]...)
	secretInput = append(secretInput, h.serverPK[:]...)
	secretInput = append(secretInput, h.keypair.Public[:]...)
	secretInput = append(secretInput, Y[:]...)
	secretInput = append(secretInput, []byte(NtorProtoID)...)

	// KEY_SEED = H(secret_input, t_key) = HMAC-SHA256(key=t_key, msg=secret_input)
	keySeed := hmacSHA256([]byte(NtorTKey), secretInput)

	// verify = H(secret_input, t_verify)
	verify := hmacSHA256([]byte(NtorTVerify), secretInput)

	// auth_input = verify | ID | B | Y | X | PROTOID | "Server"
	authInput := make([]byte, 0, 32+NodeIDLen+32+32+32+len(NtorProtoID)+6)
	authInput = append(authInput, verify...)
	authInput = append(authInput, h.serverID[:]...)
	authInput = append(authInput, h.serverPK[:]...)
	authInput = append(authInput, Y[:]...)
	authInput = append(authInput, h.keypair.Public[:]...)
	authInput = append(authInput, []byte(NtorProtoID)...)
	authInput = append(authInput, []byte("Server")...)

	// AUTH = H(auth_input, t_mac)
	computedAuth := hmacSHA256([]byte(NtorTMAC), authInput)

	// Verify AUTH
	if !hmac.Equal(computedAuth, serverAuth) {
		return nil, errors.New("ntor: authentication failed - AUTH mismatch")
	}

	var result NtorHandshakeResult
	copy(result.KeySeed[:], keySeed)
	copy(result.AuthMAC[:], computedAuth)
	return &result, nil
}

// hmacSHA256 computes HMAC-SHA256(key, message).
func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
