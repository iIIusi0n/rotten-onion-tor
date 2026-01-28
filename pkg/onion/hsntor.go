package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	torcrypto "rotten-onion-tor/pkg/crypto"

	"golang.org/x/crypto/curve25519"
)

// HS-ntor protocol constants per rend-spec-v3.
const (
	HSNtorProtoID   = "tor-hs-ntor-curve25519-sha3-256-1"
	HSNtorTHSEnc    = HSNtorProtoID + ":hs_key_extract"
	HSNtorTHSVerify = HSNtorProtoID + ":hs_verify"
	HSNtorTHSMAC    = HSNtorProtoID + ":hs_mac"
	HSNtorMHSExpand = HSNtorProtoID + ":hs_key_expand"
)

// HSNtorClientState holds the client-side state during an hs-ntor handshake.
type HSNtorClientState struct {
	EphemeralPrivate [32]byte // x
	EphemeralPublic  [32]byte // X
	EncKey           [32]byte // B - service's enc-key ntor from descriptor
	AuthKey          []byte   // KP_hs_ipt_sid - intro point auth key
	Subcredential    []byte
}

// HSNtorHandshakeResult holds the result of an hs-ntor handshake.
type HSNtorHandshakeResult struct {
	NtorKeySeed []byte // For deriving circuit keys
}

// NewHSNtorClient creates a new client-side hs-ntor handshake state.
func NewHSNtorClient(encKey, authKey, subcredential []byte) (*HSNtorClientState, error) {
	// Generate ephemeral keypair.
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("compute public key: %w", err)
	}

	state := &HSNtorClientState{
		EphemeralPrivate: priv,
		AuthKey:          authKey,
		Subcredential:    subcredential,
	}
	copy(state.EphemeralPublic[:], pub)
	copy(state.EncKey[:], encKey)

	return state, nil
}

// CreateIntroduce1Payload creates the encrypted part of an INTRODUCE1 cell.
// Returns the client public key (X), encrypted data, and MAC.
//
// Per rend-spec-v3:
//
//	intro_secret_hs_input = EXP(B, x) || AUTH_KEY || X || B || PROTOID
//	info = m_hsexpand || subcredential
//	hs_keys = SHAKE256_KDF(intro_secret_hs_input || t_hsenc || info, S_KEY_LEN + MAC_KEY_LEN)
//	ENC_KEY = hs_keys[0:32], MAC_KEY = hs_keys[32:64]
//	encrypted = AES-256-CTR(IV=0, ENC_KEY, plaintext)
//	MAC = HSMAC(MAC_KEY, auth_key_type_header || X || encrypted)
func (s *HSNtorClientState) CreateIntroduce1Payload(plaintext []byte) (clientPK []byte, encrypted []byte, mac []byte, err error) {
	// EXP(B, x)
	bx, err := curve25519.X25519(s.EphemeralPrivate[:], s.EncKey[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ecdh B*x: %w", err)
	}

	// intro_secret_hs_input = EXP(B,x) || AUTH_KEY || X || B || PROTOID
	secretInput := make([]byte, 0, 32+len(s.AuthKey)+32+32+len(HSNtorProtoID))
	secretInput = append(secretInput, bx...)
	secretInput = append(secretInput, s.AuthKey...)
	secretInput = append(secretInput, s.EphemeralPublic[:]...)
	secretInput = append(secretInput, s.EncKey[:]...)
	secretInput = append(secretInput, []byte(HSNtorProtoID)...)

	// info = m_hsexpand || subcredential
	info := append([]byte(HSNtorMHSExpand), s.Subcredential...)

	// KDF input: intro_secret_hs_input || t_hsenc || info
	kdfInput := make([]byte, 0, len(secretInput)+len(HSNtorTHSEnc)+len(info))
	kdfInput = append(kdfInput, secretInput...)
	kdfInput = append(kdfInput, []byte(HSNtorTHSEnc)...)
	kdfInput = append(kdfInput, info...)

	// Derive keys: S_KEY_LEN(32) + MAC_KEY_LEN(32) = 64
	keys := torcrypto.SHAKE256KDF(kdfInput, 64)
	encKey := keys[0:32]
	macKey := keys[32:64]

	// Encrypt plaintext with AES-256-CTR(IV=0, encKey).
	encrypted = make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encrypted, encrypted)

	// MAC input per spec: the content after ENCRYPTED_DATA in the INTRODUCE1 cell
	// which includes the auth_key_type header bytes + X + encrypted data.
	// Actually per spec section 3.3.1:
	// MAC = MAC(MAC_KEY, AUTH_KEY_TYPE(1) || AUTH_KEY_LEN(2) || AUTH_KEY || X || ENCRYPTED)
	// But we need to check: the MAC covers the unencrypted INTRODUCE1 header up to encrypted.
	// Per rend-spec: MAC covers everything from CLIENT_PK onwards... let me check.
	// Actually from the spec: The MAC is computed over:
	// msg = AUTH_KEY_TYPE || AUTH_KEY_LEN || AUTH_KEY || N_EXTENSIONS || <extensions> || CLIENT_PK || ENCRYPTED_DATA
	// Hmm, that's the full introduce1 inner content. But we don't have all that here.
	// Let's return the raw pieces and let the caller build the full MAC.

	// For simplicity, return clientPK and encrypted, and compute MAC externally.
	// Actually let me re-read the spec more carefully.
	//
	// From rend-spec-v3 section 3.3.1, the INTRODUCE1 cell encrypted portion:
	// ENCRYPTED portion is encrypted with ENC_KEY using AES-256-CTR.
	// MAC is: MAC(MAC_KEY, intro_cell_body_up_to_but_not_including_MAC)
	// where intro_cell_body is from the ENCRYPTED portion header.
	//
	// We'll compute MAC externally in the caller that knows the full message.

	return s.EphemeralPublic[:], encrypted, macKey, nil
}

// CompleteRendezvous processes RENDEZVOUS2 response and derives HS circuit keys.
// Per rend-spec-v3:
//
//	Y = rendezvous2Data[0:32]
//	AUTH = rendezvous2Data[32:64]
//	rend_secret_hs_input = EXP(Y,x) || EXP(B,x) || AUTH_KEY || B || X || Y || PROTOID
//	NTOR_KEY_SEED = MAC(rend_secret_hs_input, t_hsenc)
//	verify = MAC(rend_secret_hs_input, t_hsverify)
//	auth_input = verify || AUTH_KEY || B || Y || X || PROTOID || "Server"
//	Verify: AUTH == MAC(auth_input, t_hsmac)
func (s *HSNtorClientState) CompleteRendezvous(rendezvous2Data []byte) (*HSNtorHandshakeResult, error) {
	if len(rendezvous2Data) < 64 {
		return nil, fmt.Errorf("RENDEZVOUS2 data too short: %d", len(rendezvous2Data))
	}

	var Y [32]byte
	copy(Y[:], rendezvous2Data[0:32])
	auth := rendezvous2Data[32:64]

	// EXP(Y, x)
	yx, err := curve25519.X25519(s.EphemeralPrivate[:], Y[:])
	if err != nil {
		return nil, fmt.Errorf("ecdh Y*x: %w", err)
	}

	// EXP(B, x)
	bx, err := curve25519.X25519(s.EphemeralPrivate[:], s.EncKey[:])
	if err != nil {
		return nil, fmt.Errorf("ecdh B*x: %w", err)
	}

	// rend_secret_hs_input = EXP(Y,x) || EXP(B,x) || AUTH_KEY || B || X || Y || PROTOID
	rendSecretInput := make([]byte, 0, 32+32+len(s.AuthKey)+32+32+32+len(HSNtorProtoID))
	rendSecretInput = append(rendSecretInput, yx...)
	rendSecretInput = append(rendSecretInput, bx...)
	rendSecretInput = append(rendSecretInput, s.AuthKey...)
	rendSecretInput = append(rendSecretInput, s.EncKey[:]...)
	rendSecretInput = append(rendSecretInput, s.EphemeralPublic[:]...)
	rendSecretInput = append(rendSecretInput, Y[:]...)
	rendSecretInput = append(rendSecretInput, []byte(HSNtorProtoID)...)

	// NTOR_KEY_SEED = MAC(rend_secret_hs_input, t_hsenc)
	// Spec: MAC(key, msg) = SHA3_256(key_len || key || msg)
	// So MAC(rend_secret_hs_input, t_hsenc) = HSMAC(key=rend_secret_hs_input, msg=t_hsenc)
	ntorKeySeed := torcrypto.HSMAC(rendSecretInput, []byte(HSNtorTHSEnc))

	// verify = MAC(rend_secret_hs_input, t_hsverify)
	verify := torcrypto.HSMAC(rendSecretInput, []byte(HSNtorTHSVerify))

	// auth_input = verify || AUTH_KEY || B || Y || X || PROTOID || "Server"
	authInput := make([]byte, 0, 32+len(s.AuthKey)+32+32+32+len(HSNtorProtoID)+6)
	authInput = append(authInput, verify...)
	authInput = append(authInput, s.AuthKey...)
	authInput = append(authInput, s.EncKey[:]...)
	authInput = append(authInput, Y[:]...)
	authInput = append(authInput, s.EphemeralPublic[:]...)
	authInput = append(authInput, []byte(HSNtorProtoID)...)
	authInput = append(authInput, []byte("Server")...)

	// Verify AUTH == MAC(auth_input, t_hsmac)
	expectedAuth := torcrypto.HSMAC(authInput, []byte(HSNtorTHSMAC))
	if !bytesEqual(expectedAuth, auth) {
		return nil, fmt.Errorf("RENDEZVOUS2 authentication failed")
	}

	return &HSNtorHandshakeResult{
		NtorKeySeed: ntorKeySeed,
	}, nil
}

// DeriveHSCircuitKeys derives AES-256 + SHA3-256 circuit keys from the hs-ntor key seed.
// Per rend-spec-v3:
//
//	keys = SHAKE256_KDF(NTOR_KEY_SEED || m_hsexpand, Df(32) + Db(32) + Kf(32) + Kb(32))
func DeriveHSCircuitKeys(ntorKeySeed []byte) *HSCircuitKeysResult {
	kdfInput := make([]byte, 0, len(ntorKeySeed)+len(HSNtorMHSExpand))
	kdfInput = append(kdfInput, ntorKeySeed...)
	kdfInput = append(kdfInput, []byte(HSNtorMHSExpand)...)

	// 32*4 = 128 bytes: Df(32) + Db(32) + Kf(32) + Kb(32)
	keys := torcrypto.SHAKE256KDF(kdfInput, 128)

	return &HSCircuitKeysResult{
		ForwardDigest:  keys[0:32],
		BackwardDigest: keys[32:64],
		ForwardKey:     keys[64:96],
		BackwardKey:    keys[96:128],
	}
}

// HSCircuitKeysResult holds the derived HS circuit keys.
type HSCircuitKeysResult struct {
	ForwardDigest  []byte // 32 bytes (SHA3-256 digest seed)
	BackwardDigest []byte // 32 bytes
	ForwardKey     []byte // 32 bytes (AES-256 key)
	BackwardKey    []byte // 32 bytes
}
