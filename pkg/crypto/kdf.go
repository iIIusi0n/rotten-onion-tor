package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// KDFRFC5869 implements the key derivation function used with ntor.
// Per tor-spec section 5.2.2, this is HKDF-SHA256 with:
//   - IKM = keySeed (from ntor handshake)
//   - salt = t_key (constant, already used in ntor)
//   - info = m_expand
//
// The output is: K_1 | K_2 | K_3 | ...
//
//	K_1     = HMAC-SHA256(KEY_SEED, m_expand | 0x01)
//	K_(i+1) = HMAC-SHA256(KEY_SEED, K_i | m_expand | byte(i+1))
func KDFRFC5869(keySeed []byte, numBytes int) []byte {
	mExpand := []byte(NtorMExpand)
	result := make([]byte, 0, numBytes)
	var prev []byte

	for i := byte(1); len(result) < numBytes; i++ {
		h := hmac.New(sha256.New, keySeed)
		if prev != nil {
			h.Write(prev)
		}
		h.Write(mExpand)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		result = append(result, prev...)
	}

	return result[:numBytes]
}

// CircuitKeys holds the derived keys for a single hop in a circuit.
type CircuitKeys struct {
	ForwardDigest  []byte // Df - 20 bytes (SHA-1 seed for forward digest)
	BackwardDigest []byte // Db - 20 bytes (SHA-1 seed for backward digest)
	ForwardKey     []byte // Kf - 16 bytes (AES-128 key for forward encryption)
	BackwardKey    []byte // Kb - 16 bytes (AES-128 key for backward encryption)
	KH             []byte // 20 bytes nonce (used in HS protocol)
}

// DeriveCircuitKeys derives the circuit keys from a ntor handshake KEY_SEED.
// Per tor-spec 5.2.2:
//
//	Df (SHA1_LEN=20) | Db (20) | Kf (KEY_LEN=16) | Kb (16) | KH (20)
//
// Total = 92 bytes needed.
func DeriveCircuitKeys(keySeed []byte) *CircuitKeys {
	const totalLen = DigestLen + DigestLen + KeyLen + KeyLen + DigestLen // 20+20+16+16+20 = 92
	keystream := KDFRFC5869(keySeed, totalLen)

	off := 0
	ck := &CircuitKeys{}

	ck.ForwardDigest = keystream[off : off+DigestLen]
	off += DigestLen

	ck.BackwardDigest = keystream[off : off+DigestLen]
	off += DigestLen

	ck.ForwardKey = keystream[off : off+KeyLen]
	off += KeyLen

	ck.BackwardKey = keystream[off : off+KeyLen]
	off += KeyLen

	ck.KH = keystream[off : off+DigestLen]

	return ck
}
