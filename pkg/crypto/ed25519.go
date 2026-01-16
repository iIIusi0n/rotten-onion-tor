package crypto

import (
	"encoding/binary"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// Ed25519BlindPublicKey blinds an ed25519 public key for a given time period.
// Per rend-spec-v3 section A.2:
//
//	BLIND_STRING = "Derive temporary signing key" || INT_1(0)
//	h = SHA3_256(BLIND_STRING || A || s || B || N)
//
// where s is a secret param (empty for public derivation), B is Ed25519
// basepoint (not used for public key blinding -- the param_bytes), and N is
// "key-blind" || INT_8(period_num) || INT_8(period_length).
//
// Then clamp h and compute A' = h * A.
func Ed25519BlindPublicKey(pubkey []byte, periodNum, periodLength uint64) ([]byte, error) {
	if len(pubkey) != 32 {
		return nil, fmt.Errorf("ed25519 pubkey must be 32 bytes, got %d", len(pubkey))
	}

	// Compute the blinding factor.
	blindingFactor := computeBlindingFactor(pubkey, periodNum, periodLength)

	// Parse pubkey as ed25519 point.
	A, err := new(edwards25519.Point).SetBytes(pubkey)
	if err != nil {
		return nil, fmt.Errorf("parse ed25519 point: %w", err)
	}

	// Parse blinding factor as scalar.
	hScalar, err := new(edwards25519.Scalar).SetBytesWithClamping(blindingFactor[:])
	if err != nil {
		return nil, fmt.Errorf("set blinding scalar: %w", err)
	}

	// A' = h * A
	blindedPoint := new(edwards25519.Point).ScalarMult(hScalar, A)
	return blindedPoint.Bytes(), nil
}

// ed25519BasepointString is the string representation of the ed25519 basepoint
// used in key blinding per rend-spec-v3 appendix A.2.
const ed25519BasepointString = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"

// computeBlindingFactor computes the blinding factor h per rend-spec-v3.
func computeBlindingFactor(pubkey []byte, periodNum, periodLength uint64) [32]byte {
	// BLIND_STRING = "Derive temporary signing key" || INT_1(0)
	blindString := append([]byte("Derive temporary signing key"), 0x00)

	// N = "key-blind" || INT_8(period_num) || INT_8(period_length)
	nonce := []byte("key-blind")
	periodNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(periodNumBytes, periodNum)
	nonce = append(nonce, periodNumBytes...)
	periodLenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(periodLenBytes, periodLength)
	nonce = append(nonce, periodLenBytes...)

	// h = SHA3_256(BLIND_STRING || A || s || B || N)
	// s = empty (no secret param for standard services)
	// B = string representation of ed25519 basepoint per spec appendix A.2
	h := sha3.New256()
	h.Write(blindString)
	h.Write(pubkey)
	// s is empty (zero-length) for standard services
	h.Write([]byte(ed25519BasepointString))
	h.Write(nonce)

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
