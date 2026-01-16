package crypto

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// SHA3_256 computes the SHA3-256 hash of data.
func SHA3_256(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

// SHAKE256KDF derives numBytes of output from input using SHAKE-256.
func SHAKE256KDF(input []byte, numBytes int) []byte {
	h := sha3.NewShake256()
	h.Write(input)
	out := make([]byte, numBytes)
	h.Read(out)
	return out
}

// HSMAC computes the HS MAC per rend-spec-v3:
//
//	MAC(key, msg) = SHA3_256(key_len_as_8_bytes || key || msg)
func HSMAC(key, msg []byte) []byte {
	keyLen := make([]byte, 8)
	binary.BigEndian.PutUint64(keyLen, uint64(len(key)))
	h := sha3.New256()
	h.Write(keyLen)
	h.Write(key)
	h.Write(msg)
	return h.Sum(nil)
}
