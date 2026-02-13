package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding"
	"fmt"
	"hash"

	"golang.org/x/crypto/sha3"
)

// RelayCrypto holds the stream cipher and running digest for one direction
// of a single hop in a Tor circuit.
type RelayCrypto struct {
	cipher cipher.Stream
	digest hash.Hash
}

// NewRelayCrypto creates a new RelayCrypto with the given AES key and digest seed.
func NewRelayCrypto(key []byte, digestSeed []byte) (*RelayCrypto, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	// AES-CTR with IV of all zeros per tor-spec.
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)

	// Initialize running digest (SHA-1) with seed.
	h := sha1.New()
	h.Write(digestSeed)

	return &RelayCrypto{
		cipher: stream,
		digest: h,
	}, nil
}

// Encrypt encrypts the data in-place using AES-128-CTR.
func (rc *RelayCrypto) Encrypt(data []byte) {
	rc.cipher.XORKeyStream(data, data)
}

// Decrypt decrypts the data in-place using AES-128-CTR.
// (Same as Encrypt since CTR mode is symmetric.)
func (rc *RelayCrypto) Decrypt(data []byte) {
	rc.cipher.XORKeyStream(data, data)
}

// UpdateDigest adds data to the running SHA-1 digest.
func (rc *RelayCrypto) UpdateDigest(data []byte) {
	rc.digest.Write(data)
}

// DigestValue returns the current running digest value (20 bytes for SHA-1, 32 for SHA3-256).
func (rc *RelayCrypto) DigestValue() []byte {
	// We need to get the digest without resetting the running state.
	// hash.Hash.Sum(nil) appends the current hash to nil, without modifying state.
	return rc.digest.Sum(nil)
}

// SnapshotDigest returns a serialized snapshot of the running digest state.
func (rc *RelayCrypto) SnapshotDigest() ([]byte, error) {
	m, ok := rc.digest.(encoding.BinaryMarshaler)
	if !ok {
		return nil, fmt.Errorf("digest does not support snapshotting")
	}
	return m.MarshalBinary()
}

// RestoreDigest restores a previously snapshotted running digest state.
func (rc *RelayCrypto) RestoreDigest(snapshot []byte) error {
	u, ok := rc.digest.(encoding.BinaryUnmarshaler)
	if !ok {
		return fmt.Errorf("digest does not support restore")
	}
	return u.UnmarshalBinary(snapshot)
}

// NewRelayCryptoSHA3 creates a RelayCrypto using AES-256-CTR + SHA3-256.
// This is used for the virtual HS hop on rendezvous circuits.
func NewRelayCryptoSHA3(key []byte, digestSeed []byte) (*RelayCrypto, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES-256 cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)

	h := sha3.New256()
	h.Write(digestSeed)

	return &RelayCrypto{
		cipher: stream,
		digest: h,
	}, nil
}
