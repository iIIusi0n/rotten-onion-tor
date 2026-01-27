// Package onion implements v3 onion service client support.
package onion

import (
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	torcrypto "rotten-onion-tor/pkg/crypto"
)

// OnionAddress holds a parsed v3 .onion address.
type OnionAddress struct {
	PublicKey [32]byte // Ed25519 public key
	Checksum  [2]byte
	Version   byte
}

// ParseOnionAddress parses a v3 .onion address and validates its checksum.
// The address can be with or without the ".onion" suffix.
func ParseOnionAddress(address string) (*OnionAddress, error) {
	// Strip .onion suffix if present.
	addr := strings.TrimSuffix(address, ".onion")

	// v3 onion addresses are 56 characters of base32.
	if len(addr) != 56 {
		return nil, fmt.Errorf("invalid onion address length: %d (expected 56)", len(addr))
	}

	// Decode base32 (uppercase).
	decoded, err := base32.StdEncoding.DecodeString(strings.ToUpper(addr))
	if err != nil {
		return nil, fmt.Errorf("base32 decode: %w", err)
	}

	// decoded = PUBKEY(32) || CHECKSUM(2) || VERSION(1) = 35 bytes
	if len(decoded) != 35 {
		return nil, fmt.Errorf("decoded length %d, expected 35", len(decoded))
	}

	oa := &OnionAddress{
		Version: decoded[34],
	}
	copy(oa.PublicKey[:], decoded[0:32])
	copy(oa.Checksum[:], decoded[32:34])

	if oa.Version != 3 {
		return nil, fmt.Errorf("unsupported onion address version: %d", oa.Version)
	}

	// Validate checksum: SHA3_256(".onion checksum" || PUBKEY || VERSION)[:2]
	checksumInput := []byte(".onion checksum")
	checksumInput = append(checksumInput, oa.PublicKey[:]...)
	checksumInput = append(checksumInput, oa.Version)
	expectedChecksum := torcrypto.SHA3_256(checksumInput)

	if oa.Checksum[0] != expectedChecksum[0] || oa.Checksum[1] != expectedChecksum[1] {
		return nil, fmt.Errorf("checksum mismatch")
	}

	return oa, nil
}

// TimePeriodLength is the default HS time period length in minutes.
const TimePeriodLength = 1440 // 24 hours

// TimePeriodRotationOffset is the offset in minutes from the epoch.
const TimePeriodRotationOffset = 720 // 12 hours

// ComputeTimePeriod computes the current time period number.
// Per rend-spec-v3: TP# = (minutes_since_epoch - offset) / period_length
func ComputeTimePeriod(validAfter time.Time, periodLength uint64) uint64 {
	minutesSinceEpoch := uint64(validAfter.Unix() / 60)
	return (minutesSinceEpoch - TimePeriodRotationOffset) / periodLength
}

// ComputeBlindedKey computes the blinded public key for a given time period.
func ComputeBlindedKey(pubkey []byte, periodNum, periodLength uint64) ([]byte, error) {
	return torcrypto.Ed25519BlindPublicKey(pubkey, periodNum, periodLength)
}

// ComputeSubcredential computes the subcredential for an onion service.
// Per rend-spec-v3:
//
//	credential = SHA3_256("credential" || public_key)
//	subcredential = SHA3_256("subcredential" || credential || blinded_key)
func ComputeSubcredential(pubkey, blindedKey []byte) []byte {
	credential := torcrypto.SHA3_256(append([]byte("credential"), pubkey...))
	sub := []byte("subcredential")
	sub = append(sub, credential...)
	sub = append(sub, blindedKey...)
	return torcrypto.SHA3_256(sub)
}
