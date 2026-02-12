// Package onion implements v3 onion service client support.
package onion

import (
	"encoding/base32"
	"fmt"
	"math/big"
	"strings"
	"time"

	torcrypto "rotten-onion-tor/pkg/crypto"

	"filippo.io/edwards25519"
)

// OnionAddress holds a parsed v3 .onion address.
type OnionAddress struct {
	PublicKey [32]byte // Ed25519 public key
	Checksum  [2]byte
	Version   byte
}

const onionV3Base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567"

var ed25519GroupOrder = mustBigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989")

// ParseOnionAddress parses a v3 .onion address and validates its checksum.
// The address can be with or without the ".onion" suffix.
func ParseOnionAddress(address string) (*OnionAddress, error) {
	addr := normalizeOnionAddress(address)

	// v3 onion addresses are 56 characters of base32.
	if len(addr) != 56 {
		return nil, fmt.Errorf("invalid onion address length: %d (expected 56)", len(addr))
	}
	if !isValidOnionBase32(addr) {
		return nil, fmt.Errorf("invalid onion address characters")
	}

	// Decode base32 (uppercase, no padding).
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(addr))
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
	if !hasNoTorsionComponent(oa.PublicKey[:]) {
		return nil, fmt.Errorf("public key has non-zero torsion component")
	}

	return oa, nil
}

func normalizeOnionAddress(address string) string {
	addr := strings.TrimSpace(strings.ToLower(address))
	return strings.TrimSuffix(addr, ".onion")
}

func isValidOnionBase32(addr string) bool {
	for i := 0; i < len(addr); i++ {
		if !strings.ContainsRune(onionV3Base32Alphabet, rune(addr[i])) {
			return false
		}
	}
	return true
}

// hasNoTorsionComponent checks whether an Ed25519 point is in the prime-order
// subgroup by verifying [L]A == 0, where L is the Ed25519 group order.
func hasNoTorsionComponent(pubkey []byte) bool {
	point, err := new(edwards25519.Point).SetBytes(pubkey)
	if err != nil {
		return false
	}

	acc := edwards25519.NewIdentityPoint()
	addend := new(edwards25519.Point).Set(point)

	for i := 0; i < ed25519GroupOrder.BitLen(); i++ {
		if ed25519GroupOrder.Bit(i) == 1 {
			acc.Add(acc, addend)
		}
		addend.Add(addend, addend)
	}

	return acc.Equal(edwards25519.NewIdentityPoint()) == 1
}

func mustBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid big integer constant")
	}
	return n
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
