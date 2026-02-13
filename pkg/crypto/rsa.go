package crypto

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

// VerifyRSAPKCS1v15NoOID verifies a Tor-style RSA PKCS#1 v1.5 signature where
// the signed payload is the digest bytes directly (without ASN.1 DigestInfo).
func VerifyRSAPKCS1v15NoOID(pub *rsa.PublicKey, digest, sig []byte) error {
	if pub == nil {
		return fmt.Errorf("nil RSA public key")
	}
	k := (pub.N.BitLen() + 7) / 8
	if len(sig) != k {
		return fmt.Errorf("signature length = %d, want %d", len(sig), k)
	}
	if len(digest) == 0 {
		return fmt.Errorf("empty digest")
	}

	s := new(big.Int).SetBytes(sig)
	if s.Sign() <= 0 || s.Cmp(pub.N) >= 0 {
		return fmt.Errorf("signature representative out of range")
	}

	e := big.NewInt(int64(pub.E))
	m := new(big.Int).Exp(s, e, pub.N)
	em := m.FillBytes(make([]byte, k))

	// Expected block: 0x00 0x01 0xFF... 0x00 || digest
	if len(em) < 3+len(digest) {
		return fmt.Errorf("encoded message too short")
	}
	if em[0] != 0x00 || em[1] != 0x01 {
		return fmt.Errorf("invalid PKCS#1 block header")
	}
	i := 2
	for i < len(em) && em[i] == 0xFF {
		i++
	}
	if i < 10 { // require at least 8 bytes of 0xFF padding.
		return fmt.Errorf("insufficient PKCS#1 padding")
	}
	if i >= len(em) || em[i] != 0x00 {
		return fmt.Errorf("missing PKCS#1 separator")
	}
	i++

	if len(em)-i != len(digest) {
		return fmt.Errorf("digest length mismatch in PKCS#1 block")
	}
	for j := 0; j < len(digest); j++ {
		if em[i+j] != digest[j] {
			return fmt.Errorf("digest mismatch")
		}
	}
	return nil
}
