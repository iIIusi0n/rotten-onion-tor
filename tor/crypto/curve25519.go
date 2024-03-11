package crypto

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

type Curve25519KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func generateCurve25519KeyPairFromRandom(r io.Reader) (*Curve25519KeyPair, error) {
	kp := &Curve25519KeyPair{}

	_, err := io.ReadFull(r, kp.PrivateKey[:])
	if err != nil {
		return nil, err
	}

	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)

	return kp, nil
}

func GenerateCurve25519KeyPair() (*Curve25519KeyPair, error) {
	return generateCurve25519KeyPairFromRandom(rand.Reader)
}
