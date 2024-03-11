package crypto_test

import (
	"encoding/hex"
	"rotten-onion-tor/tor/crypto"
	"testing"
)

func TestGenerateCurve25519KeyPair(t *testing.T) {
	kp, err := crypto.GenerateCurve25519KeyPair()
	if err != nil {
		t.Error(err)
		return
	}

	t.Log("Private key:", hex.EncodeToString(kp.PrivateKey[:]))
	t.Log("Public key:", hex.EncodeToString(kp.PublicKey[:]))
}
