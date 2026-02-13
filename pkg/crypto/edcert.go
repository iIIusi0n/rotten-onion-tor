package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	ed25519CertVersion               = 1
	ed25519CertExtensionSignedWithEd = 4
	ed25519CertExtFlagAffectsValid   = 1
)

// Ed25519CertExtension represents a parsed Tor Ed25519 certificate extension.
type Ed25519CertExtension struct {
	Type  byte
	Flags byte
	Data  []byte
}

// Ed25519Cert is a parsed Tor Ed25519 certificate as specified in cert-spec.
type Ed25519Cert struct {
	Version      byte
	CertType     byte
	ExpiresAt    time.Time
	KeyType      byte
	CertifiedKey [32]byte
	Extensions   []Ed25519CertExtension
	Signature    [64]byte
	SignedData   []byte
}

// ParseEd25519Cert parses a Tor Ed25519 certificate.
func ParseEd25519Cert(raw []byte) (*Ed25519Cert, error) {
	// VERSION(1) | CERT_TYPE(1) | EXPIRATION(4) | KEY_TYPE(1) | KEY(32) |
	// N_EXT(1) | extensions... | SIG(64)
	const headerLen = 1 + 1 + 4 + 1 + 32 + 1
	if len(raw) < headerLen+64 {
		return nil, fmt.Errorf("ed25519 cert too short: %d", len(raw))
	}

	c := &Ed25519Cert{}
	off := 0

	c.Version = raw[off]
	off++
	if c.Version != ed25519CertVersion {
		return nil, fmt.Errorf("unsupported cert version: %d", c.Version)
	}

	c.CertType = raw[off]
	off++

	expiresHours := binary.BigEndian.Uint32(raw[off : off+4])
	off += 4
	c.ExpiresAt = time.Unix(int64(expiresHours)*3600, 0).UTC()

	c.KeyType = raw[off]
	off++
	copy(c.CertifiedKey[:], raw[off:off+32])
	off += 32

	nExt := int(raw[off])
	off++

	extensions := make([]Ed25519CertExtension, 0, nExt)
	for i := 0; i < nExt; i++ {
		if off+4 > len(raw)-64 {
			return nil, fmt.Errorf("certificate extension %d truncated", i)
		}
		extLen := int(binary.BigEndian.Uint16(raw[off : off+2]))
		off += 2
		extType := raw[off]
		off++
		extFlags := raw[off]
		off++

		if off+extLen > len(raw)-64 {
			return nil, fmt.Errorf("certificate extension %d overruns body", i)
		}
		extData := make([]byte, extLen)
		copy(extData, raw[off:off+extLen])
		off += extLen

		extensions = append(extensions, Ed25519CertExtension{
			Type:  extType,
			Flags: extFlags,
			Data:  extData,
		})
	}
	c.Extensions = extensions

	if off+64 != len(raw) {
		return nil, fmt.Errorf("certificate has %d unexpected trailing bytes", len(raw)-(off+64))
	}

	c.SignedData = make([]byte, off)
	copy(c.SignedData, raw[:off])
	copy(c.Signature[:], raw[off:off+64])

	return c, nil
}

// SigningKey returns the ed25519 signing key from extension type 4.
func (c *Ed25519Cert) SigningKey() ([]byte, error) {
	for _, ext := range c.Extensions {
		if ext.Type != ed25519CertExtensionSignedWithEd {
			continue
		}
		if len(ext.Data) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signed-with extension has invalid length %d", len(ext.Data))
		}
		k := make([]byte, ed25519.PublicKeySize)
		copy(k, ext.Data)
		return k, nil
	}
	return nil, fmt.Errorf("missing signed-with-ed25519-key extension")
}

// Verify checks extension handling, validity window, and signature.
func (c *Ed25519Cert) Verify(signingKey []byte, now time.Time) error {
	if len(signingKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 signing key length: %d", len(signingKey))
	}
	if now.After(c.ExpiresAt) {
		return fmt.Errorf("certificate expired at %s", c.ExpiresAt.Format(time.RFC3339))
	}

	for _, ext := range c.Extensions {
		switch ext.Type {
		case ed25519CertExtensionSignedWithEd:
			if len(ext.Data) != ed25519.PublicKeySize {
				return fmt.Errorf("invalid signed-with extension length: %d", len(ext.Data))
			}
			for i := 0; i < ed25519.PublicKeySize; i++ {
				if ext.Data[i] != signingKey[i] {
					return fmt.Errorf("signed-with extension does not match signer key")
				}
			}
		default:
			if ext.Flags&ed25519CertExtFlagAffectsValid != 0 {
				return fmt.Errorf("unsupported certificate extension type %d affects validation", ext.Type)
			}
		}
	}

	if !ed25519.Verify(ed25519.PublicKey(signingKey), c.SignedData, c.Signature[:]) {
		return fmt.Errorf("ed25519 certificate signature verification failed")
	}
	return nil
}
