package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	torcrypto "rotten-onion-tor/pkg/crypto"
)

// IntroPoint represents a parsed introduction point from an HS descriptor.
type IntroPoint struct {
	LinkSpecifiers []LinkSpecifier // For EXTEND2
	OnionKey       []byte          // curve25519 ntor key of intro point relay
	AuthKey        []byte          // ed25519 KP_hs_ipt_sid (from auth-key cert)
	EncKey         []byte          // curve25519 KP_hss_ntor (for hs-ntor)
}

// LinkSpecifier represents a link specifier for EXTEND2.
type LinkSpecifier struct {
	Type byte
	Data []byte
}

// HSDescriptor holds the parsed outer layer of an HS descriptor.
type HSDescriptor struct {
	RevisionCounter uint64
	Superencrypted  []byte // Raw superencrypted blob
	SigningKeyCert  []byte
}

// ParseHSDescriptorOuter parses the outer wrapper of an HS descriptor.
func ParseHSDescriptorOuter(body string) (*HSDescriptor, error) {
	desc := &HSDescriptor{}
	lines := strings.Split(body, "\n")

	inSuperencrypted := false
	var superencB64 strings.Builder

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		switch {
		case strings.HasPrefix(line, "revision-counter "):
			fmt.Sscanf(line, "revision-counter %d", &desc.RevisionCounter)

		case line == "-----BEGIN MESSAGE-----":
			inSuperencrypted = true

		case line == "-----END MESSAGE-----":
			inSuperencrypted = false
			decoded, err := base64DecodeFlexible(superencB64.String())
			if err != nil {
				return nil, fmt.Errorf("decode superencrypted: %w", err)
			}
			desc.Superencrypted = decoded

		default:
			if inSuperencrypted {
				superencB64.WriteString(strings.TrimSpace(line))
			}
		}
	}

	if desc.Superencrypted == nil {
		return nil, fmt.Errorf("no superencrypted data found")
	}

	return desc, nil
}

// DecryptDescriptorLayer decrypts one layer of HS descriptor encryption.
// Per rend-spec-v3 section 2.5.1.1:
//
//	secret_input = SECRET_DATA || subcredential || INT_8(revision_counter)
//	keys = SHAKE256_KDF(secret_input || SALT || STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
//	SECRET_KEY = keys[0:32], SECRET_IV = keys[32:48], MAC_KEY = keys[48:80]
//
// The encrypted blob format is: SALT(16) || ENCRYPTED || MAC(32)
func DecryptDescriptorLayer(encrypted []byte, secretData, subcredential []byte, revisionCounter uint64, stringConstant string) ([]byte, error) {
	// encrypted = SALT(16) || ciphertext || MAC(32)
	if len(encrypted) < 48 { // 16 + 0 + 32 minimum
		return nil, fmt.Errorf("encrypted data too short: %d", len(encrypted))
	}

	salt := encrypted[:16]
	mac := encrypted[len(encrypted)-32:]
	ciphertext := encrypted[16 : len(encrypted)-32]

	// Build secret_input.
	revBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(revBuf, revisionCounter)

	secretInput := make([]byte, 0, len(secretData)+len(subcredential)+8)
	secretInput = append(secretInput, secretData...)
	secretInput = append(secretInput, subcredential...)
	secretInput = append(secretInput, revBuf...)

	// KDF input: secret_input || SALT || STRING_CONSTANT
	kdfInput := make([]byte, 0, len(secretInput)+len(salt)+len(stringConstant))
	kdfInput = append(kdfInput, secretInput...)
	kdfInput = append(kdfInput, salt...)
	kdfInput = append(kdfInput, []byte(stringConstant)...)

	// Derive keys: S_KEY_LEN(32) + S_IV_LEN(16) + MAC_KEY_LEN(32) = 80
	keys := torcrypto.SHAKE256KDF(kdfInput, 80)
	secretKey := keys[0:32]
	secretIV := keys[32:48]
	macKey := keys[48:80]

	// Verify MAC: MAC = SHA3_256(MAC_KEY_LEN_8bytes || MAC_KEY || SALT_LEN_8bytes || SALT || ENCRYPTED)
	macKeyLen := make([]byte, 8)
	binary.BigEndian.PutUint64(macKeyLen, uint64(len(macKey)))
	saltLen := make([]byte, 8)
	binary.BigEndian.PutUint64(saltLen, uint64(len(salt)))

	macInput := make([]byte, 0, 8+len(macKey)+8+len(salt)+len(ciphertext))
	macInput = append(macInput, macKeyLen...)
	macInput = append(macInput, macKey...)
	macInput = append(macInput, saltLen...)
	macInput = append(macInput, salt...)
	macInput = append(macInput, ciphertext...)

	expectedMAC := torcrypto.SHA3_256(macInput)
	if !bytesEqual(expectedMAC, mac) {
		return nil, fmt.Errorf("MAC verification failed")
	}

	// Decrypt: AES-256-CTR(SECRET_IV, SECRET_KEY) XOR ciphertext
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)
	aesCTRDecrypt(secretKey, secretIV, plaintext)

	return plaintext, nil
}

// aesCTRDecrypt decrypts data in-place using AES-256-CTR.
func aesCTRDecrypt(key, iv, data []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)
}

// DecryptSuperencrypted decrypts the first (superencrypted) layer.
func DecryptSuperencrypted(superencrypted []byte, blindedKey, subcredential []byte, revisionCounter uint64) ([]byte, error) {
	return DecryptDescriptorLayer(superencrypted, blindedKey, subcredential, revisionCounter, "hsdir-superencrypted-data")
}

// DecryptEncrypted decrypts the second (encrypted) layer.
// For non-restricted-discovery, SECRET_DATA = blinded_key (no descriptor_cookie).
func DecryptEncrypted(encrypted []byte, blindedKey, subcredential []byte, revisionCounter uint64) ([]byte, error) {
	return DecryptDescriptorLayer(encrypted, blindedKey, subcredential, revisionCounter, "hsdir-encrypted-data")
}

// ParseFirstLayerPlaintext extracts the encrypted blob from the first-layer plaintext.
func ParseFirstLayerPlaintext(plaintext []byte) ([]byte, error) {
	text := string(plaintext)

	// Find the last -----BEGIN MESSAGE----- / -----END MESSAGE----- block.
	// The first layer may have multiple sections; the encrypted blob is the last one.
	beginMarker := "-----BEGIN MESSAGE-----"
	endMarker := "-----END MESSAGE-----"

	beginIdx := strings.LastIndex(text, beginMarker)
	if beginIdx < 0 {
		return nil, fmt.Errorf("no encrypted data found in first layer")
	}
	endIdx := strings.Index(text[beginIdx:], endMarker)
	if endIdx < 0 {
		return nil, fmt.Errorf("no END MESSAGE marker found")
	}

	b64Data := text[beginIdx+len(beginMarker) : beginIdx+endIdx]

	decoded, err := base64DecodeFlexible(b64Data)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted blob: %w", err)
	}
	return decoded, nil
}

// ParseIntroPoints parses introduction points from the second-layer plaintext.
func ParseIntroPoints(plaintext []byte) ([]*IntroPoint, error) {
	text := string(plaintext)
	lines := strings.Split(text, "\n")

	var introPoints []*IntroPoint
	var current *IntroPoint
	inAuthKey := false
	var authKeyB64 strings.Builder

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		switch {
		case strings.HasPrefix(line, "introduction-point "):
			if current != nil {
				introPoints = append(introPoints, current)
			}
			current = &IntroPoint{}
			// Parse link specifiers from base64.
			lsB64 := strings.TrimSpace(line[len("introduction-point "):])
			lsBytes, err := base64.StdEncoding.DecodeString(lsB64)
			if err != nil {
				// Try raw.
				lsBytes, err = base64.RawStdEncoding.DecodeString(lsB64)
				if err != nil {
					return nil, fmt.Errorf("decode link specifiers: %w", err)
				}
			}
			ls, err := parseLinkSpecifiers(lsBytes)
			if err != nil {
				return nil, fmt.Errorf("parse link specifiers: %w", err)
			}
			current.LinkSpecifiers = ls

		case strings.HasPrefix(line, "onion-key ntor "):
			if current != nil {
				keyB64 := strings.TrimSpace(line[len("onion-key ntor "):])
				keyBytes, err := base64DecodeFlexible(keyB64)
				if err != nil {
					return nil, fmt.Errorf("decode onion-key: %w", err)
				}
				current.OnionKey = keyBytes
			}

		case strings.HasPrefix(line, "enc-key ntor "):
			if current != nil {
				keyB64 := strings.TrimSpace(line[len("enc-key ntor "):])
				keyBytes, err := base64DecodeFlexible(keyB64)
				if err != nil {
					return nil, fmt.Errorf("decode enc-key: %w", err)
				}
				current.EncKey = keyBytes
			}

		case line == "auth-key":
			inAuthKey = true
			authKeyB64.Reset()

		case line == "-----BEGIN ED25519 CERT-----":
			// Start of cert, already in auth-key mode.

		case line == "-----END ED25519 CERT-----":
			if current != nil && inAuthKey {
				certBytes, err := base64.StdEncoding.DecodeString(authKeyB64.String())
				if err == nil {
					// Extract the certified key from the ed25519 cert.
					// The cert format has the key at bytes [39:71] for a v1 cert.
					// More precisely: version(1) + cert_type(1) + expiration(4) +
					// key_type(1) + certified_key(32) = key starts at offset 7+32=39
					// Actually the format is:
					// VERSION(1) CERT_TYPE(1) EXPIRATION_DATE(4) KEY_TYPE(1) CERTIFIED_KEY(32) ...
					if len(certBytes) >= 39 {
						current.AuthKey = certBytes[7:39]
					}
				}
			}
			inAuthKey = false

		default:
			if inAuthKey && !strings.HasPrefix(line, "-----") && len(strings.TrimSpace(line)) > 0 {
				authKeyB64.WriteString(strings.TrimSpace(line))
			}
		}
	}

	if current != nil {
		introPoints = append(introPoints, current)
	}

	return introPoints, nil
}

// parseLinkSpecifiers parses a link specifier block.
// Format: NSPEC(1) || [LSTYPE(1) LSLEN(1) LSPEC(LSLEN)] ...
func parseLinkSpecifiers(data []byte) ([]LinkSpecifier, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("link specifier data too short")
	}
	nspec := int(data[0])
	off := 1
	var specs []LinkSpecifier
	for i := 0; i < nspec; i++ {
		if off+2 > len(data) {
			return nil, fmt.Errorf("truncated link specifier %d", i)
		}
		lstype := data[off]
		lslen := int(data[off+1])
		off += 2
		if off+lslen > len(data) {
			return nil, fmt.Errorf("truncated link specifier data %d", i)
		}
		spec := LinkSpecifier{
			Type: lstype,
			Data: make([]byte, lslen),
		}
		copy(spec.Data, data[off:off+lslen])
		off += lslen
		specs = append(specs, spec)
	}
	return specs, nil
}

// EncodeLinkSpecifiers encodes link specifiers for an EXTEND2 cell.
// Returns NSPEC(1) || [LSTYPE(1) LSLEN(1) LSPEC(LSLEN)] ...
func EncodeLinkSpecifiers(specs []LinkSpecifier) []byte {
	size := 1
	for _, s := range specs {
		size += 2 + len(s.Data)
	}
	buf := make([]byte, 0, size)
	buf = append(buf, byte(len(specs)))
	for _, s := range specs {
		buf = append(buf, s.Type, byte(len(s.Data)))
		buf = append(buf, s.Data...)
	}
	return buf
}

func base64DecodeFlexible(s string) ([]byte, error) {
	// Strip any remaining whitespace.
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	// Try standard (padded), then raw (unpadded).
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	return b, err
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
