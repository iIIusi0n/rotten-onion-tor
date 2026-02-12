package onion

import (
	"bytes"
	"encoding/hex"
	"testing"

	torcrypto "rotten-onion-tor/pkg/crypto"
)

func TestHSNtorCreateIntroduce1PayloadVector(t *testing.T) {
	// Source: torproject rend-spec-v3 test vectors.
	// https://raw.githubusercontent.com/torproject/torspec/main/rend-spec-v3.txt
	authKey := mustDecodeHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	subcredential := mustDecodeHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	encKey := mustDecodeHex(t, "8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
	x := mustDecodeHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	X := mustDecodeHex(t, "BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D")

	plaintext := mustDecodeHex(t, "6BD364C12638DD5C3BE23D76ACA05B04E6CE932C0101000100200DE6130E4FCAC4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE565450300067F00000113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF8700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	expectedMACKey := mustDecodeHex(t, "FC4058DA59D4DF61E7B40985D122F502FD59336BC21C30CAF5E7F0D4A2C38FD5")
	macHeader := mustDecodeHex(t, "000000000000000000000000000000000000000002002034E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00")
	fullIntroduceBody := mustDecodeHex(t, "000000000000000000000000000000000000000002002034E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5DADBECCCB38E378304DCC179D3D9E437B452AF5702CED2CCFEC085BC02C4C175FA446525C1B9D5530563C362FDFFB802DAB8CD9EBC7A5EE17DA62E37DEEB0EB187FBB48C63298B0E83F391B7566F42ADC97C46BA7588278273A44CE96BC68FFDAE31EF5F0913B9A9C7E0F173DBC0BDDCD4ACB4C4600980A7DDD9EAEC6E7F3FA3FC37CD95E5B8BFB3E35717012B78B4930569F895CB349A07538E42309C993223AEA77EF8AEA64F25DDEE97DA623F1AEC0A47F150002150455845C385E5606E41A9A199E7111D54EF2D1A51B7554D8B3692D85AC587FB9E69DF990EFB776D8")
	expectedCiphertext := fullIntroduceBody[len(macHeader)+len(X) : len(fullIntroduceBody)-32]
	expectedMAC := fullIntroduceBody[len(fullIntroduceBody)-32:]

	var state HSNtorClientState
	copy(state.EphemeralPrivate[:], x)
	copy(state.EphemeralPublic[:], X)
	copy(state.EncKey[:], encKey)
	state.AuthKey = authKey
	state.Subcredential = subcredential

	clientPK, encrypted, macKey, err := state.CreateIntroduce1Payload(plaintext)
	if err != nil {
		t.Fatalf("CreateIntroduce1Payload: %v", err)
	}

	if !bytes.Equal(clientPK, X) {
		t.Fatalf("client PK mismatch\n got  %x\n want %x", clientPK, X)
	}
	if !bytes.Equal(encrypted, expectedCiphertext) {
		t.Fatalf("ciphertext mismatch\n got  %x\n want %x", encrypted, expectedCiphertext)
	}
	if !bytes.Equal(macKey, expectedMACKey) {
		t.Fatalf("MAC key mismatch\n got  %x\n want %x", macKey, expectedMACKey)
	}

	macMsg := make([]byte, 0, len(macHeader)+len(clientPK)+len(encrypted))
	macMsg = append(macMsg, macHeader...)
	macMsg = append(macMsg, clientPK...)
	macMsg = append(macMsg, encrypted...)
	mac := torcrypto.HSMAC(macKey, macMsg)
	if !bytes.Equal(mac, expectedMAC) {
		t.Fatalf("INTRODUCE1 MAC mismatch\n got  %x\n want %x", mac, expectedMAC)
	}
}

func TestHSNtorCompleteRendezvousVector(t *testing.T) {
	// Source: torproject rend-spec-v3 test vectors.
	// https://raw.githubusercontent.com/torproject/torspec/main/rend-spec-v3.txt
	authKey := mustDecodeHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	subcredential := mustDecodeHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	encKey := mustDecodeHex(t, "8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
	x := mustDecodeHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	X := mustDecodeHex(t, "BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D")

	Y := mustDecodeHex(t, "8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700")
	auth := mustDecodeHex(t, "4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208")
	expectedSeed := mustDecodeHex(t, "4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB")

	var state HSNtorClientState
	copy(state.EphemeralPrivate[:], x)
	copy(state.EphemeralPublic[:], X)
	copy(state.EncKey[:], encKey)
	state.AuthKey = authKey
	state.Subcredential = subcredential

	rendezvous2 := make([]byte, 0, 64)
	rendezvous2 = append(rendezvous2, Y...)
	rendezvous2 = append(rendezvous2, auth...)

	result, err := state.CompleteRendezvous(rendezvous2)
	if err != nil {
		t.Fatalf("CompleteRendezvous: %v", err)
	}
	if !bytes.Equal(result.NtorKeySeed, expectedSeed) {
		t.Fatalf("NTOR key seed mismatch\n got  %x\n want %x", result.NtorKeySeed, expectedSeed)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}
