package onion

import "testing"

const duckDuckGoOnionHost = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"

func TestParseOnionAddressValid(t *testing.T) {
	oa, err := ParseOnionAddress(duckDuckGoOnionHost + ".onion")
	if err != nil {
		t.Fatalf("ParseOnionAddress: %v", err)
	}
	if oa.Version != 3 {
		t.Fatalf("version = %d, want 3", oa.Version)
	}
}

func TestParseOnionAddressInvalidChecksum(t *testing.T) {
	addr := "a" + duckDuckGoOnionHost[1:]
	if _, err := ParseOnionAddress(addr); err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestParseOnionAddressInvalidCharacters(t *testing.T) {
	addr := duckDuckGoOnionHost[:20] + "!" + duckDuckGoOnionHost[21:]
	if _, err := ParseOnionAddress(addr); err == nil {
		t.Fatal("expected invalid character error")
	}
}
