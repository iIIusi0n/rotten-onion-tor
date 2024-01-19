package utils

import (
	"testing"
)

func TestBase64ToHex(t *testing.T) {
	base64Encoded := "AAoQ1DAR6kkoo19hBAX5K0QztNw="
	hexEncoded := "000a10d43011ea4928a35f610405f92b4433b4dc"
	if Base64ToHex(base64Encoded) != hexEncoded {
		t.Error("Base64ToHex failed")
		t.Error("Expected:", hexEncoded)
		t.Error("Got:", Base64ToHex(base64Encoded))
	}
}
