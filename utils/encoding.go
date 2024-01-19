package utils

import (
	"encoding/base64"
	"encoding/hex"
)

func Base64ToByteArray(data string) []byte {
	dec, _ := base64.StdEncoding.DecodeString(data)
	return dec
}

func ByteArrayToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func HexToByteArray(data string) []byte {
	dec, _ := hex.DecodeString(data)
	return dec
}

func ByteArrayToHex(data []byte) string {
	return hex.EncodeToString(data)
}

func Base64ToHex(data string) string {
	return ByteArrayToHex(Base64ToByteArray(data))
}
