package cell

import (
	"bytes"
	"testing"
)

func TestCommandIsVariableLength(t *testing.T) {
	tests := []struct {
		cmd      Command
		variable bool
	}{
		{CommandPadding, false},
		{CommandCreate, false},
		{CommandCreated, false},
		{CommandRelay, false},
		{CommandDestroy, false},
		{CommandCreateFast, false},
		{CommandCreatedFast, false},
		{CommandNetinfo, false},
		{CommandRelayEarly, false},
		{CommandCreate2, false},
		{CommandCreated2, false},
		{CommandVersions, true},
		{CommandVpadding, true},
		{CommandCerts, true},
		{CommandAuthChallenge, true},
		{CommandAuthenticate, true},
	}
	for _, tt := range tests {
		if got := tt.cmd.IsVariableLength(); got != tt.variable {
			t.Errorf("Command(%d).IsVariableLength() = %v, want %v", tt.cmd, got, tt.variable)
		}
	}
}

func TestFixedCellRoundTrip(t *testing.T) {
	original := &Cell{
		CircID:  0x80000001,
		Command: CommandCreate2,
		Payload: bytes.Repeat([]byte{0xAB}, 100),
	}

	var buf bytes.Buffer
	if err := original.Encode(&buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if buf.Len() != FixedCellLen {
		t.Fatalf("encoded size = %d, want %d", buf.Len(), FixedCellLen)
	}

	decoded, err := Decode(&buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if decoded.CircID != original.CircID {
		t.Errorf("CircID = %d, want %d", decoded.CircID, original.CircID)
	}
	if decoded.Command != original.Command {
		t.Errorf("Command = %d, want %d", decoded.Command, original.Command)
	}
	if len(decoded.Payload) != CellBodyLen {
		t.Errorf("Payload len = %d, want %d", len(decoded.Payload), CellBodyLen)
	}
	// First 100 bytes should be 0xAB, rest should be 0x00 (padding).
	for i := 0; i < 100; i++ {
		if decoded.Payload[i] != 0xAB {
			t.Errorf("Payload[%d] = %x, want 0xAB", i, decoded.Payload[i])
			break
		}
	}
	for i := 100; i < CellBodyLen; i++ {
		if decoded.Payload[i] != 0x00 {
			t.Errorf("Payload[%d] = %x, want 0x00", i, decoded.Payload[i])
			break
		}
	}
}

func TestVariableCellRoundTrip(t *testing.T) {
	payload := []byte("Hello, Tor!")
	original := &Cell{
		CircID:  0,
		Command: CommandCerts,
		Payload: payload,
	}

	var buf bytes.Buffer
	if err := original.Encode(&buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	expectedLen := CircIDLen + 1 + 2 + len(payload) // 4 + 1 + 2 + 11 = 18
	if buf.Len() != expectedLen {
		t.Fatalf("encoded size = %d, want %d", buf.Len(), expectedLen)
	}

	decoded, err := Decode(&buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if decoded.CircID != 0 {
		t.Errorf("CircID = %d, want 0", decoded.CircID)
	}
	if decoded.Command != CommandCerts {
		t.Errorf("Command = %v, want CERTS", decoded.Command)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("Payload = %q, want %q", decoded.Payload, payload)
	}
}

func TestVersionsCellRoundTrip(t *testing.T) {
	versions := []uint16{3, 4, 5}

	var buf bytes.Buffer
	if err := EncodeVersions(&buf, versions); err != nil {
		t.Fatalf("EncodeVersions: %v", err)
	}

	// Expected: 2(circid) + 1(cmd) + 2(len) + 6(versions) = 11
	if buf.Len() != 11 {
		t.Fatalf("encoded size = %d, want 11", buf.Len())
	}

	decoded, err := DecodeVersions(&buf)
	if err != nil {
		t.Fatalf("DecodeVersions: %v", err)
	}

	if decoded.CircID != 0 {
		t.Errorf("CircID = %d, want 0", decoded.CircID)
	}
	if decoded.Command != CommandVersions {
		t.Errorf("Command = %v, want VERSIONS", decoded.Command)
	}

	parsedVersions, err := ParseVersions(decoded.Payload)
	if err != nil {
		t.Fatalf("ParseVersions: %v", err)
	}
	if len(parsedVersions) != len(versions) {
		t.Fatalf("got %d versions, want %d", len(parsedVersions), len(versions))
	}
	for i, v := range parsedVersions {
		if v != versions[i] {
			t.Errorf("version[%d] = %d, want %d", i, v, versions[i])
		}
	}
}

func TestParseVersionsOddLength(t *testing.T) {
	_, err := ParseVersions([]byte{0x00, 0x03, 0x00})
	if err == nil {
		t.Error("expected error for odd-length payload")
	}
}

func TestRelayCellRoundTrip(t *testing.T) {
	original := &RelayCell{
		Command:    RelayBegin,
		Recognized: 0,
		StreamID:   42,
		Digest:     0xDEADBEEF,
		Data:       []byte("www.example.com:80\x00"),
	}

	body := original.Encode()
	if len(body) != CellBodyLen {
		t.Fatalf("body len = %d, want %d", len(body), CellBodyLen)
	}

	decoded, err := DecodeRelayCell(body)
	if err != nil {
		t.Fatalf("DecodeRelayCell: %v", err)
	}

	if decoded.Command != original.Command {
		t.Errorf("Command = %d, want %d", decoded.Command, original.Command)
	}
	if decoded.StreamID != original.StreamID {
		t.Errorf("StreamID = %d, want %d", decoded.StreamID, original.StreamID)
	}
	if decoded.Digest != original.Digest {
		t.Errorf("Digest = %x, want %x", decoded.Digest, original.Digest)
	}
	if !bytes.Equal(decoded.Data, original.Data) {
		t.Errorf("Data = %q, want %q", decoded.Data, original.Data)
	}
}

func TestRelayCellEmptyData(t *testing.T) {
	rc := &RelayCell{
		Command:  RelaySendme,
		StreamID: 0,
		Data:     nil,
	}
	body := rc.Encode()
	decoded, err := DecodeRelayCell(body)
	if err != nil {
		t.Fatalf("DecodeRelayCell: %v", err)
	}
	if len(decoded.Data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(decoded.Data))
	}
}

func TestMultipleCellsOnStream(t *testing.T) {
	cells := []*Cell{
		{CircID: 1, Command: CommandCreate2, Payload: []byte{1, 2, 3}},
		{CircID: 0, Command: CommandCerts, Payload: []byte("cert-data")},
		{CircID: 2, Command: CommandRelay, Payload: bytes.Repeat([]byte{0xFF}, 509)},
	}

	var buf bytes.Buffer
	for _, c := range cells {
		if err := c.Encode(&buf); err != nil {
			t.Fatalf("Encode: %v", err)
		}
	}

	for i, original := range cells {
		decoded, err := Decode(&buf)
		if err != nil {
			t.Fatalf("Decode cell %d: %v", i, err)
		}
		if decoded.CircID != original.CircID {
			t.Errorf("cell %d: CircID = %d, want %d", i, decoded.CircID, original.CircID)
		}
		if decoded.Command != original.Command {
			t.Errorf("cell %d: Command = %v, want %v", i, decoded.Command, original.Command)
		}
	}
}

func TestCommandString(t *testing.T) {
	if s := CommandRelay.String(); s != "RELAY" {
		t.Errorf("got %q, want RELAY", s)
	}
	if s := Command(255).String(); s != "UNKNOWN(255)" {
		t.Errorf("got %q, want UNKNOWN(255)", s)
	}
}
