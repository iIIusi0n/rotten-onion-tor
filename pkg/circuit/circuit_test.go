package circuit

import (
	"bytes"
	"encoding/binary"
	"testing"

	"rotten-onion-tor/pkg/directory"
)

func TestGenerateCircID(t *testing.T) {
	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		id, err := generateCircID()
		if err != nil {
			t.Fatalf("generateCircID: %v", err)
		}
		// MSB must be set (initiator).
		if id&0x80000000 == 0 {
			t.Errorf("CircID %x does not have MSB set", id)
		}
		// Must be non-zero.
		if id == 0 {
			t.Error("CircID is zero")
		}
		ids[id] = true
	}
	// Should have generated mostly unique IDs.
	if len(ids) < 90 {
		t.Errorf("too many duplicate CircIDs: %d unique out of 100", len(ids))
	}
}

func TestParseIPv4(t *testing.T) {
	tests := []struct {
		addr string
		want []byte
	}{
		{"1.2.3.4", []byte{1, 2, 3, 4}},
		{"192.168.1.1", []byte{192, 168, 1, 1}},
		{"255.255.255.255", []byte{255, 255, 255, 255}},
		{"0.0.0.0", []byte{0, 0, 0, 0}},
	}
	for _, tt := range tests {
		got, err := parseIPv4(tt.addr)
		if err != nil {
			t.Fatalf("parseIPv4(%q): %v", tt.addr, err)
		}
		if !bytes.Equal(got, tt.want) {
			t.Errorf("parseIPv4(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestDecodeIdentity(t *testing.T) {
	// Test with known base64-encoded identity (27 chars = 20 bytes).
	// "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" is base64 for 20 zero bytes + extra.
	identity := "AAAAAAAAAAAAAAAAAAAAAAAAAAA"
	decoded, err := decodeIdentity(identity)
	if err != nil {
		t.Fatalf("decodeIdentity: %v", err)
	}
	if len(decoded) != 20 {
		t.Fatalf("decoded length = %d, want 20", len(decoded))
	}
	for _, b := range decoded {
		if b != 0 {
			t.Errorf("expected all zeros, got %x", decoded)
			break
		}
	}
}

func TestBuildExtend2Body(t *testing.T) {
	router := testRouter()

	handshakeData := bytes.Repeat([]byte{0xAB}, 84) // ntor handshake = 84 bytes
	body, err := buildExtend2Body(router, handshakeData)
	if err != nil {
		t.Fatalf("buildExtend2Body: %v", err)
	}

	if len(body) == 0 {
		t.Fatal("empty extend2 body")
	}

	// Parse: NSPEC
	nspec := body[0]
	if nspec != 2 {
		t.Errorf("NSPEC = %d, want 2", nspec)
	}

	off := 1
	// Link spec 0: type=0x00, len=6
	if body[off] != 0x00 {
		t.Errorf("spec0 type = %x, want 0x00", body[off])
	}
	if body[off+1] != 6 {
		t.Errorf("spec0 len = %d, want 6", body[off+1])
	}
	off += 2 + 6

	// Link spec 1: type=0x02, len=20
	if body[off] != 0x02 {
		t.Errorf("spec1 type = %x, want 0x02", body[off])
	}
	if body[off+1] != 20 {
		t.Errorf("spec1 len = %d, want 20", body[off+1])
	}
	off += 2 + 20

	// HTYPE = 0x0002
	htype := binary.BigEndian.Uint16(body[off : off+2])
	if htype != 0x0002 {
		t.Errorf("HTYPE = %x, want 0x0002", htype)
	}
	off += 2

	// HLEN
	hlen := binary.BigEndian.Uint16(body[off : off+2])
	if hlen != 84 {
		t.Errorf("HLEN = %d, want 84", hlen)
	}
	off += 2

	// HDATA
	if !bytes.Equal(body[off:off+84], handshakeData) {
		t.Error("HDATA mismatch")
	}
}

func testRouter() *directory.Router {
	return &directory.Router{
		Nickname:     "TestRelay",
		Identity:     "AAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Address:      "1.2.3.4",
		ORPort:       9001,
		NtorOnionKey: bytes.Repeat([]byte{0xFF}, 32),
	}
}

func TestComputeNodeID(t *testing.T) {
	router := testRouter()
	nodeID, err := computeNodeID(router)
	if err != nil {
		t.Fatalf("computeNodeID: %v", err)
	}
	if len(nodeID) != 20 {
		t.Errorf("nodeID length = %d, want 20", len(nodeID))
	}
}
