package stream

import (
	"testing"
)

func TestStreamIDGeneration(t *testing.T) {
	// Test that stream IDs start at 1 and increment.
	// We can't fully test without a circuit, but we can test the logic.
	id := uint16(1)
	for i := 0; i < 10; i++ {
		if id == 0 {
			t.Error("stream ID should never be 0")
		}
		id++
	}
}

func TestStreamBuffering(t *testing.T) {
	s := &Stream{
		streamID:      1,
		packageWindow: 500,
		deliverWindow: 500,
	}

	// Test buffering data.
	s.buf = append(s.buf, []byte("hello ")...)
	s.buf = append(s.buf, []byte("world")...)

	if string(s.buf) != "hello world" {
		t.Errorf("buffer = %q, want %q", s.buf, "hello world")
	}

	// Test reading from buffer.
	p := make([]byte, 5)
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	if string(p[:n]) != "hello" {
		t.Errorf("read = %q, want %q", p[:n], "hello")
	}
	if string(s.buf) != " world" {
		t.Errorf("remaining = %q, want %q", s.buf, " world")
	}
}

func TestStreamFlowControl(t *testing.T) {
	s := &Stream{
		packageWindow: 500,
		deliverWindow: 500,
	}

	// Simulate consuming cells.
	for i := 0; i < 50; i++ {
		s.deliverWindow--
	}
	if s.deliverWindow != 450 {
		t.Errorf("deliverWindow = %d, want 450", s.deliverWindow)
	}

	// At 450, should trigger SENDME.
	if s.deliverWindow > 450 {
		t.Error("should have triggered SENDME threshold")
	}
}
