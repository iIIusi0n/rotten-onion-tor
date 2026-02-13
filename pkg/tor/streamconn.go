package tor

import (
	"net"
	"sync"
	"time"

	"rotten-onion-tor/pkg/stream"
)

// StreamConn wraps a Tor stream to implement net.Conn.
// This allows using TLS on top of a Tor stream.
type StreamConn struct {
	stream *stream.Stream
	mgr    *stream.Manager

	mu            sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
}

// NewStreamConn creates a new StreamConn wrapper.
func NewStreamConn(s *stream.Stream, mgr *stream.Manager) *StreamConn {
	return &StreamConn{stream: s, mgr: mgr}
}

func (sc *StreamConn) Read(p []byte) (int, error) {
	sc.mu.RLock()
	deadline := sc.readDeadline
	sc.mu.RUnlock()
	return sc.stream.ReadWithDeadline(sc.mgr, p, deadline)
}

func (sc *StreamConn) Write(p []byte) (int, error) {
	sc.mu.RLock()
	deadline := sc.writeDeadline
	sc.mu.RUnlock()
	return sc.stream.WriteWithDeadline(sc.mgr, p, deadline)
}

func (sc *StreamConn) Close() error {
	return sc.stream.Close(sc.mgr)
}

func (sc *StreamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (sc *StreamConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (sc *StreamConn) SetDeadline(t time.Time) error {
	sc.mu.Lock()
	sc.readDeadline = t
	sc.writeDeadline = t
	sc.mu.Unlock()
	return nil
}

func (sc *StreamConn) SetReadDeadline(t time.Time) error {
	sc.mu.Lock()
	sc.readDeadline = t
	sc.mu.Unlock()
	return nil
}

func (sc *StreamConn) SetWriteDeadline(t time.Time) error {
	sc.mu.Lock()
	sc.writeDeadline = t
	sc.mu.Unlock()
	return nil
}
