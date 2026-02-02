package tor

import (
	"net"
	"time"

	"rotten-onion-tor/pkg/stream"
)

// StreamConn wraps a Tor stream to implement net.Conn.
// This allows using TLS on top of a Tor stream.
type StreamConn struct {
	stream *stream.Stream
	mgr    *stream.Manager
}

// NewStreamConn creates a new StreamConn wrapper.
func NewStreamConn(s *stream.Stream, mgr *stream.Manager) *StreamConn {
	return &StreamConn{stream: s, mgr: mgr}
}

func (sc *StreamConn) Read(p []byte) (int, error) {
	return sc.stream.Read(sc.mgr, p)
}

func (sc *StreamConn) Write(p []byte) (int, error) {
	return sc.stream.Write(sc.mgr, p)
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

func (sc *StreamConn) SetDeadline(t time.Time) error      { return nil }
func (sc *StreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (sc *StreamConn) SetWriteDeadline(t time.Time) error { return nil }
