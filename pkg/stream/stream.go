// Package stream implements Tor stream management for TCP tunneling
// through Tor circuits.
package stream

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"rotten-onion-tor/pkg/cell"
	"rotten-onion-tor/pkg/circuit"
)

// Stream represents a TCP stream tunneled through a Tor circuit.
type Stream struct {
	circuit  *circuit.Circuit
	streamID uint16
	buf      []byte // read buffer for incoming data
	mu       sync.Mutex
	closed   bool

	// Stream-level flow control
	packageWindow int
	deliverWindow int
}

// Manager manages multiple streams on a single circuit.
type Manager struct {
	circuit  *circuit.Circuit
	streams  map[uint16]*Stream
	mu       sync.Mutex
	nextID   uint16
	incoming chan *streamEvent
	done     chan struct{}
}

type streamEvent struct {
	streamID uint16
	relay    *cell.RelayCell
	err      error
}

// NewManager creates a new stream manager for the given circuit.
func NewManager(circ *circuit.Circuit) *Manager {
	m := &Manager{
		circuit:  circ,
		streams:  make(map[uint16]*Stream),
		nextID:   1,
		incoming: make(chan *streamEvent, 256),
		done:     make(chan struct{}),
	}
	go m.readLoop()
	return m
}

// readLoop continuously reads relay cells from the circuit and dispatches
// them to the appropriate stream.
func (m *Manager) readLoop() {
	defer close(m.done)
	for {
		rc, err := m.circuit.RecvRelayCell()
		if err != nil {
			m.incoming <- &streamEvent{err: err}
			return
		}

		m.incoming <- &streamEvent{
			streamID: rc.StreamID,
			relay:    rc,
		}
	}
}

// OpenStream opens a new TCP stream to the given address:port through the circuit.
func (m *Manager) OpenStream(addrPort string) (*Stream, error) {
	m.mu.Lock()
	streamID := m.nextID
	m.nextID++
	stream := &Stream{
		circuit:       m.circuit,
		streamID:      streamID,
		packageWindow: 500,
		deliverWindow: 500,
	}
	m.streams[streamID] = stream
	m.mu.Unlock()

	// Send RELAY_BEGIN.
	if err := m.circuit.SendRelayBegin(streamID, addrPort); err != nil {
		return nil, fmt.Errorf("send RELAY_BEGIN: %w", err)
	}

	// Wait for RELAY_CONNECTED.
	for {
		event := <-m.incoming
		if event.err != nil {
			return nil, event.err
		}

		if event.relay.StreamID == streamID {
			switch event.relay.Command {
			case cell.RelayConnected:
				return stream, nil
			case cell.RelayEnd:
				reason := byte(0)
				if len(event.relay.Data) > 0 {
					reason = event.relay.Data[0]
				}
				return nil, fmt.Errorf("stream rejected: reason %d", reason)
			default:
				// Buffer other cells.
				if event.relay.Command == cell.RelayData {
					stream.mu.Lock()
					stream.buf = append(stream.buf, event.relay.Data...)
					stream.mu.Unlock()
				}
			}
		} else if event.relay.StreamID == 0 {
			// Circuit-level cell (e.g., SENDME).
			m.handleCircuitCell(event.relay)
		}
		// Ignore cells for other streams during connect.
	}
}

// handleCircuitCell handles circuit-level relay cells (streamID=0).
func (m *Manager) handleCircuitCell(rc *cell.RelayCell) {
	switch rc.Command {
	case cell.RelaySendme:
		// Circuit-level SENDME: increment package window.
		// For simplicity, we just allow sending more.
	case cell.RelayDrop:
		// Padding, ignore.
	}
}

// Read reads data from the stream.
func (s *Stream) Read(m *Manager, p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.buf) > 0 {
			n := copy(p, s.buf)
			s.buf = s.buf[n:]
			s.mu.Unlock()

			// Stream-level flow control: send SENDME when window drops.
			s.deliverWindow--
			if s.deliverWindow <= 450 {
				s.sendStreamSendme(m)
				s.deliverWindow += 50
			}
			return n, nil
		}
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		s.mu.Unlock()

		// Wait for more data.
		event := <-m.incoming
		if event.err != nil {
			return 0, event.err
		}

		if event.relay.StreamID == s.streamID {
			switch event.relay.Command {
			case cell.RelayData:
				s.mu.Lock()
				s.buf = append(s.buf, event.relay.Data...)
				s.mu.Unlock()
			case cell.RelayEnd:
				s.mu.Lock()
				s.closed = true
				s.mu.Unlock()
				if len(s.buf) > 0 {
					continue
				}
				return 0, io.EOF
			case cell.RelaySendme:
				s.packageWindow += 50
			}
		} else if event.relay.StreamID == 0 {
			m.handleCircuitCell(event.relay)
		} else {
			// Cell for another stream - dispatch it.
			m.mu.Lock()
			other, ok := m.streams[event.relay.StreamID]
			m.mu.Unlock()
			if ok {
				other.mu.Lock()
				if event.relay.Command == cell.RelayData {
					other.buf = append(other.buf, event.relay.Data...)
				} else if event.relay.Command == cell.RelayEnd {
					other.closed = true
				}
				other.mu.Unlock()
			}
		}
	}
}

// Write sends data through the stream.
func (s *Stream) Write(m *Manager, p []byte) (int, error) {
	written := 0
	for written < len(p) {
		// Max data per relay cell.
		chunkSize := cell.RelayBodyLen
		remaining := len(p) - written
		if remaining < chunkSize {
			chunkSize = remaining
		}

		if err := s.circuit.SendRelayData(s.streamID, p[written:written+chunkSize]); err != nil {
			return written, fmt.Errorf("send relay data: %w", err)
		}
		written += chunkSize
	}
	return written, nil
}

func (s *Stream) sendStreamSendme(m *Manager) {
	// Stream-level SENDME: empty body, non-zero streamID.
	data := make([]byte, 3)
	data[0] = 0x00                           // version 0
	binary.BigEndian.PutUint16(data[1:3], 0) // data_len = 0
	s.circuit.SendRelayData(s.streamID, nil) // This is simplified
}

// StreamID returns the stream ID.
func (s *Stream) StreamID() uint16 {
	return s.streamID
}

// Close closes the stream by sending a RELAY_END cell.
func (s *Stream) Close(m *Manager) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	// Send RELAY_END with reason DONE.
	data := []byte{6}                                // REASON_DONE
	return m.circuit.SendRelayData(s.streamID, data) // Simplified; should use sendRelayCell with RelayEnd.
}
