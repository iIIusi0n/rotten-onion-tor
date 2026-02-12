// Package stream implements Tor stream management for TCP tunneling
// through Tor circuits.
package stream

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"rotten-onion-tor/pkg/cell"
	"rotten-onion-tor/pkg/circuit"
)

const (
	defaultStreamPackageWindow = 500
	defaultStreamDeliverWindow = 500
	streamSendmeIncrement      = 50
	streamSendmeThreshold      = defaultStreamDeliverWindow - streamSendmeIncrement
	relayEndReasonMisc         = 1 // tor-spec: clients SHOULD use REASON_MISC for locally-originated streams.
	streamEventQueueSize       = 128
)

// Stream represents a TCP stream tunneled through a Tor circuit.
type Stream struct {
	circuit  *circuit.Circuit
	streamID uint16
	buf      []byte // read buffer for incoming data
	mu       sync.Mutex
	closed   bool
	events   chan *cell.RelayCell

	// Stream-level flow control
	packageWindow int
	deliverWindow int
}

// Manager manages multiple streams on a single circuit.
type Manager struct {
	circuit *circuit.Circuit
	streams map[uint16]*Stream
	mu      sync.RWMutex
	nextID  uint16
	readErr error
	done    chan struct{}
	once    sync.Once
}

var errNoStreamIDs = errors.New("no stream IDs available")

// NewManager creates a new stream manager for the given circuit.
func NewManager(circ *circuit.Circuit) *Manager {
	m := &Manager{
		circuit: circ,
		streams: make(map[uint16]*Stream),
		nextID:  1,
		done:    make(chan struct{}),
	}
	go m.readLoop()
	return m
}

// readLoop continuously reads relay cells from the circuit and dispatches
// them to the appropriate stream.
func (m *Manager) readLoop() {
	for {
		rc, err := m.circuit.RecvRelayCell()
		if err != nil {
			m.failAll(err)
			return
		}

		if rc.StreamID == 0 {
			m.handleCircuitCell(rc)
			continue
		}

		m.mu.RLock()
		s, ok := m.streams[rc.StreamID]
		if !ok {
			m.mu.RUnlock()
			continue
		}

		// Keep this non-blocking while holding RLock so stream removal and global
		// shutdown can't race with a send on a closed channel.
		select {
		case s.events <- rc:
			m.mu.RUnlock()
		default:
			m.mu.RUnlock()
			m.failAll(fmt.Errorf("stream %d event queue overflow", rc.StreamID))
			return
		}
	}
}

// OpenStream opens a new TCP stream to the given address:port through the circuit.
func (m *Manager) OpenStream(addrPort string) (*Stream, error) {
	m.mu.Lock()
	streamID, err := m.allocateStreamIDLocked()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	stream := &Stream{
		circuit:       m.circuit,
		streamID:      streamID,
		events:        make(chan *cell.RelayCell, streamEventQueueSize),
		packageWindow: defaultStreamPackageWindow,
		deliverWindow: defaultStreamDeliverWindow,
	}
	m.streams[streamID] = stream
	m.mu.Unlock()

	// Send RELAY_BEGIN.
	if err := m.circuit.SendRelayBegin(streamID, addrPort); err != nil {
		m.removeStream(streamID)
		return nil, fmt.Errorf("send RELAY_BEGIN: %w", err)
	}

	// Wait for RELAY_CONNECTED.
	for {
		rc, err := stream.nextEvent(m)
		if err != nil {
			m.removeStream(streamID)
			return nil, err
		}

		switch rc.Command {
		case cell.RelayConnected:
			return stream, nil
		case cell.RelayEnd:
			m.removeStream(streamID)
			reason := byte(0)
			if len(rc.Data) > 0 {
				reason = rc.Data[0]
			}
			return nil, fmt.Errorf("stream rejected: reason %d", reason)
		case cell.RelayData:
			stream.mu.Lock()
			stream.buf = append(stream.buf, rc.Data...)
			stream.mu.Unlock()
		case cell.RelaySendme:
			stream.mu.Lock()
			stream.packageWindow += streamSendmeIncrement
			stream.mu.Unlock()
		}
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
			// Stream-level flow control: send SENDME when window drops.
			s.deliverWindow--
			shouldSendSendme := s.deliverWindow <= streamSendmeThreshold
			if shouldSendSendme {
				s.deliverWindow += streamSendmeIncrement
			}
			s.mu.Unlock()
			if shouldSendSendme {
				_ = s.sendStreamSendme()
			}
			return n, nil
		}
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		s.mu.Unlock()

		rc, err := s.nextEvent(m)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}

		switch rc.Command {
		case cell.RelayData:
			s.mu.Lock()
			s.buf = append(s.buf, rc.Data...)
			s.mu.Unlock()
		case cell.RelayEnd:
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
		case cell.RelaySendme:
			s.mu.Lock()
			s.packageWindow += streamSendmeIncrement
			s.mu.Unlock()
		}
	}
}

// Write sends data through the stream.
func (s *Stream) Write(m *Manager, p []byte) (int, error) {
	written := 0
	for written < len(p) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return written, io.EOF
		}
		s.packageWindow--
		s.mu.Unlock()

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

func (s *Stream) sendStreamSendme() error {
	return s.circuit.SendRelayStreamSendme(s.streamID)
}

// StreamID returns the stream ID.
func (s *Stream) StreamID() uint16 {
	return s.streamID
}

// Close closes the stream by sending a RELAY_END cell.
func (s *Stream) Close(m *Manager) error {
	s.mu.Lock()
	alreadyClosed := s.closed
	s.closed = true
	s.mu.Unlock()
	if alreadyClosed {
		return nil
	}

	// Send RELAY_END with REASON_MISC per tor-spec recommendation for local closes.
	err := m.circuit.SendRelayEnd(s.streamID, relayEndReasonMisc)
	m.removeStream(s.streamID)
	return err
}

func (s *Stream) nextEvent(m *Manager) (*cell.RelayCell, error) {
	rc, ok := <-s.events
	if ok {
		return rc, nil
	}

	if err := m.readError(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func (m *Manager) allocateStreamIDLocked() (uint16, error) {
	for i := 0; i < 0xFFFF; i++ {
		id := m.nextID
		m.nextID++
		if m.nextID == 0 {
			m.nextID = 1
		}
		if id == 0 {
			continue
		}
		if _, exists := m.streams[id]; !exists {
			return id, nil
		}
	}
	return 0, errNoStreamIDs
}

func (m *Manager) removeStream(streamID uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.streams[streamID]; ok {
		delete(m.streams, streamID)
		close(s.events)
	}
}

func (m *Manager) failAll(err error) {
	m.once.Do(func() {
		m.mu.Lock()
		m.readErr = err
		for id, s := range m.streams {
			delete(m.streams, id)
			close(s.events)
		}
		m.mu.Unlock()
		close(m.done)
	})
}

func (m *Manager) readError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.readErr != nil {
		return m.readErr
	}
	return io.EOF
}
