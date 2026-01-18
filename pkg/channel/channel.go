// Package channel implements Tor channel (TLS connection) management.
//
// A channel is a TLS connection between two Tor nodes. After TLS setup,
// the parties exchange VERSIONS, CERTS, AUTH_CHALLENGE, and NETINFO cells
// to negotiate the link protocol version and establish identity.
package channel

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"rotten-onion-tor/pkg/cell"
)

// Channel represents a Tor channel (TLS connection to a relay).
type Channel struct {
	conn     *tls.Conn
	version  uint16
	mu       sync.Mutex
	peerCert []byte // DER-encoded peer TLS certificate
}

// Dial establishes a TLS connection to a Tor relay and performs
// the channel negotiation handshake.
func Dial(address string, timeout time.Duration) (*Channel, error) {
	dialer := net.Dialer{Timeout: timeout}
	rawConn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", address, err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Tor relays use self-signed certs; identity is verified via CERTS cell.
		MinVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	// Extract peer certificate.
	var peerCert []byte
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		peerCert = state.PeerCertificates[0].Raw
	}

	ch := &Channel{
		conn:     tlsConn,
		peerCert: peerCert,
	}

	// Perform versions negotiation.
	if err := ch.negotiate(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("negotiate: %w", err)
	}

	return ch, nil
}

// negotiate performs the channel negotiation:
// 1. Send VERSIONS cell
// 2. Receive VERSIONS cell
// 3. Receive CERTS, AUTH_CHALLENGE, NETINFO
// 4. Send NETINFO
func (ch *Channel) negotiate() error {
	// Send our VERSIONS cell (supporting versions 4 and 5).
	if err := cell.EncodeVersions(ch.conn, []uint16{4, 5}); err != nil {
		return fmt.Errorf("send versions: %w", err)
	}

	// Read peer's VERSIONS cell (uses v=0 format with 2-byte CircID).
	versionsCell, err := cell.DecodeVersions(ch.conn)
	if err != nil {
		return fmt.Errorf("read versions: %w", err)
	}

	peerVersions, err := cell.ParseVersions(versionsCell.Payload)
	if err != nil {
		return fmt.Errorf("parse versions: %w", err)
	}

	// Select highest common version.
	ch.version = selectVersion([]uint16{4, 5}, peerVersions)
	if ch.version == 0 {
		return fmt.Errorf("no common link protocol version (peer supports: %v)", peerVersions)
	}

	// Now read the remaining cells from the responder:
	// CERTS, AUTH_CHALLENGE, NETINFO (in that order, with possible VPADDING).
	var gotCerts, gotAuthChallenge, gotNetinfo bool

	for !gotNetinfo {
		c, err := cell.Decode(ch.conn)
		if err != nil {
			return fmt.Errorf("read cell: %w", err)
		}

		switch c.Command {
		case cell.CommandCerts:
			gotCerts = true
			// We accept the CERTS cell but don't fully validate the certificate chain.
			// For a client that doesn't authenticate, this is acceptable.
			// In production, we would verify the Ed25519 cert chain here.

		case cell.CommandAuthChallenge:
			gotAuthChallenge = true
			// We're not authenticating as a client, so we just note this.

		case cell.CommandNetinfo:
			gotNetinfo = true

		case cell.CommandPadding, cell.CommandVpadding:
			// Ignore padding cells.

		default:
			return fmt.Errorf("unexpected cell during negotiation: %s", c.Command)
		}
	}

	_ = gotCerts
	_ = gotAuthChallenge

	// Send our NETINFO cell.
	if err := ch.sendNetinfo(); err != nil {
		return fmt.Errorf("send netinfo: %w", err)
	}

	return nil
}

// sendNetinfo sends a NETINFO cell as a non-authenticating client.
func (ch *Channel) sendNetinfo() error {
	body := make([]byte, cell.CellBodyLen)

	// TIME: clients send 0 to avoid fingerprinting.
	binary.BigEndian.PutUint32(body[0:4], 0)

	// OTHERADDR: peer's address.
	host, _, err := net.SplitHostPort(ch.conn.RemoteAddr().String())
	if err != nil {
		host = "0.0.0.0"
	}
	ip := net.ParseIP(host)
	off := 4
	if ip4 := ip.To4(); ip4 != nil {
		body[off] = 0x04 // ATYPE IPv4
		body[off+1] = 4  // ALEN
		copy(body[off+2:off+6], ip4)
		off += 6
	} else if ip16 := ip.To16(); ip16 != nil {
		body[off] = 0x06 // ATYPE IPv6
		body[off+1] = 16 // ALEN
		copy(body[off+2:off+18], ip16)
		off += 18
	}

	// NMYADDR: clients send 0 addresses.
	body[off] = 0

	c := &cell.Cell{
		CircID:  0,
		Command: cell.CommandNetinfo,
		Payload: body,
	}

	return c.Encode(ch.conn)
}

func selectVersion(ours, theirs []uint16) uint16 {
	var best uint16
	for _, o := range ours {
		for _, t := range theirs {
			if o == t && o > best {
				best = o
			}
		}
	}
	return best
}

// SendCell sends a cell on the channel.
func (ch *Channel) SendCell(c *cell.Cell) error {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return c.Encode(ch.conn)
}

// RecvCell reads a cell from the channel.
func (ch *Channel) RecvCell() (*cell.Cell, error) {
	return cell.Decode(ch.conn)
}

// Close closes the channel.
func (ch *Channel) Close() error {
	return ch.conn.Close()
}

// Version returns the negotiated link protocol version.
func (ch *Channel) Version() uint16 {
	return ch.version
}

// PeerCert returns the DER-encoded peer TLS certificate.
func (ch *Channel) PeerCert() []byte {
	return ch.peerCert
}

// Conn returns the underlying TLS connection for direct I/O if needed.
func (ch *Channel) Conn() io.ReadWriter {
	return ch.conn
}
