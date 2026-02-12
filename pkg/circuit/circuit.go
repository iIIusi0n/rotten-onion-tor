// Package circuit implements Tor circuit management including creation,
// extension, and relay cell encryption/decryption.
package circuit

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"rotten-onion-tor/pkg/cell"
	"rotten-onion-tor/pkg/channel"
	torcrypto "rotten-onion-tor/pkg/crypto"
	"rotten-onion-tor/pkg/directory"
)

// HopCrypto holds the cryptographic state for one hop of a circuit.
type HopCrypto struct {
	Forward  *torcrypto.RelayCrypto // Client -> Relay
	Backward *torcrypto.RelayCrypto // Relay -> Client
}

// Circuit represents an established Tor circuit through one or more relays.
type Circuit struct {
	channel *channel.Channel
	circID  uint32
	hops    []*HopCrypto
	mu      sync.Mutex

	// Flow control
	packageWindow int // cells we can send
	deliverWindow int // cells we're willing to receive
}

// New creates a new circuit object on the given channel.
func New(ch *channel.Channel) (*Circuit, error) {
	circID, err := generateCircID()
	if err != nil {
		return nil, err
	}

	return &Circuit{
		channel:       ch,
		circID:        circID,
		packageWindow: 1000,
		deliverWindow: 1000,
	}, nil
}

// generateCircID generates a random circuit ID with MSB set to 1
// (as required for the initiator in link protocol v4+).
func generateCircID() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	id := binary.BigEndian.Uint32(buf[:])
	id |= 0x80000000 // Set MSB for initiator.
	return id, nil
}

// Create sends a CREATE2 cell with an ntor handshake to the first relay
// and processes the CREATED2 response.
func (c *Circuit) Create(router *directory.Router) error {
	nodeID, err := computeNodeID(router)
	if err != nil {
		return fmt.Errorf("compute node ID: %w", err)
	}

	var ntorPK torcrypto.NtorPublicKey
	copy(ntorPK[:], router.NtorOnionKey)

	handshake, err := torcrypto.NewNtorClientHandshake(nodeID, ntorPK)
	if err != nil {
		return fmt.Errorf("create ntor handshake: %w", err)
	}

	clientData := handshake.ClientHandshakeData()

	// Build CREATE2 cell payload: HTYPE(2) | HLEN(2) | HDATA(84)
	payload := make([]byte, 4+len(clientData))
	binary.BigEndian.PutUint16(payload[0:2], 0x0002) // ntor handshake type
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(clientData)))
	copy(payload[4:], clientData)

	createCell := &cell.Cell{
		CircID:  c.circID,
		Command: cell.CommandCreate2,
		Payload: payload,
	}

	if err := c.channel.SendCell(createCell); err != nil {
		return fmt.Errorf("send CREATE2: %w", err)
	}

	// Read CREATED2 response.
	resp, err := c.recvCellExpect(cell.CommandCreated2)
	if err != nil {
		return err
	}

	// Parse CREATED2: HLEN(2) | HDATA(HLEN)
	if len(resp.Payload) < 2 {
		return fmt.Errorf("CREATED2 payload too short")
	}
	hlen := binary.BigEndian.Uint16(resp.Payload[0:2])
	if len(resp.Payload) < int(2+hlen) {
		return fmt.Errorf("CREATED2 HDATA too short: %d < %d", len(resp.Payload)-2, hlen)
	}
	hdata := resp.Payload[2 : 2+hlen]

	// Complete the ntor handshake.
	result, err := handshake.Complete(hdata)
	if err != nil {
		return fmt.Errorf("complete ntor handshake: %w", err)
	}

	// Derive circuit keys.
	keys := torcrypto.DeriveCircuitKeys(result.KeySeed[:])

	// Create hop crypto state.
	hop, err := newHopCrypto(keys)
	if err != nil {
		return fmt.Errorf("create hop crypto: %w", err)
	}

	c.hops = append(c.hops, hop)
	return nil
}

// Extend extends the circuit to an additional relay by sending an
// EXTEND2 relay message through the existing circuit.
func (c *Circuit) Extend(router *directory.Router) error {
	nodeID, err := computeNodeID(router)
	if err != nil {
		return fmt.Errorf("compute node ID: %w", err)
	}

	var ntorPK torcrypto.NtorPublicKey
	copy(ntorPK[:], router.NtorOnionKey)

	handshake, err := torcrypto.NewNtorClientHandshake(nodeID, ntorPK)
	if err != nil {
		return fmt.Errorf("create ntor handshake: %w", err)
	}

	clientData := handshake.ClientHandshakeData()

	// Build EXTEND2 relay message body.
	extendBody, err := buildExtend2Body(router, clientData)
	if err != nil {
		return fmt.Errorf("build EXTEND2 body: %w", err)
	}

	// Send as RELAY_EARLY cell with EXTEND2 command.
	if err := c.sendRelayCell(cell.RelayExtend2, 0, extendBody, true); err != nil {
		return fmt.Errorf("send EXTEND2: %w", err)
	}

	// Read EXTENDED2 response.
	relayCell, err := c.recvRelayCell()
	if err != nil {
		return fmt.Errorf("recv EXTENDED2: %w", err)
	}
	if relayCell.Command != cell.RelayExtended2 {
		return fmt.Errorf("expected EXTENDED2, got relay command %d", relayCell.Command)
	}

	// Parse EXTENDED2: HLEN(2) | HDATA(HLEN)
	if len(relayCell.Data) < 2 {
		return fmt.Errorf("EXTENDED2 data too short")
	}
	hlen := binary.BigEndian.Uint16(relayCell.Data[0:2])
	if len(relayCell.Data) < int(2+hlen) {
		return fmt.Errorf("EXTENDED2 HDATA too short")
	}
	hdata := relayCell.Data[2 : 2+hlen]

	// Complete ntor handshake.
	result, err := handshake.Complete(hdata)
	if err != nil {
		return fmt.Errorf("complete ntor handshake: %w", err)
	}

	// Derive keys for the new hop.
	keys := torcrypto.DeriveCircuitKeys(result.KeySeed[:])
	hop, err := newHopCrypto(keys)
	if err != nil {
		return fmt.Errorf("create hop crypto: %w", err)
	}

	c.hops = append(c.hops, hop)
	return nil
}

func buildExtend2Body(router *directory.Router, handshakeData []byte) ([]byte, error) {
	// Parse the router's IP address.
	ip, err := parseIPv4(router.Address)
	if err != nil {
		return nil, fmt.Errorf("parse router IPv4 address: %w", err)
	}

	// Link specifiers: [00] IPv4 (6 bytes), [02] legacy identity (20 bytes)
	// NSPEC(1) | [LSTYPE(1) LSLEN(1) LSPEC(LSLEN)] ... | HTYPE(2) | HLEN(2) | HDATA
	nspec := byte(2) // 2 link specifiers

	// Spec 0: IPv4 address + port (type 0x00, len 6)
	spec0 := make([]byte, 8)
	spec0[0] = 0x00 // type
	spec0[1] = 6    // len
	copy(spec0[2:6], ip)
	binary.BigEndian.PutUint16(spec0[6:8], router.ORPort)

	// Spec 1: Legacy identity - SHA1 fingerprint (type 0x02, len 20)
	// We compute this from the router's identity (base64-encoded in consensus).
	identityHash, err := computeIdentityHash(router)
	if err != nil {
		return nil, fmt.Errorf("decode legacy identity: %w", err)
	}
	spec1 := make([]byte, 22)
	spec1[0] = 0x02 // type
	spec1[1] = 20   // len
	copy(spec1[2:], identityHash[:])

	body := make([]byte, 0, 1+len(spec0)+len(spec1)+4+len(handshakeData))
	body = append(body, nspec)
	body = append(body, spec0...)
	body = append(body, spec1...)

	// HTYPE = 0x0002 (ntor)
	htype := make([]byte, 2)
	binary.BigEndian.PutUint16(htype, 0x0002)
	body = append(body, htype...)

	// HLEN
	hlen := make([]byte, 2)
	binary.BigEndian.PutUint16(hlen, uint16(len(handshakeData)))
	body = append(body, hlen...)

	// HDATA
	body = append(body, handshakeData...)

	return body, nil
}

func parseIPv4(addr string) ([]byte, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %q", addr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("expected IPv4 address, got: %q", addr)
	}
	out := make([]byte, 4)
	copy(out, ipv4)
	return out, nil
}

func computeNodeID(router *directory.Router) (torcrypto.NodeID, error) {
	// The NodeID in ntor is SHA1(DER(RSA identity key)).
	// In the consensus, the identity is a base64-encoded 20-byte SHA1 hash
	// of the DER-encoded RSA identity key - this IS the NodeID.
	var id torcrypto.NodeID
	identityBytes, err := decodeIdentity(router.Identity)
	if err != nil {
		return id, err
	}
	copy(id[:], identityBytes)
	return id, nil
}

func computeIdentityHash(router *directory.Router) ([20]byte, error) {
	// The identity field in consensus is base64-encoded SHA1(DER(RSA_key)).
	// For EXTEND2 link specifier, we need exactly this hash.
	var hash [20]byte
	identityBytes, err := decodeIdentity(router.Identity)
	if err != nil {
		return hash, err
	}
	copy(hash[:], identityBytes)
	return hash, nil
}

func decodeIdentity(identity string) ([]byte, error) {
	// Consensus identity is base64-encoded (without padding) 20-byte hash.
	decoded, err := base64.RawStdEncoding.DecodeString(identity)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(identity)
		if err != nil {
			return nil, fmt.Errorf("decode identity: %w", err)
		}
	}
	if len(decoded) != torcrypto.NodeIDLen {
		return nil, fmt.Errorf("identity length = %d, want %d", len(decoded), torcrypto.NodeIDLen)
	}
	return decoded, nil
}

func newHopCrypto(keys *torcrypto.CircuitKeys) (*HopCrypto, error) {
	forward, err := torcrypto.NewRelayCrypto(keys.ForwardKey, keys.ForwardDigest)
	if err != nil {
		return nil, err
	}
	backward, err := torcrypto.NewRelayCrypto(keys.BackwardKey, keys.BackwardDigest)
	if err != nil {
		return nil, err
	}
	return &HopCrypto{
		Forward:  forward,
		Backward: backward,
	}, nil
}

// sendRelayCell encrypts and sends a relay cell through the circuit.
func (c *Circuit) sendRelayCell(cmd cell.RelayCommand, streamID uint16, data []byte, early bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	rc := &cell.RelayCell{
		Command:    cmd,
		Recognized: 0,
		StreamID:   streamID,
		Digest:     0,
		Data:       data,
	}

	body := rc.Encode()

	// Set digest: compute running digest with digest field zeroed.
	lastHop := c.hops[len(c.hops)-1]
	lastHop.Forward.UpdateDigest(body)
	digest := lastHop.Forward.DigestValue()
	binary.BigEndian.PutUint32(body[5:9], binary.BigEndian.Uint32(digest[:4]))

	// Encrypt: from last hop to first (onion layering).
	for i := len(c.hops) - 1; i >= 0; i-- {
		c.hops[i].Forward.Encrypt(body)
	}

	command := cell.CommandRelay
	if early {
		command = cell.CommandRelayEarly
	}

	cellMsg := &cell.Cell{
		CircID:  c.circID,
		Command: command,
		Payload: body,
	}

	return c.channel.SendCell(cellMsg)
}

// recvRelayCell reads and decrypts a relay cell from the circuit.
func (c *Circuit) recvRelayCell() (*cell.RelayCell, error) {
	for {
		msg, err := c.channel.RecvCell()
		if err != nil {
			return nil, fmt.Errorf("recv cell: %w", err)
		}

		switch msg.Command {
		case cell.CommandRelay, cell.CommandRelayEarly:
			// Decrypt onion layers.
			body := msg.Payload
			for i := 0; i < len(c.hops); i++ {
				c.hops[i].Backward.Decrypt(body)

				// Check if this hop is the origin.
				recognized := binary.BigEndian.Uint16(body[1:3])
				if recognized == 0 {
					// Check digest.
					recvDigest := binary.BigEndian.Uint32(body[5:9])

					// Zero out digest field for verification.
					body[5] = 0
					body[6] = 0
					body[7] = 0
					body[8] = 0

					c.hops[i].Backward.UpdateDigest(body)
					expectedDigest := c.hops[i].Backward.DigestValue()
					expected := binary.BigEndian.Uint32(expectedDigest[:4])

					if recvDigest == expected {
						// Restore digest for decode.
						binary.BigEndian.PutUint32(body[5:9], recvDigest)
						rc, err := cell.DecodeRelayCell(body)
						if err != nil {
							return nil, err
						}
						return rc, nil
					}

					// Digest didn't match; undo the digest update.
					// Since we can't undo SHA-1, we need to re-initialize.
					// This is a simplification; in practice, the recognized==0
					// but wrong digest case is very rare (2^-16 probability).
					// For now, continue to next hop.
					// Note: This means our backward digest state is now wrong
					// for this hop. In practice, this almost never happens.
					body[5] = byte(recvDigest >> 24)
					body[6] = byte(recvDigest >> 16)
					body[7] = byte(recvDigest >> 8)
					body[8] = byte(recvDigest)
				}
			}
			return nil, fmt.Errorf("relay cell not recognized at any hop")

		case cell.CommandDestroy:
			reason := byte(0)
			if len(msg.Payload) > 0 {
				reason = msg.Payload[0]
			}
			return nil, fmt.Errorf("circuit destroyed: reason %d", reason)

		case cell.CommandPadding, cell.CommandVpadding:
			continue // Ignore padding.

		default:
			// Ignore unexpected cell types during relay communication.
			continue
		}
	}
}

// recvCellExpect reads a cell expecting a specific command.
func (c *Circuit) recvCellExpect(expected cell.Command) (*cell.Cell, error) {
	for {
		msg, err := c.channel.RecvCell()
		if err != nil {
			return nil, fmt.Errorf("recv cell: %w", err)
		}
		switch msg.Command {
		case expected:
			return msg, nil
		case cell.CommandDestroy:
			reason := byte(0)
			if len(msg.Payload) > 0 {
				reason = msg.Payload[0]
			}
			return nil, fmt.Errorf("circuit destroyed: reason %d", reason)
		case cell.CommandPadding, cell.CommandVpadding:
			continue
		default:
			return nil, fmt.Errorf("expected %s, got %s", expected, msg.Command)
		}
	}
}

// SendRelayCell sends an arbitrary relay cell through the circuit.
// This is used by the HS protocol for sending ESTABLISH_RENDEZVOUS, INTRODUCE1, etc.
func (c *Circuit) SendRelayCell(cmd cell.RelayCommand, streamID uint16, data []byte, early bool) error {
	return c.sendRelayCell(cmd, streamID, data, early)
}

// SendRelayData sends a RELAY_DATA cell with the given data.
func (c *Circuit) SendRelayData(streamID uint16, data []byte) error {
	return c.sendRelayCell(cell.RelayData, streamID, data, false)
}

// SendRelayEnd sends a RELAY_END cell with the given one-byte reason code.
func (c *Circuit) SendRelayEnd(streamID uint16, reason byte) error {
	return c.sendRelayCell(cell.RelayEnd, streamID, []byte{reason}, false)
}

// SendRelayStreamSendme sends a stream-level SENDME (empty body, non-zero stream ID).
func (c *Circuit) SendRelayStreamSendme(streamID uint16) error {
	return c.sendRelayCell(cell.RelaySendme, streamID, nil, false)
}

// SendRelayBegin sends a RELAY_BEGIN cell to open a stream.
func (c *Circuit) SendRelayBegin(streamID uint16, addrPort string) error {
	// Body: ADDRPORT\0 [FLAGS]
	data := append([]byte(addrPort), 0)
	return c.sendRelayCell(cell.RelayBegin, streamID, data, false)
}

// SendRelaySendme sends a circuit-level SENDME cell.
func (c *Circuit) SendRelaySendme() error {
	// Version 1 SENDME with authenticated digest.
	lastHop := c.hops[len(c.hops)-1]
	digest := lastHop.Forward.DigestValue()

	// SENDME body: VERSION(1) | DATA_LEN(2) | DATA(20)
	data := make([]byte, 23)
	data[0] = 0x01 // Version 1
	binary.BigEndian.PutUint16(data[1:3], 20)
	copy(data[3:23], digest[:20])

	return c.sendRelayCell(cell.RelaySendme, 0, data, false)
}

// RecvRelayCell reads and decrypts a relay cell.
func (c *Circuit) RecvRelayCell() (*cell.RelayCell, error) {
	return c.recvRelayCell()
}

// CircID returns the circuit ID.
func (c *Circuit) CircID() uint32 {
	return c.circID
}

// Destroy sends a DESTROY cell to tear down the circuit.
func (c *Circuit) Destroy() error {
	payload := make([]byte, cell.CellBodyLen)
	payload[0] = byte(cell.DestroyReasonFinished)

	destroyCell := &cell.Cell{
		CircID:  c.circID,
		Command: cell.CommandDestroy,
		Payload: payload,
	}
	return c.channel.SendCell(destroyCell)
}

// HSCircuitKeys holds AES-256 keys + SHA3-256 digest seeds for an HS hop.
type HSCircuitKeys struct {
	ForwardDigest  []byte // 32 bytes (SHA3-256 seed)
	BackwardDigest []byte // 32 bytes
	ForwardKey     []byte // 32 bytes (AES-256)
	BackwardKey    []byte // 32 bytes
}

// AddHSHop adds a virtual hidden service hop to the circuit using
// AES-256-CTR + SHA3-256 (instead of AES-128-CTR + SHA-1).
func (c *Circuit) AddHSHop(keys *HSCircuitKeys) error {
	forward, err := torcrypto.NewRelayCryptoSHA3(keys.ForwardKey, keys.ForwardDigest)
	if err != nil {
		return fmt.Errorf("create HS forward crypto: %w", err)
	}
	backward, err := torcrypto.NewRelayCryptoSHA3(keys.BackwardKey, keys.BackwardDigest)
	if err != nil {
		return fmt.Errorf("create HS backward crypto: %w", err)
	}
	c.hops = append(c.hops, &HopCrypto{
		Forward:  forward,
		Backward: backward,
	})
	return nil
}

// Channel returns the underlying channel for this circuit.
func (c *Circuit) Channel() *channel.Channel {
	return c.channel
}

// ExtendRaw extends the circuit using raw link specifiers and handshake data.
// This is used for extending to introduction points where we have link specs
// from the HS descriptor rather than a Router object.
func (c *Circuit) ExtendRaw(linkSpecs []byte, ntorPK []byte, nodeID torcrypto.NodeID) error {
	var pk torcrypto.NtorPublicKey
	copy(pk[:], ntorPK)

	handshake, err := torcrypto.NewNtorClientHandshake(nodeID, pk)
	if err != nil {
		return fmt.Errorf("create ntor handshake: %w", err)
	}

	clientData := handshake.ClientHandshakeData()

	// Build EXTEND2 body: NSPEC + link_specs + HTYPE(2) + HLEN(2) + HDATA
	body := make([]byte, 0, len(linkSpecs)+4+len(clientData))
	body = append(body, linkSpecs...)
	// HTYPE = 0x0002 (ntor)
	body = append(body, 0x00, 0x02)
	// HLEN
	hlen := make([]byte, 2)
	binary.BigEndian.PutUint16(hlen, uint16(len(clientData)))
	body = append(body, hlen...)
	body = append(body, clientData...)

	if err := c.sendRelayCell(cell.RelayExtend2, 0, body, true); err != nil {
		return fmt.Errorf("send EXTEND2: %w", err)
	}

	relayCell, err := c.recvRelayCell()
	if err != nil {
		return fmt.Errorf("recv EXTENDED2: %w", err)
	}
	if relayCell.Command != cell.RelayExtended2 {
		return fmt.Errorf("expected EXTENDED2, got relay command %d", relayCell.Command)
	}

	if len(relayCell.Data) < 2 {
		return fmt.Errorf("EXTENDED2 data too short")
	}
	hlenResp := binary.BigEndian.Uint16(relayCell.Data[0:2])
	if len(relayCell.Data) < int(2+hlenResp) {
		return fmt.Errorf("EXTENDED2 HDATA too short")
	}
	hdata := relayCell.Data[2 : 2+hlenResp]

	result, err := handshake.Complete(hdata)
	if err != nil {
		return fmt.Errorf("complete ntor handshake: %w", err)
	}

	keys := torcrypto.DeriveCircuitKeys(result.KeySeed[:])
	hop, err := newHopCrypto(keys)
	if err != nil {
		return fmt.Errorf("create hop crypto: %w", err)
	}

	c.hops = append(c.hops, hop)
	return nil
}
