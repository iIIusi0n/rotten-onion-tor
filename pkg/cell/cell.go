// Package cell implements Tor cell encoding and decoding.
//
// Cells are the basic unit of communication on a Tor channel.
// Fixed-length cells are 514 bytes (for link protocol v4+):
//
//	CircID [4 bytes] | Command [1 byte] | Body [509 bytes]
//
// Variable-length cells have a length field:
//
//	CircID [4 bytes] | Command [1 byte] | Length [2 bytes] | Body [Length bytes]
package cell

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Constants for cell sizes and protocol parameters.
const (
	// CellBodyLen is the fixed body length for all cells.
	CellBodyLen = 509

	// CircIDLen is the circuit ID length for link protocol v4+.
	CircIDLen = 4

	// FixedCellLen is the total length of a fixed-length cell (v4+).
	FixedCellLen = CircIDLen + 1 + CellBodyLen // 514

	// MaxPayloadLen is the maximum payload length for variable-length cells.
	MaxPayloadLen = 65535
)

// Command represents a Tor cell command byte.
type Command uint8

// Fixed-length cell commands.
const (
	CommandPadding          Command = 0
	CommandCreate           Command = 1
	CommandCreated          Command = 2
	CommandRelay            Command = 3
	CommandDestroy          Command = 4
	CommandCreateFast       Command = 5
	CommandCreatedFast      Command = 6
	CommandNetinfo          Command = 8
	CommandRelayEarly       Command = 9
	CommandCreate2          Command = 10
	CommandCreated2         Command = 11
	CommandPaddingNegotiate Command = 12
)

// Variable-length cell commands.
const (
	CommandVersions      Command = 7
	CommandVpadding      Command = 128
	CommandCerts         Command = 129
	CommandAuthChallenge Command = 130
	CommandAuthenticate  Command = 131
	CommandAuthorize     Command = 132
)

// IsVariableLength returns true if the command indicates a variable-length cell.
func (c Command) IsVariableLength() bool {
	return c == CommandVersions || c >= 128
}

func (c Command) String() string {
	names := map[Command]string{
		CommandPadding:          "PADDING",
		CommandCreate:           "CREATE",
		CommandCreated:          "CREATED",
		CommandRelay:            "RELAY",
		CommandDestroy:          "DESTROY",
		CommandCreateFast:       "CREATE_FAST",
		CommandCreatedFast:      "CREATED_FAST",
		CommandVersions:         "VERSIONS",
		CommandNetinfo:          "NETINFO",
		CommandRelayEarly:       "RELAY_EARLY",
		CommandCreate2:          "CREATE2",
		CommandCreated2:         "CREATED2",
		CommandPaddingNegotiate: "PADDING_NEGOTIATE",
		CommandVpadding:         "VPADDING",
		CommandCerts:            "CERTS",
		CommandAuthChallenge:    "AUTH_CHALLENGE",
		CommandAuthenticate:     "AUTHENTICATE",
		CommandAuthorize:        "AUTHORIZE",
	}
	if name, ok := names[c]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", c)
}

// Cell represents a Tor cell (either fixed or variable length).
type Cell struct {
	CircID  uint32
	Command Command
	Payload []byte // For fixed cells, always 509 bytes; for variable, the actual payload.
}

// Encode writes the cell to the writer in wire format (link protocol v4+).
func (c *Cell) Encode(w io.Writer) error {
	// Write CircID (4 bytes, big-endian).
	if err := binary.Write(w, binary.BigEndian, c.CircID); err != nil {
		return fmt.Errorf("write circid: %w", err)
	}

	// Write Command (1 byte).
	if _, err := w.Write([]byte{byte(c.Command)}); err != nil {
		return fmt.Errorf("write command: %w", err)
	}

	if c.Command.IsVariableLength() {
		// Variable-length: write length + payload.
		if len(c.Payload) > MaxPayloadLen {
			return fmt.Errorf("payload too large: %d > %d", len(c.Payload), MaxPayloadLen)
		}
		if err := binary.Write(w, binary.BigEndian, uint16(len(c.Payload))); err != nil {
			return fmt.Errorf("write length: %w", err)
		}
		if _, err := w.Write(c.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	} else {
		// Fixed-length: write body padded to CellBodyLen.
		body := make([]byte, CellBodyLen)
		copy(body, c.Payload)
		if _, err := w.Write(body); err != nil {
			return fmt.Errorf("write body: %w", err)
		}
	}
	return nil
}

// Decode reads a cell from the reader (link protocol v4+).
// For VERSIONS cells received before version negotiation, use DecodeVersions.
func Decode(r io.Reader) (*Cell, error) {
	// Read CircID (4 bytes).
	var circID uint32
	if err := binary.Read(r, binary.BigEndian, &circID); err != nil {
		return nil, fmt.Errorf("read circid: %w", err)
	}

	// Read Command (1 byte).
	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, cmdBuf); err != nil {
		return nil, fmt.Errorf("read command: %w", err)
	}
	cmd := Command(cmdBuf[0])

	var payload []byte
	if cmd.IsVariableLength() {
		// Read Length (2 bytes).
		var length uint16
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return nil, fmt.Errorf("read length: %w", err)
		}
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	} else {
		// Read fixed body (CellBodyLen bytes).
		payload = make([]byte, CellBodyLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
	}

	return &Cell{
		CircID:  circID,
		Command: cmd,
		Payload: payload,
	}, nil
}

// DecodeVersions reads a VERSIONS cell from a connection before version
// negotiation. The VERSIONS cell always uses CircID length of 2 (v=0).
func DecodeVersions(r io.Reader) (*Cell, error) {
	// CircID is 2 bytes for VERSIONS cell.
	var circID uint16
	if err := binary.Read(r, binary.BigEndian, &circID); err != nil {
		return nil, fmt.Errorf("read circid: %w", err)
	}

	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, cmdBuf); err != nil {
		return nil, fmt.Errorf("read command: %w", err)
	}
	cmd := Command(cmdBuf[0])
	if cmd != CommandVersions {
		return nil, fmt.Errorf("expected VERSIONS command (7), got %d", cmd)
	}

	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if length%2 != 0 {
		return nil, errors.New("VERSIONS cell body has odd length")
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	return &Cell{
		CircID:  uint32(circID),
		Command: cmd,
		Payload: payload,
	}, nil
}

// EncodeVersions writes a VERSIONS cell with CircID length of 2 (v=0).
func EncodeVersions(w io.Writer, versions []uint16) error {
	// CircID = 0 (2 bytes for VERSIONS cell).
	if err := binary.Write(w, binary.BigEndian, uint16(0)); err != nil {
		return fmt.Errorf("write circid: %w", err)
	}
	// Command = 7 (VERSIONS).
	if _, err := w.Write([]byte{byte(CommandVersions)}); err != nil {
		return fmt.Errorf("write command: %w", err)
	}
	// Length.
	if err := binary.Write(w, binary.BigEndian, uint16(len(versions)*2)); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	// Versions.
	for _, v := range versions {
		if err := binary.Write(w, binary.BigEndian, v); err != nil {
			return fmt.Errorf("write version: %w", err)
		}
	}
	return nil
}

// ParseVersions extracts the version list from a VERSIONS cell payload.
func ParseVersions(payload []byte) ([]uint16, error) {
	if len(payload)%2 != 0 {
		return nil, errors.New("VERSIONS payload has odd length")
	}
	versions := make([]uint16, len(payload)/2)
	for i := range versions {
		versions[i] = binary.BigEndian.Uint16(payload[i*2:])
	}
	return versions, nil
}

// Relay cell constants.
const (
	RelayHeaderLen = 11 // cmd(1) + recognized(2) + streamID(2) + digest(4) + length(2)
	RelayBodyLen   = CellBodyLen - RelayHeaderLen
)

// RelayCommand represents a relay cell sub-command.
type RelayCommand uint8

const (
	RelayBegin        RelayCommand = 1
	RelayData         RelayCommand = 2
	RelayEnd          RelayCommand = 3
	RelayConnected    RelayCommand = 4
	RelaySendme       RelayCommand = 5
	RelayExtend       RelayCommand = 6
	RelayExtended     RelayCommand = 7
	RelayTruncate     RelayCommand = 8
	RelayTruncated    RelayCommand = 9
	RelayDrop         RelayCommand = 10
	RelayResolve      RelayCommand = 11
	RelayResolved     RelayCommand = 12
	RelayBeginDir     RelayCommand = 13
	RelayExtend2      RelayCommand = 14
	RelayExtended2    RelayCommand = 15

	// Hidden service relay commands.
	RelayEstablishIntro      RelayCommand = 32
	RelayEstablishRendezvous RelayCommand = 33
	RelayIntroduce1          RelayCommand = 34
	RelayIntroduce2          RelayCommand = 35
	RelayRendezvous1         RelayCommand = 36
	RelayRendezvous2         RelayCommand = 37
	RelayIntroEstablished    RelayCommand = 38
	RelayRendezvousEstablished RelayCommand = 39
	RelayIntroduceAck        RelayCommand = 40
)

// RelayCell represents the decrypted contents of a RELAY cell.
type RelayCell struct {
	Command    RelayCommand
	Recognized uint16
	StreamID   uint16
	Digest     uint32
	Data       []byte
}

// EncodeRelay encodes a relay cell into a CellBodyLen-byte body.
func (rc *RelayCell) Encode() []byte {
	body := make([]byte, CellBodyLen)
	body[0] = byte(rc.Command)
	binary.BigEndian.PutUint16(body[1:3], rc.Recognized)
	binary.BigEndian.PutUint16(body[3:5], rc.StreamID)
	binary.BigEndian.PutUint32(body[5:9], rc.Digest)
	binary.BigEndian.PutUint16(body[9:11], uint16(len(rc.Data)))
	copy(body[11:], rc.Data)
	return body
}

// DecodeRelayCell decodes a CellBodyLen-byte body into a RelayCell.
func DecodeRelayCell(body []byte) (*RelayCell, error) {
	if len(body) < RelayHeaderLen {
		return nil, fmt.Errorf("relay cell body too short: %d", len(body))
	}
	dataLen := binary.BigEndian.Uint16(body[9:11])
	if int(dataLen) > len(body)-RelayHeaderLen {
		return nil, fmt.Errorf("relay data length %d exceeds body", dataLen)
	}
	return &RelayCell{
		Command:    RelayCommand(body[0]),
		Recognized: binary.BigEndian.Uint16(body[1:3]),
		StreamID:   binary.BigEndian.Uint16(body[3:5]),
		Digest:     binary.BigEndian.Uint32(body[5:9]),
		Data:       body[11 : 11+dataLen],
	}, nil
}

// Destroy reason codes.
const (
	DestroyReasonNone            = 0
	DestroyReasonProtocol        = 1
	DestroyReasonInternal        = 2
	DestroyReasonRequested       = 3
	DestroyReasonHibernating     = 4
	DestroyReasonResourceLimit   = 5
	DestroyReasonConnectFailed   = 6
	DestroyReasonOrIdentity      = 7
	DestroyReasonChannelClosing  = 8
	DestroyReasonFinished        = 9
	DestroyReasonTimeout         = 10
	DestroyReasonDestroyed       = 11
	DestroyReasonNoSuchService   = 12
)
