package proxy

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
) 

var (
	ErrInvalidPacket    = errors.New("invalid packet")
	ErrInvalidHandshake = errors.New("invalid handshake")
	ErrAuthFailed       = errors.New("authentication failed")
)

type Packet struct {
	Length   uint32
	Sequence uint8
	Payload  []byte
}

func ReadPacket(r io.Reader) (*Packet, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	length := uint32(header[0]) | (uint32(header[1]) << 8) | (uint32(header[2]) << 16)
	sequence := header[3]

	if length == 0 {
		return &Packet{Length: 0, Sequence: sequence}, nil
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	return &Packet{Length: length, Sequence: sequence, Payload: payload}, nil
}

func WritePacket(w io.Writer, sequence uint8, payload []byte) error {
	if len(payload) > 0xFFFFFF {
		return fmt.Errorf("payload too large: %d", len(payload))
	}

	header := make([]byte, 4)
	header[0] = byte(len(payload))
	header[1] = byte(len(payload) >> 8)
	header[2] = byte(len(payload) >> 16)
	header[3] = sequence

	_, err := w.Write(append(header, payload...))
	return err
}

func SendHandshake(w io.Writer) ([]byte, error) {
	const (
		capClientLongPassword uint32 = 0x00000001
		capFoundRows          uint32 = 0x00000002
		capLongFlag           uint32 = 0x00000004
		capConnectWithDB      uint32 = 0x00000008
		capProtocol41         uint32 = 0x00000200
		capTransactions       uint32 = 0x00002000
		capSecureConnection   uint32 = 0x00008000
		capPluginAuth         uint32 = 0x00080000
	)

	capabilities := capClientLongPassword | capFoundRows | capLongFlag | capConnectWithDB | capProtocol41 | capTransactions | capSecureConnection | capPluginAuth

	var buf bytes.Buffer
	buf.WriteByte(10)
	buf.WriteString("metal-db-proxy-1.0")
	buf.WriteByte(0)
	connID := make([]byte, 4)
	rand.Read(connID)
	buf.Write(connID)
	scramblePart1 := make([]byte, 8)
	rand.Read(scramblePart1)
	buf.Write(scramblePart1)
	buf.WriteByte(0x00)
	binary.Write(&buf, binary.LittleEndian, uint16(capabilities))
	buf.WriteByte(0x21)
	binary.Write(&buf, binary.LittleEndian, uint16(0x0002))
	binary.Write(&buf, binary.LittleEndian, uint16(capabilities>>16))
	buf.WriteByte(21) // 8 + 13
	buf.Write(make([]byte, 10))
	scramblePart2 := make([]byte, 12)
	rand.Read(scramblePart2)
	buf.Write(scramblePart2)
	buf.WriteByte(0)
	buf.WriteString("mysql_native_password")
	buf.WriteByte(0)

	if err := WritePacket(w, 0, buf.Bytes()); err != nil {
		return nil, err
	}

	scramble := make([]byte, 20)
	copy(scramble[:8], scramblePart1)
	copy(scramble[8:], scramblePart2[:12])
	return scramble, nil
}

func HandleHandshake(r io.Reader, w io.Writer, scramble []byte, sequence uint8) error {
	pkt, err := ReadPacket(r)
	if err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}

	return handleClientHandshakePacket(pkt.Payload, w, scramble, pkt.Sequence)
}

func handleClientHandshakePacket(payload []byte, w io.Writer, scramble []byte, sequence uint8) error {
	if len(payload) < 32 {
		return ErrInvalidHandshake
	}

	_ = binary.LittleEndian.Uint32(payload[4:8])

	pos := 36

	username, n, err := ReadNullTerminatedString(payload[pos:])
	if err != nil {
		return fmt.Errorf("parse username: %w", err)
	}
	pos += n

	authLen, authSize, err := ReadLengthEncodedInt(payload[pos:])
	if err != nil {
		return fmt.Errorf("parse auth len: %w", err)
	}
	pos += authSize

	if pos+int(authLen) > len(payload) {
		return ErrInvalidPacket
	}
	authResp := payload[pos : pos+int(authLen)]

	if !verifyMySQLNativePassword(string(authResp), "password", scramble) {
		errPkt := NewErrPacket(1045, "28000", "Access denied for user '"+username+"'")
		return WritePacket(w, sequence+1, errPkt)
	}

	okPkt := NewOKPacket(0, 0, 0)
	return WritePacket(w, sequence+1, okPkt)
}

func verifyMySQLNativePassword(clientResp, password string, scramble []byte) bool {
	resp := []byte(clientResp)
	if len(resp) != 20 || len(scramble) < 20 {
		return false
	}

	h1 := sha1.New()
	h1.Write([]byte(password))
	stage1 := h1.Sum(nil)

	h2 := sha1.New()
	h2.Write(stage1)
	stage2 := h2.Sum(nil)

	h3 := sha1.New()
	h3.Write(scramble)
	h3.Write(stage2)
	candidate := h3.Sum(nil)

	for i := 0; i < 20; i++ {
		if resp[i] != (candidate[i] ^ stage1[i]) {
			return false
		}
	}
	return true
}

func ReadNullTerminatedString(data []byte) (string, int, error) {
	i := bytes.IndexByte(data, 0)
	if i == -1 {
		return "", 0, ErrInvalidPacket
	}
	return string(data[:i]), i + 1, nil
}

func ReadLengthEncodedInt(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrInvalidPacket
	}

	first := data[0]
	if first < 0xFB {
		return uint64(first), 1, nil
	} else if first == 0xFB {
		return 0, 1, nil // NULL value
	}

	switch first {
	case 0xFC:
		if len(data) < 3 {
			return 0, 0, ErrInvalidPacket
		}
		return uint64(data[1]) | (uint64(data[2]) << 8), 3, nil
	case 0xFD:
		if len(data) < 4 {
			return 0, 0, ErrInvalidPacket
		}
		return uint64(data[1]) | (uint64(data[2]) << 8) | (uint64(data[3]) << 16), 4, nil
	case 0xFE:
		if len(data) < 9 {
			return 0, 0, ErrInvalidPacket
		}
		return binary.LittleEndian.Uint64(data[1:9]), 9, nil
	default:
		return 0, 0, ErrInvalidPacket
	}
}

func NewOKPacket(affectedRows, lastInsertID uint64, status uint16) []byte {
	payload := []byte{0x00} // OK header

	arBytes, _ := lengthEncode(affectedRows)
	payload = append(payload, arBytes...)

	liBytes, _ := lengthEncode(lastInsertID)
	payload = append(payload, liBytes...)

	statusBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(statusBytes, status)
	payload = append(payload, statusBytes...)

	warningsBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(warningsBytes, 0)
	payload = append(payload, warningsBytes...)

	return payload
}

func NewErrPacket(code uint16, sqlState, message string) []byte {
	payload := make([]byte, 0, 64)
	payload = append(payload, 0xFF)                      // error header
	payload = append(payload, byte(code), byte(code>>8)) // errno (2 bytes)
	payload = append(payload, '#')                       // sqlstate marker
	payload = append(payload, []byte(sqlState)...)       // sqlstate (5 chars)
	payload = append(payload, message...)                // message
	return payload
}

func lengthEncode(n uint64) ([]byte, error) {
	if n < 251 {
		return []byte{byte(n)}, nil
	} else if n < (1 << 16) {
		return []byte{0xFC, byte(n), byte(n >> 8)}, nil
	} else if n < (1 << 24) {
		return []byte{0xFD, byte(n), byte(n >> 8), byte(n >> 16)}, nil
	} else {
		buf := make([]byte, 9)
		buf[0] = 0xFE
		binary.LittleEndian.PutUint64(buf[1:], n)
		return buf, nil
	}
}
