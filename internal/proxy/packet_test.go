package proxy

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

func TestWriteReadPacket(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello")
	if err := WritePacket(&buf, 7, payload); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	pkt, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if pkt.Sequence != 7 {
		t.Fatalf("sequence mismatch: got %d", pkt.Sequence)
	}
	if !bytes.Equal(pkt.Payload, payload) {
		t.Fatalf("payload mismatch: got %q", pkt.Payload)
	}
}

func TestReadLengthEncodedInt(t *testing.T) {
	cases := []struct {
		in       []byte
		expected uint64
		size     int
	}{
		{[]byte{0xFA}, 0xFA, 1},
		{[]byte{0xFC, 0x01, 0x02}, 0x0201, 3},
		{[]byte{0xFD, 0x01, 0x02, 0x03}, 0x030201, 4},
		{[]byte{0xFE, 0x01, 0, 0, 0, 0, 0, 0, 0}, 1, 9},
	}
	for _, c := range cases {
		val, size, err := ReadLengthEncodedInt(c.in)
		if err != nil {
			t.Fatalf("unexpected error for %v: %v", c.in, err)
		}
		if val != c.expected || size != c.size {
			t.Fatalf("got val=%d size=%d expected val=%d size=%d", val, size, c.expected, c.size)
		}
	}
	// NULL
	val, size, err := ReadLengthEncodedInt([]byte{0xFB})
	if err != nil || val != 0 || size != 1 {
		t.Fatalf("NULL case mismatch: val=%d size=%d err=%v", val, size, err)
	}
}

func TestOKPacketFormat(t *testing.T) {
	p := NewOKPacket(1, 2, 0x0002)
	if len(p) < 7 {
		t.Fatalf("packet too short: %d", len(p))
	}
	if p[0] != 0x00 {
		t.Fatalf("expected OK header, got %x", p[0])
	}
	// status at the end of affectedRows/lastInsertId (length-encoded 1 byte each)
	status := binary.LittleEndian.Uint16(p[len(p)-4 : len(p)-2])
	if status != 0x0002 {
		t.Fatalf("status mismatch: %x", status)
	}
}

func TestErrPacketFormat(t *testing.T) {
	p := NewErrPacket(1045, "28000", "Access denied")
	if len(p) < 9 {
		t.Fatalf("packet too short: %d", len(p))
	}
	if p[0] != 0xFF {
		t.Fatalf("expected ERR header, got %x", p[0])
	}
	code := binary.LittleEndian.Uint16(p[1:3])
	if code != 1045 {
		t.Fatalf("code mismatch: %d", code)
	}
	if p[3] != '#' {
		t.Fatalf("missing sqlstate marker")
	}
}

func TestVerifyMySQLNativePassword(t *testing.T) {
	password := "password"
	scramble := bytes.Repeat([]byte{0x01}, 20)

	// Recreate client response according to algorithm in verifyMySQLNativePassword
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h3 := sha1.New()
	h3.Write(scramble)
	h3.Write(h2[:])
	candidate := h3.Sum(nil)

	resp := make([]byte, 20)
	for i := 0; i < 20; i++ {
		resp[i] = candidate[i] ^ h1[i]
	}

	if !verifyMySQLNativePassword(string(resp), password, scramble) {
		t.Fatalf("expected password verification to succeed")
	}

	if verifyMySQLNativePassword(string(resp), "wrong", scramble) {
		t.Fatalf("expected password verification to fail with wrong password")
	}
}
