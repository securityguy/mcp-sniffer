/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package sniffer

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// mockPort captures Write calls for inspection and returns zero bytes on Read.
type mockPort struct {
	written []byte
}

func (m *mockPort) Read(buf []byte) (int, error) { return 0, nil }
func (m *mockPort) Write(data []byte) (int, error) {
	m.written = append(m.written, data...)
	return len(data), nil
}
func (m *mockPort) Close() error { return nil }

// newTestSniffer returns a Sniffer wired to a mockPort with running=true.
// It does not open a serial port or send any firmware commands.
func newTestSniffer() (*Sniffer, *mockPort) {
	mock := &mockPort{}
	s := &Sniffer{
		port:    mock,
		packets: make(chan RawPacket, 16),
		stopCh:  make(chan struct{}),
	}
	s.running.Store(true)
	return s, mock
}

// decodeWritten strips the SLIP framing from a mockPort's captured bytes
// and returns the inner V1 frame content (header + payload, unescaped).
func decodeWritten(t *testing.T, data []byte) []byte {
	t.Helper()
	if len(data) < 2 || data[0] != slipStart {
		t.Fatalf("expected SLIP start byte 0x%02X, got 0x%02X", slipStart, data[0])
	}
	end := bytes.IndexByte(data[1:], slipEnd)
	if end < 0 {
		t.Fatalf("no SLIP end byte found")
	}
	return slipUnescape(data[1 : end+1])
}

// ---------------------------------------------------------------------------
// parseAddr
// ---------------------------------------------------------------------------

func TestParseAddr(t *testing.T) {
	tests := []struct {
		input    string
		wantB    [6]byte
		wantType byte
		wantErr  bool
	}{
		// Normal public address (top 2 bits of MSB = 00 → public, type 0)
		{"04:E3:E5:B0:87:05", [6]byte{0x04, 0xE3, 0xE5, 0xB0, 0x87, 0x05}, 0, false},
		// Lowercase input should be treated identically
		{"04:e3:e5:b0:87:05", [6]byte{0x04, 0xE3, 0xE5, 0xB0, 0x87, 0x05}, 0, false},
		// Dash separator
		{"04-E3-E5-B0-87-05", [6]byte{0x04, 0xE3, 0xE5, 0xB0, 0x87, 0x05}, 0, false},
		// Static random address (top 2 bits of MSB = 11 → type 1)
		{"C0:FF:EE:11:22:33", [6]byte{0xC0, 0xFF, 0xEE, 0x11, 0x22, 0x33}, 1, false},
		// Another static random
		{"FF:AA:BB:CC:DD:EE", [6]byte{0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}, 1, false},
		// Errors
		{"04:E3:E5:B0:87",         [6]byte{}, 0, true}, // too few octets
		{"04:E3:E5:B0:87:05:11",   [6]byte{}, 0, true}, // too many octets
		{"ZZ:E3:E5:B0:87:05",      [6]byte{}, 0, true}, // invalid hex
		{"",                        [6]byte{}, 0, true}, // empty string
	}

	for _, tt := range tests {
		b, addrType, err := parseAddr(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseAddr(%q): want error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseAddr(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if b != tt.wantB {
			t.Errorf("parseAddr(%q): bytes = %02X, want %02X", tt.input, b[:], tt.wantB[:])
		}
		if addrType != tt.wantType {
			t.Errorf("parseAddr(%q): addrType = %d, want %d", tt.input, addrType, tt.wantType)
		}
	}
}

// ---------------------------------------------------------------------------
// Follow — payload byte order
// ---------------------------------------------------------------------------

// TestFollowPayloadByteOrder verifies that Follow() encodes the address in
// MSB-first order, matching the Nordic SnifferAPI reference implementation
// (Packet.py extractAddresses reverses OTA/LSB-first bytes to MSB-first
// before calling sendFollow).
func TestFollowPayloadByteOrder(t *testing.T) {
	s, mock := newTestSniffer()

	if err := s.Follow("04:E3:E5:B0:87:05"); err != nil {
		t.Fatalf("Follow: %v", err)
	}

	frame := decodeWritten(t, mock.written)

	// V1 header: [0] hdr_len, [1] payload_len, [2] proto_ver=1,
	//            [3-4] counter LE, [5] packet_id
	if len(frame) < headerLen {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	if frame[2] != protoVerV1 {
		t.Errorf("proto_ver = %d, want %d", frame[2], protoVerV1)
	}
	if frame[5] != reqFollow {
		t.Errorf("packet_id = 0x%02X, want 0x%02X (reqFollow)", frame[5], reqFollow)
	}

	payload := frame[headerLen:]
	if len(payload) < 8 {
		t.Fatalf("payload too short: %d bytes (want 8)", len(payload))
	}

	// Bytes [0-5]: address MSB-first (same as human-readable string)
	wantAddr := []byte{0x04, 0xE3, 0xE5, 0xB0, 0x87, 0x05}
	if !bytes.Equal(payload[:6], wantAddr) {
		t.Errorf("address bytes = %02X\n                want %02X (MSB-first)", payload[:6], wantAddr)
		t.Log("If bytes are reversed the firmware will follow the wrong device.")
	}

	// Byte [6]: addrType — 0x04 MSB has top bits 00, so public (0)
	if payload[6] != 0 {
		t.Errorf("addrType = %d, want 0 (public)", payload[6])
	}
	// Byte [7]: full_follow = 0 (capture connections, not advertising-only)
	if payload[7] != 0 {
		t.Errorf("full_follow = %d, want 0", payload[7])
	}
}

// TestFollowPayloadByteOrderRandom checks a static-random address (addrType=1).
func TestFollowPayloadByteOrderRandom(t *testing.T) {
	s, mock := newTestSniffer()

	if err := s.Follow("C0:11:22:33:44:55"); err != nil {
		t.Fatalf("Follow: %v", err)
	}

	frame := decodeWritten(t, mock.written)
	payload := frame[headerLen:]

	wantAddr := []byte{0xC0, 0x11, 0x22, 0x33, 0x44, 0x55}
	if !bytes.Equal(payload[:6], wantAddr) {
		t.Errorf("address bytes = %02X, want %02X", payload[:6], wantAddr)
	}
	if payload[6] != 1 {
		t.Errorf("addrType = %d, want 1 (static random)", payload[6])
	}
}

// ---------------------------------------------------------------------------
// SLIP encoding / decoding round-trip
// ---------------------------------------------------------------------------

func TestSlipRoundTrip(t *testing.T) {
	// Include all special SLIP bytes to exercise the escape paths.
	original := []byte{0x00, slipStart, slipEnd, slipEsc, 0xFF, 0xAB, 0xBC, 0xCD}
	encoded := slipEncode(original)
	decoded := slipUnescape(encoded[1 : len(encoded)-1]) // strip START/END
	if !bytes.Equal(decoded, original) {
		t.Errorf("round-trip mismatch\n got:  %02X\n want: %02X", decoded, original)
	}
}

// ---------------------------------------------------------------------------
// buildV1Frame
// ---------------------------------------------------------------------------

func TestBuildV1Frame(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	frame := buildV1Frame(0xAB, payload, 0x0102)

	if frame[2] != protoVerV1 {
		t.Errorf("proto_ver = %d, want %d", frame[2], protoVerV1)
	}
	counter := binary.LittleEndian.Uint16(frame[3:5])
	if counter != 0x0102 {
		t.Errorf("counter = 0x%04X, want 0x0102", counter)
	}
	if frame[5] != 0xAB {
		t.Errorf("packet_id = 0x%02X, want 0xAB", frame[5])
	}
	if !bytes.Equal(frame[6:], payload) {
		t.Errorf("payload = %02X, want %02X", frame[6:], payload)
	}
}
