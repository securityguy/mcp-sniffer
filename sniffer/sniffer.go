/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package sniffer

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CapabilityReporter is implemented by a packet store and used by the
// auto-tuner to decide which scan capabilities are still needed.
type CapabilityReporter interface {
	HasExtendedAdv() bool
	FilterActive() bool
}

// RawPacket is a decoded sniffer packet as received from the firmware.
type RawPacket struct {
	ReceivedAt time.Time
	ID         byte
	ProtoVer   byte
	Counter    uint16
	Payload    []byte
}

// Sniffer manages a serial connection to the nRF BLE sniffer firmware and
// streams decoded RawPackets to the caller via a channel.
type Sniffer struct {
	device      string
	baudRate    int
	channelSize int
	scanFlags   byte

	autoTune       bool
	autoTunePeriod time.Duration
	reporter       CapabilityReporter

	port    serialPort
	packets chan RawPacket
	stopCh  chan struct{}
	wg      sync.WaitGroup
	running atomic.Bool

	writeMu   sync.Mutex
	txCounter uint16
}

// Option is a functional option for configuring a Sniffer.
type Option func(*Sniffer)

// WithDevice sets the serial port path.
func WithDevice(path string) Option {
	return func(s *Sniffer) {
		s.device = path
	}
}

// WithBaudRate sets the baud rate for the serial port.
func WithBaudRate(baud int) Option {
	return func(s *Sniffer) {
		s.baudRate = baud
	}
}

// WithChannelSize sets the output channel buffer depth.
func WithChannelSize(n int) Option {
	return func(s *Sniffer) {
		s.channelSize = n
	}
}

// WithScanFlags sets the scan flags byte sent in REQ_SCAN_CONT.
func WithScanFlags(flags byte) Option {
	return func(s *Sniffer) { s.scanFlags = flags }
}

// WithoutScanRsp disables forwarding of SCAN_RSP packets.
//
//goland:noinspection GoUnusedExportedFunction,GoUnusedExportedFunction
func WithoutScanRsp() Option {
	return func(s *Sniffer) { s.scanFlags &^= ScanFlagScanRsp }
}

// WithoutExtendedAdv disables following ADV_EXT_IND to secondary channels (BT5).
//
//goland:noinspection GoUnusedExportedFunction,GoUnusedExportedFunction
func WithoutExtendedAdv() Option {
	return func(s *Sniffer) { s.scanFlags &^= ScanFlagExtAdv }
}

// WithoutCodedPHY disables scanning Coded PHY advertising channels (BT5 long-range).
//
//goland:noinspection GoUnusedExportedFunction,GoUnusedExportedFunction
func WithoutCodedPHY() Option {
	return func(s *Sniffer) { s.scanFlags &^= ScanFlagCodedPHY }
}

// New creates a new Sniffer with the provided options.
func New(opts ...Option) *Sniffer {
	s := &Sniffer{
		device:      DefaultDevice,
		baudRate:    DefaultBaud,
		channelSize: 1024,
		scanFlags:   ScanFlagAll,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.packets = make(chan RawPacket, s.channelSize)
	return s
}

// Start opens the serial port, sends the firmware initialisation sequence, and
// begins the read loop.
func (s *Sniffer) Start() error {
	// openNativePort drops then asserts DTR/RTS to reset the firmware, then switches
	// to the operational baud rate. The read goroutine must be running before we send
	// any commands so that responses are not lost.
	port, err := openNativePort(s.device, s.baudRate)
	if err != nil {
		return fmt.Errorf("open serial port: %w", err)
	}

	s.port = port
	s.stopCh = make(chan struct{})
	s.running.Store(true)

	s.wg.Add(1)
	go s.readLoop()

	// Wait for the firmware to be ready before sending the init sequence.
	time.Sleep(200 * time.Millisecond)

	if err := s.sendInitSequence(); err != nil {
		s.running.Store(false)
		_ = port.Close()
		return fmt.Errorf("send init sequence: %w", err)
	}

	return nil
}

// Stop signals the read loop to exit, closes the serial port, and waits for
// the goroutine to finish.
func (s *Sniffer) Stop() error {
	if !s.running.Swap(false) {
		return nil
	}
	close(s.stopCh)
	// Closing the port causes any blocking Read to return with an error,
	// which lets the readLoop observe that running is false and exit.
	err := s.port.Close()
	s.wg.Wait()
	close(s.packets)
	return err
}

// Packets returns the channel on which decoded RawPackets are delivered.
func (s *Sniffer) Packets() <-chan RawPacket {
	return s.packets
}

// sendInitSequence sends the full startup command sequence the firmware requires.
// Must match what the Nordic SnifferAPI Python library sends before scanning:
// SET_ADV_CHANNEL_HOP_SEQ → REQ_SCAN_CONT → SET_TEMPORARY_KEY.
func (s *Sniffer) sendInitSequence() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	sendCmd := func(id byte, payload []byte) error {
		frame := buildV1Frame(id, payload, s.txCounter)
		s.txCounter++
		_, err := s.port.Write(slipEncode(frame))
		return err
	}

	for _, cmd := range []struct {
		id      byte
		payload []byte
	}{
		{reqSetAdvHopSeq, []byte{3, 37, 38, 39}},
		{reqVersion, nil},
		{reqPing, nil},
		{reqTimestamp, nil},
	} {
		if err := sendCmd(cmd.id, cmd.payload); err != nil {
			return fmt.Errorf("write 0x%02X: %w", cmd.id, err)
		}
	}

	if err := s.sendReqScanContLocked(); err != nil {
		return err
	}
	if err := sendCmd(reqSetTemporaryKey, make([]byte, 16)); err != nil {
		return fmt.Errorf("write SET_TEMPORARY_KEY: %w", err)
	}

	return nil
}

// sendReqScanContLocked sends REQ_SCAN_CONT using the current scanFlags.
// Caller must hold writeMu.
func (s *Sniffer) sendReqScanContLocked() error {
	frame := buildV1Frame(ReqScanCont, []byte{s.scanFlags}, s.txCounter)
	s.txCounter++
	if _, err := s.port.Write(slipEncode(frame)); err != nil {
		return fmt.Errorf("write REQ_SCAN_CONT: %w", err)
	}
	return nil
}

// ScanFlags returns the current scan flag byte.
func (s *Sniffer) ScanFlags() byte {
	s.writeMu.Lock()
	f := s.scanFlags
	s.writeMu.Unlock()
	return f
}

// UpdateScanFlags atomically updates the scan flags and sends a new
// REQ_SCAN_CONT to the firmware. Returns an error if the sniffer is not running.
func (s *Sniffer) UpdateScanFlags(flags byte) error {
	if !s.running.Load() {
		return fmt.Errorf("sniffer is not running")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.scanFlags = flags
	return s.sendReqScanContLocked()
}

// Follow sends a REQ_FOLLOW command to the firmware, instructing it to follow
// the specified BLE device. addr must be a colon- or dash-separated hex address
// (e.g. "AA:BB:CC:DD:EE:FF"). Returns an error if the sniffer is not running.
func (s *Sniffer) Follow(addr string) error {
	if !s.running.Load() {
		return fmt.Errorf("sniffer is not running")
	}

	b, addrType, err := parseAddr(addr)
	if err != nil {
		return fmt.Errorf("follow: %w", err)
	}

	// Payload: 6 address bytes LSB-first (as transmitted OTA) + addrType + 0x00 = 8 bytes.
	// The firmware compares this against the AdvA field in received BLE packets,
	// which is also LSB-first, so the human-readable address must be reversed.
	payload := []byte{b[5], b[4], b[3], b[2], b[1], b[0], addrType, 0x00}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.txCounter++
	frame := buildV1Frame(reqFollow, payload, s.txCounter)
	encoded := slipEncode(frame)
	_, err = s.port.Write(encoded)
	if err != nil {
		return fmt.Errorf("write REQ_FOLLOW: %w", err)
	}
	return nil
}

// parseAddr parses a BLE address string into its 6 bytes and address type.
// The input may use colons or dashes as separators. Address type is auto-detected:
// if the top two bits of the first byte are both set (0xC0), type is 1 (static random);
// otherwise type is 0 (public).
func parseAddr(addr string) ([6]byte, byte, error) {
	norm := strings.ToUpper(strings.ReplaceAll(addr, "-", ":"))
	parts := strings.Split(norm, ":")
	if len(parts) != 6 {
		return [6]byte{}, 0, fmt.Errorf("address %q must have exactly 6 octets", addr)
	}

	var b [6]byte
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return [6]byte{}, 0, fmt.Errorf("address %q: invalid octet %q", addr, p)
		}
		b[i] = byte(v)
	}

	var addrType byte
	if b[0]&0xC0 == 0xC0 {
		addrType = 1 // static random
	}
	return b, addrType, nil
}

// buildV1Frame constructs a V1 firmware packet (sent frames are always V1).
func buildV1Frame(packetID byte, payload []byte, counter uint16) []byte {
	frame := make([]byte, headerLen+len(payload))
	frame[0] = headerLen
	frame[1] = byte(len(payload))
	frame[2] = protoVerV1
	binary.LittleEndian.PutUint16(frame[3:5], counter)
	frame[5] = packetID
	copy(frame[6:], payload)
	return frame
}

// slipEncode wraps data with SLIP START/END bytes, escaping special bytes.
func slipEncode(data []byte) []byte {
	// Pre-allocate with a reasonable capacity.
	out := make([]byte, 0, len(data)+4)
	out = append(out, slipStart)
	for _, b := range data {
		switch b {
		case slipStart:
			out = append(out, slipEsc, slipEscStart)
		case slipEnd:
			out = append(out, slipEsc, slipEscEnd)
		case slipEsc:
			out = append(out, slipEsc, slipEscEsc)
		default:
			out = append(out, b)
		}
	}
	out = append(out, slipEnd)
	return out
}

// readLoop reads bytes from the serial port and assembles SLIP frames.
func (s *Sniffer) readLoop() {
	defer s.wg.Done()

	buf := make([]byte, 1)
	var frame []byte
	inFrame := false

	for {
		n, err := s.port.Read(buf)
		if err != nil {
			// If we're stopping, the error is expected.
			if !s.running.Load() {
				return
			}
			_, _ = fmt.Fprintf(os.Stderr, "sniffer: read error: %v\n", err)
			return
		}
		if n == 0 {
			// VTIME read timeout — check if Stop has been called.
			if !s.running.Load() {
				return
			}
			continue
		}

		b := buf[0]
		switch {
		case b == slipStart:
			// Begin accumulating a new frame.
			frame = frame[:0]
			if frame == nil {
				frame = make([]byte, 0, 128)
			}
			inFrame = true

		case b == slipEnd:
			if !inFrame || len(frame) == 0 {
				inFrame = false
				continue
			}
			// Complete frame: unescape and parse.
			inFrame = false
			data := slipUnescape(frame)
			pkt, err := parsePacket(data)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "sniffer: parse error (len=%d): %v\n", len(data), err)
				continue
			}
			// Non-blocking send; drop packet if channel is full.
			select {
			case s.packets <- pkt:
			default:
			}

		case inFrame:
			frame = append(frame, b)
		}
	}
}

// slipUnescape removes escape sequences from raw SLIP frame content.
func slipUnescape(data []byte) []byte {
	out := make([]byte, 0, len(data))
	esc := false
	for _, b := range data {
		if esc {
			switch b {
			case slipEscStart:
				out = append(out, slipStart)
			case slipEscEnd:
				out = append(out, slipEnd)
			case slipEscEsc:
				out = append(out, slipEsc)
			default:
				// Unknown escape; emit both bytes to preserve data.
				out = append(out, slipEsc, b)
			}
			esc = false
			continue
		}
		if b == slipEsc {
			esc = true
			continue
		}
		out = append(out, b)
	}
	return out
}

// parsePacket decodes the header of a SLIP-unescaped frame into a RawPacket.
// Supports V1 (old firmware) and V3 (current firmware) header formats.
//
//goland:noinspection GoErrorStringFormat
func parsePacket(data []byte) (RawPacket, error) {
	if len(data) < 3 {
		return RawPacket{}, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	protoVer := data[2]

	var counter uint16
	var packetID byte
	var payload []byte

	switch protoVer {
	case protoVerV3:
		// V3: [0-1] payload_len uint16 LE, [2] proto_ver, [3-4] counter uint16 LE, [5] packet_id, [6…] payload
		if len(data) < 6 {
			return RawPacket{}, fmt.Errorf("V3 packet too short: %d bytes", len(data))
		}
		payloadLen := int(binary.LittleEndian.Uint16(data[0:2]))
		counter = binary.LittleEndian.Uint16(data[3:5])
		packetID = data[5]
		if len(data) < 6+payloadLen {
			return RawPacket{}, fmt.Errorf("V3 payload truncated: have %d, want %d", len(data)-6, payloadLen)
		}
		payload = make([]byte, payloadLen)
		copy(payload, data[6:6+payloadLen])

	case protoVerV1:
		// V1: [0] header_len (=6), [1] payload_len uint8, [2] proto_ver, [3-4] counter uint16 LE, [5] packet_id, [6…] payload
		if len(data) < 6 {
			return RawPacket{}, fmt.Errorf("V1 packet too short: %d bytes", len(data))
		}
		payloadLen := int(data[1])
		counter = binary.LittleEndian.Uint16(data[3:5])
		packetID = data[5]
		if len(data) < 6+payloadLen {
			return RawPacket{}, fmt.Errorf("V1 payload truncated: have %d, want %d", len(data)-6, payloadLen)
		}
		payload = make([]byte, payloadLen)
		copy(payload, data[6:6+payloadLen])

	default:
		return RawPacket{}, fmt.Errorf("unknown protocol version: %d", protoVer)
	}

	return RawPacket{
		ReceivedAt: time.Now(),
		ID:         packetID,
		ProtoVer:   protoVer,
		Counter:    counter,
		Payload:    payload,
	}, nil
}
