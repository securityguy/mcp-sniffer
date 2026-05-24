/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

// Package mcpserver exposes the BLE sniffer as an MCP server over stdio.
// Call Run to start serving; it blocks until the context is cancelled or the
// client disconnects.
package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tenebris-tech/mcp-sniffer/blecap"
	"github.com/tenebris-tech/mcp-sniffer/bledata"
	"github.com/tenebris-tech/mcp-sniffer/bledev"
	"github.com/tenebris-tech/mcp-sniffer/blepdu"
)

// captureSession holds the state of a running (or recently stopped) capture.
type captureSession struct {
	cap       *blecap.Capture
	device    string
	filter    string
	follow    string
	startedAt time.Time
	baseIndex int        // virtual "clear" point; packets before this index are hidden
	stopTimer *time.Timer
}

var (
	sessMu sync.Mutex
	sess   *captureSession
)

// ---------------------------------------------------------------------------
// Tool input / output types
// ---------------------------------------------------------------------------

// StartInput is the input schema for sniffer_start.
type StartInput struct {
	Device   string `json:"device,omitempty"   jsonschema:"description=Serial port path. Leave empty for auto-detection."`
	Filter   string `json:"filter,omitempty"   jsonschema:"description=Comma-separated BLE addresses or OUI prefixes to capture (e.g. AA:BB:CC:DD:EE:FF or 04:E3). Empty captures all."`
	Follow   string `json:"follow,omitempty"   jsonschema:"description=Single BLE address for hardware follow mode (captures DATA_PDUs during BLE connections)."`
	Duration int    `json:"duration,omitempty" jsonschema:"description=Capture duration in seconds. 0 means run until sniffer_stop is called."`
}

// StartOutput is the result of sniffer_start.
type StartOutput struct {
	Status  string `json:"status"`
	Device  string `json:"device"`
	Filter  string `json:"filter,omitempty"`
	Follow  string `json:"follow,omitempty"`
	Message string `json:"message,omitempty"`
}

// StopOutput is the result of sniffer_stop.
type StopOutput struct {
	Status          string `json:"status"`
	PacketsCaptured int    `json:"packets_captured"`
	Duration        string `json:"duration"`
}

// StatusOutput is the result of sniffer_status.
type StatusOutput struct {
	Running     bool   `json:"running"`
	PacketCount int    `json:"packet_count"`
	Device      string `json:"device,omitempty"`
	Filter      string `json:"filter,omitempty"`
	Follow      string `json:"follow,omitempty"`
	Elapsed     string `json:"elapsed,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
}

// SetFilterInput is the input schema for sniffer_set_filter.
type SetFilterInput struct {
	Addresses       string `json:"addresses"                  jsonschema:"description=Comma-separated BLE addresses or OUI prefixes. Empty string clears the filter."`
	DiscardExisting bool   `json:"discard_existing,omitempty" jsonschema:"description=If true discard all previously captured packets from results."`
}

// SetFilterOutput is the result of sniffer_set_filter.
type SetFilterOutput struct {
	Status string `json:"status"`
	Filter string `json:"filter"`
}

// GetPacketsInput is the input schema for sniffer_get_packets.
type GetPacketsInput struct {
	Offset     int    `json:"offset,omitempty"      jsonschema:"description=Starting index for pagination (default 0)."`
	Limit      int    `json:"limit,omitempty"       jsonschema:"description=Maximum packets to return 1-200 (default 50)."`
	PDUType    string `json:"pdu_type,omitempty"    jsonschema:"description=Filter by PDU type substring e.g. ADV_IND CONNECT_IND DATA_PDU SCAN_RSP. Empty returns all."`
	Address    string `json:"address,omitempty"     jsonschema:"description=Filter to packets containing this address substring (case-insensitive)."`
	OutputMode string `json:"output_mode,omitempty" jsonschema:"description=Output detail: summary (default) or full (adds raw_hex)."`
}

// GetPacketsOutput is the result of sniffer_get_packets.
type GetPacketsOutput struct {
	Packets []PacketInfo `json:"packets"`
	Total   int          `json:"total"`
	Offset  int          `json:"offset"`
	Limit   int          `json:"limit"`
	HasMore bool         `json:"has_more"`
}

// GetPacketInput is the input schema for sniffer_get_packet.
type GetPacketInput struct {
	Index int `json:"index" jsonschema:"description=Absolute packet index to retrieve."`
}

// ClearOutput is the result of sniffer_clear_packets.
type ClearOutput struct {
	Status    string `json:"status"`
	Discarded int    `json:"discarded"`
}

// AddressEntry pairs a role label with a BLE address.
type AddressEntry struct {
	Role    string `json:"role"`
	Address string `json:"address"`
}

// PacketInfo is the per-packet representation returned by get_packets and get_packet.
type PacketInfo struct {
	Index     int            `json:"index"`
	Timestamp string         `json:"timestamp"`
	PDUType   string         `json:"pdu_type"`
	Channel   int            `json:"channel"`
	RSSIdbm   int            `json:"rssi_dbm"`
	Addresses []AddressEntry `json:"addresses,omitempty"`
	RawHex    string         `json:"raw_hex,omitempty"` // only populated in full output mode
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// toPacketInfo converts a bledata.Packet to the MCP-facing PacketInfo.
// When full is true the raw payload is included as a compact hex string.
func toPacketInfo(pkt bledata.Packet, full bool) PacketInfo {
	info := PacketInfo{
		Index:     pkt.Index,
		Timestamp: pkt.ReceivedAt.Format(time.RFC3339Nano),
		PDUType:   blepdu.PDUTypeName(pkt.ID, pkt.Raw),
	}
	if len(pkt.Raw) >= 4 {
		info.Channel = int(pkt.Raw[2])
		// RSSI is stored as an unsigned byte; actual signal level is -raw dBm.
		info.RSSIdbm = -int(pkt.Raw[3])
	}
	roles := blepdu.AddressRoles(pkt.ID, pkt.Raw)
	for i, addr := range pkt.Addresses {
		role := "addr"
		if i < len(roles) {
			role = roles[i]
		}
		info.Addresses = append(info.Addresses, AddressEntry{Role: role, Address: addr})
	}
	if full {
		info.RawHex = fmt.Sprintf("%x", pkt.Raw)
	}
	return info
}

// splitFilter splits a comma-separated address string into a normalised slice,
// discarding empty entries.
func splitFilter(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Tool handlers
// ---------------------------------------------------------------------------

// startCapture implements the sniffer_start tool.
func startCapture(_ context.Context, _ *mcp.CallToolRequest, input StartInput) (*mcp.CallToolResult, StartOutput, error) {
	sessMu.Lock()
	defer sessMu.Unlock()

	if sess != nil {
		return nil, StartOutput{}, fmt.Errorf("capture already running; call sniffer_stop first")
	}

	device := input.Device
	if device == "" {
		var err error
		device, err = bledev.Find()
		if err != nil {
			return nil, StartOutput{}, fmt.Errorf("auto-detect device: %w", err)
		}
	}

	opts := []blecap.Option{
		blecap.WithDevice(device),
		blecap.WithAutoTune(),
	}
	if input.Filter != "" {
		opts = append(opts, blecap.WithFilter(splitFilter(input.Filter)))
	}
	if input.Follow != "" {
		opts = append(opts, blecap.WithFollow(input.Follow))
	}

	cap, err := blecap.New(opts...)
	if err != nil {
		return nil, StartOutput{}, fmt.Errorf("create capture: %w", err)
	}
	if err := cap.Start(); err != nil {
		return nil, StartOutput{}, fmt.Errorf("start capture: %w", err)
	}

	s := &captureSession{
		cap:       cap,
		device:    device,
		filter:    input.Filter,
		follow:    input.Follow,
		startedAt: time.Now(),
	}
	if input.Duration > 0 {
		s.stopTimer = time.AfterFunc(time.Duration(input.Duration)*time.Second, func() {
			sessMu.Lock()
			defer sessMu.Unlock()
			if sess == s {
				_ = s.cap.Stop()
				sess = nil
			}
		})
	}
	sess = s

	out := StartOutput{
		Status:  "started",
		Device:  device,
		Filter:  input.Filter,
		Follow:  input.Follow,
		Message: "BLE capture started",
	}
	if input.Duration > 0 {
		out.Message = fmt.Sprintf("BLE capture started; will auto-stop after %d seconds", input.Duration)
	}
	return nil, out, nil
}

// stopCapture implements the sniffer_stop tool.
func stopCapture(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, StopOutput, error) {
	sessMu.Lock()
	defer sessMu.Unlock()

	if sess == nil {
		return nil, StopOutput{Status: "not_running"}, nil
	}

	if sess.stopTimer != nil {
		sess.stopTimer.Stop()
	}

	count := sess.cap.Count() - sess.baseIndex
	elapsed := time.Since(sess.startedAt)

	if err := sess.cap.Stop(); err != nil {
		// Non-fatal: record the error in the message but still clean up.
		sess = nil
		return nil, StopOutput{
			Status:          "stopped_with_error",
			PacketsCaptured: count,
			Duration:        elapsed.Round(time.Millisecond).String(),
		}, nil
	}

	sess = nil
	return nil, StopOutput{
		Status:          "stopped",
		PacketsCaptured: count,
		Duration:        elapsed.Round(time.Millisecond).String(),
	}, nil
}

// captureStatus implements the sniffer_status tool.
func captureStatus(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, StatusOutput, error) {
	sessMu.Lock()
	defer sessMu.Unlock()

	if sess == nil {
		return nil, StatusOutput{Running: false}, nil
	}

	return nil, StatusOutput{
		Running:     true,
		PacketCount: sess.cap.Count() - sess.baseIndex,
		Device:      sess.device,
		Filter:      sess.filter,
		Follow:      sess.follow,
		Elapsed:     time.Since(sess.startedAt).Round(time.Millisecond).String(),
		StartedAt:   sess.startedAt.Format(time.RFC3339),
	}, nil
}

// setFilter implements the sniffer_set_filter tool.
func setFilter(_ context.Context, _ *mcp.CallToolRequest, input SetFilterInput) (*mcp.CallToolResult, SetFilterOutput, error) {
	sessMu.Lock()
	defer sessMu.Unlock()

	if sess == nil {
		return nil, SetFilterOutput{}, fmt.Errorf("no capture running; start one with sniffer_start first")
	}

	addrs := splitFilter(input.Addresses)
	if err := sess.cap.SetFilter(addrs); err != nil {
		return nil, SetFilterOutput{}, fmt.Errorf("set filter: %w", err)
	}
	sess.filter = input.Addresses

	if input.DiscardExisting {
		sess.baseIndex = sess.cap.Count()
	}

	return nil, SetFilterOutput{
		Status: "ok",
		Filter: input.Addresses,
	}, nil
}

// getPackets implements the sniffer_get_packets tool.
func getPackets(_ context.Context, _ *mcp.CallToolRequest, input GetPacketsInput) (*mcp.CallToolResult, GetPacketsOutput, error) {
	sessMu.Lock()
	if sess == nil {
		sessMu.Unlock()
		return nil, GetPacketsOutput{Packets: []PacketInfo{}}, nil
	}
	// Snapshot the values we need under the lock, then release so packet
	// processing doesn't block the capture goroutine.
	cap := sess.cap
	baseIndex := sess.baseIndex
	sessMu.Unlock()

	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	// Fetch all visible packets.
	total := cap.Count()
	visibleCount := total - baseIndex
	all := cap.Get(baseIndex, visibleCount)

	// Apply optional PDU type filter.
	pduFilter := strings.ToUpper(strings.TrimSpace(input.PDUType))
	addrFilter := strings.ToUpper(strings.TrimSpace(input.Address))
	full := strings.EqualFold(strings.TrimSpace(input.OutputMode), "full")

	var filtered []bledata.Packet
	for _, pkt := range all {
		if pduFilter != "" {
			name := strings.ToUpper(blepdu.PDUTypeName(pkt.ID, pkt.Raw))
			if !strings.Contains(name, pduFilter) {
				continue
			}
		}
		if addrFilter != "" {
			match := false
			for _, addr := range pkt.Addresses {
				if strings.Contains(strings.ToUpper(addr), addrFilter) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		filtered = append(filtered, pkt)
	}

	// Paginate.
	filteredTotal := len(filtered)
	offset := input.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > filteredTotal {
		offset = filteredTotal
	}
	end := offset + limit
	if end > filteredTotal {
		end = filteredTotal
	}
	page := filtered[offset:end]

	infos := make([]PacketInfo, 0, len(page))
	for _, pkt := range page {
		infos = append(infos, toPacketInfo(pkt, full))
	}

	return nil, GetPacketsOutput{
		Packets: infos,
		Total:   filteredTotal,
		Offset:  offset,
		Limit:   limit,
		HasMore: end < filteredTotal,
	}, nil
}

// getPacket implements the sniffer_get_packet tool.
func getPacket(_ context.Context, _ *mcp.CallToolRequest, input GetPacketInput) (*mcp.CallToolResult, PacketInfo, error) {
	sessMu.Lock()
	if sess == nil {
		sessMu.Unlock()
		return nil, PacketInfo{}, fmt.Errorf("no capture running")
	}
	cap := sess.cap
	sessMu.Unlock()

	pkts := cap.Get(input.Index, 1)
	if len(pkts) == 0 {
		return nil, PacketInfo{}, fmt.Errorf("packet index %d not found", input.Index)
	}
	return nil, toPacketInfo(pkts[0], true), nil
}

// clearPackets implements the sniffer_clear_packets tool.
func clearPackets(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, ClearOutput, error) {
	sessMu.Lock()
	defer sessMu.Unlock()

	if sess == nil {
		return nil, ClearOutput{Status: "ok", Discarded: 0}, nil
	}

	current := sess.cap.Count()
	discarded := current - sess.baseIndex
	sess.baseIndex = current

	return nil, ClearOutput{
		Status:    "ok",
		Discarded: discarded,
	}, nil
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

// Run starts the MCP server on stdio and blocks until the context is cancelled
// or the client disconnects.
func Run(ctx context.Context) error {
	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-sniffer", Version: "1.0.0"}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sniffer_start",
		Description: "Start a BLE advertising packet capture. Auto-detects the Nordic nRF52840-MDK dongle if device is not specified.",
	}, startCapture)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sniffer_stop",
		Description: "Stop the current capture and return a packet count summary.",
	}, stopCapture)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sniffer_status",
		Description: "Return the current capture status including packet count, device, and elapsed time.",
	}, captureStatus)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sniffer_set_filter",
		Description: "Update the BLE address filter while a capture is running. Optionally discard previously captured packets.",
	}, setFilter)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sniffer_get_packets",
		Description: "Retrieve captured BLE packets with pagination and optional filtering by PDU type or address.",
	}, getPackets)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sniffer_get_packet",
		Description: "Get full details for a single captured packet by its index.",
	}, getPacket)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sniffer_clear_packets",
		Description: "Discard all currently buffered packets. The capture continues running if active.",
	}, clearPackets)

	return s.Run(ctx, &mcp.StdioTransport{})
}
