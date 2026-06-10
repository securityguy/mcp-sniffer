# CLAUDE.md — mcp-sniffer

## Release status

**Unreleased.** No backwards-compatibility obligations. Change freely.

## Module path

`github.com/tenebris-tech/mcp-sniffer` (go.mod) — repo is at
`github.com/securityguy/mcp-sniffer`. The module path is internal only; it
does not need to match the repo URL since this is not a published library.

## Go version

1.22. macOS only (`sniffer/port_darwin.go` uses Darwin-specific syscalls).

## What this project is

A CLI tool that captures BLE advertising packets from the Nordic nRF52840-MDK
USB dongle running Nordic sniffer firmware v4.1.1. Primary research goal:
reverse-engineer the BLE advertising protocol of Bell IQ pest trap monitors
(`ca.smartwave.bellsensing`, company ID `0x07CD`) to decode sensor data.

## Architecture

```
blecap → bledata → blepdu
      → sniffer
```

- `sniffer`: serial port + SLIP + Nordic firmware protocol
- `bledata`: packet store, address filter, consumes sniffer channel
- `blepdu`: PDU type/address decoding (no I/O)
- `blecap`: wires sniffer+store into a single lifecycle object; used by main.go

## Critical firmware gotchas

**Never set `ScanFlagCodedPHY` (bit 2 = 0x04) in REQ_SCAN_CONT.** Firmware
v4.1.1 silently stops scanning when that flag is set. `ScanFlagAll = 0x03`
(ScanRsp + ExtAdv only). This was the root cause of a 0-packets bug.

**REQ_FOLLOW address is LSB-first.** The 6-byte address in the REQ_FOLLOW
payload must be sent in the same byte order as BLE air packets (LSB-first),
not in human-readable MSB-first order. For `04:E3:E5:B0:87:05` the payload
bytes are `05 87 B0 E5 E3 04`. Sending MSB-first causes the firmware to wait
for the bit-reversed address and never follow the target. This manifests as a
single ADV_IND at capture start (before follow takes effect) and then silence.

**REQ_SCAN_CONT resets follow state.** Sending REQ_SCAN_CONT while in follow
mode causes the firmware to exit follow mode. Auto-tune must be suppressed when
`--follow` is active (already fixed in `blecap/capture.go`).

## Serial port (macOS)

`sniffer/port_darwin.go`:
- Uses `golang.org/x/sys/unix` for termios and ioctl
- IOSSIOSPEED ioctl for 1 Mbps (non-standard baud)
- TIOCEXCL for exclusive access
- VMIN=0, VTIME=1 (100ms read timeout for clean shutdown)
- DTR/RTS are asserted (not toggled — toggling caused USB re-enumeration)
- Default device: `/dev/cu.usbmodem2101`

## Nordic SLIP framing

Non-standard variant: START=0xAB, END=0xBC, ESC=0xCD, ESC_START=0xAC,
ESC_END=0xBD, ESC_ESC=0xCE.

Sent frames are always V1. Received frames are V3 from firmware v4.1.1:
- V3 header: [0-1] payload_len uint16 LE, [2] proto_ver=3, [3-4] counter, [5] packet_id

## Startup sequence

SET_ADV_CHANNEL_HOP_SEQ (channels 37,38,39) → REQ_VERSION → REQ_PING →
REQ_TIMESTAMP → REQ_SCAN_CONT (flags=0x03) → SET_TEMPORARY_KEY (16 zero bytes)

200ms delay after opening serial port before sending init sequence.

## Payload layout

Nordic header is 10 bytes prepended to every PDU:
```
[0]     ble_header_len (= 10)
[1]     flags
[2]     channel
[3]     rssi
[4-5]   event_counter LE uint16
[6-9]   timestamp LE uint32 µs
[10-13] access_address
[14]    PDU type byte (bits[3:0] = advType for legacy PDUs)
[15]    PDU length
[16]    PADDING BYTE — hardware-inserted, must skip
[17+]   PDU body
```
Firmware appends 3 CRC bytes at end of payload.

## BT5 extended advertising

ADV_EXT_IND (advType=7) on primary channels does NOT contain AdvA — it carries
an AuxPtr. The sniffer follows the AuxPtr and delivers the secondary packet as
EventPacketAdvAuxPDU (0x14). AdvA appears in the secondary packet's extended
header (flags byte at payload[18], bit 0).

`EventPacketAdvAuxPDU = 0x14` is a third event type alongside 0x02 and 0x06.

## Bell IQ payload (key research finding)

Device: `04:E3:E5:AF:EE:C0`, protocol: advertising-only (no GATT).
Manufacturer-specific payload (19 bytes, company 0x07CD) after `ff cd 07`:

```
[0-1]   01 22        — protocol version/subtype (constant)
[2-7]   MAC LE       — device MAC reversed (e5 e3 04 → 04:E3:E5:...)
[8-9]   LE uint16    — 414 on observed device; field unknown (temp?)
[10]    byte         — 153 on observed device; field unknown
[11]    byte         — 100 on observed device; likely battery %
[12-14] 3 bytes      — event counter; confirmed 0 = zero events
[15-18] LE uint32    — RTC/uptime seconds counter (~1 tick/sec)
```

Event history is cloud-side. App reads ADV_IND, uploads to
Bell/Smartwave cloud. SCAN_RSP is always empty.

### Next step: decode unknown fields

`private/ca.smartwave.bellsensing.apk_Decompiler.com/` contains the
decompiled Bell IQ APK — look here to confirm field meanings. Also capture
from a trap with events to see non-zero values at bytes [12-14].

## Files in private/ (gitignored)

- `nrf_sniffer_ble.py` — Nordic Python reference sniffer
- `client.txt` — capture while app was collecting data (108 packets, ADV+SCAN only)
- `no-client.txt` — capture with no app present
- `ca.smartwave.bellsensing.apk_Decompiler.com/` — decompiled Bell IQ APK
- `ca.smartwave.bellsensing.apk_Decompiler.com.zip` — same, zipped

## Testing

No unit tests yet. Run with `go run .` against the live hardware.
`test.sh` is a shortcut for `go run .`.

## Build check

After any changes: `go build ./...`
