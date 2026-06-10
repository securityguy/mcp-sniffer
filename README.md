# mcp-sniffer

A Go CLI tool and MCP server for capturing and decoding BLE advertising packets
using the Nordic nRF52840-MDK USB dongle and Nordic sniffer firmware.

## Hardware

- **Dongle**: Nordic nRF52840-MDK (or compatible nRF52840 USB dongle)
- **Firmware**: Nordic BLE Sniffer firmware v4.1.1
- **Host OS**: macOS and Linux — serial port code in `sniffer/port_darwin.go` / `sniffer/port_linux.go`
- **Default port**: `/dev/cu.usbmodem2101`
- **Baud rate**: 1,000,000

## Build and Run

```sh
go build .
./mcp-sniffer [flags]
```

Or directly:

```sh
go run . [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--duration` | 30 | Capture duration in seconds |
| `--filter` | (none) | Comma-separated BLE addresses or OUI prefixes, e.g. `AA:BB:CC:DD:EE:FF,50:32:5F` |
| `--follow` | (none) | Single BLE address for hardware follow mode (DATA_PDU capture) |
| `--device` | (auto) | Serial port path; auto-detected if omitted |
| `--mcp` | false | Run as MCP server on stdio instead of CLI |

### Examples

```sh
# Capture all advertising traffic for 60 seconds
go run . --duration 60

# Capture only traffic from a specific device
go run . --filter 04:E3:E5:AF:EE:C0 --duration 60

# Follow a device into a BLE connection (captures DATA_PDUs)
go run . --follow AA:BB:CC:DD:EE:FF

# Start as an MCP server (for LLM tool use)
./mcp-sniffer --mcp
```

## MCP Server

mcp-sniffer can run as an [MCP (Model Context Protocol)](https://modelcontextprotocol.io)
server, exposing the sniffer as a set of tools that an LLM (Claude, etc.) can call
directly to drive BLE captures without a human operator.

### Starting the server

```sh
./mcp-sniffer --mcp
```

The server communicates over stdio using the standard MCP JSON-RPC transport.
Add it to your MCP client configuration the same way you would any stdio-based
MCP server.

### Tools

#### `sniffer_start`

Start a BLE capture. The dongle is auto-detected if `device` is not specified.

| Parameter | Type | Description |
|-----------|------|-------------|
| `device` | string | Serial port path (e.g. `/dev/cu.usbmodem2101`). Omit for auto-detection. |
| `filter` | string | Comma-separated BLE addresses or OUI prefixes. Empty captures all traffic. |
| `follow` | string | Single BLE address for hardware follow mode (records DATA_PDUs during a connection). |
| `duration` | int | Auto-stop after this many seconds. 0 = run until `sniffer_stop` is called. |
| `output_file` | string | Path to write captured packets to. Created if missing, appended if existing. Uses the same text format as the CLI output. |

Returns: `status`, `device`, `filter`, `follow`, `output_file`, `message`.

---

#### `sniffer_stop`

Stop the running capture. If an output file is open, flushes any remaining
packets and closes it before returning.

Returns: `status`, `packets_captured`, `duration`.

---

#### `sniffer_status`

Return the current capture state without changing anything.

Returns: `running`, `packet_count`, `device`, `filter`, `follow`,
`output_file`, `elapsed`, `started_at`.

---

#### `sniffer_set_filter`

Update the BLE address filter on a running capture.

| Parameter | Type | Description |
|-----------|------|-------------|
| `addresses` | string | Comma-separated BLE addresses or OUI prefixes. Empty string clears the filter. |
| `discard_existing` | bool | If true, mark all previously captured packets as discarded (they are excluded from future `sniffer_get_packets` calls). |

Returns: `status`, `filter`.

---

#### `sniffer_set_follow`

Change the hardware follow target on a running capture. Can be called to begin
following a device after it has been identified in advertising traffic.

| Parameter | Type | Description |
|-----------|------|-------------|
| `address` | string | BLE address to follow. Empty string disables follow mode. |

Returns: `status`, `follow`.

---

#### `sniffer_get_packets`

Retrieve captured packets with pagination and optional filtering.

| Parameter | Type | Description |
|-----------|------|-------------|
| `offset` | int | Starting index within the result set (default 0). |
| `limit` | int | Maximum packets to return, 1–200 (default 50). |
| `pdu_type` | string | Case-insensitive substring filter on PDU type, e.g. `ADV_IND`, `CONNECT_IND`, `DATA_PDU`, `SCAN_RSP`. |
| `address` | string | Case-insensitive substring filter — only packets containing this address are returned. |
| `output_mode` | string | `summary` (default) or `full` (adds `raw_hex` field with the complete payload as a hex string). |

Returns: `packets` (array of `PacketInfo`), `total`, `offset`, `limit`, `has_more`.

Each `PacketInfo` contains:

| Field | Description |
|-------|-------------|
| `index` | Global packet index (use with `sniffer_get_packet`) |
| `timestamp` | RFC3339Nano receive time |
| `pdu_type` | Human-readable PDU type (e.g. `ADV_IND`, `CONNECT_IND`) |
| `channel` | BLE channel number |
| `rssi_dbm` | Signal strength in dBm (negative value) |
| `addresses` | Array of `{role, address}` — roles are `AdvA`, `ScanA`, `InitA`, `TargetA`, or `addr` |
| `raw_hex` | Full payload hex string (only in `full` output mode) |

---

#### `sniffer_get_packet`

Get full details (including raw payload) for a single packet by index.

| Parameter | Type | Description |
|-----------|------|-------------|
| `index` | int | Absolute packet index from a previous `sniffer_get_packets` call. |

Returns: a single `PacketInfo` with `raw_hex` populated.

---

#### `sniffer_clear_packets`

Discard all buffered packets from the visible result set. The capture continues
running; new packets after this call are visible again from index 0. The
underlying store is not modified — this is a virtual clear.

Returns: `status`, `discarded` (number of packets hidden).

---

### Example LLM workflow

```
1. sniffer_start  { filter: "04:E3:E5", duration: 60, output_file: "/tmp/capture.txt" }
2. (wait a few seconds)
3. sniffer_get_packets  { pdu_type: "ADV_IND", limit: 10 }
   → inspect addresses in results
4. sniffer_set_follow  { address: "04:E3:E5:AF:EE:C0" }
5. sniffer_get_packets  { pdu_type: "DATA_PDU" }
6. sniffer_stop
```

## Linux: Serial Port Permissions

On Linux the dongle appears as `/dev/ttyACM*`. By default this device is
owned by `root:dialout` and not accessible to normal users.

### One-time setup

**1. Add a udev rule** so the device gets group-readable permissions
automatically when plugged in:

```sh
sudo tee /etc/udev/rules.d/99-nordic-sniffer.rules <<'EOF'
SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", MODE="0660", GROUP="dialout"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger
```

**2. Add your user to the `dialout` group:**

```sh
sudo usermod -aG dialout $USER
```

Log out and back in (or run `newgrp dialout` in the current shell) for the
group membership to take effect.

After this, the sniffer can be run without `sudo`.

## Package Architecture

```
mcp-sniffer/
├── main.go           — CLI entry point; --mcp flag delegates to mcpserver
├── blecap/           — High-level capture API (owns sniffer + store)
├── bledata/          — Packet store, address filtering, BLE address decoding
├── bledev/           — OS-specific sniffer device auto-detection
├── blepdu/           — BLE PDU type names, address role labels, address parsing
├── mcpserver/        — MCP server (stdio transport, 8 tools)
└── sniffer/          — Nordic firmware protocol, SLIP framing, serial port I/O
```

### Package responsibilities

**`sniffer`** — Low-level firmware communication:
- SLIP framing (Nordic non-standard variant: START=0xAB, END=0xBC, ESC=0xCD)
- V1 (sent) and V3 (received) packet header formats
- Serial port management (macOS: IOSSIOSPEED, TIOCEXCL, VMIN=0/VTIME=1)
- Startup sequence: SET_ADV_CHANNEL_HOP_SEQ → REQ_VERSION → REQ_PING → REQ_TIMESTAMP → REQ_SCAN_CONT → SET_TEMPORARY_KEY
- `UpdateScanFlags` for runtime scan flag changes
- `Follow` for hardware follow mode — sends REQ_FOLLOW with address **LSB-first** (see protocol notes below)

**`bledata`** — Packet storage and filtering:
- Consumes `sniffer.RawPacket` from a channel
- Decodes BLE addresses from ADV_PDU and AUX_PDU payloads
- Thread-safe store with offset/limit pagination
- Address filter: full MAC or OUI prefix (1–6 octets), normalised to uppercase colon-hex

**`blepdu`** — BLE PDU decoding:
- `PDUTypeName` — human-readable name for each PDU type
- `AddressRoles` — BLE role labels (AdvA, ScanA, InitA, TargetA) aligned with parsed addresses
- `ParseLegacyAdvAddresses` — addresses from EVENT_PACKET_ADV_PDU (0x02) payloads
- `ParseExtAdvAddresses` — addresses from EVENT_PACKET_ADV_AUX_PDU (0x14) payloads

**`blecap`** — Unified capture lifecycle:
- Wires sniffer → store, exposes `Start`/`Stop`/`Get`/`Count`/`SetFilter`/`SetFollow`
- Optional auto-tune: after observation window, disables unused scan capabilities when a filter is active
- Auto-tune is suppressed when follow mode is active (sending REQ_SCAN_CONT resets firmware follow state)

## Nordic Sniffer Protocol

### REQ_FOLLOW Payload

```
[0-5]  BD_ADDR — device address, byte 0 is LSB (reversed from human-readable)
[6]    ADDRESS_TYPE — 0=public, 1=random
[7]    FULL_FOLLOW — 0=capture full connection, 1=advertising only
```

**Address byte order is LSB-first.** For address `04:E3:E5:B0:87:05` the
payload bytes are `05 87 B0 E5 E3 04`. Sending in MSB-first (human-readable)
order causes the firmware to silently follow the wrong device — it captures one
advertising packet at startup then goes silent.

**Follow mode suppresses ADV_IND delivery.** Once follow mode is active, the
firmware forwards very few advertising packets from the target; it is primarily
waiting for a CONNECT_IND. Do not use `--follow` if you only want advertising
payload — `--filter` alone is sufficient and delivers all packets normally.

**REQ_SCAN_CONT resets follow state.** Sending REQ_SCAN_CONT while in follow
mode causes the firmware to exit follow mode. The auto-tune feature in
`blecap` is suppressed when follow is active to prevent this.

### Scan Flags (REQ_SCAN_CONT payload byte)

| Bit | Constant | Effect |
|-----|----------|--------|
| 0 | `ScanFlagScanRsp` | Forward SCAN_RSP packets |
| 1 | `ScanFlagExtAdv` | Follow ADV_EXT_IND to secondary channels (BT5) |
| 2 | `ScanFlagCodedPHY` | Scan Coded PHY channels (BT5 long-range) |

`ScanFlagAll = 0x03` (ScanRsp + ExtAdv). **Do not set CodedPHY (0x04)** — firmware
v4.1.1 silently stops scanning when that bit is set.

### Packet ID Constants

| ID | Constant | Direction |
|----|----------|-----------|
| 0x00 | `reqFollow` | Host → device: follow a specific BLE device |
| 0x02 | `EventPacketAdvPDU` | Device → host: BLE advertising PDU |
| 0x06 | `EventPacketDataPDU` | Device → host: BLE data PDU (follow mode) |
| 0x07 | `ReqScanCont` | Host → device: start continuous scanning |
| 0x14 | `EventPacketAdvAuxPDU` | Device → host: BT5 AUX secondary channel PDU |

### Payload Layout (EventPacketAdvPDU / EventPacketAdvAuxPDU)

```
[0]     ble_header_len (= 10)
[1]     flags
[2]     channel
[3]     rssi
[4-5]   event_counter (LE uint16)
[6-9]   timestamp (LE uint32, µs)
[10-13] access_address
[14]    PDU type byte (advType = bits[3:0])
[15]    PDU length
[16]    PADDING BYTE (hardware-inserted, skip)
[17+]   PDU body
[last 3] BLE CRC (appended by firmware)
```

## BLE PDU Types

### Legacy (EventPacketAdvPDU, id=0x02)

| advType | Name | Addresses |
|---------|------|-----------|
| 0 | ADV_IND | AdvA |
| 1 | ADV_DIRECT_IND | AdvA, TargetA |
| 2 | ADV_NONCONN_IND | AdvA |
| 3 | SCAN_REQ | ScanA, AdvA |
| 4 | SCAN_RSP | AdvA |
| 5 | CONNECT_IND | InitA, AdvA |
| 6 | ADV_SCAN_IND | AdvA |
| 7 | ADV_EXT_IND | (no AdvA in primary packet; follow AuxPtr to secondary) |

### Extended (EventPacketAdvAuxPDU, id=0x14)

| AdvMode | Name | Notes |
|---------|------|-------|
| 0 | AUX_NONCONN_IND | Non-connectable, non-scannable |
| 1 | AUX_CONN_IND | Connectable |
| 2 | AUX_SCAN_IND | Scannable (also covers AUX_SCAN_RSP) |

Extended PDU extended header (at payload[17+]):
- byte[17]: ExtHdrLen[5:0] | AdvMode[7:6]
- byte[18]: flags bitmap (bit0=AdvA, bit1=TargetA, bit2=CTEInfo, bit3=ADI, bit4=AuxPtr, bit5=SyncInfo, bit6=TxPower)
- bytes[19+]: optional fields in flag order

### ADV_EXT_IND Note

BT5 extended advertising splits across two hops: the primary channel packet
(ADV_EXT_IND) carries an AuxPtr pointing to a secondary channel packet
(AUX_ADV_IND). **AdvA is typically absent from ADV_EXT_IND** — it appears in
the secondary packet. Enable `ScanFlagExtAdv` to capture both; the sniffer
firmware follows the AuxPtr automatically and delivers the secondary packet as
`EventPacketAdvAuxPDU` (0x14).

## Bell IQ Pest Monitor — Protocol Analysis

The Bell IQ smart pest trap (app: `ca.smartwave.bellsensing`) uses
advertising-only BLE — no GATT connection is required for data collection.

### Observed device

- MAC: `04:E3:E5:AF:EE:C0`
- PDU type: ADV_IND (connectable, scannable)
- Advertising interval: ~15ms
- SCAN_RSP: empty (AdvA only, no AD data)
- Company ID: `0x07CD`

### ADV_IND AD record structure

```
AD type 0x01 (Flags):       02 01 06
AD type 0x09 (Complete Name): 03 09 42 47  → "BG"
AD type 0xFF (Manufacturer): 16 ff cd 07 [19 bytes payload]
```

### Manufacturer-specific payload (19 bytes after company ID)

```
Offset  Bytes        Notes
------  -----------  -----
0-1     01 22        Protocol version / subtype (constant)
2-7     c0 ee af     Device MAC address, LSB-first (= 04:E3:E5:AF:EE:C0 reversed)
        e5 e3 04
8-9     9e 01        LE uint16 = 414 — field unknown, does not change between packets
10      99           = 153 — field unknown
11      64           = 100 — likely battery percentage (100% = full)
12-14   00 00 00     Event/catch counter — confirmed 0 for a trap with 0 reported events
15-18   xx xx xx xx  LE uint32 RTC/uptime counter, increments at ~1 tick/second
```

### Architecture

- Event history is **cloud-side**: the technician's app reads current ADV_IND
  state, uploads to Bell/Smartwave cloud, and the app displays the cloud's
  accumulated history across all visits.
- The device does not transfer event logs via GATT or SCAN_RSP.
- Binding: device MAC registered to account during provisioning via the app.

### Unresolved fields

- Bytes 8-9 (`9e 01` = 414): possibly temperature (tenths of °C? °F?)
- Byte 10 (`99` = 153): unknown — not battery (>100), not obvious sensor value
- Bytes 12-14: encoding of non-zero value when events exist — need capture from
  a trap with events to confirm (count vs. timestamp of last event)

### Reference material

`private/` contains:
- `nrf_sniffer_ble.py` — Nordic Python sniffer reference implementation
- `client.txt` — sniffer capture while Bell IQ app was collecting data
- `no-client.txt` — sniffer capture with no app present
- `ca.smartwave.bellsensing.apk_Decompiler.com/` — decompiled Bell IQ APK
  (useful for confirming payload field meanings)
