/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

// Package blepdu parses BLE advertising PDU payloads from Nordic sniffer packets.
package blepdu

import "strings"

// Sniffer event IDs used for PDU type dispatch.
const (
	eventAdvPDU    = 0x02
	eventDataPDU   = 0x06
	eventAdvAuxPDU = 0x14
)

// PDUTypeName returns a human-readable name for a sniffer event packet.
//
// For legacy advertising PDUs (id=0x02) the name reflects the advType field
// in payload[14]. For BT5 extended advertising PDUs (id=0x14) the name
// reflects the AdvMode field in payload[17]; all AUX PDU subtypes share the
// same PDU-type value of 7 in the header byte so AdvMode is the best
// single-field discriminator without full exchange tracking.
func PDUTypeName(id byte, payload []byte) string {
	switch id {
	case eventAdvPDU:
		if len(payload) < 15 {
			return "ADV_PDU"
		}
		switch payload[14] & 0x0F {
		case 0:
			return "ADV_IND"
		case 1:
			return "ADV_DIRECT_IND"
		case 2:
			return "ADV_NONCONN_IND"
		case 3:
			return "SCAN_REQ"
		case 4:
			return "SCAN_RSP"
		case 5:
			return "CONNECT_IND"
		case 6:
			return "ADV_SCAN_IND"
		case 7:
			return "ADV_EXT_IND"
		default:
			return "ADV_PDU"
		}

	case eventAdvAuxPDU:
		if len(payload) < 18 {
			return "AUX_ADV_PDU"
		}
		// AdvMode is bits [7:6] of the ExtHdrLen/AdvMode byte.
		switch (payload[17] >> 6) & 0x03 {
		case 0:
			return "AUX_NONCONN_IND" // non-connectable, non-scannable
		case 1:
			return "AUX_CONN_IND" // connectable
		case 2:
			return "AUX_SCAN_IND" // scannable (also covers AUX_SCAN_RSP)
		default:
			return "AUX_ADV_PDU" // reserved
		}

	case eventDataPDU:
		return "DATA_PDU"

	default:
		return "PKT"
	}
}

// AddressRoles returns the BLE role label ("AdvA", "ScanA", "TargetA", "InitA") for
// each address position returned by ParseLegacyAdvAddresses or ParseExtAdvAddresses
// for the same packet. The slice is positionally aligned with the addresses slice.
func AddressRoles(id byte, payload []byte) []string {
	switch id {
	case eventAdvPDU:
		if len(payload) < 15 {
			return nil
		}
		switch payload[14] & 0x0F {
		case 0, 2, 4, 6: // ADV_IND, ADV_NONCONN_IND, SCAN_RSP, ADV_SCAN_IND
			return []string{"AdvA"}
		case 1: // ADV_DIRECT_IND: AdvA then TargetA
			return []string{"AdvA", "TargetA"}
		case 3: // SCAN_REQ: ScanA then AdvA
			return []string{"ScanA", "AdvA"}
		case 5: // CONNECT_IND: InitA then AdvA
			return []string{"InitA", "AdvA"}
		}
	case eventAdvAuxPDU:
		if len(payload) < 19 {
			return nil
		}
		flags := payload[18]
		var roles []string
		if flags&0x01 != 0 {
			roles = append(roles, "AdvA")
		}
		if flags&0x02 != 0 {
			roles = append(roles, "TargetA")
		}
		return roles
	}
	return nil
}

// ParseLegacyAdvAddresses parses BLE addresses out of an EVENT_PACKET_ADV_PDU payload.
//
// Payload layout (offset from payload[0]):
//
//	[0]     ble_header_len  (= 10)
//	[1]     flags
//	[2]     channel
//	[3]     rssi
//	[4-5]   event_counter
//	[6-9]   timestamp
//	[10-13] access_address
//	[14]    pdu_type_byte   (advType = bits[3:0])
//	[15]    pdu_len
//	[16]    PADDING BYTE   ← skip
//	[17-22] first address  (6 bytes, LSB first)
//	[23-28] second address (if applicable)
func ParseLegacyAdvAddresses(payload []byte) []string {
	if len(payload) < 23 {
		return nil
	}

	advType := payload[14] & 0x0F

	switch advType {
	case 7:
		// Extended advertising: AdvA is optional in the primary channel packet.
		// Use the same extended header parser as AUX PDUs — same wire format.
		return ParseExtAdvAddresses(payload)

	case 0, 2, 4, 6:
		// ADV_IND, ADV_NONCONN_IND, SCAN_RSP, ADV_SCAN_IND: one address.
		return []string{FormatAddr(payload[17:23])}

	case 1:
		// ADV_DIRECT_IND: AdvA + TargetA.
		if len(payload) < 29 {
			return []string{FormatAddr(payload[17:23])}
		}
		return []string{
			FormatAddr(payload[17:23]),
			FormatAddr(payload[23:29]),
		}

	case 3, 5:
		// SCAN_REQ, CONNECT_IND: ScanA/InitA + AdvA.
		if len(payload) < 29 {
			return []string{FormatAddr(payload[17:23])}
		}
		return []string{
			FormatAddr(payload[17:23]),
			FormatAddr(payload[23:29]),
		}

	default:
		// Unknown type; return whatever first address is present.
		return []string{FormatAddr(payload[17:23])}
	}
}

// ParseExtAdvAddresses parses BLE addresses from an EVENT_PACKET_ADV_AUX_PDU payload.
//
// Payload layout (offset from payload[0]):
//
//	[0]     ble_header_len (= 10)
//	[1]     flags
//	[2]     channel
//	[3]     rssi
//	[4-5]   event_counter
//	[6-9]   timestamp
//	[10-13] access_address
//	[14]    PDU byte 0 (PDU type [3:0] + flags)
//	[15]    PDU byte 1 (PDU length)
//	[16]    PADDING BYTE  ← hardware-inserted, skip
//	[17]    ExtHdrLen [5:0] | AdvMode [7:6]
//	[18]    Extended header flags (presence bitmap):
//	          bit 0: AdvA present    (6 bytes)
//	          bit 1: TargetA present (6 bytes)
//	          bit 2: CTEInfo present (1 byte)   -- skip
//	          bit 3: ADI present     (2 bytes)  -- skip
//	          bit 4: AuxPtr present  (3 bytes)  -- skip
//	          bit 5: SyncInfo present(18 bytes) -- skip
//	          bit 6: TxPower present (1 byte)   -- skip
//	[19+]   Optional fields in the order listed above
func ParseExtAdvAddresses(payload []byte) []string {
	if len(payload) < 19 {
		return nil
	}

	extHdrLen := int(payload[17] & 0x3F)
	if extHdrLen == 0 {
		return nil
	}

	// extHdrEnd is the exclusive upper bound of the extended header region.
	// The extended header content starts at payload[18] and spans extHdrLen bytes.
	extHdrEnd := 18 + extHdrLen

	flags := payload[18]
	offset := 19

	var addrs []string

	// bit 0: AdvA present (6 bytes)
	if flags&0x01 != 0 {
		if offset+6 > extHdrEnd || offset+6 > len(payload) {
			return addrs
		}
		addrs = append(addrs, FormatAddr(payload[offset:offset+6]))
		offset += 6
	}

	// bit 1: TargetA present (6 bytes)
	if flags&0x02 != 0 {
		if offset+6 > extHdrEnd || offset+6 > len(payload) {
			return addrs
		}
		addrs = append(addrs, FormatAddr(payload[offset:offset+6]))
	}

	return addrs
}

// FormatAddr formats 6 bytes (LSB-first on air) as MSB-first colon-hex uppercase.
func FormatAddr(b []byte) string {
	return strings.ToUpper(
		strings.Join([]string{
			byteHex(b[5]),
			byteHex(b[4]),
			byteHex(b[3]),
			byteHex(b[2]),
			byteHex(b[1]),
			byteHex(b[0]),
		}, ":"),
	)
}

// byteHex returns a two-character uppercase hex string for a byte.
func byteHex(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{hex[b>>4], hex[b&0x0F]})
}
