// Package sniffer implements communication with the Nordic nRF BLE sniffer firmware.
package sniffer

// SLIP framing constants (Nordic non-standard variant).
const (
	slipStart    = 0xAB // marks start of frame
	slipEnd      = 0xBC // marks end of frame
	slipEsc      = 0xCD // escape byte
	slipEscStart = 0xAC // escaped slipStart in data
	slipEscEnd   = 0xBD // escaped slipEnd in data
	slipEscEsc   = 0xCE // escaped slipEsc in data
)

// Packet header constants.
const (
	headerLen  = 6
	protoVerV1 = 1
	protoVerV3 = 3
)

// Unexported request constants.
const (
	reqFollow          byte = 0x00
	reqSetAdvHopSeq    byte = 0x17
	reqSetTemporaryKey byte = 0x0C
	reqPing            byte = 0x0D
	reqVersion         byte = 0x1B
	reqTimestamp       byte = 0x1D
)

// Exported packet ID constants.
const (
	// ReqScanCont is sent by the host to start continuous BLE scanning.
	ReqScanCont byte = 0x07
	// EventPacketAdvPDU is sent by the device for BLE advertising PDU events (all types including BT5 ADV_EXT_IND).
	EventPacketAdvPDU byte = 0x02
	// EventPacketDataPDU is sent by the device for BLE data PDU events (follow mode).
	EventPacketDataPDU byte = 0x06
	// EventPacketAdvAuxPDU is sent by the device for BT5 extended advertising PDU events
	// on secondary channels, following an AuxPtr from an ADV_EXT_IND.
	EventPacketAdvAuxPDU byte = 0x14
)

// Scan flag bits for REQ_SCAN_CONT.
const (
	ScanFlagScanRsp  byte = 1 << 0 // forward SCAN_RSP packets
	ScanFlagExtAdv   byte = 1 << 1 // follow ADV_EXT_IND to secondary channels (BT5)
	ScanFlagCodedPHY byte = 1 << 2 // scan Coded PHY advertising channels (BT5 long-range)
	ScanFlagAll      byte = ScanFlagScanRsp | ScanFlagExtAdv
)

// DefaultDevice is the default serial port path for the nRF52840-MDK dongle.
const DefaultDevice = "/dev/cu.usbmodem2101"

// DefaultBaud is the default baud rate for the sniffer firmware.
const DefaultBaud = 1_000_000
