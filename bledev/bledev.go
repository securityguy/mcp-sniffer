// Package bledev locates the Nordic nRF52840-MDK sniffer USB serial device.
package bledev

import (
	"errors"
	"fmt"
)

// NordicVendorID is the USB vendor ID for Nordic Semiconductor ASA.
const NordicVendorID = 0x1915

// ErrNotFound is returned when no compatible sniffer device is found.
var ErrNotFound = errors.New("sniffer device not found")

// Find returns the serial port path for the connected Nordic nRF52840-MDK
// sniffer dongle (e.g. "/dev/cu.usbmodem2101" on macOS, "/dev/ttyACM0" on
// Linux). Returns ErrNotFound if no device is detected.
func Find() (string, error) {
	path, err := findDevice()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", fmt.Errorf("%w: is the nRF52840-MDK dongle plugged in?", ErrNotFound)
		}
		return "", err
	}
	return path, nil
}
