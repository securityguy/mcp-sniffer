//go:build linux

package bledev

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	sysClassTTY = "/sys/class/tty"
	nordicVID   = "1915" // sysfs idVendor is lowercase hex without "0x"
)

// findDevice locates the Nordic sniffer serial port on Linux using sysfs.
//
// It enumerates ttyACM devices under /sys/class/tty, follows each device
// symlink to its parent USB device, checks idVendor, and returns the /dev/
// path for the first device with Nordic Semiconductor's vendor ID (1915).
func findDevice() (string, error) {
	entries, err := os.ReadDir(sysClassTTY)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", sysClassTTY, err)
	}

	var candidates []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "ttyACM") {
			continue
		}
		if isNordicDevice(name) {
			candidates = append(candidates, "/dev/"+name)
		}
	}

	switch len(candidates) {
	case 0:
		return "", ErrNotFound
	case 1:
		return candidates[0], nil
	default:
		// Multiple Nordic devices attached; return the lowest-numbered ACM port.
		return candidates[0], nil
	}
}

// isNordicDevice reports whether the named ttyACM device is backed by a USB
// device with Nordic Semiconductor's vendor ID.
//
// Sysfs path structure:
//
//	/sys/class/tty/<name>/device  →  .../usb1/1-1/1-1:1.0   (USB interface)
//	                                  parent: .../usb1/1-1    (USB device, has idVendor)
func isNordicDevice(ttyName string) bool {
	devLink := filepath.Join(sysClassTTY, ttyName, "device")
	ifacePath, err := filepath.EvalSymlinks(devLink)
	if err != nil {
		return false
	}
	// Step up from USB interface to USB device.
	usbDevPath := filepath.Dir(ifacePath)
	data, err := os.ReadFile(filepath.Join(usbDevPath, "idVendor"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == nordicVID
}
