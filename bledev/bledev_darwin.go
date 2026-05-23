//go:build darwin

/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package bledev

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// findDevice locates the Nordic sniffer serial port on macOS.
//
// It queries IOKit via ioreg to find a USB serial device with Nordic's
// vendor ID (0x1915). Falls back to the sole /dev/cu.usbmodem* device if
// exactly one is present and ioreg is inconclusive.
func findDevice() (string, error) {
	// Primary: identify by USB VID via ioreg.
	if path, err := findViaIoreg(); err == nil {
		return path, nil
	}

	// Fallback: unambiguous single usbmodem device.
	matches, err := filepath.Glob("/dev/cu.usbmodem*")
	if err != nil || len(matches) == 0 {
		return "", ErrNotFound
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", fmt.Errorf("%w: multiple candidates (%s); use --device to specify",
		ErrNotFound, strings.Join(matches, ", "))
}

// findViaIoreg uses ioreg to find the serial port for the Nordic USB device.
//
// It queries IOUSBHostDevice entries recursively, looking for one with
// idVendor=0x1915 (Nordic Semiconductor), then searches the same subtree
// for its IOCalloutDevice serial port path.
func findViaIoreg() (string, error) {
	out, err := exec.Command("ioreg", "-r", "-c", "IOUSBHostDevice", "-l").Output()
	if err != nil {
		return "", fmt.Errorf("ioreg: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		// Find the line asserting Nordic's VID.
		if !strings.Contains(line, `"idVendor"`) || !strings.Contains(line, "0x1915") {
			continue
		}
		// Search forward within the same device subtree for the callout device.
		// 300 lines is well beyond any single USB device subtree in practice.
		end := min(i+300, len(lines))
		for _, sub := range lines[i:end] {
			if path := extractCalloutDevice(sub); path != "" {
				return path, nil
			}
		}
	}
	return "", ErrNotFound
}

// extractCalloutDevice extracts the path from an ioreg property line of the form:
//
//	"IOCalloutDevice" = "/dev/cu.usbmodemXXXX"
func extractCalloutDevice(line string) string {
	const key = `"IOCalloutDevice"`
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key):]
	start := strings.Index(rest, `"/dev/`)
	if start < 0 {
		return ""
	}
	rest = rest[start+1:] // skip the opening quote
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
