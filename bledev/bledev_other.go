//go:build !darwin && !linux

package bledev

import "fmt"

// findDevice returns an unsupported-platform error.
// Use --device to specify the serial port path explicitly.
func findDevice() (string, error) {
	return "", fmt.Errorf("%w: automatic device detection is not supported on this platform; use --device to specify the serial port", ErrNotFound)
}
