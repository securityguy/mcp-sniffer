//go:build darwin

package sniffer

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// kIOSSIOSPEED is the macOS ioctl for setting non-standard baud rates (e.g. 1 Mbit/s).
const kIOSSIOSPEED uint = 0x80045402

// serialPort is the minimal interface used by Sniffer to communicate with
// the hardware. Keeping it narrow lets us swap implementations easily.
type serialPort interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// nativePort wraps a raw file descriptor for a serial port opened directly
// with unix syscalls.
type nativePort struct {
	fd int
}

// openNativePort opens the serial port at device with baud rate baud and
// configures it to match what the Nordic Python SnifferAPI does:
//   - CRTSCTS (hardware flow control) enabled — pyserial rtscts=True sets 0x30000 in c_cflag
//   - DTR and RTS asserted before the baud rate switch
//   - Port switched from 9600 to baud via IOSSIOSPEED (handles non-standard rates)
//   - Input buffer flushed to discard stale firmware output
func openNativePort(device string, baud int) (*nativePort, error) {
	// O_NDELAY avoids blocking on carrier detect at open time.
	fd, err := unix.Open(device, unix.O_RDWR|unix.O_NOCTTY|unix.O_NDELAY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", device, err)
	}

	settings, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TIOCGETA: %w", err)
	}

	// Raw mode: 8N1, no software flow control, no hardware flow control.
	// We set DTR/RTS explicitly below; CRTSCTS is intentionally not set because
	// macOS USB CDC apparently suppresses firmware output when CRTS_IFLOW is active.
	settings.Cflag = unix.CREAD | unix.CLOCAL | unix.CS8
	settings.Lflag = 0
	settings.Iflag = 0
	settings.Oflag = 0
	// VMIN=0, VTIME=1 (100 ms): read returns with whatever is available, or times
	// out after 100 ms with n=0 — lets the read loop detect Stop() without needing
	// Close() to interrupt a blocking unix.Read().
	settings.Cc[unix.VMIN] = 0
	settings.Cc[unix.VTIME] = 1
	// Initial baud rate; will be overridden by IOSSIOSPEED below.
	settings.Ispeed = unix.B9600
	settings.Ospeed = unix.B9600

	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, settings); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TIOCSETA: %w", err)
	}

	if err := unix.IoctlSetPointerInt(fd, unix.TIOCMSET, unix.TIOCM_DTR|unix.TIOCM_RTS); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TIOCMSET DTR+RTS: %w", err)
	}

	// Switch to the operational baud rate (1 Mbit/s is not in the standard table,
	// so we must use the macOS IOSSIOSPEED extension rather than termios ispeed/ospeed).
	if err := unix.IoctlSetPointerInt(fd, kIOSSIOSPEED, baud); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("IOSSIOSPEED %d: %w", baud, err)
	}

	// Discard any data that arrived during initialisation.
	_ = unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, unix.TCIFLUSH)

	// Prevent another process from opening the same port.
	_ = unix.IoctlSetInt(fd, unix.TIOCEXCL, 0)

	// Switch back to blocking I/O for the read loop (O_NDELAY opened non-blocking).
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("SetNonblock: %w", err)
	}

	return &nativePort{fd: fd}, nil
}

func (p *nativePort) Read(buf []byte) (int, error) {
	n, err := unix.Read(p.fd, buf)
	if n < 0 {
		n = 0
	}
	return n, err
}

func (p *nativePort) Write(data []byte) (int, error) {
	n, err := unix.Write(p.fd, data)
	if n < 0 {
		n = 0
	}
	return n, err
}

func (p *nativePort) Close() error {
	return unix.Close(p.fd)
}
