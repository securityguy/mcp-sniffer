//go:build linux

package sniffer

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// cbaud is the CBAUD mask in the Linux termios Cflag — the bits that hold
// the baud rate. Defined locally because unix.CBAUD is not exported by all
// versions of golang.org/x/sys.
const cbaud = 0x100F

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
// configures it for raw 8N1 communication with the Nordic sniffer firmware.
//
// On Linux 1 Mbit/s is a standard termios speed (B1000000), so no
// non-standard ioctl is required. Only 1,000,000 and common debug rates
// are explicitly mapped; add entries to baudToSpeed as needed.
func openNativePort(device string, baud int) (*nativePort, error) {
	speed, err := baudToSpeed(baud)
	if err != nil {
		return nil, err
	}

	// O_NDELAY avoids blocking on carrier-detect at open time.
	fd, err := unix.Open(device, unix.O_RDWR|unix.O_NOCTTY|unix.O_NDELAY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", device, err)
	}

	settings, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TCGETS: %w", err)
	}

	// Raw mode: 8N1, no software or hardware flow control.
	settings.Cflag = unix.CS8 | unix.CREAD | unix.CLOCAL
	settings.Lflag = 0
	settings.Iflag = 0
	settings.Oflag = 0

	// VMIN=0, VTIME=1 (100 ms): reads return with available data, or time out
	// after 100 ms — lets the read loop detect Stop() without needing Close()
	// to interrupt a blocking read.
	settings.Cc[unix.VMIN] = 0
	settings.Cc[unix.VTIME] = 1

	// Set baud rate: clear CBAUD bits then OR in the new speed, matching what
	// cfsetspeed(3) does. Also set Ispeed/Ospeed for completeness.
	settings.Cflag = (settings.Cflag &^ uint32(cbaud)) | (speed & uint32(cbaud))
	settings.Ispeed = speed
	settings.Ospeed = speed

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, settings); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TCSETS: %w", err)
	}

	// Assert DTR and RTS.
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCMSET, unix.TIOCM_DTR|unix.TIOCM_RTS); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TIOCMSET DTR+RTS: %w", err)
	}

	// Flush the input buffer to discard stale firmware output.
	// TCFLSH takes the queue selector as a direct integer argument (not a
	// pointer), so we use Syscall rather than IoctlSetPointerInt.
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TCFLSH, uintptr(unix.TCIFLUSH))

	// Prevent another process from opening the same port.
	_ = unix.IoctlSetInt(fd, unix.TIOCEXCL, 0)

	// Switch back to blocking I/O (O_NDELAY opened non-blocking).
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("SetNonblock: %w", err)
	}

	return &nativePort{fd: fd}, nil
}

// baudToSpeed maps an integer baud rate to the Linux termios speed constant.
func baudToSpeed(baud int) (uint32, error) {
	switch baud {
	case 9600:
		return unix.B9600, nil
	case 19200:
		return unix.B19200, nil
	case 38400:
		return unix.B38400, nil
	case 57600:
		return unix.B57600, nil
	case 115200:
		return unix.B115200, nil
	case 230400:
		return unix.B230400, nil
	case 460800:
		return unix.B460800, nil
	case 921600:
		return unix.B921600, nil
	case 1000000:
		return unix.B1000000, nil
	case 2000000:
		return unix.B2000000, nil
	default:
		return 0, fmt.Errorf("unsupported baud rate: %d", baud)
	}
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
