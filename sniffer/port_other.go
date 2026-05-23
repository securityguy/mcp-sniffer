//go:build !darwin && !linux

/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package sniffer

import "fmt"

// serialPort is the minimal interface used by Sniffer to communicate with
// the hardware.
type serialPort interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// openNativePort returns an error on unsupported platforms.
func openNativePort(_ string, _ int) (*nativePort, error) {
	return nil, fmt.Errorf("serial port is not supported on this platform")
}

// nativePort is an empty stub on unsupported platforms.
type nativePort struct{}

func (p *nativePort) Read([]byte) (int, error)  { return 0, fmt.Errorf("not supported") }
func (p *nativePort) Write([]byte) (int, error) { return 0, fmt.Errorf("not supported") }
func (p *nativePort) Close() error              { return fmt.Errorf("not supported") }
