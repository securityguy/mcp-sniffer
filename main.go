/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tenebris-tech/mcp-sniffer/blecap"
	"github.com/tenebris-tech/mcp-sniffer/bledev"
	"github.com/tenebris-tech/mcp-sniffer/blepdu"
)

const defaultCaptureSecs = 30

func main() {
	deviceFlag := flag.String("device", "", "serial port path (auto-detected if empty)")
	filterFlag := flag.String("filter", "", "comma-separated BLE addresses or OUI prefixes (e.g. \"AA:BB:CC:DD:EE:FF,50:32:5F\")")
	followFlag := flag.String("follow", "", "single BLE address for hardware follow mode")
	durationFlag := flag.Int("duration", defaultCaptureSecs, "capture duration in seconds")
	flag.Parse()

	device := *deviceFlag
	if device == "" {
		var err error
		device, err = bledev.Find()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Detected sniffer at %s\n\n", device)
	}

	var filterAddrs []string
	if *filterFlag != "" {
		for _, part := range strings.Split(*filterFlag, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				filterAddrs = append(filterAddrs, trimmed)
			}
		}
	}

	capture, err := blecap.New(
		blecap.WithDevice(device),
		blecap.WithFilter(filterAddrs),
		blecap.WithFollow(*followFlag),
		blecap.WithAutoTune(),
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)

	if err = capture.Start(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	go printPackets(capture)

	select {
	case <-time.After(time.Duration(*durationFlag) * time.Second):
	case sig := <-sigCh:
		_, _ = fmt.Fprintf(os.Stderr, "\nreceived %s, stopping...\n", sig)
	}

	if err := capture.Stop(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: stop: %v\n", err)
	}

	fmt.Printf("\nTotal packets captured: %d\n", capture.Count())
}

// printPackets polls the capture and prints any newly stored packets.
func printPackets(cap *blecap.Capture) {
	offset := 0
	for {
		pkts := cap.Get(offset, 64)
		if len(pkts) == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		for _, pkt := range pkts {
			fmt.Printf("--- [%d] %s id=0x%02X at=%s\n",
				pkt.Index, blecap.PDUTypeName(pkt), pkt.ID, pkt.ReceivedAt.Format(time.RFC3339Nano))
			roles := blepdu.AddressRoles(pkt.ID, pkt.Raw)
			for i, addr := range pkt.Addresses {
				role := "addr"
				if i < len(roles) {
					role = roles[i]
				}
				fmt.Printf("    %-8s %s\n", role+":", addr)
			}
			if len(pkt.Raw) > 0 {
				fmt.Print(hex.Dump(pkt.Raw))
			}
		}
		offset += len(pkts)
	}
}
