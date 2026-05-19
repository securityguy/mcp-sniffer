// Package blecap provides a single high-level API for configuring and
// running a BLE capture. It owns the sniffer and store internally so
// callers do not need to coordinate between the two packages.
package blecap

import (
	"fmt"
	"sync"
	"time"

	"github.com/tenebris-tech/mcp-sniffer/bledata"
	"github.com/tenebris-tech/mcp-sniffer/blepdu"
	"github.com/tenebris-tech/mcp-sniffer/sniffer"
)

// Capture owns a sniffer and a packet store, exposing a unified lifecycle API.
type Capture struct {
	// configuration — set by options before New builds the subsystems
	device      string
	baudRate    int
	channelSize int
	scanFlags   byte
	filterAddrs []string
	followAddr  string
	autoTune    bool
	tunePeriod  time.Duration

	// subsystems — created in New
	snif  *sniffer.Sniffer
	store *bledata.Store

	// auto-tune lifecycle
	stopTuneCh chan struct{}
	wg         sync.WaitGroup
}

// Option configures a Capture.
type Option func(*Capture)

// WithDevice sets the serial port path for the sniffer.
func WithDevice(path string) Option { return func(c *Capture) { c.device = path } }

// WithBaudRate sets the baud rate for the serial port.
func WithBaudRate(baud int) Option { return func(c *Capture) { c.baudRate = baud } }

// WithChannelSize sets the sniffer packet channel buffer depth.
func WithChannelSize(n int) Option { return func(c *Capture) { c.channelSize = n } }

// WithFilter sets the BLE address or OUI-prefix filter. Only packets matching
// one of the provided addresses will be stored.
func WithFilter(addrs []string) Option { return func(c *Capture) { c.filterAddrs = addrs } }

// WithFollow sets a single BLE address for hardware follow mode.
func WithFollow(addr string) Option { return func(c *Capture) { c.followAddr = addr } }

// WithoutScanRsp disables forwarding of SCAN_RSP packets.
func WithoutScanRsp() Option { return func(c *Capture) { c.scanFlags &^= sniffer.ScanFlagScanRsp } }

// WithoutExtendedAdv disables following ADV_EXT_IND to secondary channels (BT5).
func WithoutExtendedAdv() Option { return func(c *Capture) { c.scanFlags &^= sniffer.ScanFlagExtAdv } }

// WithoutCodedPHY disables scanning Coded PHY advertising channels (BT5 long-range).
func WithoutCodedPHY() Option { return func(c *Capture) { c.scanFlags &^= sniffer.ScanFlagCodedPHY } }

// AutoTuneOption configures the auto-tuner.
type AutoTuneOption func(*Capture)

// WithAutoTunePeriod overrides the default 30-second observation window.
func WithAutoTunePeriod(d time.Duration) AutoTuneOption {
	return func(c *Capture) { c.tunePeriod = d }
}

// WithAutoTune enables automatic scan-flag optimisation. After the
// observation period (default 30 s) unused scan capabilities are disabled
// when an address filter is active. Pass WithAutoTunePeriod to override
// the window.
func WithAutoTune(opts ...AutoTuneOption) Option {
	return func(c *Capture) {
		c.autoTune = true
		for _, o := range opts {
			o(c)
		}
	}
}

// New constructs a Capture, applying all provided options and initialising
// the sniffer and store subsystems. Returns an error if the filter addresses
// are invalid.
func New(opts ...Option) (*Capture, error) {
	c := &Capture{
		device:      sniffer.DefaultDevice,
		baudRate:    sniffer.DefaultBaud,
		channelSize: 1024,
		scanFlags:   sniffer.ScanFlagAll,
		tunePeriod:  30 * time.Second,
		stopTuneCh:  make(chan struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}

	snifOpts := []sniffer.Option{
		sniffer.WithDevice(c.device),
		sniffer.WithBaudRate(c.baudRate),
		sniffer.WithChannelSize(c.channelSize),
		sniffer.WithScanFlags(c.scanFlags),
	}
	c.snif = sniffer.New(snifOpts...)
	c.store = bledata.New(c.snif.Packets())

	if len(c.filterAddrs) > 0 {
		if err := c.store.SetFilter(c.filterAddrs); err != nil {
			return nil, fmt.Errorf("blecap: invalid filter: %w", err)
		}
	}
	return c, nil
}

// Start launches the store consumer and the sniffer read loop. If an address
// was configured via WithFollow, the follow command is sent after the sniffer
// starts. If WithAutoTune was set the auto-tune goroutine is also started.
func (c *Capture) Start() error {
	c.store.Start()

	if err := c.snif.Start(); err != nil {
		c.store.Stop()
		return fmt.Errorf("blecap: start sniffer: %w", err)
	}

	if c.followAddr != "" {
		if err := c.snif.Follow(c.followAddr); err != nil {
			return fmt.Errorf("blecap: follow %s: %w", c.followAddr, err)
		}
	}

	if c.autoTune {
		c.wg.Add(1)
		go c.autoTuneLoop()
	}

	return nil
}

// Stop signals the auto-tune goroutine to exit, stops the sniffer, and stops
// the store. It is safe to call Stop more than once.
func (c *Capture) Stop() error {
	// Signal auto-tune goroutine to exit.
	select {
	case <-c.stopTuneCh:
	default:
		close(c.stopTuneCh)
	}
	c.wg.Wait()

	err := c.snif.Stop()
	c.store.Stop()
	return err
}

// autoTuneLoop waits for the observation period then disables any scan
// capabilities not seen in traffic from the filtered addresses.
func (c *Capture) autoTuneLoop() {
	defer c.wg.Done()
	select {
	case <-time.After(c.tunePeriod):
	case <-c.stopTuneCh:
		return
	}
	if !c.store.FilterActive() {
		return
	}
	current := c.snif.ScanFlags()
	flags := current
	if !c.store.HasExtendedAdv() {
		flags &^= sniffer.ScanFlagExtAdv
	}
	// ScanFlagScanRsp and ScanFlagCodedPHY are kept conservatively.
	if flags != current {
		_ = c.snif.UpdateScanFlags(flags)
	}
}

// Get returns a page of stored packets starting at offset, up to limit packets.
func (c *Capture) Get(offset, limit int) []bledata.Packet { return c.store.Get(offset, limit) }

// Count returns the number of packets stored so far.
func (c *Capture) Count() int { return c.store.Count() }

// SetFilter replaces the current address filter atomically.
func (c *Capture) SetFilter(addrs []string) error { return c.store.SetFilter(addrs) }

// PDUTypeName returns a human-readable PDU type label for a packet.
func PDUTypeName(pkt bledata.Packet) string { return blepdu.PDUTypeName(pkt.ID, pkt.Raw) }
