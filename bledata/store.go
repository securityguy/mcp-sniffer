// Package bledata processes and stores BLE advertising packets from the sniffer.
package bledata

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tenebris-tech/mcp-sniffer/blepdu"
	"github.com/tenebris-tech/mcp-sniffer/sniffer"
)

// Packet is a processed and stored BLE sniffer packet.
type Packet struct {
	Index      int
	ReceivedAt time.Time
	ID         byte
	Raw        []byte   // copy of sniffer.RawPacket.Payload
	Addresses  []string // extracted BLE addresses, MSB-first colon-hex uppercase
}

// Store receives RawPackets from a sniffer, decodes BLE addresses from
// advertising PDUs, applies an optional address filter, and provides
// thread-safe access to the stored packets.
type Store struct {
	src    <-chan sniffer.RawPacket
	stopCh chan struct{}
	wg     sync.WaitGroup

	mu         sync.RWMutex
	packets    []Packet
	seenExtAdv bool // protected by mu; set when EventPacketAdvAuxPDU is stored

	filterMu sync.RWMutex
	filter   []string // normalised prefix strings; nil or empty = accept all
}

// Option is a functional option for configuring a Store.
type Option func(*Store)

// WithFilter pre-configures the store to accept only packets from the given
// BLE addresses or OUI prefixes. An empty slice means accept all.
// Panics if any entry is invalid (programming error).
func WithFilter(addrs []string) Option {
	return func(s *Store) {
		if err := s.SetFilter(addrs); err != nil {
			panic(fmt.Sprintf("bledata.WithFilter: invalid address: %v", err))
		}
	}
}

// New creates a Store that reads from src.
func New(src <-chan sniffer.RawPacket, opts ...Option) *Store {
	s := &Store{
		src:    src,
		stopCh: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Start launches the packet-consuming goroutine.
func (s *Store) Start() {
	s.wg.Add(1)
	go s.consume()
}

// Stop signals the consumer goroutine to exit and waits for it to finish.
func (s *Store) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// SetFilter replaces the current address filter atomically.
// An empty slice clears the filter, accepting all packets.
// Returns an error if any address entry is invalid.
func (s *Store) SetFilter(addrs []string) error {
	f, err := normaliseFilter(addrs)
	if err != nil {
		return err
	}
	s.filterMu.Lock()
	s.filter = f
	s.filterMu.Unlock()
	return nil
}

// Count returns the number of packets stored so far.
func (s *Store) Count() int {
	s.mu.RLock()
	n := len(s.packets)
	s.mu.RUnlock()
	return n
}

// Get returns a page of stored packets starting at offset, up to limit packets.
// It is safe to call concurrently with the consumer goroutine.
func (s *Store) Get(offset, limit int) []Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.packets)
	if offset >= total || limit <= 0 {
		return nil
	}
	end := min(offset+limit, total)
	// Return a copy of the slice header so callers hold independent references.
	result := make([]Packet, end-offset)
	copy(result, s.packets[offset:end])
	return result
}

// consume reads from the source channel until it is closed or Stop is called.
func (s *Store) consume() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		case pkt, ok := <-s.src:
			if !ok {
				return
			}
			s.process(pkt)
		}
	}
}

// process decides whether to store a packet and extracts BLE addresses.
func (s *Store) process(raw sniffer.RawPacket) {
	switch raw.ID {
	case sniffer.EventPacketAdvPDU:
		addrs := blepdu.ParseLegacyAdvAddresses(raw.Payload)

		// Check filter.
		s.filterMu.RLock()
		f := s.filter
		s.filterMu.RUnlock()

		if len(f) > 0 && !matchFilter(f, addrs) {
			return
		}

		s.append(raw, addrs)

	case sniffer.EventPacketAdvAuxPDU:
		addrs := blepdu.ParseExtAdvAddresses(raw.Payload)

		s.filterMu.RLock()
		f := s.filter
		s.filterMu.RUnlock()

		if len(f) > 0 && !matchFilter(f, addrs) {
			return
		}

		s.append(raw, addrs)

	case sniffer.EventPacketDataPDU:
		// Data PDUs only arrive when follow mode is active; always store them.
		s.append(raw, nil)

	default:
		// All other packet IDs are discarded.
	}
}

// append adds a packet to the store under write lock.
func (s *Store) append(raw sniffer.RawPacket, addrs []string) {
	payload := make([]byte, len(raw.Payload))
	copy(payload, raw.Payload)

	s.mu.Lock()
	idx := len(s.packets)
	s.packets = append(s.packets, Packet{
		Index:      idx,
		ReceivedAt: raw.ReceivedAt, // time.Time
		ID:         raw.ID,
		Raw:        payload,
		Addresses:  addrs,
	})
	if raw.ID == sniffer.EventPacketAdvAuxPDU ||
		(raw.ID == sniffer.EventPacketAdvPDU && len(raw.Payload) >= 15 && raw.Payload[14]&0x0F == 7) {
		s.seenExtAdv = true
	}
	s.mu.Unlock()
}

// HasExtendedAdv reports whether any BT5 extended advertising PDU has been
// stored from a filtered address (or any address when no filter is active).
func (s *Store) HasExtendedAdv() bool {
	s.mu.RLock()
	v := s.seenExtAdv
	s.mu.RUnlock()
	return v
}

// FilterActive reports whether an address filter is currently set.
func (s *Store) FilterActive() bool {
	s.filterMu.RLock()
	active := len(s.filter) > 0
	s.filterMu.RUnlock()
	return active
}

// normaliseAddr uppercases and replaces dashes with colons in an address string.
func normaliseAddr(addr string) string {
	return strings.ToUpper(strings.ReplaceAll(addr, "-", ":"))
}

// normaliseFilter normalises and validates a slice of address or prefix strings.
// Returns nil if addrs is empty. Returns an error if any entry is invalid.
func normaliseFilter(addrs []string) ([]string, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		norm := normaliseAddr(a)
		if !validFilterEntry(norm) {
			return nil, fmt.Errorf("invalid filter entry %q: must be 1–6 complete hex octets separated by colons", a)
		}
		out = append(out, norm)
	}
	return out, nil
}

// validFilterEntry reports whether norm is a valid normalised filter entry.
// Valid lengths are 2, 5, 8, 11, 14, or 17 characters (1–6 complete octets).
func validFilterEntry(norm string) bool {
	validLengths := [6]int{2, 5, 8, 11, 14, 17}
	found := false
	for _, l := range validLengths {
		if len(norm) == l {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	parts := strings.Split(norm, ":")
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		for _, c := range p {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// matchFilter returns true if any address in addrs has any filter entry as a
// HasPrefix match. Both addresses and filter entries are expected to be normalised.
func matchFilter(filters []string, addrs []string) bool {
	for _, a := range addrs {
		norm := normaliseAddr(a)
		for _, f := range filters {
			if strings.HasPrefix(norm, f) {
				return true
			}
		}
	}
	return false
}
