package l2

import (
	"log"
	"net"
	"net/netip"
	"sync"
)

// MAC is a 48-bit hardware address used as the switch's learning key.
type MAC [6]byte

// Port is one attachment to the Switch. It is created by AddPort; the caller
// runs a reader goroutine that feeds inbound frames via Switch.Inject and
// removes the port (RemovePort) when its medium closes.
type Port struct {
	name      string
	send      func([]byte) error
	allowedV4 []netip.Prefix
	allowedV6 []netip.Prefix
}

// Name returns the port's label (for logging).
func (p *Port) Name() string { return p.name }

// PortConfig configures a port at attach time.
type PortConfig struct {
	Name string
	// AllowedV4/AllowedV6, when non-empty, restrict the source IP of frames
	// arriving on this port to the given prefixes (anti-spoofing). Empty means
	// no restriction — required for ports that aggregate many nodes with
	// self-assigned addresses (e.g. a UDP endpoint fronting udpt clients).
	AllowedV4 []netip.Prefix
	AllowedV6 []netip.Prefix
}

// Switch is a userspace learning bridge. Ports are yamux streams, TAP devices,
// or UDP endpoints; the switch learns source MAC -> port and forwards by
// destination MAC, flooding broadcast/multicast and unknown unicast.
type Switch struct {
	mu     sync.RWMutex
	macs   map[MAC]*Port
	ports  map[*Port]struct{}
	onIPv6 func(src net.IP) // optional: server-side IPv6 passthrough hook
	logger *log.Logger
}

// New creates a Switch. onIPv6 may be nil (client side); when set it is invoked
// with the global-unicast IPv6 source of forwarded frames for route/NDP setup.
func New(onIPv6 func(src net.IP), logger *log.Logger) *Switch {
	if logger == nil {
		logger = log.Default()
	}
	return &Switch{
		macs:   make(map[MAC]*Port),
		ports:  make(map[*Port]struct{}),
		onIPv6: onIPv6,
		logger: logger,
	}
}

// AddPort attaches a new port whose send delivers a frame out of its medium.
func (s *Switch) AddPort(send func([]byte) error, cfg PortConfig) *Port {
	p := &Port{name: cfg.Name, send: send, allowedV4: cfg.AllowedV4, allowedV6: cfg.AllowedV6}
	s.mu.Lock()
	s.ports[p] = struct{}{}
	s.mu.Unlock()
	return p
}

// RemovePort detaches a port and forgets any MACs learned on it.
func (s *Switch) RemovePort(p *Port) {
	s.mu.Lock()
	delete(s.ports, p)
	for mac, owner := range s.macs {
		if owner == p {
			delete(s.macs, mac)
		}
	}
	s.mu.Unlock()
}

// Inject forwards one frame that arrived on port from. Frames shorter than an
// Ethernet header, or whose source IP violates from's allow list, are dropped.
func (s *Switch) Inject(from *Port, frame []byte) {
	if len(frame) < 14 {
		return
	}
	if !s.sourceAllowed(from, frame) {
		return
	}
	var src, dst MAC
	copy(dst[:], frame[0:6])
	copy(src[:], frame[6:12])

	// Learn the source MAC (unicast addresses only).
	if src[0]&0x01 == 0 {
		s.mu.Lock()
		if s.macs[src] != from {
			s.macs[src] = from
		}
		s.mu.Unlock()
	}

	// IPv6 passthrough: surface global-unicast sources to the hook.
	if s.onIPv6 != nil && etherType(frame) == 0x86dd && len(frame) >= 38 {
		if frame[22]&0xe0 == 0x20 { // 2000::/3 global unicast
			ip := make(net.IP, 16)
			copy(ip, frame[22:38])
			s.onIPv6(ip)
		}
	}

	// Multicast (and broadcast, a subset) floods to every other port.
	if dst[0]&0x01 == 1 {
		s.flood(from, frame)
		return
	}

	s.mu.RLock()
	target := s.macs[dst]
	s.mu.RUnlock()
	switch {
	case target == nil:
		// Unknown unicast: flood and let learning catch up.
		s.flood(from, frame)
	case target != from:
		if err := target.send(frame); err != nil {
			s.logger.Printf("l2: send to %s: %v", target.name, err)
		}
	}
}

// flood sends frame to every port except the source.
func (s *Switch) flood(from *Port, frame []byte) {
	s.mu.RLock()
	dsts := make([]*Port, 0, len(s.ports))
	for p := range s.ports {
		if p != from {
			dsts = append(dsts, p)
		}
	}
	s.mu.RUnlock()
	for _, p := range dsts {
		if err := p.send(frame); err != nil {
			s.logger.Printf("l2: flood to %s: %v", p.name, err)
		}
	}
}

// sourceAllowed enforces a port's source-IP allow list (anti-spoofing). A port
// with no configured prefixes accepts any source.
func (s *Switch) sourceAllowed(p *Port, frame []byte) bool {
	if len(p.allowedV4) == 0 && len(p.allowedV6) == 0 {
		return true
	}
	switch etherType(frame) {
	case 0x0800: // IPv4
		if len(frame) < 30 {
			return false
		}
		return prefixesContain(p.allowedV4, netip.AddrFrom4([4]byte(frame[26:30])))
	case 0x0806: // ARP — check sender protocol address (IPv4)
		if len(frame) < 32 || frame[18] != 4 { // plen field
			return true // non-IPv4 ARP: leave to other checks
		}
		return prefixesContain(p.allowedV4, netip.AddrFrom4([4]byte(frame[28:32])))
	case 0x86dd: // IPv6
		if len(frame) < 38 {
			return false
		}
		return prefixesContain(p.allowedV6, netip.AddrFrom16([16]byte(frame[22:38])))
	default:
		// Non-IP (e.g. IPv6 ND without addresses we parse here) is permitted;
		// MAC learning still applies.
		return true
	}
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, pfx := range prefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func etherType(frame []byte) uint16 {
	if len(frame) < 14 {
		return 0
	}
	return uint16(frame[12])<<8 | uint16(frame[13])
}
