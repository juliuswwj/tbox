//go:build linux

package l2

import (
	"log"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"time"
)

// Passthrough implements the reference udpt.py IPv6 transparent passthrough: as
// global-unicast IPv6 sources appear on the segment, it installs a /80 route
// toward the TAP/bridge and restarts ndppd so the upstream answers NDP for the
// prefix. ndppd itself is provisioned by the operator for the pool prefix.
type Passthrough struct {
	dev    string
	logger *log.Logger

	mu          sync.Mutex
	seen        map[netip.Prefix]struct{}
	lastRestart time.Time
}

// NewPassthrough returns a passthrough manager that routes /80s out of dev.
func NewPassthrough(dev string, logger *log.Logger) *Passthrough {
	if logger == nil {
		logger = log.Default()
	}
	return &Passthrough{dev: dev, logger: logger, seen: make(map[netip.Prefix]struct{})}
}

// OnIPv6 is the Switch IPv6 hook. src is a global-unicast IPv6 source address.
func (p *Passthrough) OnIPv6(src net.IP) {
	addr, ok := netip.AddrFromSlice(src)
	if !ok || !addr.Is6() {
		return
	}
	pfx, err := addr.Prefix(80)
	if err != nil {
		return
	}

	p.mu.Lock()
	if _, dup := p.seen[pfx]; dup {
		p.mu.Unlock()
		return
	}
	p.seen[pfx] = struct{}{}
	p.mu.Unlock()

	if err := exec.Command("ip", "-6", "route", "replace", pfx.String(), "dev", p.dev).Run(); err != nil {
		p.logger.Printf("l2: add v6 route %s dev %s: %v", pfx, p.dev, err)
		p.mu.Lock()
		delete(p.seen, pfx)
		p.mu.Unlock()
		return
	}
	p.logger.Printf("l2: ipv6 passthrough route %s via %s", pfx, p.dev)
	p.restartNdppd()
}

func (p *Passthrough) restartNdppd() {
	p.mu.Lock()
	if time.Since(p.lastRestart) < 5*time.Second {
		p.mu.Unlock()
		return // debounce: ndppd's prefix config still covers later /80s
	}
	p.lastRestart = time.Now()
	p.mu.Unlock()
	if err := exec.Command("systemctl", "restart", "ndppd").Run(); err != nil {
		p.logger.Printf("l2: restart ndppd: %v", err)
	}
}
