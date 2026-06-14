// Package ban implements a fail2ban-style throttle for the HTTP publishing
// path: it counts authentication failures per source IP within a sliding
// window, bans an IP that crosses a threshold, and escalates to banning a whole
// /24 once enough distinct IPs in it are banned. State is in-memory.
package ban

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Config controls failure detection and banning. The zero value is unused;
// build one via the server config.
type Config struct {
	Methods         []string       // request methods that count (e.g. POST); empty = any
	Statuses        []int          // response statuses that count (e.g. 401, 403)
	PathPrefix      string         // optional request-path prefix filter; "" = any
	Window          time.Duration  // sliding window for per-IP failure counting
	Threshold       int            // failures per IP within Window -> ban the IP
	BanDuration     time.Duration  // how long an IP or /24 ban lasts
	SubnetThreshold int            // distinct banned IPs in a /24 -> ban the /24; 0 disables
	Exempt          []netip.Prefix // sources never counted or blocked
}

// Banner tracks failures and bans. It is safe for concurrent use.
type Banner struct {
	cfg      Config
	methods  map[string]bool
	statuses map[int]bool
	now      func() time.Time // injectable clock (tests)

	mu        sync.Mutex
	fails     map[netip.Addr][]time.Time
	bannedIP  map[netip.Addr]time.Time   // ip -> banned until
	bannedNet map[netip.Prefix]time.Time // /24 -> banned until
}

// New builds a Banner from cfg.
func New(cfg Config) *Banner {
	methods := make(map[string]bool, len(cfg.Methods))
	for _, m := range cfg.Methods {
		methods[strings.ToUpper(m)] = true
	}
	statuses := make(map[int]bool, len(cfg.Statuses))
	for _, s := range cfg.Statuses {
		statuses[s] = true
	}
	return &Banner{
		cfg:       cfg,
		methods:   methods,
		statuses:  statuses,
		now:       time.Now,
		fails:     make(map[netip.Addr][]time.Time),
		bannedIP:  make(map[netip.Addr]time.Time),
		bannedNet: make(map[netip.Prefix]time.Time),
	}
}

// Counts reports whether a response to (method, path, status) is an
// authentication failure that should be recorded.
func (b *Banner) Counts(method, path string, status int) bool {
	if !b.statuses[status] {
		return false
	}
	if len(b.methods) > 0 && !b.methods[strings.ToUpper(method)] {
		return false
	}
	if b.cfg.PathPrefix != "" && !strings.HasPrefix(path, b.cfg.PathPrefix) {
		return false
	}
	return true
}

// Blocked reports whether ip (or its /24) is currently banned.
func (b *Banner) Blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if b.isExempt(ip) {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if until, ok := b.bannedIP[ip]; ok {
		if now.Before(until) {
			return true
		}
		delete(b.bannedIP, ip)
	}
	if pfx, ok := subnet(ip); ok {
		if until, ok := b.bannedNet[pfx]; ok {
			if now.Before(until) {
				return true
			}
			delete(b.bannedNet, pfx)
		}
	}
	return false
}

// Fail records one authentication failure from ip, banning the IP (and possibly
// its /24) when thresholds are crossed. Returns the bans newly applied, for
// logging: bannedIP is true if this call banned the IP, bannedSubnet is the /24
// string if this call banned the subnet.
func (b *Banner) Fail(ip netip.Addr) (bannedIP bool, bannedSubnet string) {
	ip = ip.Unmap()
	if b.isExempt(ip) {
		return false, ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.sweepLocked(now)

	cutoff := now.Add(-b.cfg.Window)
	times := append(pruneBefore(b.fails[ip], cutoff), now)
	b.fails[ip] = times
	if len(times) < b.cfg.Threshold {
		return false, ""
	}

	// Threshold crossed: ban the IP and reset its window.
	b.bannedIP[ip] = now.Add(b.cfg.BanDuration)
	delete(b.fails, ip)
	bannedIP = true

	// Escalate to the /24 once enough distinct IPs in it are banned.
	if b.cfg.SubnetThreshold > 0 {
		if pfx, ok := subnet(ip); ok {
			if _, already := b.bannedNet[pfx]; !already {
				count := 0
				for banned, until := range b.bannedIP {
					if now.Before(until) {
						if bp, ok := subnet(banned); ok && bp == pfx {
							count++
						}
					}
				}
				if count >= b.cfg.SubnetThreshold {
					b.bannedNet[pfx] = now.Add(b.cfg.BanDuration)
					bannedSubnet = pfx.String()
				}
			}
		}
	}
	return bannedIP, bannedSubnet
}

func (b *Banner) isExempt(ip netip.Addr) bool {
	for _, p := range b.cfg.Exempt {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// sweepLocked drops expired bans and stale failure windows. Caller holds mu.
func (b *Banner) sweepLocked(now time.Time) {
	for ip, until := range b.bannedIP {
		if !now.Before(until) {
			delete(b.bannedIP, ip)
		}
	}
	for p, until := range b.bannedNet {
		if !now.Before(until) {
			delete(b.bannedNet, p)
		}
	}
	cutoff := now.Add(-b.cfg.Window)
	for ip, ts := range b.fails {
		if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
			delete(b.fails, ip)
		}
	}
}

// subnet returns the /24 of an IPv4 address. The /24 rule applies to IPv4 only;
// IPv6 sources are banned per-address.
func subnet(ip netip.Addr) (netip.Prefix, bool) {
	if !ip.Is4() {
		return netip.Prefix{}, false
	}
	p, err := ip.Prefix(24)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// pruneBefore returns the timestamps strictly after cutoff (ts is ascending).
func pruneBefore(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return append([]time.Time(nil), ts[i:]...)
}
