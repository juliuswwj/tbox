// Package ipallow implements an atomically-swappable source-IP allow list,
// shared by the L4 router and the HTTP/WS publish handlers.
package ipallow

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
)

// Set is a concurrency-safe, atomically replaceable CIDR allow list.
// An empty set allows everything.
type Set struct {
	v atomic.Pointer[[]netip.Prefix]
}

// New builds a Set from a list of CIDR strings (or bare IPs).
func New(cidrs []string) (*Set, error) {
	prefixes, err := parse(cidrs)
	if err != nil {
		return nil, err
	}
	s := &Set{}
	s.v.Store(&prefixes)
	return s, nil
}

// Replace atomically swaps the allow list.
func (s *Set) Replace(cidrs []string) error {
	prefixes, err := parse(cidrs)
	if err != nil {
		return err
	}
	s.v.Store(&prefixes)
	return nil
}

// List returns the current allow list as CIDR strings.
func (s *Set) List() []string {
	p := s.v.Load()
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(*p))
	for _, pre := range *p {
		out = append(out, pre.String())
	}
	return out
}

// Allowed reports whether addr is permitted. An empty list allows all.
func (s *Set) Allowed(addr netip.Addr) bool {
	p := s.v.Load()
	if p == nil || len(*p) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, pre := range *p {
		if pre.Contains(addr) {
			return true
		}
	}
	return false
}

// AllowedConn extracts the remote IP from a net.Addr and checks it.
func (s *Set) AllowedConn(remote net.Addr) bool {
	return s.AllowedString(remote.String())
}

// AllowedString checks a "host:port" or bare-host string (e.g. http.Request.RemoteAddr).
func (s *Set) AllowedString(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return s.Allowed(addr)
}

func parse(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		if pre, err := netip.ParsePrefix(c); err == nil {
			out = append(out, pre)
			continue
		}
		// Bare IP -> /32 or /128.
		addr, err := netip.ParseAddr(c)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR or IP %q: %w", c, err)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}
