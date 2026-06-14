// Package destallow matches a connection destination (host + port) against an
// allow list, used by published socks5 services to avoid being an open proxy.
//
// Each rule is one of:
//
//   - any host, any port
//     *:443             any host, port 443
//     example.com       exact host (any port)
//     example.com:22    exact host + port
//     *.example.com     any host under example.com (any port)
//     10.0.0.0/8        any IP in the CIDR (any port; matches IP destinations)
//     [::1]:22          bracketed IPv6 host + port
//
// An empty allow list denies everything (a socks5 service must opt in to
// destinations explicitly).
package destallow

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type rule struct {
	any    bool
	exact  string       // lower-case exact host
	suffix string       // ".example.com" for *.example.com
	cidr   netip.Prefix // valid if cidr.IsValid()
	port   uint16       // 0 = any
}

// Set is a parsed destination allow list.
type Set struct {
	rules []rule
}

// New parses an allow list.
func New(entries []string) (*Set, error) {
	s := &Set{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		r, err := parseRule(e)
		if err != nil {
			return nil, err
		}
		s.rules = append(s.rules, r)
	}
	return s, nil
}

// Allowed reports whether dialing host:port is permitted.
func (s *Set) Allowed(host string, port uint16) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, r := range s.rules {
		if r.port != 0 && r.port != port {
			continue
		}
		if r.matchHost(host) {
			return true
		}
	}
	return false
}

func (r rule) matchHost(host string) bool {
	switch {
	case r.any:
		return true
	case r.cidr.IsValid():
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return false // a CIDR rule only matches literal IP destinations
		}
		return r.cidr.Contains(addr.Unmap())
	case r.suffix != "":
		return strings.HasSuffix(host, r.suffix)
	default:
		return host == r.exact
	}
}

func parseRule(e string) (rule, error) {
	host, port, err := splitHostPort(e)
	if err != nil {
		return rule{}, err
	}
	r := rule{port: port}
	switch {
	case host == "*":
		r.any = true
	case strings.Contains(host, "/"):
		pre, err := netip.ParsePrefix(host)
		if err != nil {
			return rule{}, fmt.Errorf("invalid CIDR %q: %w", host, err)
		}
		r.cidr = pre
	case strings.HasPrefix(host, "*."):
		r.suffix = strings.ToLower(host[1:]) // ".example.com"
	default:
		r.exact = strings.ToLower(host)
	}
	return r, nil
}

// splitHostPort splits "host" or "host:port", leaving CIDRs and bare IPv6
// untouched (port 0). Bracketed IPv6 with a port is supported.
func splitHostPort(s string) (host string, port uint16, err error) {
	if strings.Contains(s, "/") {
		return s, 0, nil // CIDR: no port
	}
	if strings.HasPrefix(s, "[") {
		// [ipv6] or [ipv6]:port
		end := strings.LastIndex(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("invalid bracketed host %q", s)
		}
		h := s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return h, 0, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("invalid host:port %q", s)
		}
		p, err := parsePort(rest[1:])
		return h, p, err
	}
	i := strings.LastIndex(s, ":")
	if i >= 0 && !strings.Contains(s[:i], ":") && isDigits(s[i+1:]) {
		p, err := parsePort(s[i+1:])
		return s[:i], p, err
	}
	return s, 0, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(n), nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
