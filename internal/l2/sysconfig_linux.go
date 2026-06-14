//go:build linux

package l2

import (
	"fmt"
	"os"

	"github.com/coreos/go-iptables/iptables"
)

// EnableIPForward turns on IPv4 and IPv6 forwarding so the server can route
// tunnel traffic out to the internet (global egress) and between nodes.
func EnableIPForward() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable ipv4 forwarding: %w", err)
	}
	// IPv6 forwarding is best-effort (kernel may lack IPv6).
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1\n"), 0o644)
	return nil
}

// EnsureMasquerade installs an idempotent NAT rule so the v4 pool egresses via
// wanIface. It returns a cleanup that removes the rule.
func EnsureMasquerade(poolV4CIDR, wanIface string) (func() error, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("iptables: %w", err)
	}
	rule := []string{"-s", poolV4CIDR, "-o", wanIface, "-j", "MASQUERADE"}
	if err := ipt.AppendUnique("nat", "POSTROUTING", rule...); err != nil {
		return nil, fmt.Errorf("add masquerade: %w", err)
	}
	cleanup := func() error { return ipt.DeleteIfExists("nat", "POSTROUTING", rule...) }
	return cleanup, nil
}
