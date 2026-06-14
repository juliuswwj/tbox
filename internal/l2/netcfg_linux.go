//go:build linux

package l2

import (
	"fmt"
	"net"

	"github.com/sagernet/netlink"
)

// SetUp sets the MTU (if >0) and brings the interface up.
func SetUp(name string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %q: %w", name, err)
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set mtu %d on %q: %w", mtu, name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up %q: %w", name, err)
	}
	return nil
}

// AddAddr assigns an IPv4 or IPv6 address (CIDR form) to the interface.
func AddAddr(name, cidr string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %q: %w", name, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", cidr, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("add addr %s to %q: %w", cidr, name, err)
	}
	return nil
}

// AddToBridge enslaves the interface to an existing Linux bridge.
func AddToBridge(name, bridge string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %q: %w", name, err)
	}
	br, err := netlink.LinkByName(bridge)
	if err != nil {
		return fmt.Errorf("bridge %q: %w", bridge, err)
	}
	return netlink.LinkSetMaster(link, br)
}

// AddRoute installs a link-scoped route for dstCIDR via the interface.
func AddRoute(name, dstCIDR string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %q: %w", name, err)
	}
	_, dst, err := net.ParseCIDR(dstCIDR)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", dstCIDR, err)
	}
	r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Scope: netlink.SCOPE_LINK}
	if err := netlink.RouteReplace(r); err != nil {
		return fmt.Errorf("add route %s via %q: %w", dstCIDR, name, err)
	}
	return nil
}

// AddDefaultRoute points the default route at gw via the interface.
func AddDefaultRoute(name, gw string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %q: %w", name, err)
	}
	g := net.ParseIP(gw)
	if g == nil {
		return fmt.Errorf("bad gateway %q", gw)
	}
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Gw: g}
	if err := netlink.RouteReplace(r); err != nil {
		return fmt.Errorf("set default route via %q: %w", name, err)
	}
	return nil
}

// AddHostRouteViaCurrentGateway pins ip/32 (or /128) to whatever the current
// default route uses, so the encrypted carrier to the server is not captured
// by the tunnel's own default route.
func AddHostRouteViaCurrentGateway(ip string) error {
	dest := net.ParseIP(ip)
	if dest == nil {
		return fmt.Errorf("bad ip %q", ip)
	}
	routes, err := netlink.RouteGet(dest)
	if err != nil || len(routes) == 0 {
		return fmt.Errorf("route get %s: %w", ip, err)
	}
	cur := routes[0]
	mask := net.CIDRMask(32, 32)
	if dest.To4() == nil {
		mask = net.CIDRMask(128, 128)
	}
	r := &netlink.Route{
		LinkIndex: cur.LinkIndex,
		Dst:       &net.IPNet{IP: dest, Mask: mask},
		Gw:        cur.Gw,
		Src:       cur.Src,
	}
	if err := netlink.RouteReplace(r); err != nil {
		return fmt.Errorf("pin host route %s: %w", ip, err)
	}
	return nil
}
