//go:build linux

package control

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/juliuswwj/tbox/internal/dhcpclient"
	"github.com/juliuswwj/tbox/internal/l2"
)

// runDHCP performs a one-shot DHCPv4 DORA on ipDev and installs the leased
// IPv4, subnet route, and (when AcceptDefaultRoute is set) a default route via
// the offered gateway. If the server's DHCP ACK provides a router option, we
// also pin the carrier's real host route so the encrypted TCP to the server is
// not captured by the tunnel's own default route.
func (c *Client) runDHCP(ipDev string, tap *l2.ClientTAP) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lease, err := dhcpclient.Discover(ctx, ipDev, c.logger)
	if err != nil {
		return err
	}
	ones, _ := lease.SubnetMask.Size()
	if ones == 0 {
		return fmt.Errorf("DHCP ACK missing subnet mask")
	}
	cidr := fmt.Sprintf("%s/%d", lease.IPv4.String(), ones)
	if err := l2.AddAddr(ipDev, cidr); err != nil {
		return fmt.Errorf("apply leased addr %s: %w", cidr, err)
	}
	subnet := &net.IPNet{IP: lease.IPv4.Mask(lease.SubnetMask), Mask: lease.SubnetMask}
	if err := l2.AddRoute(ipDev, subnet.String()); err != nil {
		c.logger.Printf("control: tun DHCP subnet route %s: %v", subnet.String(), err)
	}
	if c.tun.AcceptDefaultRoute && lease.Gateway != nil && lease.DefaultRoute {
		if c.serverRealIP != "" {
			if err := l2.AddHostRouteViaCurrentGateway(c.serverRealIP); err != nil {
				c.logger.Printf("control: pin carrier host route %s: %v", c.serverRealIP, err)
			}
		}
		if err := l2.AddDefaultRoute(ipDev, lease.Gateway.String()); err != nil {
			return fmt.Errorf("default route via %s: %w", lease.Gateway.String(), err)
		}
	}
	c.logger.Printf("control: tun DHCP applied %s on %s", cidr, ipDev)
	return nil
}
