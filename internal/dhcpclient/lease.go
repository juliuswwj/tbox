// Package dhcpclient runs a one-shot DHCPv4 DORA on a L2 interface to obtain
// an IPv4 address, subnet mask, default gateway, and (optionally) default
// route from the embedded tbox DHCP server. It is used when tun.tap.dhcp is
// enabled and no static ipv4_cidr is set — the alternative to the legacy
// in-protocol TunAssignment scheme.
//
//go:build linux

package dhcpclient

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
)

// Lease is the result of a successful DORA exchange.
type Lease struct {
	IPv4         net.IP        // client IP assigned by the server
	SubnetMask   net.IPMask    // option 1
	Gateway      net.IP        // option 3 (first router, may be nil)
	ServerID     net.IP        // server identifier
	LeaseTime    time.Duration // option 51
	DefaultRoute bool          // whether the ACK offered a router we should install as default
}

// Discover runs the 4-way Discover-Offer-Request-Ack on iface and returns the
// resulting lease. Fails with a timeout after ctx is cancelled or the client
// library exhausts its retries.
func Discover(ctx context.Context, iface string, logger *log.Logger) (*Lease, error) {
	if logger == nil {
		logger = log.Default()
	}
	cl, err := nclient4.New(iface,
		nclient4.WithTimeout(5*time.Second),
		nclient4.WithRetry(3),
		nclient4.WithLogger(nclient4.ShortSummaryLogger{Printfer: logger}),
	)
	if err != nil {
		return nil, fmt.Errorf("dhcp client: %w", err)
	}
	defer cl.Close()

	logger.Printf("dhcpclient: DORA on %s", iface)
	lease, err := cl.Request(ctx,
		dhcpv4.WithRequestedOptions(
			dhcpv4.OptionSubnetMask,
			dhcpv4.OptionRouter,
			dhcpv4.OptionIPAddressLeaseTime,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dhcp DORA: %w", err)
	}
	out := leaseFromACK(lease.ACK)
	logger.Printf("dhcpclient: leased %s via %s (gw %s, server %s, lease %s)",
		out.IPv4, iface, out.Gateway, out.ServerID, out.LeaseTime)
	return out, nil
}

// leaseFromACK converts a DHCPv4 ACK packet into the Lease summary shared with
// callers. Pulled out for unit testing (the live path above needs a real L2
// socket and CAP_NET_RAW).
func leaseFromACK(ack *dhcpv4.DHCPv4) *Lease {
	out := &Lease{
		IPv4:         ack.YourIPAddr,
		SubnetMask:   ack.SubnetMask(),
		ServerID:     ack.ServerIdentifier(),
		DefaultRoute: len(ack.Router()) > 0,
	}
	if r := ack.Router(); len(r) > 0 {
		out.Gateway = r[0]
	}
	if lt := ack.IPAddressLeaseTime(0); lt > 0 {
		out.LeaseTime = lt
	}
	return out
}
