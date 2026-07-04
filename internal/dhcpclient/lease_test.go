package dhcpclient

import (
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// TestLeaseFromACK builds a synthetic DHCPv4 ACK and verifies that
// leaseFromACK maps every option of interest to the Lease struct.
func TestLeaseFromACK(t *testing.T) {
	server := net.IPv4(10, 42, 0, 1)
	client := net.IPv4(10, 42, 0, 7)
	mask := net.IPv4Mask(255, 255, 255, 0)

	// A "request" frame is the canonical base for NewReplyFromRequest; the
	// only thing we need off it is a chaddr + xid.
	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 0xaa})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(client),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(server)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(mask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(server)),
		dhcpv4.WithLeaseTime(3600),
	)
	if err != nil {
		t.Fatal(err)
	}

	lease := leaseFromACK(ack)
	if !lease.IPv4.Equal(client) {
		t.Fatalf("IPv4: got %s, want %s", lease.IPv4, client)
	}
	if !lease.ServerID.Equal(server) {
		t.Fatalf("ServerID: got %s, want %s", lease.ServerID, server)
	}
	if lease.SubnetMask.String() != mask.String() {
		t.Fatalf("SubnetMask: got %s, want %s", lease.SubnetMask, mask)
	}
	if !lease.Gateway.Equal(server) {
		t.Fatalf("Gateway: got %s, want %s", lease.Gateway, server)
	}
	if !lease.DefaultRoute {
		t.Fatal("DefaultRoute should be true when ACK has option 3")
	}
	if lease.LeaseTime != 3600*time.Second {
		t.Fatalf("LeaseTime: got %s, want 3600s", lease.LeaseTime)
	}
}

// TestLeaseFromACKNoRouter makes sure an ACK without the router option is
// still parsed cleanly (DefaultRoute=false, Gateway=nil).
func TestLeaseFromACKNoRouter(t *testing.T) {
	server := net.IPv4(10, 42, 0, 1)
	client := net.IPv4(10, 42, 0, 8)
	mask := net.IPv4Mask(255, 255, 255, 0)

	req, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 0xbb})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(client),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(server)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(mask)),
		dhcpv4.WithLeaseTime(600),
	)
	if err != nil {
		t.Fatal(err)
	}

	lease := leaseFromACK(ack)
	if lease.Gateway != nil {
		t.Fatalf("Gateway should be nil, got %s", lease.Gateway)
	}
	if lease.DefaultRoute {
		t.Fatal("DefaultRoute should be false when ACK omits option 3")
	}
	if lease.LeaseTime != 600*time.Second {
		t.Fatalf("LeaseTime: got %s, want 600s", lease.LeaseTime)
	}
}
