package dhcpserver

import (
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func newTestServer(t *testing.T, poolCIDR, gateway string) *Server {
	t.Helper()
	_, pool, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		t.Fatal(err)
	}
	gw := net.ParseIP(gateway)
	if gw == nil {
		t.Fatalf("bad gateway %q", gateway)
	}
	s, err := New(Config{Pool: pool, Gateway: gw, LeaseTime: time.Hour}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustDiscover(id byte) *dhcpv4.DHCPv4 {
	d, err := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, id})
	if err != nil {
		panic(err)
	}
	return d
}

// buildACK modifies server state but does not actually send packets — perfect
// for offline unit testing of allocation logic.
func TestAllocStableAndDistinct(t *testing.T) {
	s := newTestServer(t, "10.42.0.0/24", "10.42.0.1")

	req1 := mustDiscover(1)
	offer, err := s.buildOffer(req1)
	if err != nil || offer == nil {
		t.Fatalf("clientA offer: %+v %v", offer, err)
	}
	a := offer.YourIPAddr.String()
	// The gateway is never returned.
	if a == "10.42.0.1" {
		t.Fatalf("assigned the gateway address")
	}

	// Repeated discovers from the same client before ACK return the same
	// candidate (server-side reservation is stable across DISCOVERs).
	offer1b, _ := s.buildOffer(req1)
	if offer1b == nil {
		t.Fatal("clientA second offer nil")
	}
	if offer1b.YourIPAddr.String() != a {
		t.Fatalf("unstable pre-ACK offer: %s then %s", a, offer1b.YourIPAddr.String())
	}

	// A different client must get a different IP.
	req2 := mustDiscover(2)
	offerB, _ := s.buildOffer(req2)
	if offerB == nil {
		t.Fatal("clientB offer nil")
	}
	if offerB.YourIPAddr.String() == a {
		t.Fatalf("two clients share %s", a)
	}
}

func TestPoolExhaustion(t *testing.T) {
	// 10.0.0.0/30: network .0, gateway .1, one usable host .2, broadcast .3.
	s := newTestServer(t, "10.0.0.0/30", "10.0.0.1")

	req := mustDiscover(1)
	offer, err := s.buildOffer(req)
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	if offer == nil {
		t.Fatal("expected an offer")
	}
	if offer.YourIPAddr.String() != "10.0.0.2" {
		t.Fatalf("got %s, want 10.0.0.2", offer.YourIPAddr.String())
	}
	// Commit the lease so the pool is fully consumed.
	if _, err := s.buildACK(req); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Second client: no free host.
	req2 := mustDiscover(2)
	offer2, err := s.buildOffer(req2)
	if err != nil {
		t.Fatalf("second offer returned err: %v", err)
	}
	if offer2 != nil {
		t.Fatalf("expected nil offer (pool exhausted), got %v", offer2.YourIPAddr)
	}
}

func TestGatewayNeverAllocated(t *testing.T) {
	s := newTestServer(t, "10.42.0.0/24", "10.42.0.1")
	for i := 0; i < 50; i++ { // try more than pool size is unlikely; just sanity
		// Use a unique chaddr so we don't keep getting the same allocation.
		req, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, byte(i)})
		offer, err := s.buildOffer(req)
		if err != nil {
			t.Fatalf("offer %d: %v", i, err)
		}
		if offer == nil {
			break // pool exhausted
		}
		if offer.YourIPAddr.Equal(net.ParseIP("10.42.0.1")) {
			t.Fatalf("offered the gateway address")
		}
		if _, err := s.buildACK(req); err != nil {
			t.Fatalf("ack %d: %v", i, err)
		}
	}
}

// TestFullDORAFlow exercises DISCOVER→OFFER→REQUEST→ACK against the in-process
// server and verifies the assigned IP, server-id, subnet mask, and (when
// OfferDefaultRoute is set) the router option on the ACK.
func TestFullDORAFlow(t *testing.T) {
	_, pool, _ := net.ParseCIDR("10.42.0.0/24")
	gw := net.ParseIP("10.42.0.1")
	srv, err := New(Config{
		Pool:              pool,
		Gateway:           gw,
		LeaseTime:         time.Hour,
		OfferDefaultRoute: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 0x07}

	// DISCOVER
	disc, _ := dhcpv4.NewDiscovery(mac)
	offer, err := srv.buildReply(disc)
	if err != nil || offer == nil {
		t.Fatalf("offer: %+v %v", offer, err)
	}
	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("offer type: %s", offer.MessageType())
	}
	ip := offer.YourIPAddr
	if ip.Equal(gw) || !pool.Contains(ip) {
		t.Fatalf("offer IP %s out of pool / equal to gateway", ip)
	}
	if !offer.ServerIdentifier().Equal(gw) {
		t.Fatalf("offer server-id: %s", offer.ServerIdentifier())
	}

	// REQUEST (sharing the same xid/mac, requesting the offered IP explicitly)
	req, err := dhcpv4.NewRequestFromOffer(offer,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(ip)),
	)
	if err != nil {
		t.Fatal(err)
	}
	// NewRequestFromOffer uses the original chaddr in its ClientHWAddr.
	ack, err := srv.buildReply(req)
	if err != nil || ack == nil {
		t.Fatalf("ack: %+v %v", ack, err)
	}
	t.Logf("chid=%v want=%v current=%v acktype=%s msg=%s",
		req.ClientHWAddr, req.RequestedIPAddress(), srv.byChid[req.ClientHWAddr.String()], ack.MessageType(), ack.Message())
	if ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("ack type: %s", ack.MessageType())
	}
	if !ack.YourIPAddr.Equal(ip) {
		t.Fatalf("ack IP %s != offer IP %s", ack.YourIPAddr, ip)
	}
	// Subnet mask option carried into the ACK.
	if ack.SubnetMask().String() != pool.Mask.String() {
		t.Fatalf("ack subnet mask: %s, want %s", ack.SubnetMask(), pool.Mask)
	}
	// Default-route: the ACK must carry a router option pointing at the gateway.
	routers := ack.Router()
	if len(routers) != 1 || !routers[0].Equal(gw) {
		t.Fatalf("ack router option: %+v, want [%s]", routers, gw)
	}

	// After ACK the IP is committed: another DISCOVER from a new client must
	// never get the same IP.
	disc2, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 0x08})
	offer2, _ := srv.buildReply(disc2)
	if offer2 == nil {
		t.Fatal("second offer nil")
	}
	if offer2.YourIPAddr.Equal(ip) {
		t.Fatalf("offered an already-leased IP %s", ip)
	}
}

// TestReleaseReallocates verifies RELEASE frees the IP and a new client can
// immediately obtain it. The test drives a real DISCOVER→OFFER→REQUEST→ACK
// exchange (allocFor commits the offer-time reservation; buildACK commits the
// final lease) so the pool is genuinely exhausted before RELEASE.
func TestReleaseReallocates(t *testing.T) {
	s := newTestServer(t, "10.0.0.0/30", "10.0.0.1") // 1 usable host: .2

	// Client 1: DISCOVER → OFFER → REQUEST → ACK
	disc, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 0x01})
	offer, err := s.buildOffer(disc)
	if err != nil || offer == nil {
		t.Fatalf("offer1: %+v %v", offer, err)
	}
	offered := offer.YourIPAddr
	if !offered.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("expected 10.0.0.2, got %s", offered)
	}
	req, _ := dhcpv4.NewRequestFromOffer(offer)
	ack, err := s.buildACK(req)
	if err != nil || ack == nil {
		t.Fatalf("ack1: %+v %v", ack, err)
	}
	if ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("first ack type: %s", ack.MessageType())
	}

	// Pool is now exhausted — client 2 gets no offer.
	disc2, _ := dhcpv4.NewDiscovery(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 0x02})
	if o, _ := s.buildOffer(disc2); o != nil {
		t.Fatalf("expected nil offer (pool exhausted), got %v", o.YourIPAddr)
	}

	// Client 1 releases its lease.
	rel, err := dhcpv4.NewReleaseFromACK(ack)
	if err != nil {
		t.Fatal(err)
	}
	s.handle(nil, nil, rel) // release just clears server state

	// Now client 2 can obtain the released IP.
	offer2, _ := s.buildOffer(disc2)
	if offer2 == nil {
		t.Fatal("expected an offer after release")
	}
	if !offer2.YourIPAddr.Equal(offered) {
		t.Fatalf("post-release offer: %s, want %s", offer2.YourIPAddr, offered)
	}
}
