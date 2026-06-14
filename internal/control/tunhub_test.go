package control

import (
	"io"
	"log"
	"net"
	"testing"

	"github.com/juliuswwj/tbox/internal/l2"
)

func newTestHub(t *testing.T, poolCIDR, gateway string) *TunHub {
	t.Helper()
	_, pool, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		t.Fatal(err)
	}
	sw := l2.New(nil, log.New(io.Discard, "", 0))
	return NewTunHub(sw, gateway, pool, 1448, true, "203.0.113.5", log.New(io.Discard, "", 0))
}

func TestTunHubAssignStableAndDistinct(t *testing.T) {
	hub := newTestHub(t, "10.42.0.0/24", "10.42.0.1")

	a := hub.Assign("clientA")
	if a == nil {
		t.Fatal("clientA got nil assignment")
	}
	// Same client always gets the same address.
	if again := hub.Assign("clientA"); again.IPv4CIDR != a.IPv4CIDR {
		t.Fatalf("unstable assignment: %q then %q", a.IPv4CIDR, again.IPv4CIDR)
	}
	// A different client gets a different address.
	b := hub.Assign("clientB")
	if b.IPv4CIDR == a.IPv4CIDR {
		t.Fatalf("two clients share %q", a.IPv4CIDR)
	}
	// The gateway address is never handed out.
	for _, asg := range []*TunAssignment{a, b} {
		if asg.IPv4CIDR == "10.42.0.1/24" {
			t.Fatalf("assigned the gateway address: %q", asg.IPv4CIDR)
		}
	}
	// Assignment fields propagate.
	if a.Gateway != "10.42.0.1" || a.MTU != 1448 || a.SubnetRoute != "10.42.0.0/24" ||
		!a.DefaultRoute || a.ServerRealIP != "203.0.113.5" {
		t.Fatalf("unexpected assignment fields: %+v", a)
	}
}

func TestTunHubPoolExhaustion(t *testing.T) {
	// 10.0.0.0/30: network .0, gateway .1, one usable host .2, broadcast .3.
	hub := newTestHub(t, "10.0.0.0/30", "10.0.0.1")
	if a := hub.Assign("c1"); a == nil || a.IPv4CIDR != "10.0.0.2/30" {
		t.Fatalf("c1 = %+v, want 10.0.0.2/30", a)
	}
	if a := hub.Assign("c2"); a != nil {
		t.Fatalf("c2 = %+v, want nil (pool exhausted)", a)
	}
}
