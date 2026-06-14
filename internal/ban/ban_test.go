package ban

import (
	"net/netip"
	"testing"
	"time"
)

func testBanner() (*Banner, *time.Time) {
	clock := time.Unix(1_700_000_000, 0)
	b := New(Config{
		Methods:         []string{"POST"},
		Statuses:        []int{401, 403},
		Window:          10 * time.Minute,
		Threshold:       5,
		BanDuration:     time.Hour,
		SubnetThreshold: 2,
	})
	b.now = func() time.Time { return clock }
	return b, &clock
}

func TestCountsRule(t *testing.T) {
	b, _ := testBanner()
	cases := []struct {
		method, path string
		status       int
		want         bool
	}{
		{"POST", "/api/login", 401, true},
		{"POST", "/api/login", 403, true},
		{"GET", "/api/me", 401, false}, // benign unauthenticated GET
		{"POST", "/api/login", 200, false},
		{"POST", "/api/login", 500, false},
	}
	for _, c := range cases {
		if got := b.Counts(c.method, c.path, c.status); got != c.want {
			t.Errorf("Counts(%s %s %d) = %v, want %v", c.method, c.path, c.status, got, c.want)
		}
	}
}

func TestPerIPBanAfterThreshold(t *testing.T) {
	b, _ := testBanner()
	ip := netip.MustParseAddr("198.51.100.7")
	for i := 0; i < 4; i++ {
		if banned, _ := b.Fail(ip); banned {
			t.Fatalf("banned too early at attempt %d", i+1)
		}
		if b.Blocked(ip) {
			t.Fatalf("blocked too early at attempt %d", i+1)
		}
	}
	if banned, _ := b.Fail(ip); !banned { // 5th
		t.Fatal("expected ban on 5th failure")
	}
	if !b.Blocked(ip) {
		t.Fatal("ip should be blocked after threshold")
	}
}

func TestBanExpires(t *testing.T) {
	b, clock := testBanner()
	ip := netip.MustParseAddr("198.51.100.7")
	for i := 0; i < 5; i++ {
		b.Fail(ip)
	}
	if !b.Blocked(ip) {
		t.Fatal("should be blocked")
	}
	*clock = clock.Add(time.Hour + time.Second)
	if b.Blocked(ip) {
		t.Fatal("ban should have expired after 1h")
	}
}

func TestWindowSlidingResetsCount(t *testing.T) {
	b, clock := testBanner()
	ip := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 4; i++ {
		b.Fail(ip)
	}
	// Advance beyond the window so the 4 prior failures age out.
	*clock = clock.Add(11 * time.Minute)
	if banned, _ := b.Fail(ip); banned {
		t.Fatal("stale failures should have aged out of the window")
	}
}

func TestSubnetBanAfterTwoIPs(t *testing.T) {
	b, _ := testBanner()
	ipA := netip.MustParseAddr("203.0.113.10")
	ipB := netip.MustParseAddr("203.0.113.20")
	other := netip.MustParseAddr("203.0.114.5") // different /24

	for i := 0; i < 5; i++ {
		b.Fail(ipA)
	}
	// First banned IP in the /24: no subnet ban yet.
	if b.Blocked(other) {
		t.Fatal("unrelated /24 should not be blocked")
	}
	var subnet string
	for i := 0; i < 5; i++ {
		_, s := b.Fail(ipB)
		if s != "" {
			subnet = s
		}
	}
	if subnet != "203.0.113.0/24" {
		t.Fatalf("expected /24 ban, got %q", subnet)
	}
	// A third, previously-unseen IP in the same /24 is now blocked by the
	// subnet ban without any failures of its own.
	fresh := netip.MustParseAddr("203.0.113.200")
	if !b.Blocked(fresh) {
		t.Fatal("fresh IP in banned /24 should be blocked")
	}
	if b.Blocked(other) {
		t.Fatal("IP outside the banned /24 must not be blocked")
	}
}

func TestExemptNeverBanned(t *testing.T) {
	b, _ := testBanner()
	b.cfg.Exempt = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	ip := netip.MustParseAddr("203.0.113.7")
	for i := 0; i < 20; i++ {
		if banned, _ := b.Fail(ip); banned {
			t.Fatal("exempt IP must never be banned")
		}
	}
	if b.Blocked(ip) {
		t.Fatal("exempt IP must never be blocked")
	}
}
