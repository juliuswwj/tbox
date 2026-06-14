package destallow

import "testing"

func TestAllowed(t *testing.T) {
	set, err := New([]string{
		"example.com",
		"api.example.com:443",
		"*.internal.test",
		"10.0.0.0/8",
		"[::1]:22",
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		port uint16
		want bool
	}{
		{"example.com", 80, true},  // exact host, any port
		{"example.com", 443, true}, // exact host, any port
		{"api.example.com", 443, true},
		{"api.example.com", 80, false}, // wrong port
		{"db.internal.test", 5432, true},
		{"deep.db.internal.test", 5432, true},
		{"internal.test", 5432, false}, // wildcard needs a label
		{"10.1.2.3", 22, true},         // in CIDR
		{"11.0.0.1", 22, false},        // not in CIDR
		{"other.com", 80, false},
		{"::1", 22, true},
		{"::1", 23, false},
	}
	for _, c := range cases {
		if got := set.Allowed(c.host, c.port); got != c.want {
			t.Errorf("Allowed(%q,%d)=%v want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestEmptyDeniesAll(t *testing.T) {
	set, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if set.Allowed("example.com", 443) {
		t.Fatal("empty allow list must deny all")
	}
}

func TestStar(t *testing.T) {
	set, _ := New([]string{"*:443"})
	if !set.Allowed("anything.com", 443) {
		t.Fatal("*:443 should allow any host on 443")
	}
	if set.Allowed("anything.com", 80) {
		t.Fatal("*:443 should not allow port 80")
	}
}

func TestInvalid(t *testing.T) {
	if _, err := New([]string{"10.0.0.0/999"}); err == nil {
		t.Fatal("expected invalid CIDR error")
	}
	if _, err := New([]string{"host:0"}); err == nil {
		t.Fatal("expected invalid port error")
	}
}
