package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const serverBase = `mimic: "www.microsoft.com:443"
reality_private_key: "k"
short_id: "abcd"
clients:
  - name: c1
    uuid: u1
`

func TestServerTunValidation(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		c, err := LoadServer(writeTemp(t, serverBase+`tun:
  enable: true
  pool_v4: "10.42.0.0/24"
`))
		if err != nil {
			t.Fatal(err)
		}
		if c.Tun.Gateway != "10.42.0.1" {
			t.Fatalf("gateway default = %q, want 10.42.0.1", c.Tun.Gateway)
		}
		if c.Tun.MTU != 1448 {
			t.Fatalf("mtu default = %d, want 1448", c.Tun.MTU)
		}
		if c.Tun.TapName != "tbox0" {
			t.Fatalf("tap_name default = %q, want tbox0", c.Tun.TapName)
		}
	})

	bad := map[string]string{
		"missing pool": `tun:
  enable: true
`,
		"invalid pool": `tun:
  enable: true
  pool_v4: "not-a-cidr"
`,
		"nat without wan": `tun:
  enable: true
  pool_v4: "10.42.0.0/24"
  enable_nat: true
`,
		"invalid ipv6_prefix": `tun:
  enable: true
  pool_v4: "10.42.0.0/24"
  ipv6_prefix: "zzz"
`,
		"invalid gateway": `tun:
  enable: true
  pool_v4: "10.42.0.0/24"
  gateway: "nope"
`,
	}
	for name, tun := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadServer(writeTemp(t, serverBase+tun)); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		})
	}

	t.Run("nat with wan ok", func(t *testing.T) {
		if _, err := LoadServer(writeTemp(t, serverBase+`tun:
  enable: true
  pool_v4: "10.42.0.0/24"
  enable_nat: true
  wan_interface: "eth0"
`)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestClientTunValidation(t *testing.T) {
	const base = "token: \"tbox://x\"\n"

	t.Run("udp only", func(t *testing.T) {
		c, err := LoadClient(writeTemp(t, base+`tun:
  enable: true
  udp:
    listen: "127.0.0.1:3390"
`))
		if err != nil {
			t.Fatal(err)
		}
		if c.Tun.MTU != 1448 {
			t.Fatalf("mtu default = %d, want 1448", c.Tun.MTU)
		}
	})

	t.Run("tap defaults name", func(t *testing.T) {
		c, err := LoadClient(writeTemp(t, base+`tun:
  enable: true
  tap:
    ipv4_cidr: "10.42.0.9/24"
`))
		if err != nil {
			t.Fatal(err)
		}
		if c.Tun.TAP.Name != "tbox0" {
			t.Fatalf("tap name default = %q, want tbox0", c.Tun.TAP.Name)
		}
	})

	t.Run("dhcp defaults true when ipv4_cidr unset", func(t *testing.T) {
		c, err := LoadClient(writeTemp(t, base+`tun:
  enable: true
  tap: {}
`))
		if err != nil {
			t.Fatal(err)
		}
		if c.Tun.TAP.DHCP == nil || !*c.Tun.TAP.DHCP {
			t.Fatalf("dhcp default = %+v, want true", c.Tun.TAP.DHCP)
		}
	})

	t.Run("dhcp explicit false respected", func(t *testing.T) {
		c, err := LoadClient(writeTemp(t, base+`tun:
  enable: true
  tap:
    dhcp: false
`))
		if err != nil {
			t.Fatal(err)
		}
		if c.Tun.TAP.DHCP == nil || *c.Tun.TAP.DHCP {
			t.Fatalf("dhcp = %+v, want false", c.Tun.TAP.DHCP)
		}
	})

	t.Run("dhcp ignored when ipv4_cidr set", func(t *testing.T) {
		// A static IPv4 takes precedence; DHCP remains whatever the user set
		// (or its default) but the client never sends a Discover when TAPv4
		// is non-empty. We only verify the static value parses.
		c, err := LoadClient(writeTemp(t, base+`tun:
  enable: true
  tap:
    ipv4_cidr: "10.42.0.9/24"
`))
		if err != nil {
			t.Fatal(err)
		}
		if c.Tun.TAP.IPv4CIDR != "10.42.0.9/24" {
			t.Fatalf("ipv4_cidr = %q", c.Tun.TAP.IPv4CIDR)
		}
	})

	t.Run("bridge with members and routes", func(t *testing.T) {
		if _, err := LoadClient(writeTemp(t, base+`tun:
  enable: true
  tap:
    bridge: "br0"
    bridge_members: ["eth1"]
    ipv4_cidr: "10.42.0.9/24"
    routes:
      - "192.168.9.0/24"
      - "10.9.0.0/16 via 10.42.0.1"
`)); err != nil {
			t.Fatal(err)
		}
	})

	bad := map[string]string{
		"enable without endpoint": `tun:
  enable: true
`,
		"udp without listen": `tun:
  enable: true
  udp: {}
`,
		"tap invalid cidr": `tun:
  enable: true
  tap:
    ipv4_cidr: "999.0.0.0/8"
`,
		"bridge_members without bridge": `tun:
  enable: true
  tap:
    ipv4_cidr: "10.42.0.9/24"
    bridge_members: ["eth1"]
`,
		"invalid route": `tun:
  enable: true
  tap:
    ipv4_cidr: "10.42.0.9/24"
    routes: ["not-a-cidr"]
`,
		"invalid route gateway": `tun:
  enable: true
  tap:
    ipv4_cidr: "10.42.0.9/24"
    routes: ["10.0.0.0/8 via nope"]
`,
	}
	for name, tun := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadClient(writeTemp(t, base+tun)); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		})
	}
}

func TestParseTunRoute(t *testing.T) {
	cases := []struct {
		in      string
		dst, gw string
		wantErr bool
	}{
		{in: "192.168.9.0/24", dst: "192.168.9.0/24"},
		{in: "10.9.0.0/16 via 10.42.0.1", dst: "10.9.0.0/16", gw: "10.42.0.1"},
		{in: "10.0.0.0/8 gw 1.2.3.4", wantErr: true},
		{in: "bad", wantErr: true},
		{in: "10.0.0.0/8 via bad", wantErr: true},
	}
	for _, c := range cases {
		dst, gw, err := ParseTunRoute(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseTunRoute(%q): expected error", c.in)
			}
			continue
		}
		if err != nil || dst != c.dst || gw != c.gw {
			t.Errorf("ParseTunRoute(%q) = (%q,%q,%v), want (%q,%q,nil)", c.in, dst, gw, err, c.dst, c.gw)
		}
	}
}
