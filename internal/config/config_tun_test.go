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
	}
	for name, tun := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadClient(writeTemp(t, base+tun)); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		})
	}
}
