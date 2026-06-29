package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleConfigsParse(t *testing.T) {
	if _, err := LoadServer("../../configs/server.example.yaml"); err != nil {
		t.Fatalf("server.example.yaml: %v", err)
	}
	if _, err := LoadClient("../../configs/client.example.yaml"); err != nil {
		t.Fatalf("client.example.yaml: %v", err)
	}
}

func TestClientConfigDefaultsAndURLs(t *testing.T) {
	c, err := LoadClient("../../configs/client.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.SocksListen == "" || c.AdminListen == "" {
		t.Fatalf("expected defaults to be populated: %+v", c)
	}
	modes := map[string]bool{}
	for _, p := range c.Publish {
		mode, host, _, err := p.Parse()
		if err != nil {
			t.Fatalf("parse %q: %v", p.URL, err)
		}
		if host == "" {
			t.Fatalf("%q: empty host", p.URL)
		}
		modes[mode] = true
	}
	for _, want := range []string{"http", "ws", "tcp"} {
		if !modes[want] {
			t.Fatalf("expected example to exercise %q mode; got %v", want, modes)
		}
	}
}

func TestServerPublish(t *testing.T) {
	const base = `
listen: ":443"
server_addr: "vps.example.com"
mimic: "www.microsoft.com:443"
reality_private_key: "k"
short_id: "s"
clients:
  - name: "c1"
    uuid: "u1"
`
	write := func(t *testing.T, extra string) string {
		t.Helper()
		dir := t.TempDir()
		p := filepath.Join(dir, "server.yaml")
		if err := os.WriteFile(p, []byte(base+extra), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("accepts https/wss/tcp", func(t *testing.T) {
		c, err := LoadServer(write(t, `
publish:
  - url: "https://dc.example.com/"
    upstream: "127.0.0.1:3000"
  - url: "wss://dc.example.com/ws"
    upstream: "127.0.0.1:22"
  - url: "tcp://ssh.dc.example.com"
    upstream: "127.0.0.1:22"
`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(c.Publish) != 3 {
			t.Fatalf("want 3 publish entries, got %d", len(c.Publish))
		}
	})

	t.Run("rejects socks5", func(t *testing.T) {
		_, err := LoadServer(write(t, `
publish:
  - url: "socks5://proxy.dc.example.com"
`))
		if err == nil || !strings.Contains(err.Error(), "socks5") {
			t.Fatalf("want socks5 rejection, got %v", err)
		}
	})

	t.Run("requires upstream", func(t *testing.T) {
		_, err := LoadServer(write(t, `
publish:
  - url: "https://dc.example.com/"
`))
		if err == nil || !strings.Contains(err.Error(), "upstream") {
			t.Fatalf("want upstream-required error, got %v", err)
		}
	})
}

func TestPublishParse(t *testing.T) {
	cases := []struct {
		url, mode, host, path string
		wantErr               bool
	}{
		{url: "https://dc.example.com/", mode: "http", host: "dc.example.com", path: "/"},
		{url: "https://app.dc.example.com/location/", mode: "http", host: "app.dc.example.com", path: "/location/"},
		{url: "wss://app.dc.example.com/tunnel/ssh", mode: "ws", host: "app.dc.example.com", path: "/tunnel/ssh"},
		{url: "tcp://ssh.dc.example.com", mode: "tcp", host: "ssh.dc.example.com", path: ""},
		{url: "tcp://ssh.dc.example.com/x", wantErr: true},
		{url: "ftp://x.example.com", wantErr: true},
	}
	for _, tc := range cases {
		mode, host, path, err := Publish{URL: tc.url}.Parse()
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q: expected error", tc.url)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.url, err)
		}
		if mode != tc.mode || host != tc.host || path != tc.path {
			t.Fatalf("%q: got (%s,%s,%s) want (%s,%s,%s)", tc.url, mode, host, path, tc.mode, tc.host, tc.path)
		}
	}
}
