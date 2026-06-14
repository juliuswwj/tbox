package config

import "testing"

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
