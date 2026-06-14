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

func TestClientConfigDefaultsAndValidation(t *testing.T) {
	c, err := LoadClient("../../configs/client.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.SocksListen == "" || c.AdminListen == "" {
		t.Fatalf("expected defaults to be populated: %+v", c)
	}
	// http publish must have routes; ws publish must have upstream.
	for _, p := range c.Publish {
		switch p.Mode {
		case "http":
			if len(p.Routes) == 0 {
				t.Fatalf("%s: http mode without routes", p.Domain)
			}
		case "ws":
			if p.Upstream == "" || p.Path == "" {
				t.Fatalf("%s: ws mode missing upstream/path", p.Domain)
			}
		}
	}
}
