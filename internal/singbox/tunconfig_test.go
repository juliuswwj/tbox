package singbox

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func TestTunClientConfigParses(t *testing.T) {
	raw, err := TunClientConfigJSON(TunClientParams{
		ServerAddr: "vps.example.com", ServerPort: 443,
		UUID:      "11111111-1111-4111-8111-111111111111",
		SNI:       "www.microsoft.com",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID:   "0123abcd", IPv6: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("config: %s", raw)
	ctx := include.Context(context.Background())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
		t.Fatalf("sing-box rejected tun config: %v", err)
	}
}

func TestTunClientConfigIPv4Only(t *testing.T) {
	raw, err := TunClientConfigJSON(TunClientParams{
		ServerAddr: "vps.example.com", ServerPort: 443,
		UUID:      "11111111-1111-4111-8111-111111111111",
		SNI:       "www.microsoft.com",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID:   "0123abcd", IPv6: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	inbounds, _ := m["inbounds"].([]any)
	tunIn, _ := inbounds[0].(map[string]any)
	addrs, _ := tunIn["address"].([]any)
	if len(addrs) != 1 {
		t.Errorf("expected 1 address for IPv4-only, got %d", len(addrs))
	}
}

func TestTunClientConfigCustomDNS(t *testing.T) {
	raw, err := TunClientConfigJSON(TunClientParams{
		ServerAddr: "vps.example.com", ServerPort: 443,
		UUID:       "11111111-1111-4111-8111-111111111111",
		SNI:        "www.microsoft.com",
		PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID:    "0123abcd",
		DNSAddress: "1.1.1.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	dns, _ := m["dns"].(map[string]any)
	servers, _ := dns["servers"].([]any)
	remote, _ := servers[0].(map[string]any)
	if remote["server"] != "1.1.1.1" {
		t.Errorf("remote DNS server = %q, want %q", remote["server"], "1.1.1.1")
	}
}

func TestTunClientConfigCustomMTU(t *testing.T) {
	raw, err := TunClientConfigJSON(TunClientParams{
		ServerAddr: "vps.example.com", ServerPort: 443,
		UUID:      "11111111-1111-4111-8111-111111111111",
		SNI:       "www.microsoft.com",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID:   "0123abcd",
		MTU:       1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	inbounds, _ := m["inbounds"].([]any)
	tunIn, _ := inbounds[0].(map[string]any)
	mtu := tunIn["mtu"].(float64)
	if mtu != 1500 {
		t.Errorf("MTU = %v, want 1500", mtu)
	}
}

func TestTunClientConfigCustomFingerprint(t *testing.T) {
	raw, err := TunClientConfigJSON(TunClientParams{
		ServerAddr:  "vps.example.com", ServerPort: 443,
		UUID:        "11111111-1111-4111-8111-111111111111",
		SNI:         "www.microsoft.com",
		PublicKey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID:     "0123abcd",
		Fingerprint: "firefox",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	outbounds, _ := m["outbounds"].([]any)
	vless, _ := outbounds[0].(map[string]any)
	tls, _ := vless["tls"].(map[string]any)
	utls, _ := tls["utls"].(map[string]any)
	if utls["fingerprint"] != "firefox" {
		t.Errorf("fingerprint = %q, want %q", utls["fingerprint"], "firefox")
	}
}

func TestTunClientConfigRejectsMissingServerAddr(t *testing.T) {
	_, err := TunClientConfigJSON(TunClientParams{
		ServerPort: 443,
		UUID:       "11111111-1111-4111-8111-111111111111",
		PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})
	if err == nil {
		t.Error("expected error for missing server address")
	}
}

func TestTunClientConfigRejectsMissingUUID(t *testing.T) {
	_, err := TunClientConfigJSON(TunClientParams{
		ServerAddr: "vps.example.com", ServerPort: 443,
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})
	if err == nil {
		t.Error("expected error for missing UUID")
	}
}

func TestTunClientConfigRejectsMissingPublicKey(t *testing.T) {
	_, err := TunClientConfigJSON(TunClientParams{
		ServerAddr: "vps.example.com", ServerPort: 443,
		UUID: "11111111-1111-4111-8111-111111111111",
	})
	if err == nil {
		t.Error("expected error for missing public key")
	}
}

func TestTunAddress(t *testing.T) {
	a := TunAddress()
	if a == "" {
		t.Error("TunAddress returned empty string")
	}
}

func TestTunClientConfigLogLevel(t *testing.T) {
	raw, err := TunClientConfigJSON(TunClientParams{
		ServerAddr: "vps.example.com", ServerPort: 443,
		UUID:      "11111111-1111-4111-8111-111111111111",
		SNI:       "www.microsoft.com",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID:   "0123abcd",
		LogLevel:  "debug",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	logObj, _ := m["log"].(map[string]any)
	if logObj["level"] != "debug" {
		t.Errorf("log level = %q, want %q", logObj["level"], "debug")
	}
}
