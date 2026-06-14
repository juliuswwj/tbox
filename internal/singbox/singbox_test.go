package singbox

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func genKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.Bytes())
}

// TestClientConfigStartsAndStops validates the whole embedding path: build a
// client-style config (mixed inbound + direct outbound, final -> direct so no
// real server is needed), start the box, and stop it.
func TestClientConfigStartsAndStops(t *testing.T) {
	cfg := config{
		Log: &logOpts{Level: "warn"},
		Inbounds: []inbound{{
			Type:       "mixed",
			Tag:        "socks-in",
			Listen:     "127.0.0.1",
			ListenPort: 0, // OS-assigned free port
		}},
		Outbounds: []outbound{{Type: "direct", Tag: "direct"}},
		Route:     &routeOpts{Final: "direct"},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	inst, err := New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := inst.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestServerConfigJSONShape(t *testing.T) {
	raw, err := ServerConfigJSON(ServerParams{
		ListenPort: 8444,
		MimicHost:  "www.microsoft.com",
		PrivateKey: genKey(t),
		ShortID:    "0123456789abcdef",
		Users:      []User{{Name: "a", UUID: "bf000d23-0752-40b4-affe-68f7707a9661"}},
	})
	if err != nil {
		t.Fatalf("ServerConfigJSON: %v", err)
	}
	// Must round-trip through sing-box's own parser.
	inst, err := New(raw)
	if err != nil {
		t.Fatalf("server config rejected by sing-box: %v\n%s", err, raw)
	}
	_ = inst
}
