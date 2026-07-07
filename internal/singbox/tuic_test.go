//go:build with_quic

package singbox

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

const tuicUUID = "11111111-1111-4111-8111-111111111111"

// mustParseSingBox ensures sing-box's own JSON schema accepts the config. This
// file is built only with the with_quic tag, under which the TUIC protocol is
// registered; without the tag TUIC configs would be rejected by the stub, so
// the whole file is excluded to keep `go test` (no tags) green.
func mustParseSingBox(t *testing.T, raw []byte) {
	t.Helper()
	ctx := include.Context(context.Background())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
		t.Fatalf("sing-box rejected config: %v\n%s", err, raw)
	}
}

func TestClientConfigJSONTuicParses(t *testing.T) {
	raw, err := ClientConfigJSON(ClientParams{
		Carrier:      "tuic",
		SocksListen:  "127.0.0.1:1080",
		ServerAddr:   "vps.example.com",
		ServerPort:   443,
		UUID:         tuicUUID,
		TuicPassword: "hunter2",
		TuicSNI:      "tuic.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustParseSingBox(t, raw)
}

func TestTunClientConfigJSONTuicParses(t *testing.T) {
	raw, err := TunClientConfigJSON(TunClientParams{
		Carrier:      "tuic",
		ServerAddr:   "vps.example.com",
		ServerPort:   443,
		UUID:         tuicUUID,
		TuicPassword: "hunter2",
		TuicSNI:      "tuic.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustParseSingBox(t, raw)
}

func TestServerConfigJSONWithTuicParses(t *testing.T) {
	raw, err := ServerConfigJSON(ServerParams{
		ListenPort: 8444,
		MimicHost:  "www.microsoft.com",
		PrivateKey: genKey(t),
		ShortID:    "0123456789abcdef",
		Users:      []User{{Name: "a", UUID: tuicUUID}},
		Tuic: &TuicServerParams{
			ListenPort: 8445,
			SNI:        "tuic.example.com",
			CertPath:   "/tmp/nonexistent.crt", // not read at parse time
			KeyPath:    "/tmp/nonexistent.key",
			Users:      []User{{Name: "a", UUID: tuicUUID, Password: "hunter2"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustParseSingBox(t, raw)
}
