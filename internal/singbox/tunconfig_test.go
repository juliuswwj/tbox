package singbox

import (
	"context"
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
