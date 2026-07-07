//go:build with_quic

package mobile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func TestBuildConfigTuic(t *testing.T) {
	raw, err := BuildConfig(mustTuicToken(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(t.Context())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, []byte(raw)); err != nil {
		t.Fatalf("sing-box rejected TUIC config: %v", err)
	}
}

func TestBuildConfigTuicUsesTuicOutbound(t *testing.T) {
	raw, err := BuildConfig(mustTuicToken(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	outbounds, _ := m["outbounds"].([]any)
	first, _ := outbounds[0].(map[string]any)
	if got := first["type"]; got != "tuic" {
		t.Errorf("outbound type = %q, want tuic", got)
	}
	tls, _ := first["tls"].(map[string]any)
	if sni, _ := tls["server_name"].(string); sni != "tuic.example.com" {
		t.Errorf("TUIC TLS SNI = %q, want tuic.example.com", sni)
	}
}

func TestBuildConfigRealityUsesVlessOutbound(t *testing.T) {
	raw, err := BuildConfig(mustToken(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	outbounds, _ := m["outbounds"].([]any)
	first, _ := outbounds[0].(map[string]any)
	if got := first["type"]; got != "vless" {
		t.Errorf("outbound type = %q, want vless", got)
	}
}

func TestBuildConfigTuicInvalidToken(t *testing.T) {
	_, err := BuildConfig("tbox://bad", nil)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error = %v, want token error", err)
	}
}
