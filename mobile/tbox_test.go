package mobile

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"github.com/juliuswwj/tbox/internal/token"
)

func mustToken(t *testing.T) string {
	t.Helper()
	s, err := token.Encode(token.Token{
		ServerAddr:  "vps.example.com",
		ServerPort:  443,
		UUID:        "11111111-1111-4111-8111-111111111111",
		PublicKey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID:     "0123abcd",
		SNI:         "www.microsoft.com",
		ControlAddr: "127.0.0.1:8443",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseTokenValid(t *testing.T) {
	info, err := ParseToken(mustToken(t))
	if err != nil {
		t.Fatal(err)
	}
	if info.ServerAddr != "vps.example.com" {
		t.Errorf("ServerAddr = %q, want %q", info.ServerAddr, "vps.example.com")
	}
	if info.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want 443", info.ServerPort)
	}
	if info.SNI != "www.microsoft.com" {
		t.Errorf("SNI = %q, want %q", info.SNI, "www.microsoft.com")
	}
	if info.UUID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("UUID = %q, want %q", info.UUID, "11111111-1111-4111-8111-111111111111")
	}
}

func TestParseTokenInvalid(t *testing.T) {
	inputs := []string{
		"",
		"tbox://",
		"tbox://not-base64!!!",
		"tbox://" + "aW52YWxpZCBqc29u", // base64url of "invalid json"
	}
	for _, in := range inputs {
		if _, err := ParseToken(in); err == nil {
			t.Errorf("ParseToken(%q) = nil error; want error", in)
		}
	}
}

func TestTokenSummary(t *testing.T) {
	s, err := TokenSummary(mustToken(t))
	if err != nil {
		t.Fatal(err)
	}
	want := "vps.example.com:443 (SNI www.microsoft.com)"
	if s != want {
		t.Errorf("TokenSummary = %q, want %q", s, want)
	}
}

func TestTokenSummaryInvalid(t *testing.T) {
	if _, err := TokenSummary("tbox://bad"); err == nil {
		t.Error("TokenSummary(bad) = nil error; want error")
	}
}

func TestDefaultTunAddress(t *testing.T) {
	a := DefaultTunAddress()
	if a == "" {
		t.Error("DefaultTunAddress returned empty string")
	}
}

func TestBuildConfigValid(t *testing.T) {
	raw, err := BuildConfig(mustToken(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(t.Context())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, []byte(raw)); err != nil {
		t.Fatalf("sing-box rejected config: %v", err)
	}
}

func TestBuildConfigWithOptions(t *testing.T) {
	raw, err := BuildConfig(mustToken(t), &Options{
		LogLevel: "warn",
		MTU:      1500,
		IPv6:     false,
		DNS:      "1.1.1.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(t.Context())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, []byte(raw)); err != nil {
		t.Fatalf("sing-box rejected config: %v", err)
	}
}

func TestBuildConfigOptionsNil(t *testing.T) {
	raw, err := BuildConfig(mustToken(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	// Log level defaults to "info" when nil opts is passed.
	logObj, ok := m["log"].(map[string]any)
	if !ok {
		t.Fatal("config missing log section")
	}
	if logObj["level"] != "info" {
		t.Errorf("log level = %q, want %q", logObj["level"], "info")
	}
}

func TestBuildConfigInvalidToken(t *testing.T) {
	if _, err := BuildConfig("not-a-token", nil); err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestServiceCloseNil(t *testing.T) {
	var s *Service
	if err := s.Close(); err != nil {
		t.Errorf("Close on nil Service: %v", err)
	}

	s = &Service{box: nil}
	if err := s.Close(); err != nil {
		t.Errorf("Close on Service with nil box: %v", err)
	}
}

func mustTuicToken(t *testing.T) string {
	t.Helper()
	s, err := token.Encode(token.Token{
		ServerAddr:   "vps.example.com",
		ServerPort:   443,
		UUID:         "11111111-1111-4111-8111-111111111111",
		SNI:          "www.microsoft.com",
		ControlAddr:  "127.0.0.1:8443",
		Protocol:     "tuic",
		TuicPort:     443,
		TuicPassword: "hunter2",
		TuicSNI:      "tuic.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseTokenTuic(t *testing.T) {
	info, err := ParseToken(mustTuicToken(t))
	if err != nil {
		t.Fatal(err)
	}
	if info.Carrier != "tuic" {
		t.Errorf("Carrier = %q, want %q", info.Carrier, "tuic")
	}
	if info.ServerAddr != "vps.example.com" {
		t.Errorf("ServerAddr = %q", info.ServerAddr)
	}
}

func TestTokenSummaryTuic(t *testing.T) {
	s, err := TokenSummary(mustTuicToken(t))
	if err != nil {
		t.Fatal(err)
	}
	want := "vps.example.com:443 (SNI www.microsoft.com)"
	if s != want {
		t.Errorf("TokenSummary = %q, want %q", s, want)
	}
}

func TestStartNilPlatform(t *testing.T) {
	_, err := Start(mustToken(t), nil, nil)
	if err == nil {
		t.Error("Start with nil platform should fail")
	}
}
