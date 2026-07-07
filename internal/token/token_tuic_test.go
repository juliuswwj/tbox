package token

import "testing"

func TestCarrier(t *testing.T) {
	cases := []struct {
		name string
		tok  Token
		want string
	}{
		{"legacy-no-protocol", Token{PublicKey: "pk"}, "reality"},
		{"explicit-reality", Token{Protocol: "reality", PublicKey: "pk"}, "reality"},
		{"explicit-tuic", Token{Protocol: "tuic", TuicPassword: "pw", PublicKey: "pk"}, "tuic"},
		{"tuic-by-creds-only", Token{TuicPassword: "pw"}, "tuic"}, // protocol empty, no reality key
		{"reality-wins-when-explicit", Token{Protocol: "reality", TuicPassword: "pw", PublicKey: "pk"}, "reality"},
	}
	for _, c := range cases {
		if got := c.tok.Carrier(); got != c.want {
			t.Errorf("%s: Carrier() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestEncodeDecodeTUICRoundTrip(t *testing.T) {
	in := Token{
		ServerAddr:     "vps.example.com",
		ServerPort:     443,
		UUID:           "11111111-1111-4111-8111-111111111111",
		ControlAddr:    "127.0.0.1:8443",
		TuicPort:       443,
		TuicPassword:   "hunter2",
		TuicSNI:        "tuic.example.com",
		TuicCongestion: "bbr",
		Protocol:       "tuic",
	}
	s, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
	if out.Carrier() != "tuic" {
		t.Fatalf("Carrier() = %q, want tuic", out.Carrier())
	}
}

// TestDecodeLegacyRealityToken ensures tokens minted before TUIC existed (no
// protocol / tuic fields) still decode and report the reality carrier.
func TestDecodeLegacyRealityToken(t *testing.T) {
	in := Token{
		ServerAddr: "vps.example.com", ServerPort: 443,
		UUID: "u", PublicKey: "pk", ShortID: "s", SNI: "n", ControlAddr: "c",
	}
	s, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(s)
	if err != nil {
		t.Fatalf("legacy reality token should decode: %v", err)
	}
	if out.Carrier() != "reality" {
		t.Fatalf("Carrier() = %q, want reality", out.Carrier())
	}
}

func TestDecodeRejectsTUICMissingPassword(t *testing.T) {
	in := Token{ServerAddr: "v", ServerPort: 443, UUID: "u", Protocol: "tuic"}
	s, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(s); err == nil {
		t.Fatal("expected error for tuic token missing tuic_password")
	}
}
