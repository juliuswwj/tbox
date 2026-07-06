package token

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := Token{
		ServerAddr:  "vps.example.com",
		ServerPort:  443,
		UUID:        "a4a34e9a-a2d3-4852-9730-0f81cd1d0027",
		PublicKey:   "qRtTOoEUUBoDRVCsMdNuASrUnybf6yD9XaeuqIWjVlw",
		ShortID:     "272010f7",
		SNI:         "www.microsoft.com",
		ControlAddr: "127.0.0.1:8443",
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
}

func TestEncodeDecodeWithFlow(t *testing.T) {
	in := Token{
		ServerAddr:  "vps.example.com",
		ServerPort:  443,
		UUID:        "a4a34e9a-a2d3-4852-9730-0f81cd1d0027",
		PublicKey:   "qRtTOoEUUBoDRVCsMdNuASrUnybf6yD9XaeuqIWjVlw",
		ShortID:     "272010f7",
		SNI:         "www.microsoft.com",
		ControlAddr: "127.0.0.1:8443",
		Flow:        "xtls-rprx-vision",
	}
	s, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if out.Flow != in.Flow {
		t.Fatalf("Flow = %q, want %q", out.Flow, in.Flow)
	}
}

func TestDecodeWithoutScheme(t *testing.T) {
	raw, err := json.Marshal(Token{
		ServerAddr:  "vps.example.com",
		ServerPort:  443,
		UUID:        "a4a34e9a-a2d3-4852-9730-0f81cd1d0027",
		PublicKey:   "qRtTOoEUUBoDRVCsMdNuASrUnybf6yD9XaeuqIWjVlw",
		ShortID:     "272010f7",
		SNI:         "www.microsoft.com",
		ControlAddr: "127.0.0.1:8443",
	})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	out, err := Decode(b64)
	if err != nil {
		t.Fatalf("Decode without scheme prefix: %v", err)
	}
	if out.ServerAddr != "vps.example.com" {
		t.Errorf("ServerAddr = %q", out.ServerAddr)
	}
}

func TestDecodeRejectsInvalidBase64(t *testing.T) {
	if _, err := Decode("tbox://!!!!not-base64"); err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecodeRejectsInvalidJSON(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	if _, err := Decode("tbox://" + b64); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDecodeRejectsIncomplete(t *testing.T) {
	if _, err := Decode("tbox://" + "e30"); err == nil { // base64url of "{}"
		t.Fatal("expected error for token missing required fields")
	}
}

func TestDecodeRejectsMissingUUID(t *testing.T) {
	raw, err := json.Marshal(Token{
		ServerAddr:  "vps.example.com",
		ServerPort:  443,
		UUID:        "",
		PublicKey:   "qRtTOoEUUBoDRVCsMdNuASrUnybf6yD9XaeuqIWjVlw",
		ShortID:     "272010f7",
		SNI:         "www.microsoft.com",
		ControlAddr: "127.0.0.1:8443",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := "tbox://" + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(s); err == nil {
		t.Error("expected error for missing UUID")
	}
}

func TestDecodeRejectsMissingServerAddr(t *testing.T) {
	raw, err := json.Marshal(Token{
		ServerAddr:  "",
		ServerPort:  443,
		UUID:        "a4a34e9a-a2d3-4852-9730-0f81cd1d0027",
		PublicKey:   "qRtTOoEUUBoDRVCsMdNuASrUnybf6yD9XaeuqIWjVlw",
		ShortID:     "272010f7",
		SNI:         "www.microsoft.com",
		ControlAddr: "127.0.0.1:8443",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := "tbox://" + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(s); err == nil {
		t.Error("expected error for missing server_addr")
	}
}

func TestDecodeRejectsMissingPublicKey(t *testing.T) {
	raw, err := json.Marshal(Token{
		ServerAddr:  "vps.example.com",
		ServerPort:  443,
		UUID:        "a4a34e9a-a2d3-4852-9730-0f81cd1d0027",
		PublicKey:   "",
		ShortID:     "272010f7",
		SNI:         "www.microsoft.com",
		ControlAddr: "127.0.0.1:8443",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := "tbox://" + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(s); err == nil {
		t.Error("expected error for missing public_key")
	}
}

func TestKeypairPublicDerivation(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFromPrivate(kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub != kp.PublicKey {
		t.Fatalf("derived public key %q != generated %q", pub, kp.PublicKey)
	}
}

func TestPublicKeyFromPrivateInvalid(t *testing.T) {
	if _, err := PublicKeyFromPrivate("not-base64!!"); err == nil {
		t.Error("expected error for invalid base64 private key")
	}
	if _, err := PublicKeyFromPrivate(""); err == nil {
		t.Error("expected error for empty private key")
	}
	short := base64.RawURLEncoding.EncodeToString([]byte{0x00})
	if _, err := PublicKeyFromPrivate(short); err == nil {
		t.Error("expected error for too-short private key")
	}
}

func TestGenerateShortID(t *testing.T) {
	id, err := GenerateShortID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 8 {
		t.Errorf("short id length = %d, want 8", len(id))
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("short id contains non-hex char %c", c)
		}
	}
	// Two consecutive calls should produce different values.
	id2, err := GenerateShortID()
	if err != nil {
		t.Fatal(err)
	}
	if id == id2 {
		t.Error("two sequential GenerateShortID calls returned same value")
	}
}

func TestGenerateUUID(t *testing.T) {
	u, err := GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRe.MatchString(u) {
		t.Errorf("GenerateUUID = %q, does not match RFC 4122 v4 format", u)
	}

	// Two consecutive calls should produce different values.
	u2, err := GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	if u == u2 {
		t.Error("two sequential GenerateUUID calls returned same value")
	}
}
