package token

import "testing"

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

func TestDecodeRejectsIncomplete(t *testing.T) {
	if _, err := Decode("tbox://" + "e30"); err == nil { // base64url of "{}"
		t.Fatal("expected error for token missing required fields")
	}
}
