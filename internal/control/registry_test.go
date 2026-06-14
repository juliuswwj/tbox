package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/juliuswwj/tbox/internal/tunnel"
)

func newSession(t *testing.T) *yamux.Session {
	t.Helper()
	c1, c2 := net.Pipe()
	s, err := tunnel.Server(c1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := tunnel.Client(c2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); other.Close(); c1.Close(); c2.Close() })
	return s
}

func testCert(t *testing.T, domain string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{domain},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestSharedDomainAcrossClients(t *testing.T) {
	reg := NewRegistry()
	sA := newSession(t)
	sB := newSession(t)
	cert, key := testCert(t, "shared.test")

	// Client A owns the domain (provides the cert) and serves "/".
	if err := reg.Register("A", sA, ServiceReg{
		Domain: "shared.test", Mode: "http", CertPEM: cert, KeyPEM: key,
		Routes: []RouteReg{{Path: "/", Upstream: "127.0.0.1:1"}},
	}); err != nil {
		t.Fatalf("A register: %v", err)
	}
	// Client B adds a location "/b/" with no cert of its own.
	if err := reg.Register("B", sB, ServiceReg{
		Domain: "shared.test", Mode: "http",
		Routes: []RouteReg{{Path: "/b/", Upstream: "127.0.0.1:2"}},
	}); err != nil {
		t.Fatalf("B register: %v", err)
	}

	dom, ok := reg.Lookup("shared.test")
	if !ok {
		t.Fatal("domain missing")
	}
	if _, ok := dom.Cert(); !ok {
		t.Fatal("domain should have a cert from A")
	}
	owner := map[string]string{}
	for _, r := range dom.Routes() {
		owner[r.Path] = r.ClientID
	}
	if owner["/"] != "A" || owner["/b/"] != "B" {
		t.Fatalf("unexpected ownership: %v", owner)
	}

	// A path already owned by another client cannot be taken.
	if err := reg.Register("B", sB, ServiceReg{
		Domain: "shared.test", Mode: "http",
		Routes: []RouteReg{{Path: "/", Upstream: "127.0.0.1:3"}},
	}); err == nil {
		t.Fatal("expected path conflict for B taking '/'")
	}
}

func TestPerClientWhitelistAndRemoval(t *testing.T) {
	reg := NewRegistry()
	sA := newSession(t)
	sB := newSession(t)
	cert, key := testCert(t, "shared.test")

	reg.Register("A", sA, ServiceReg{Domain: "shared.test", Mode: "http", CertPEM: cert, KeyPEM: key,
		Routes: []RouteReg{{Path: "/", Upstream: "127.0.0.1:1"}}})
	reg.Register("B", sB, ServiceReg{Domain: "shared.test", Mode: "http", Allow: []string{"10.0.0.0/8"},
		Routes: []RouteReg{{Path: "/b/", Upstream: "127.0.0.1:2"}}})

	dom, _ := reg.Lookup("shared.test")

	// A allows all -> domain admits any IP at L4 (union).
	if !dom.AllowedConn(addr("8.8.8.8")) {
		t.Fatal("domain should admit 8.8.8.8 via A's allow-all")
	}
	// B's location is restricted; A's is not.
	for _, r := range dom.Routes() {
		switch r.ClientID {
		case "A":
			if !r.Allow.Allowed(netip.MustParseAddr("8.8.8.8")) {
				t.Fatal("A route should allow all")
			}
		case "B":
			if r.Allow.Allowed(netip.MustParseAddr("8.8.8.8")) {
				t.Fatal("B route should not allow 8.8.8.8")
			}
		}
	}

	// Update B's whitelist at runtime.
	if err := reg.UpdateWhitelist("B", "shared.test", []string{"8.8.8.0/24"}); err != nil {
		t.Fatalf("update whitelist: %v", err)
	}
	for _, r := range dom.Routes() {
		if r.ClientID == "B" && !r.Allow.Allowed(netip.MustParseAddr("8.8.8.8")) {
			t.Fatal("B route should now allow 8.8.8.8")
		}
	}

	// Removing B's session drops only B's location; the domain survives.
	reg.RemoveSession(sB)
	dom, ok := reg.Lookup("shared.test")
	if !ok {
		t.Fatal("domain should survive after B leaves")
	}
	if len(dom.Routes()) != 1 || dom.Routes()[0].ClientID != "A" {
		t.Fatalf("expected only A's route, got %+v", dom.Routes())
	}

	// Removing A (the cert owner) empties the domain.
	reg.RemoveSession(sA)
	if reg.Has("shared.test") {
		t.Fatal("domain should be gone after all clients leave")
	}
}

func addr(s string) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(s), Port: 12345}
}
