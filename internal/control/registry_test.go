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

// wildcardCert returns a cert covering both base and *.base.
func wildcardCert(t *testing.T, base string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: base},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{base, "*." + base},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestWildcardCertLookup(t *testing.T) {
	reg := NewRegistry()
	cert, key := wildcardCert(t, "dc.example.com")
	if err := reg.AddServerCert(cert, key); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"dc.example.com", "app.dc.example.com", "ssh.dc.example.com"} {
		if _, ok := reg.LookupCert(host); !ok {
			t.Fatalf("expected cert match for %s", host)
		}
	}
	for _, host := range []string{"other.com", "a.b.dc.example.com"} {
		if _, ok := reg.LookupCert(host); ok {
			t.Fatalf("did not expect cert match for %s", host)
		}
	}
}

func TestServerCertWithClientServices(t *testing.T) {
	reg := NewRegistry()
	cert, key := wildcardCert(t, "dc.example.com")
	if err := reg.AddServerCert(cert, key); err != nil {
		t.Fatal(err)
	}
	sA := newSession(t)
	sB := newSession(t)

	// A: http root on the apex + ws on a subdomain; no cert of its own.
	if err := reg.Register("A", sA, nil, []ServiceReg{
		{Mode: "http", Host: "dc.example.com", Path: "/", Upstream: "127.0.0.1:1"},
		{Mode: "ws", Host: "app.dc.example.com", Path: "/tunnel/ssh", Upstream: "127.0.0.1:22"},
	}); err != nil {
		t.Fatalf("A register: %v", err)
	}
	// B: a sub-location on the same subdomain + a tcp host. No cert.
	if err := reg.Register("B", sB, nil, []ServiceReg{
		{Mode: "http", Host: "app.dc.example.com", Path: "/location/", Upstream: "127.0.0.1:8080"},
		{Mode: "tcp", Host: "ssh.dc.example.com", Upstream: "127.0.0.1:22"},
	}); err != nil {
		t.Fatalf("B register: %v", err)
	}

	if !reg.HasHTTPHost("dc.example.com") {
		t.Fatal("apex http missing")
	}
	if got := len(reg.HTTPServices("app.dc.example.com")); got != 2 {
		t.Fatalf("app.dc.example.com should have 2 http/ws services, got %d", got)
	}
	if _, ok := reg.RawService("ssh.dc.example.com"); !ok {
		t.Fatal("tcp service missing")
	}
	// The server-provided wildcard cert serves all of them.
	for _, h := range []string{"dc.example.com", "app.dc.example.com", "ssh.dc.example.com"} {
		if _, ok := reg.LookupCert(h); !ok {
			t.Fatalf("cert lookup failed for %s", h)
		}
	}
}

func TestConflicts(t *testing.T) {
	reg := NewRegistry()
	sA := newSession(t)
	sB := newSession(t)
	reg.Register("A", sA, nil, []ServiceReg{{Mode: "http", Host: "app.example.com", Path: "/x/", Upstream: "127.0.0.1:1"}})

	// Same path, different client -> conflict.
	if err := reg.Register("B", sB, nil, []ServiceReg{{Mode: "http", Host: "app.example.com", Path: "/x/", Upstream: "127.0.0.1:2"}}); err == nil {
		t.Fatal("expected path conflict")
	}
	// tcp on a host already used for http -> conflict.
	if err := reg.Register("B", sB, nil, []ServiceReg{{Mode: "tcp", Host: "app.example.com", Upstream: "127.0.0.1:2"}}); err == nil {
		t.Fatal("expected tcp/http host conflict")
	}
	// Different path on same host, different client -> OK (shared host).
	if err := reg.Register("B", sB, nil, []ServiceReg{{Mode: "http", Host: "app.example.com", Path: "/y/", Upstream: "127.0.0.1:2"}}); err != nil {
		t.Fatalf("shared-host different path should be allowed: %v", err)
	}
}

func TestPerServiceWhitelistAndRemoval(t *testing.T) {
	reg := NewRegistry()
	sA := newSession(t)
	reg.Register("A", sA, nil, []ServiceReg{
		{Mode: "tcp", Host: "ssh.example.com", Upstream: "127.0.0.1:22", Allow: []string{"203.0.113.0/24"}},
	})
	svc, ok := reg.RawService("ssh.example.com")
	if !ok {
		t.Fatal("missing tcp service")
	}
	id := svc.ID()
	if id != "tcp://ssh.example.com" {
		t.Fatalf("unexpected service id %q", id)
	}
	if svc.Allow.Allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("8.8.8.8 should be blocked initially")
	}
	if err := reg.UpdateWhitelist("A", id, []string{"8.8.8.0/24"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !svc.Allow.Allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("8.8.8.8 should be allowed after update")
	}
	// Wrong owner can't update.
	if err := reg.UpdateWhitelist("B", id, []string{"0.0.0.0/0"}); err == nil {
		t.Fatal("expected ownership error")
	}
	// Session removal drops the service.
	reg.RemoveSession(sA)
	if _, ok := reg.RawService("ssh.example.com"); ok {
		t.Fatal("service should be gone after session removal")
	}
}
