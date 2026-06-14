//go:build with_utls

// Package integration drives a full loopback round trip: a tbox server and one
// or more tbox clients connected over a real VLESS-REALITY tunnel (mimicking
// www.microsoft.com), exercising the SOCKS5H proxy, HTTP publishing with
// rewrites, WebSocket publishing, dynamic whitelists, and multi-client.
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/proxy"

	"github.com/juliuswwj/tbox/internal/control"
	"github.com/juliuswwj/tbox/internal/l4router"
	"github.com/juliuswwj/tbox/internal/singbox"
	"github.com/juliuswwj/tbox/internal/token"
)

const mimic = "www.microsoft.com"

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test performs a real REALITY handshake to the mimic host; skipped in -short mode")
	}
	logger := log.New(io.Discard, "", 0)
	if testing.Verbose() {
		logger = log.New(log.Writer(), "", log.LstdFlags)
	}

	// REALITY parameters shared by server and clients.
	kp, err := token.GenerateKeypair()
	must(t, err)
	shortID, err := token.GenerateShortID()
	must(t, err)
	uuidA, _ := token.GenerateUUID()
	uuidB, _ := token.GenerateUUID()

	publicPort := freePort(t)
	realityPort := freePort(t)
	ctrlPort := freePort(t)

	publicAddr := fmt.Sprintf("127.0.0.1:%d", publicPort)
	realityAddr := fmt.Sprintf("127.0.0.1:%d", realityPort)
	ctrlAddr := fmt.Sprintf("127.0.0.1:%d", ctrlPort)

	// --- server sing-box (VLESS-REALITY inbound) ---
	srvJSON, err := singbox.ServerConfigJSON(singbox.ServerParams{
		ListenAddr: "127.0.0.1",
		ListenPort: uint16(realityPort),
		MimicHost:  mimic,
		MimicPort:  443,
		PrivateKey: kp.PrivateKey,
		ShortID:    shortID,
		Users:      []singbox.User{{Name: "a", UUID: uuidA}, {Name: "b", UUID: uuidB}},
		LogLevel:   "error",
	})
	must(t, err)
	srvBox, err := singbox.New(srvJSON)
	must(t, err)
	must(t, srvBox.Start())
	defer srvBox.Close()

	// --- server control plane + L4 router ---
	reg := control.NewRegistry()
	csrv := control.NewServer(reg, map[string]string{uuidA: "a", uuidB: "b"}, logger)
	ctrlLn, err := net.Listen("tcp", ctrlAddr)
	must(t, err)
	defer ctrlLn.Close()
	go csrv.Serve(ctrlLn)

	router := l4router.New(reg, realityAddr, logger)
	go func() { _ = router.ListenAndServe(publicAddr) }()
	waitDial(t, publicAddr)

	// --- local origin services (what clients publish) ---
	originAddr := startOriginHTTP(t)         // HTTP app for client A
	echoAddr := startEchoTCP(t)              // raw TCP echo for WS publish (client A)
	originBAddr := startOriginHTTP(t)        // HTTP app for client B
	sharedOriginA := startOrigin(t, "Aroot") // shared.test "/" served by A
	sharedOriginB := startOrigin(t, "Bsub")  // shared.test "/b/" served by B

	// certs for the published domains
	certApp, keyApp := genCert(t, "app.test")
	certWS, keyWS := genCert(t, "ws.test")
	certB, keyB := genCert(t, "b.test")
	certShared, keyShared := genCert(t, "shared.test")

	// --- client A: publishes app.test (http, with rewrite) and ws.test (ws) ---
	socksA := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	servicesA := []control.ServiceReg{
		{
			Domain: "app.test", Mode: "http", CertPEM: certApp, KeyPEM: keyApp,
			Routes: []control.RouteReg{{
				Path: "/api/", Upstream: originAddr, StripPrefix: true,
				SetHost: "origin.internal", RequestHeaders: map[string]string{"X-Test": "hello"},
			}, {
				Path: "/", Upstream: originAddr,
			}},
		},
		{Domain: "ws.test", Mode: "ws", CertPEM: certWS, KeyPEM: keyWS, WSPath: "/tunnel", WSUpstream: echoAddr},
		// Shared domain: A owns the cert and serves the root location.
		{Domain: "shared.test", Mode: "http", CertPEM: certShared, KeyPEM: keyShared,
			Routes: []control.RouteReg{{Path: "/", Upstream: sharedOriginA}}},
	}
	startClient(t, socksA, publicAddr, uuidA, kp.PublicKey, shortID, ctrlAddr, servicesA, logger)

	// --- client B: publishes b.test, with an initial whitelist that blocks all ---
	socksB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	servicesB := []control.ServiceReg{
		{Domain: "b.test", Mode: "http", CertPEM: certB, KeyPEM: keyB, Allow: []string{"203.0.113.0/24"},
			Routes: []control.RouteReg{{Path: "/", Upstream: originBAddr}}},
		// Shared domain: B adds a cert-free sub-location under A's domain.
		{Domain: "shared.test", Mode: "http",
			Routes: []control.RouteReg{{Path: "/b/", Upstream: sharedOriginB, StripPrefix: true}}},
	}
	ccB := startClient(t, socksB, publicAddr, uuidB, kp.PublicKey, shortID, ctrlAddr, servicesB, logger)

	// Wait for both clients to register all domains.
	waitRegistered(t, reg, "app.test", "ws.test", "b.test", "shared.test")
	waitRoutes(t, reg, "shared.test", 2)

	t.Run("forward-socks5h", func(t *testing.T) {
		body := socksGet(t, socksA, "http://"+originAddr+"/hello")
		if !strings.Contains(body, "ORIGIN-OK") {
			t.Fatalf("socks proxy body = %q", body)
		}
	})

	t.Run("http-publish-fullsite", func(t *testing.T) {
		body := httpsGet(t, publicAddr, "https://app.test/page")
		if !strings.Contains(body, "ORIGIN-OK") || !strings.Contains(body, "path=/page") {
			t.Fatalf("fullsite body = %q", body)
		}
	})

	t.Run("http-publish-rewrite-sublocation", func(t *testing.T) {
		body := httpsGet(t, publicAddr, "https://app.test/api/widgets")
		// strip_prefix turns /api/widgets into /widgets; SetHost + X-Test applied.
		if !strings.Contains(body, "path=/widgets") {
			t.Fatalf("expected stripped path /widgets, got %q", body)
		}
		if !strings.Contains(body, "host=origin.internal") {
			t.Fatalf("expected rewritten host, got %q", body)
		}
		if !strings.Contains(body, "xtest=hello") {
			t.Fatalf("expected injected header, got %q", body)
		}
		if !strings.Contains(body, "xfh=app.test") {
			t.Fatalf("expected X-Forwarded-Host=app.test, got %q", body)
		}
	})

	t.Run("ws-publish", func(t *testing.T) {
		echoOverWS(t, publicAddr, "wss://ws.test/tunnel", "ping-123")
	})

	t.Run("whitelist-dynamic", func(t *testing.T) {
		// Initially b.test only allows 203.0.113.0/24 -> our loopback is blocked.
		if _, err := tryHTTPS(publicAddr, "https://b.test/"); err == nil {
			t.Fatalf("expected b.test to be blocked by whitelist")
		}
		// Open it up to loopback at runtime.
		must(t, ccB.UpdateWhitelist("b.test", []string{"127.0.0.1/32"}))
		time.Sleep(150 * time.Millisecond)
		body := httpsGet(t, publicAddr, "https://b.test/")
		if !strings.Contains(body, "ORIGIN-OK") {
			t.Fatalf("after whitelist add, body = %q", body)
		}
	})

	t.Run("multi-client-isolation", func(t *testing.T) {
		// app.test (client A) and b.test (client B) both serve concurrently.
		a := httpsGet(t, publicAddr, "https://app.test/")
		b := httpsGet(t, publicAddr, "https://b.test/")
		if !strings.Contains(a, "ORIGIN-OK") || !strings.Contains(b, "ORIGIN-OK") {
			t.Fatalf("multi-client serve failed: a=%q b=%q", a, b)
		}
	})

	t.Run("shared-domain-locations", func(t *testing.T) {
		// One domain, two owners: A serves "/", B serves the "/b/" location.
		root := httpsGet(t, publicAddr, "https://shared.test/index")
		if !strings.Contains(root, "label=Aroot") || !strings.Contains(root, "path=/index") {
			t.Fatalf("shared root (A) = %q", root)
		}
		sub := httpsGet(t, publicAddr, "https://shared.test/b/page")
		if !strings.Contains(sub, "label=Bsub") {
			t.Fatalf("shared sub-location should be served by B, got %q", sub)
		}
		if !strings.Contains(sub, "path=/page") { // strip_prefix removed /b
			t.Fatalf("expected /b stripped to /page, got %q", sub)
		}
	})
}

// --- client wiring ---

func startClient(t *testing.T, socksAddr, publicAddr, uuid, pubKey, shortID, ctrlAddr string, services []control.ServiceReg, logger *log.Logger) *control.Client {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(publicAddr)
	var port uint16
	fmt.Sscan(portStr, &port)
	cliJSON, err := singbox.ClientConfigJSON(singbox.ClientParams{
		SocksListen: socksAddr,
		ServerAddr:  host,
		ServerPort:  port,
		UUID:        uuid,
		SNI:         mimic,
		PublicKey:   pubKey,
		ShortID:     shortID,
		LogLevel:    "error",
	})
	must(t, err)
	cliBox, err := singbox.New(cliJSON)
	must(t, err)
	must(t, cliBox.Start())
	t.Cleanup(func() { cliBox.Close() })
	waitDial(t, socksAddr)

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 10 * time.Second})
	must(t, err)
	ctxDialer := dialer.(proxy.ContextDialer)
	dial := func(ctx context.Context) (net.Conn, error) {
		return ctxDialer.DialContext(ctx, "tcp", ctrlAddr)
	}
	cc := control.NewClient(uuid, services, dial, logger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go cc.Run(ctx)
	return cc
}

// --- test helpers ---

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitDial(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

func waitRegistered(t *testing.T, reg *control.Registry, domains ...string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, d := range domains {
			if !reg.Has(d) {
				all = false
				break
			}
		}
		if all {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("domains not registered in time: %v", domains)
}

func waitRoutes(t *testing.T, reg *control.Registry, domain string, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if d, ok := reg.Lookup(domain); ok && len(d.Routes()) >= n {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("domain %s did not reach %d routes in time", domain, n)
}

func startOriginHTTP(t *testing.T) string { return startOrigin(t, "") }

func startOrigin(t *testing.T, label string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ORIGIN-OK label=%s path=%s host=%s xtest=%s xfh=%s",
			label, r.URL.Path, r.Host, r.Header.Get("X-Test"), r.Header.Get("X-Forwarded-Host"))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// httpsTransport dials the public L4 router regardless of the request host, and
// skips cert verification (self-signed test certs). SNI follows the request host.
func httpsTransport(publicAddr string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, publicAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
}

func tryHTTPS(publicAddr, url string) (string, error) {
	client := &http.Client{Transport: httpsTransport(publicAddr), Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func httpsGet(t *testing.T, publicAddr, url string) string {
	t.Helper()
	body, err := tryHTTPS(publicAddr, url)
	must(t, err)
	return body
}

func socksGet(t *testing.T, socksAddr, url string) string {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 10 * time.Second})
	must(t, err)
	ctxDialer := dialer.(proxy.ContextDialer)
	client := &http.Client{Transport: &http.Transport{DialContext: ctxDialer.DialContext}, Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	must(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func echoOverWS(t *testing.T, publicAddr, url, msg string) {
	t.Helper()
	client := &http.Client{Transport: httpsTransport(publicAddr)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: client})
	must(t, err)
	defer c.Close(websocket.StatusNormalClosure, "")
	must(t, c.Write(ctx, websocket.MessageBinary, []byte(msg)))
	_, data, err := c.Read(ctx)
	must(t, err)
	if string(data) != msg {
		t.Fatalf("ws echo = %q, want %q", data, msg)
	}
}

func genCert(t *testing.T, domain string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	must(t, err)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}
