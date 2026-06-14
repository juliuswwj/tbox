//go:build with_utls

// Package integration drives a full loopback round trip: a tbox server and two
// tbox clients connected over a real VLESS-REALITY tunnel (mimicking
// www.microsoft.com). It exercises the SOCKS5H proxy and all publish modes
// (HTTP, WebSocket, TLS+TCP) served under a single server-provided wildcard
// cert, plus a shared host across clients and a dynamic whitelist.
package integration

import (
	"bufio"
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

	kp, err := token.GenerateKeypair()
	must(t, err)
	shortID, err := token.GenerateShortID()
	must(t, err)
	uuidA, _ := token.GenerateUUID()
	uuidB, _ := token.GenerateUUID()

	publicAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	realityAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	ctrlAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	// --- server sing-box (VLESS-REALITY inbound) ---
	srvJSON, err := singbox.ServerConfigJSON(singbox.ServerParams{
		ListenAddr: "127.0.0.1",
		ListenPort: portOf(realityAddr),
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

	// --- server control plane + L4 router, with a server-provided wildcard cert ---
	reg := control.NewRegistry()
	cert, key := genCert(t, "dc.example.com", "*.dc.example.com")
	must(t, reg.AddServerCert(cert, key))

	csrv := control.NewServer(reg, map[string]string{uuidA: "a", uuidB: "b"}, logger)
	ctrlLn, err := net.Listen("tcp", ctrlAddr)
	must(t, err)
	defer ctrlLn.Close()
	go csrv.Serve(ctrlLn)

	router := l4router.New(reg, realityAddr, logger)
	go func() { _ = router.ListenAndServe(publicAddr) }()
	waitDial(t, publicAddr)

	// --- local origin services ---
	originApex := startOrigin(t, "Aroot") // https://dc.example.com/
	originLoc := startOrigin(t, "loc")    // https://app.dc.example.com/location/
	originTeamB := startOrigin(t, "Bsub") // https://app.dc.example.com/teamb/ (client B)
	echoWS := startEchoTCP(t)             // wss://app.dc.example.com/tunnel/ssh
	echoTCP := startEchoTCP(t)            // tcp://ssh.dc.example.com

	// --- client A: apex http, sub-location http (rewrite), ws, and tcp ---
	socksA := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	servicesA := []control.ServiceReg{
		{Mode: "http", Host: "dc.example.com", Path: "/", Upstream: originApex},
		{Mode: "http", Host: "app.dc.example.com", Path: "/location/", Upstream: originLoc,
			StripPrefix: true, SetHost: "app.internal", RequestHeaders: map[string]string{"X-Test": "hello"}},
		{Mode: "ws", Host: "app.dc.example.com", Path: "/tunnel/ssh", Upstream: echoWS},
		{Mode: "tcp", Host: "ssh.dc.example.com", Upstream: echoTCP, Allow: []string{"203.0.113.0/24"}},
	}
	ccA := startClient(t, socksA, publicAddr, uuidA, kp.PublicKey, shortID, ctrlAddr, nil, servicesA, logger)

	// --- client B: a sub-location on the SAME shared host, no cert ---
	socksB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	servicesB := []control.ServiceReg{
		{Mode: "http", Host: "app.dc.example.com", Path: "/teamb/", Upstream: originTeamB, StripPrefix: true},
	}
	startClient(t, socksB, publicAddr, uuidB, kp.PublicKey, shortID, ctrlAddr, nil, servicesB, logger)

	waitFor(t, func() bool {
		return reg.HasHTTPHost("dc.example.com") &&
			len(reg.HTTPServices("app.dc.example.com")) >= 3 &&
			tcpExists(reg, "ssh.dc.example.com")
	})

	t.Run("forward-socks5h", func(t *testing.T) {
		body := socksGet(t, socksA, "http://"+originApex+"/hello")
		if !strings.Contains(body, "ORIGIN-OK") {
			t.Fatalf("socks proxy body = %q", body)
		}
	})

	t.Run("http-apex", func(t *testing.T) {
		body := httpsGet(t, publicAddr, "https://dc.example.com/index")
		if !strings.Contains(body, "label=Aroot") || !strings.Contains(body, "path=/index") {
			t.Fatalf("apex body = %q", body)
		}
	})

	t.Run("http-sublocation-rewrite", func(t *testing.T) {
		body := httpsGet(t, publicAddr, "https://app.dc.example.com/location/widgets")
		if !strings.Contains(body, "label=loc") || !strings.Contains(body, "path=/widgets") {
			t.Fatalf("expected stripped /widgets from loc origin, got %q", body)
		}
		if !strings.Contains(body, "host=app.internal") || !strings.Contains(body, "xtest=hello") {
			t.Fatalf("expected rewritten host + injected header, got %q", body)
		}
	})

	t.Run("ws", func(t *testing.T) {
		echoOverWS(t, publicAddr, "wss://app.dc.example.com/tunnel/ssh", "ping-123")
	})

	t.Run("shared-host-locations", func(t *testing.T) {
		a := httpsGet(t, publicAddr, "https://app.dc.example.com/location/x")
		b := httpsGet(t, publicAddr, "https://app.dc.example.com/teamb/y")
		if !strings.Contains(a, "label=loc") {
			t.Fatalf("/location/ should be client A's, got %q", a)
		}
		if !strings.Contains(b, "label=Bsub") || !strings.Contains(b, "path=/y") {
			t.Fatalf("/teamb/ should be client B's (stripped), got %q", b)
		}
	})

	t.Run("tcp-tls-and-whitelist", func(t *testing.T) {
		// tcp://ssh.dc.example.com starts whitelisted to 203.0.113.0/24 -> blocked.
		if _, err := tlsEcho(publicAddr, "ssh.dc.example.com", "hi"); err == nil {
			t.Fatal("expected tcp service to be blocked by whitelist")
		}
		// Open it to loopback at runtime, then it must terminate TLS and echo.
		must(t, ccA.UpdateWhitelist("tcp://ssh.dc.example.com", []string{"127.0.0.1/32"}))
		time.Sleep(150 * time.Millisecond)
		got, err := tlsEcho(publicAddr, "ssh.dc.example.com", "hello-ssh")
		must(t, err)
		if got != "hello-ssh" {
			t.Fatalf("tcp echo = %q, want %q", got, "hello-ssh")
		}
	})
}

// --- client wiring ---

func startClient(t *testing.T, socksAddr, publicAddr, uuid, pubKey, shortID, ctrlAddr string, certs []control.CertReg, services []control.ServiceReg, logger *log.Logger) *control.Client {
	t.Helper()
	host, _, _ := net.SplitHostPort(publicAddr)
	cliJSON, err := singbox.ClientConfigJSON(singbox.ClientParams{
		SocksListen: socksAddr,
		ServerAddr:  host,
		ServerPort:  portOf(publicAddr),
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
	cc := control.NewClient(uuid, certs, services, dial, logger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go cc.Run(ctx)
	return cc
}

// --- helpers ---

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func portOf(addr string) uint16 {
	_, p, _ := net.SplitHostPort(addr)
	var n uint16
	fmt.Sscan(p, &n)
	return n
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
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func tcpExists(reg *control.Registry, host string) bool {
	_, ok := reg.TCPService(host)
	return ok
}

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

func httpsTransport(publicAddr string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, publicAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
}

func httpsGet(t *testing.T, publicAddr, url string) string {
	t.Helper()
	client := &http.Client{Transport: httpsTransport(publicAddr), Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	must(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
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

// tlsEcho dials the public router with the given SNI, completes the TLS
// handshake (TLS+TCP service), writes msg, and reads the echo back.
func tlsEcho(publicAddr, sni, msg string) (string, error) {
	raw, err := net.DialTimeout("tcp", publicAddr, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err != nil {
		return "", err
	}
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(bufio.NewReader(c), buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func genCert(t *testing.T, names ...string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	must(t, err)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}
