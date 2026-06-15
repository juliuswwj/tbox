// Package l4router owns the public :443 listener. It peeks the TLS SNI of each
// connection and routes by host:
//
//   - a registered tcp service -> TLS terminated here, then raw-piped to the
//     owning client (TLS+TCP, e.g. ssh);
//   - a host with http/ws services -> handed to the publish HTTP server, which
//     terminates TLS (cert chosen by SNI) and dispatches by path;
//   - everything else (the mimic host, probes, unknown SNI) -> replayed to the
//     embedded sing-box VLESS-REALITY inbound, which serves real proxy clients
//     and falls back to the genuine mimic site for everyone else.
package l4router

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/juliuswwj/tbox/internal/ban"
	"github.com/juliuswwj/tbox/internal/control"
	"github.com/juliuswwj/tbox/internal/publish"
	"github.com/juliuswwj/tbox/internal/tunnel"
)

// Logger is a minimal Printf-style logging sink.
type Logger interface {
	Printf(format string, v ...any)
}

// Router routes inbound :443 connections by SNI.
type Router struct {
	reg         *control.Registry
	realityAddr string      // address of the embedded sing-box reality inbound
	banner      *ban.Banner // nil = banning disabled
	logger      Logger

	publishLn *connListener
	httpSrv   *http.Server

	mu      sync.Mutex
	handler map[string]*cachedHandler // host -> cached publish handler
}

type cachedHandler struct {
	version uint64
	h       *publish.Handler
}

// New creates a Router. banner may be nil to disable HTTP fail2ban throttling.
func New(reg *control.Registry, realityAddr string, banner *ban.Banner, logger Logger) *Router {
	r := &Router{
		reg:         reg,
		realityAddr: realityAddr,
		banner:      banner,
		logger:      logger,
		publishLn:   newConnListener(),
		handler:     make(map[string]*cachedHandler),
	}
	r.httpSrv = &http.Server{
		Handler:           http.HandlerFunc(r.serveHTTP),
		ReadHeaderTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: r.getCertificate,
		},
	}
	return r
}

// ListenAndServe binds addr and serves until the listener errors.
func (r *Router) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// The publish HTTP server performs the TLS handshake itself (via
	// GetCertificate), so r.TLS.ServerName is populated for dispatch.
	go func() {
		if err := r.httpSrv.ServeTLS(r.publishLn, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.logger.Printf("l4: publish server: %v", err)
		}
	}()
	r.logger.Printf("l4: listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(conn)
	}
}

func (r *Router) handle(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	sni, raw, err := peekClientHelloSNI(conn)
	_ = conn.SetReadDeadline(time.Time{})
	replayed := newPrefixConn(conn, raw)
	if err != nil {
		// Couldn't parse a ClientHello — treat as a probe, hand to reality.
		r.toReality(replayed)
		return
	}
	host := strings.ToLower(strings.TrimSpace(sni))

	if svc, ok := r.reg.RawService(host); ok {
		r.handleRaw(svc, replayed, conn.RemoteAddr())
		return
	}
	if r.reg.HasHTTPHost(host) {
		if !r.reg.HTTPHostAllowed(host, conn.RemoteAddr()) {
			r.logger.Printf("l4: blocked %s -> %s (not in any whitelist)", conn.RemoteAddr(), host)
			_ = replayed.Close()
			return
		}
		r.publishLn.push(replayed)
		return
	}
	// Mimic host, unknown SNI, or empty SNI: let REALITY handle it.
	r.toReality(replayed)
}

// handleRaw terminates TLS for a whole-host tcp/socks5 service and raw-pipes the
// decrypted stream to the owning client (which dials the upstream or runs a
// SOCKS5 server).
func (r *Router) handleRaw(svc *control.Service, conn net.Conn, remote net.Addr) {
	if !svc.Allow.AllowedConn(remote) {
		r.logger.Printf("l4: blocked %s -> %s (not in whitelist)", remote, svc.ID())
		_ = conn.Close()
		return
	}
	cert, ok := r.reg.LookupCert(svc.Host)
	if !ok {
		r.logger.Printf("l4: no certificate for %s", svc.ID())
		_ = conn.Close()
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	stream, err := svc.OpenStream()
	if err != nil {
		r.logger.Printf("l4: %s open reverse stream: %v", svc.ID(), err)
		_ = tlsConn.Close()
		return
	}
	tunnel.Pipe(tlsConn, stream)
}

// toReality splices a connection to the embedded sing-box reality inbound.
func (r *Router) toReality(conn net.Conn) {
	upstream, err := net.DialTimeout("tcp", r.realityAddr, 10*time.Second)
	if err != nil {
		r.logger.Printf("l4: dial reality inbound %s: %v", r.realityAddr, err)
		_ = conn.Close()
		return
	}
	tunnel.Pipe(conn, upstream)
}

// getCertificate selects the cert matching the SNI during the publish TLS handshake.
func (r *Router) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, ok := r.reg.LookupCert(hello.ServerName)
	if !ok {
		return nil, errors.New("no certificate for " + hello.ServerName)
	}
	return cert, nil
}

// serveHTTP dispatches an already-TLS-terminated request to the publish handler
// for its SNI host.
func (r *Router) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}
	host := dispatchHost(req)
	services := r.reg.HTTPServices(host)
	if len(services) == 0 {
		http.NotFound(w, req)
		return
	}
	r.handlerFor(host, services).ServeHTTP(w, req)
}

// dispatchHost picks the virtual host for a request from its Host header (the
// HTTP/2 :authority or HTTP/1.1 Host), not the TLS SNI. Browsers coalesce
// HTTP/2 connections across hostnames that share a certificate and IP, so one
// connection (one SNI) can carry requests for several hosts; the Host header is
// what names the intended virtual host per request. It falls back to the SNI
// only when Host is absent (e.g. HTTP/1.0).
func dispatchHost(req *http.Request) string {
	host := strings.ToLower(req.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" && req.TLS != nil {
		host = strings.ToLower(req.TLS.ServerName)
	}
	return host
}

// handlerFor returns a cached publish handler for the host, rebuilding it
// whenever the registry changes (tracked by Version).
func (r *Router) handlerFor(host string, services []*control.Service) *publish.Handler {
	v := r.reg.Version()
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.handler[host]; ok && c.version == v {
		return c.h
	}
	h := publish.NewHandler(services, r.banner, r.logger)
	r.handler[host] = &cachedHandler{version: v, h: h}
	return h
}

// --- prefixConn: replays peeked bytes then the live conn ---

type prefixConn struct {
	net.Conn
	r io.Reader
}

func newPrefixConn(c net.Conn, prefix []byte) net.Conn {
	return &prefixConn{Conn: c, r: io.MultiReader(strings.NewReader(string(prefix)), c)}
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// --- connListener: feeds accepted conns to the publish http.Server ---

type connListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnListener() *connListener {
	return &connListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.closed:
		_ = c.Close()
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}
