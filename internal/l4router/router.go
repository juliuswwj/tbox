// Package l4router owns the public :443 listener. It peeks the TLS SNI of each
// connection and routes it: registered publish domains are TLS-terminated and
// served by the publish layer; everything else (the mimic host, probes, unknown
// SNI) is replayed to the embedded sing-box VLESS-REALITY inbound, which serves
// real proxy clients and falls back to the genuine mimic site for everyone else.
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
	realityAddr string // address of the embedded sing-box reality inbound
	logger      Logger

	publishLn *connListener
	httpSrv   *http.Server

	mu      sync.Mutex
	handler map[string]*cachedHandler // domain -> cached publish handler
}

type cachedHandler struct {
	version uint64
	h       *publish.Handler
}

// New creates a Router.
func New(reg *control.Registry, realityAddr string, logger Logger) *Router {
	r := &Router{
		reg:         reg,
		realityAddr: realityAddr,
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
	domain := strings.ToLower(strings.TrimSpace(sni))

	dom, ok := r.reg.Lookup(domain)
	if !ok {
		// Mimic host, unknown SNI, or empty SNI: let REALITY handle it.
		r.toReality(replayed)
		return
	}

	// Coarse source-IP gate at L4 (pre-TLS): allow if any location on the
	// domain would admit this peer; precise per-location enforcement happens at
	// the HTTP layer. Dropping here avoids revealing the site to peers no
	// location admits.
	if !dom.AllowedConn(conn.RemoteAddr()) {
		r.logger.Printf("l4: blocked %s -> %s (not in any whitelist)", conn.RemoteAddr(), domain)
		_ = replayed.Close()
		return
	}

	r.publishLn.push(replayed)
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

// getCertificate selects the cert for a registered domain during the publish
// TLS handshake.
func (r *Router) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	dom, ok := r.reg.Lookup(hello.ServerName)
	if !ok {
		return nil, errors.New("no certificate for " + hello.ServerName)
	}
	cert, ok := dom.Cert()
	if !ok {
		return nil, errors.New("no certificate registered for " + hello.ServerName)
	}
	return &cert, nil
}

// serveHTTP dispatches an already-TLS-terminated request to the publish handler
// for its SNI.
func (r *Router) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.TLS == nil {
		http.Error(w, "TLS required", http.StatusBadRequest)
		return
	}
	domain := strings.ToLower(req.TLS.ServerName)
	dom, ok := r.reg.Lookup(domain)
	if !ok {
		http.NotFound(w, req)
		return
	}
	r.handlerFor(domain, dom).ServeHTTP(w, req)
}

// handlerFor returns a cached publish handler for the domain, rebuilding it
// whenever the domain's routes/cert change (tracked by Version).
func (r *Router) handlerFor(domain string, dom *control.Domain) *publish.Handler {
	v := dom.Version()
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.handler[domain]; ok && c.version == v {
		return c.h
	}
	h := publish.NewHandler(dom, r.logger)
	r.handler[domain] = &cachedHandler{version: v, h: h}
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
