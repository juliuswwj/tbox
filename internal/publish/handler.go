// Package publish serves the HTTP/WS side of a published host: it matches a
// request path to one of the host's services (possibly owned by different
// clients) and forwards it over a reverse stream — HTTP reverse proxy (with
// URL/header rewriting) or WebSocket-to-raw-TCP bridge. (Whole-host tcp
// services are handled directly by the L4 router, not here.)
package publish

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"

	"github.com/juliuswwj/tbox/internal/ban"
	"github.com/juliuswwj/tbox/internal/control"
)

// Logger is a minimal Printf-style logging sink (*log.Logger satisfies it).
type Logger interface {
	Printf(format string, v ...any)
}

// Handler serves the http/ws services registered for one host.
type Handler struct {
	routes []*routeHandler
	banner *ban.Banner // nil = banning disabled
	logger Logger
}

type routeHandler struct {
	svc   *control.Service
	proxy *httputil.ReverseProxy // nil for ws services
}

// NewHandler builds the HTTP handler for a host's services. banner may be nil
// to disable fail2ban-style throttling.
func NewHandler(services []*control.Service, banner *ban.Banner, logger Logger) *Handler {
	h := &Handler{banner: banner, logger: logger}
	for _, s := range services {
		rh := &routeHandler{svc: s}
		if s.Mode == "http" {
			rh.proxy = newReverseProxy(s, logger)
		}
		h.routes = append(h.routes, rh)
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rh := h.match(r.URL.Path)
	if rh == nil {
		http.NotFound(w, r)
		return
	}
	// fail2ban-style block: reject sources (or /24s) that crossed the
	// auth-failure threshold, before doing any upstream work.
	ip, ipOK := remoteIP(r.RemoteAddr)
	if h.banner != nil && ipOK && h.banner.Blocked(ip) {
		h.logger.Printf("publish: blocked banned source %s -> %s%s", ip, r.Host, r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Per-service source-IP whitelist (precise). Use the real connection
	// remote, never X-Forwarded-For.
	if !rh.svc.Allow.AllowedString(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if rh.svc.Mode == "ws" {
		h.serveWS(w, r, rh.svc)
		return
	}
	// Account auth failures for banning: capture the response status and, when
	// it matches the configured rule, record a failure against the source IP.
	if h.banner != nil && ipOK {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		rh.proxy.ServeHTTP(rec, r)
		if h.banner.Counts(r.Method, r.URL.Path, rec.status) {
			if banned, subnet := h.banner.Fail(ip); banned {
				if subnet != "" {
					h.logger.Printf("publish: banned %s and subnet %s after repeated auth failures", ip, subnet)
				} else {
					h.logger.Printf("publish: banned %s after repeated auth failures", ip)
				}
			}
		}
		return
	}
	rh.proxy.ServeHTTP(w, r)
}

// remoteIP extracts the IP from a "host:port" RemoteAddr.
func remoteIP(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}

// statusRecorder captures the response status while preserving streaming
// (Flush) for the reverse proxy. Hijack is not needed here (WS is handled
// separately, before this point).
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *Handler) match(path string) *routeHandler {
	var best *routeHandler
	bestLen := -1
	for _, rh := range h.routes {
		if pathHasPrefix(path, rh.svc.Path) && len(rh.svc.Path) > bestLen {
			best = rh
			bestLen = len(rh.svc.Path)
		}
	}
	return best
}
