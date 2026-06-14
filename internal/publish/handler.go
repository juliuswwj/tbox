// Package publish serves the HTTP/WS side of a published host: it matches a
// request path to one of the host's services (possibly owned by different
// clients) and forwards it over a reverse stream — HTTP reverse proxy (with
// URL/header rewriting) or WebSocket-to-raw-TCP bridge. (Whole-host tcp
// services are handled directly by the L4 router, not here.)
package publish

import (
	"net/http"
	"net/http/httputil"

	"github.com/juliuswwj/tbox/internal/control"
)

// Logger is a minimal Printf-style logging sink (*log.Logger satisfies it).
type Logger interface {
	Printf(format string, v ...any)
}

// Handler serves the http/ws services registered for one host.
type Handler struct {
	routes []*routeHandler
	logger Logger
}

type routeHandler struct {
	svc   *control.Service
	proxy *httputil.ReverseProxy // nil for ws services
}

// NewHandler builds the HTTP handler for a host's services.
func NewHandler(services []*control.Service, logger Logger) *Handler {
	h := &Handler{logger: logger}
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
	rh.proxy.ServeHTTP(w, r)
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
