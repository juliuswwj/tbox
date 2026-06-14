// Package publish terminates TLS for a registered domain and serves it as a mix
// of HTTP reverse-proxy locations (with URL/header rewriting) and WebSocket
// bridges, each forwarding over a reverse stream to the location's owning tbox
// client. A single domain may aggregate locations from multiple clients.
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

// Handler serves a single registered domain across all its locations.
type Handler struct {
	routes []*routeHandler
	logger Logger
}

type routeHandler struct {
	entry *control.RouteEntry
	proxy *httputil.ReverseProxy // nil for ws routes
}

// NewHandler builds the HTTP handler for a domain snapshot.
func NewHandler(domain *control.Domain, logger Logger) *Handler {
	h := &Handler{logger: logger}
	for _, e := range domain.Routes() {
		rh := &routeHandler{entry: e}
		if e.Mode == "http" {
			rh.proxy = newReverseProxy(e, logger)
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
	// Per-location source-IP whitelist (precise). Use the real connection
	// remote, never X-Forwarded-For.
	if !rh.entry.Allow.AllowedString(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if rh.entry.Mode == "ws" {
		h.serveWS(w, r, rh.entry)
		return
	}
	rh.proxy.ServeHTTP(w, r)
}

func (h *Handler) match(path string) *routeHandler {
	var best *routeHandler
	bestLen := -1
	for _, rh := range h.routes {
		if pathHasPrefix(path, rh.entry.Path) && len(rh.entry.Path) > bestLen {
			best = rh
			bestLen = len(rh.entry.Path)
		}
	}
	return best
}
