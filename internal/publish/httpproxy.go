package publish

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/juliuswwj/tbox/internal/control"
	"github.com/juliuswwj/tbox/internal/tunnel"
)

// newReverseProxy builds a ReverseProxy whose transport dials a fresh reverse
// stream to the route's owning client for every connection.
func newReverseProxy(entry *control.RouteEntry, logger Logger) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return entry.OpenStream(tunnel.ModeHTTP, entry.Upstream)
		},
		// Each request dials a brand-new reverse stream; pooling across the
		// shared yamux session buys little and complicates lifetime, so disable it.
		DisableKeepAlives: true,
	}
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			applyRequestRewrite(req, entry, req.Host)
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			applyResponseRewrite(resp, entry)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Printf("publish: %s%s -> %s: %v", r.Host, r.URL.Path, entry.Upstream, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}
