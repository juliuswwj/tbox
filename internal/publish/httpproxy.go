package publish

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/juliuswwj/tbox/internal/control"
)

// newReverseProxy builds a ReverseProxy whose transport dials the service
// upstream for every connection: a fresh reverse stream to the owning client,
// or a direct dial for a server-owned service.
func newReverseProxy(svc *control.Service, logger Logger) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return svc.Dial()
		},
		// Each request dials a brand-new reverse stream; pooling across the
		// shared yamux session buys little and complicates lifetime, so disable it.
		DisableKeepAlives: true,
	}
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			applyRequestRewrite(req, svc, req.Host)
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			applyResponseRewrite(resp, svc)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Printf("publish: %s%s -> %s: %v", r.Host, r.URL.Path, svc.Upstream, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}
