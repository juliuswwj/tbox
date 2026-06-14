package publish

import (
	"net/http"
	"strings"

	"github.com/juliuswwj/tbox/internal/control"
)

// pathHasPrefix reports whether reqPath is under prefix, treating "/" as a
// match-all and matching on path-segment boundaries otherwise.
func pathHasPrefix(reqPath, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if reqPath == prefix {
		return true
	}
	return strings.HasPrefix(reqPath, prefix+"/")
}

// applyRequestRewrite rewrites the outbound request URL/headers per the service,
// nginx-proxy_pass style. origHost is the public Host as received.
func applyRequestRewrite(req *http.Request, svc *control.Service, origHost string) {
	path := req.URL.Path
	if svc.StripPrefix && svc.Path != "" && svc.Path != "/" {
		trimmed := strings.TrimSuffix(svc.Path, "/")
		path = strings.TrimPrefix(path, trimmed)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}
	if svc.AddPrefix != "" {
		path = strings.TrimSuffix(svc.AddPrefix, "/") + path
	}
	req.URL.Scheme = "http"
	req.URL.Host = svc.Upstream
	req.URL.Path = path
	req.URL.RawPath = "" // let net/http re-encode from Path

	// Forwarded headers (set before overriding Host).
	req.Header.Set("X-Forwarded-Proto", "https")
	if origHost != "" {
		req.Header.Set("X-Forwarded-Host", origHost)
	}

	if svc.SetHost != "" {
		req.Host = svc.SetHost
	} else {
		req.Host = svc.Upstream
	}

	for k, v := range svc.RequestHeaders {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
}

// applyResponseRewrite mutates response headers per the service.
func applyResponseRewrite(resp *http.Response, svc *control.Service) {
	for k, v := range svc.ResponseHeaders {
		if v == "" {
			resp.Header.Del(k)
		} else {
			resp.Header.Set(k, v)
		}
	}
}
