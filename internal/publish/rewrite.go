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

// applyRequestRewrite rewrites the outbound request URL/headers per the route,
// nginx-proxy_pass style. origHost is the public Host as received.
func applyRequestRewrite(req *http.Request, route *control.RouteEntry, origHost string) {
	path := req.URL.Path
	if route.StripPrefix && route.Path != "" && route.Path != "/" {
		trimmed := strings.TrimSuffix(route.Path, "/")
		path = strings.TrimPrefix(path, trimmed)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}
	if route.AddPrefix != "" {
		path = strings.TrimSuffix(route.AddPrefix, "/") + path
	}
	req.URL.Scheme = "http"
	req.URL.Host = route.Upstream
	req.URL.Path = path
	req.URL.RawPath = "" // let net/http re-encode from Path

	// Forwarded headers (set before overriding Host).
	req.Header.Set("X-Forwarded-Proto", "https")
	if origHost != "" {
		req.Header.Set("X-Forwarded-Host", origHost)
	}

	if route.SetHost != "" {
		req.Host = route.SetHost
	} else {
		req.Host = route.Upstream
	}

	for k, v := range route.RequestHeaders {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
}

// applyResponseRewrite mutates response headers per the route.
func applyResponseRewrite(resp *http.Response, route *control.RouteEntry) {
	for k, v := range route.ResponseHeaders {
		if v == "" {
			resp.Header.Del(k)
		} else {
			resp.Header.Set(k, v)
		}
	}
}
