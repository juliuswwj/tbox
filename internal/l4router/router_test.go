package l4router

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestDispatchHost(t *testing.T) {
	cases := []struct {
		name string
		host string
		sni  string
		want string
	}{
		{
			// HTTP/2 coalescing: the connection's SNI is one host but the
			// request targets another (shared cert + IP). Dispatch must follow
			// the Host header, not the SNI.
			name: "coalesced request follows Host not SNI",
			host: "ai.rainier.lango-tech.com",
			sni:  "rainier.lango-tech.com",
			want: "ai.rainier.lango-tech.com",
		},
		{name: "host with port is stripped", host: "example.com:443", sni: "example.com", want: "example.com"},
		{name: "uppercase host is lowercased", host: "Example.COM", sni: "", want: "example.com"},
		{name: "empty host falls back to SNI", host: "", sni: "Fallback.Example.com", want: "fallback.example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := &http.Request{Host: c.host}
			if c.sni != "" {
				req.TLS = &tls.ConnectionState{ServerName: c.sni}
			}
			if got := dispatchHost(req); got != c.want {
				t.Fatalf("dispatchHost(host=%q sni=%q) = %q, want %q", c.host, c.sni, got, c.want)
			}
		})
	}
}
