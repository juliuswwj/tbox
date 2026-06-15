package publish

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hijackableRW is a ResponseWriter that also implements http.Hijacker.
type hijackableRW struct {
	http.ResponseWriter
	hijacked bool
}

func (h *hijackableRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestStatusRecorderHijackPassthrough(t *testing.T) {
	// When the underlying writer supports hijacking (as the real HTTP server's
	// does), the recorder must pass it through so WebSocket upgrades work.
	under := &hijackableRW{ResponseWriter: httptest.NewRecorder()}
	sr := &statusRecorder{ResponseWriter: under, status: http.StatusOK}
	if _, ok := interface{}(sr).(http.Hijacker); !ok {
		t.Fatal("statusRecorder must implement http.Hijacker")
	}
	if _, _, err := sr.Hijack(); err != nil {
		t.Fatalf("Hijack passthrough failed: %v", err)
	}
	if !under.hijacked {
		t.Fatal("Hijack did not reach the underlying writer")
	}

	// When the underlying writer can't hijack, it returns an error (not a panic).
	srPlain := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	if _, _, err := srPlain.Hijack(); err == nil {
		t.Fatal("expected an error hijacking a non-Hijacker writer")
	}
}

func TestRemoteIP(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want string
	}{
		{"203.0.113.7:54321", true, "203.0.113.7"},
		{"[2001:db8::1]:443", true, "2001:db8::1"},
		{"198.51.100.9", true, "198.51.100.9"}, // no port
		{"garbage", false, ""},
	}
	for _, c := range cases {
		ip, ok := remoteIP(c.in)
		if ok != c.ok {
			t.Errorf("remoteIP(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && ip.String() != c.want {
			t.Errorf("remoteIP(%q) = %q, want %q", c.in, ip.String(), c.want)
		}
	}
}

func TestStatusRecorderCapturesStatus(t *testing.T) {
	// Explicit WriteHeader is captured.
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: http.StatusOK}
	sr.WriteHeader(http.StatusUnauthorized)
	if sr.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", sr.status)
	}
	// A later WriteHeader must not overwrite the recorded status.
	sr.WriteHeader(http.StatusInternalServerError)
	if sr.status != http.StatusUnauthorized {
		t.Fatalf("status overwritten to %d", sr.status)
	}

	// Write without WriteHeader implies 200.
	rec2 := httptest.NewRecorder()
	sr2 := &statusRecorder{ResponseWriter: rec2, status: http.StatusOK}
	_, _ = sr2.Write([]byte("ok"))
	if sr2.status != http.StatusOK {
		t.Fatalf("implicit status = %d, want 200", sr2.status)
	}
}
