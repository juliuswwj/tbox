package tunnel

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// yamuxConfig returns a yamux config with keepalive tuned for a long-lived
// carrier connection that may sit idle.
func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 30 * time.Second
	c.LogOutput = io.Discard
	return c
}

// Server wraps a carrier net.Conn as the yamux server side (the tbox server,
// which opens reverse streams toward the client).
func Server(conn net.Conn) (*yamux.Session, error) {
	return yamux.Server(conn, yamuxConfig())
}

// Client wraps a carrier net.Conn as the yamux client side (the tbox client,
// which accepts reverse streams).
func Client(conn net.Conn) (*yamux.Session, error) {
	return yamux.Client(conn, yamuxConfig())
}

// Pipe copies bytes bidirectionally between a and b and closes both when
// either direction finishes.
func Pipe(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = a.Close(); _ = b.Close() }) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); closeBoth() }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); closeBoth() }()
	wg.Wait()
}
