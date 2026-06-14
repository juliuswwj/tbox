package socks5

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// runServe wires a client side (x/net/proxy SOCKS5) to Serve over net.Pipe and
// returns the dialer.
func dialViaServe(t *testing.T, allow AllowFunc, dial DialFunc) proxy.Dialer {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", "pipe", nil, pipeDialer{t: t, allow: allow, dial: dial})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

type pipeDialer struct {
	t     *testing.T
	allow AllowFunc
	dial  DialFunc
}

func (p pipeDialer) Dial(_, _ string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() { _ = Serve(c2, p.allow, p.dial) }()
	return c1, nil
}

func TestServeAllowedAndDenied(t *testing.T) {
	// A fake upstream echo for the allowed destination.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	upstream := ln.Addr().String()

	uHost, uPortStr, _ := net.SplitHostPort(upstream)
	uPortN, _ := strconv.ParseUint(uPortStr, 10, 16)
	uPort := uint16(uPortN)
	allow := func(host string, port uint16) bool {
		return host == uHost && port == uPort
	}

	d := dialViaServe(t, allow, nil)

	// allowed
	conn, err := d.Dial("tcp", upstream)
	if err != nil {
		t.Fatalf("allowed dial failed: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo failed: %q %v", buf, err)
	}
	conn.Close()

	// denied
	if _, err := d.Dial("tcp", "127.0.0.1:9"); err == nil {
		t.Fatal("expected denied destination to fail")
	}
}
