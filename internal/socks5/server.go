// Package socks5 implements a minimal SOCKS5 CONNECT server used by a tbox
// client to back a published socks5 service. Access to the listener is already
// gated (TLS + source-IP whitelist at the server), so no SOCKS-level auth is
// required; the only policy enforced here is the destination allow list.
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	version5   = 0x05
	cmdConnect = 0x01
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repNotAllowed      = 0x02
	repHostUnreachable = 0x04
	repCmdNotSupported = 0x07
)

// AllowFunc reports whether dialing host:port is permitted.
type AllowFunc func(host string, port uint16) bool

// DialFunc dials a destination (defaults to net.Dialer).
type DialFunc func(host string, port uint16) (net.Conn, error)

// Serve handles one SOCKS5 client connection over conn: greeting, a single
// CONNECT request (checked against allow), dial, reply, then bidirectional copy.
// conn is always closed before Serve returns.
func Serve(conn net.Conn, allow AllowFunc, dial DialFunc) error {
	defer conn.Close()
	if dial == nil {
		dial = func(host string, port uint16) (net.Conn, error) {
			return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 10*time.Second)
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := handshake(conn); err != nil {
		return err
	}
	host, port, err := readConnect(conn)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})

	if allow == nil || !allow(host, port) {
		_ = reply(conn, repNotAllowed)
		return fmt.Errorf("socks5: destination %s:%d not allowed", host, port)
	}

	upstream, err := dial(host, port)
	if err != nil {
		_ = reply(conn, repHostUnreachable)
		return fmt.Errorf("socks5: dial %s:%d: %w", host, port, err)
	}
	defer upstream.Close()

	if err := reply(conn, repSuccess); err != nil {
		return err
	}
	pipe(conn, upstream)
	return nil
}

func handshake(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != version5 {
		return fmt.Errorf("socks5: bad version 0x%02x", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	// Reply: no authentication required (0x00).
	_, err := conn.Write([]byte{version5, 0x00})
	return err
}

func readConnect(conn net.Conn) (string, uint16, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", 0, err
	}
	if hdr[0] != version5 {
		return "", 0, fmt.Errorf("socks5: bad request version 0x%02x", hdr[0])
	}
	if hdr[1] != cmdConnect {
		_ = reply(conn, repCmdNotSupported)
		return "", 0, fmt.Errorf("socks5: unsupported command 0x%02x", hdr[1])
	}
	var host string
	switch hdr[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		_ = reply(conn, repGeneralFailure)
		return "", 0, fmt.Errorf("socks5: bad address type 0x%02x", hdr[3])
	}
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(p[:]), nil
}

// reply writes a SOCKS5 reply with a zero BND.ADDR/PORT (clients ignore it for CONNECT).
func reply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{version5, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
}
