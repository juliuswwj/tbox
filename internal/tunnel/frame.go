// Package tunnel carries the reverse-tunnel multiplexing over a single
// VLESS-REALITY carrier connection. The server opens yamux streams toward the
// client; each stream begins with a small frame naming the service the stream
// belongs to. The client resolves what to do (dial an upstream, run a SOCKS5
// server, …) from its own configuration for that service id — it never trusts a
// server-provided destination.
package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame is the stream header written by the server when opening a reverse
// stream. Service is the canonical service id (e.g. "https://app.example.com/x/"
// or "tcp://ssh.example.com").
type Frame struct {
	Service string `json:"service"`
}

const maxFrameLen = 64 * 1024

// WriteFrame writes a length-prefixed JSON frame.
func WriteFrame(w io.Writer, f Frame) error {
	data := mustJSON(f)
	if len(data) > maxFrameLen {
		return fmt.Errorf("frame too large: %d", len(data))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadFrame reads a length-prefixed JSON frame.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrameLen {
		return Frame{}, fmt.Errorf("invalid frame length: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Frame{}, err
	}
	return parseJSON(buf)
}
