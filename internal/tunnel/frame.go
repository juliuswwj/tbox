// Package tunnel carries the reverse-tunnel multiplexing over a single
// VLESS-REALITY carrier connection. The server opens yamux streams toward the
// client; each stream begins with a small frame naming the local target the
// client should dial.
package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Mode identifies how the server is using a reverse stream (informational for
// the client, which always just dials Target and pipes bytes).
type Mode string

const (
	ModeHTTP Mode = "http" // server runs an HTTP reverse proxy over the stream
	ModeTCP  Mode = "tcp"  // server bridges a WebSocket (or raw TCP) over the stream
)

// Frame is the stream header written by the server when opening a reverse
// stream. Target is the local upstream the client must connect to; the client
// validates Target against the set it registered.
type Frame struct {
	Mode   Mode   `json:"mode"`
	Target string `json:"target"`
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
