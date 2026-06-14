// Package l2 carries raw Ethernet frames across a tbox carrier so the tunnel
// can act as an L2 segment, absorbing the model of the reference udpt.py
// bridge. A central Switch does MAC learning and forwarding between ports; a
// port may be a yamux stream, a local TAP device, or a UDP endpoint that
// fronts external udpt clients.
package l2

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxEtherFrame bounds a single frame on the wire. The reference bridge uses an
// MTU of 1448; 1600 leaves headroom for the 14-byte Ethernet header and any
// VLAN tags while staying well under the 2-byte length prefix's range.
const MaxEtherFrame = 1600

// WritePacket frames one Ethernet frame as a 2-byte big-endian length prefix
// followed by the raw frame bytes. It mirrors tunnel.WriteFrame but is a
// per-packet datagram codec rather than a one-shot header.
func WritePacket(w io.Writer, frame []byte) error {
	if len(frame) == 0 || len(frame) > MaxEtherFrame {
		return fmt.Errorf("l2: frame length %d out of range", len(frame))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(frame)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(frame)
	return err
}

// ReadPacket reads one length-prefixed frame into buf and returns its length.
// buf must be at least MaxEtherFrame bytes.
func ReadPacket(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > MaxEtherFrame {
		return 0, fmt.Errorf("l2: invalid frame length %d", n)
	}
	if n > len(buf) {
		return 0, fmt.Errorf("l2: buffer too small for frame of %d bytes", n)
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}
