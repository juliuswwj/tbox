package l4router

import (
	"errors"
	"io"
)

// peekClientHelloSNI reads the initial TLS ClientHello from r, returning the
// SNI server name (may be empty) and the exact raw bytes consumed so they can
// be replayed to the real TLS terminator. It never discards bytes.
func peekClientHelloSNI(r io.Reader) (sni string, raw []byte, err error) {
	// TLS record header: type(1) version(2) length(2).
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", nil, err
	}
	if hdr[0] != 0x16 { // not a handshake record
		return "", hdr, errors.New("not a TLS handshake")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 16*1024 {
		return "", hdr, errors.New("invalid TLS record length")
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", append(hdr, body...), err
	}
	raw = append(hdr, body...)
	sni = parseSNIFromHandshake(body)
	return sni, raw, nil
}

// parseSNIFromHandshake extracts the SNI from a ClientHello handshake body.
// Returns "" if absent or on any parse issue (caller falls back to mimic).
func parseSNIFromHandshake(b []byte) string {
	p := newParser(b)
	htype, ok := p.u8()
	if !ok || htype != 0x01 { // ClientHello
		return ""
	}
	if _, ok := p.bytes(3); !ok { // handshake length
		return ""
	}
	if _, ok := p.bytes(2); !ok { // client_version
		return ""
	}
	if _, ok := p.bytes(32); !ok { // random
		return ""
	}
	sidLen, ok := p.u8() // session_id
	if !ok {
		return ""
	}
	if _, ok := p.bytes(int(sidLen)); !ok {
		return ""
	}
	csLen, ok := p.u16() // cipher_suites
	if !ok {
		return ""
	}
	if _, ok := p.bytes(int(csLen)); !ok {
		return ""
	}
	cmLen, ok := p.u8() // compression_methods
	if !ok {
		return ""
	}
	if _, ok := p.bytes(int(cmLen)); !ok {
		return ""
	}
	extTotal, ok := p.u16() // extensions length
	if !ok {
		return ""
	}
	ext := newParser(mustBytes(&p, int(extTotal)))
	for ext.remaining() >= 4 {
		extType, _ := ext.u16()
		extLen, _ := ext.u16()
		extData, ok := ext.bytes(int(extLen))
		if !ok {
			return ""
		}
		if extType == 0x0000 { // server_name
			return parseSNIExtension(extData)
		}
	}
	return ""
}

func parseSNIExtension(b []byte) string {
	p := newParser(b)
	if _, ok := p.u16(); !ok { // server_name_list length
		return ""
	}
	for p.remaining() >= 3 {
		nameType, _ := p.u8()
		nameLen, _ := p.u16()
		name, ok := p.bytes(int(nameLen))
		if !ok {
			return ""
		}
		if nameType == 0x00 { // host_name
			return string(name)
		}
	}
	return ""
}

// --- tiny byte parser ---

type parser struct {
	b   []byte
	pos int
}

func newParser(b []byte) parser { return parser{b: b} }

func (p *parser) remaining() int { return len(p.b) - p.pos }

func (p *parser) bytes(n int) ([]byte, bool) {
	if n < 0 || p.pos+n > len(p.b) {
		return nil, false
	}
	out := p.b[p.pos : p.pos+n]
	p.pos += n
	return out, true
}

func (p *parser) u8() (uint8, bool) {
	b, ok := p.bytes(1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func (p *parser) u16() (uint16, bool) {
	b, ok := p.bytes(2)
	if !ok {
		return 0, false
	}
	return uint16(b[0])<<8 | uint16(b[1]), true
}

func mustBytes(p *parser, n int) []byte {
	b, ok := p.bytes(n)
	if !ok {
		return nil
	}
	return b
}
