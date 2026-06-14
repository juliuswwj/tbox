package l2

import (
	"io"
	"log"
	"net/netip"
	"sync"
	"testing"
)

// collector is a test port sink that records frames sent to it.
type collector struct {
	mu     sync.Mutex
	frames [][]byte
}

func (c *collector) send(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(frame))
	copy(cp, frame)
	c.frames = append(c.frames, cp)
	return nil
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.frames)
}

var (
	macA  = MAC{0x02, 0, 0, 0, 0, 0xA}
	macB  = MAC{0x02, 0, 0, 0, 0, 0xB}
	macC  = MAC{0x02, 0, 0, 0, 0, 0xC}
	bcast = MAC{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
)

func frame(dst, src MAC, etherType uint16, payload []byte) []byte {
	f := make([]byte, 14+len(payload))
	copy(f[0:6], dst[:])
	copy(f[6:12], src[:])
	f[12] = byte(etherType >> 8)
	f[13] = byte(etherType)
	copy(f[14:], payload)
	return f
}

func ipv4Frame(dst, src MAC, srcIP [4]byte) []byte {
	// minimal IPv4 header: src IP lives at frame bytes 26..30 (eth 14 + ip 12)
	payload := make([]byte, 20)
	copy(payload[12:16], srcIP[:])
	return frame(dst, src, 0x0800, payload)
}

func newTestSwitch() *Switch {
	return New(nil, log.New(io.Discard, "", 0))
}

func TestUnicastForwardingAfterLearning(t *testing.T) {
	sw := newTestSwitch()
	ca, cb, cc := &collector{}, &collector{}, &collector{}
	pa := sw.AddPort(ca.send, PortConfig{Name: "a"})
	pb := sw.AddPort(cb.send, PortConfig{Name: "b"})
	_ = sw.AddPort(cc.send, PortConfig{Name: "c"})

	// A -> B before B is known: unknown unicast floods to B and C (not A).
	sw.Inject(pa, frame(macB, macA, 0x0800, nil))
	if cb.count() != 1 || cc.count() != 1 || ca.count() != 0 {
		t.Fatalf("unknown unicast flood wrong: a=%d b=%d c=%d", ca.count(), cb.count(), cc.count())
	}

	// B -> A: A was learned from the first frame, so this is a clean unicast to A only.
	sw.Inject(pb, frame(macA, macB, 0x0800, nil))
	if ca.count() != 1 || cb.count() != 1 || cc.count() != 1 {
		t.Fatalf("unicast not delivered to A only: a=%d b=%d c=%d", ca.count(), cb.count(), cc.count())
	}
}

func TestBroadcastFloods(t *testing.T) {
	sw := newTestSwitch()
	ca, cb, cc := &collector{}, &collector{}, &collector{}
	pa := sw.AddPort(ca.send, PortConfig{Name: "a"})
	_ = sw.AddPort(cb.send, PortConfig{Name: "b"})
	_ = sw.AddPort(cc.send, PortConfig{Name: "c"})

	sw.Inject(pa, frame(bcast, macA, 0x0806, nil))
	if ca.count() != 0 || cb.count() != 1 || cc.count() != 1 {
		t.Fatalf("broadcast flood wrong: a=%d b=%d c=%d", ca.count(), cb.count(), cc.count())
	}
}

func TestAntiSpoofDropsForeignSource(t *testing.T) {
	sw := newTestSwitch()
	ca, cb := &collector{}, &collector{}
	pa := sw.AddPort(ca.send, PortConfig{
		Name:      "a",
		AllowedV4: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/24")},
	})
	_ = sw.AddPort(cb.send, PortConfig{Name: "b"})

	// Source 10.42.0.7 is allowed -> forwarded (floods to b).
	sw.Inject(pa, ipv4Frame(macB, macA, [4]byte{10, 42, 0, 7}))
	if cb.count() != 1 {
		t.Fatalf("allowed source dropped: b=%d", cb.count())
	}
	// Source 192.168.1.1 is outside the allow list -> dropped, B unchanged.
	sw.Inject(pa, ipv4Frame(macB, macA, [4]byte{192, 168, 1, 1}))
	if cb.count() != 1 {
		t.Fatalf("spoofed source not dropped: b=%d", cb.count())
	}
}

func TestRemovePortForgetsMACs(t *testing.T) {
	sw := newTestSwitch()
	ca, cb := &collector{}, &collector{}
	pa := sw.AddPort(ca.send, PortConfig{Name: "a"})
	pb := sw.AddPort(cb.send, PortConfig{Name: "b"})

	sw.Inject(pa, frame(macB, macA, 0x0800, nil)) // learn A on port a
	sw.RemovePort(pa)

	// B -> A now that A's port is gone: should not panic; A is unknown so it
	// floods to remaining ports (none except b, which is the source) => nothing.
	sw.Inject(pb, frame(macA, macB, 0x0800, nil))
	if ca.count() != 0 {
		t.Fatalf("frame delivered to removed port: a=%d", ca.count())
	}
}
