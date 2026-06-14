package l2

import (
	"bytes"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func waitCount(c *collector, want int) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.count() >= want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestUDPEndpointPingPongAndBridging(t *testing.T) {
	sw := New(nil, log.New(io.Discard, "", 0))
	uplink := &collector{}
	uplinkPort := sw.AddPort(uplink.send, PortConfig{Name: "uplink"})

	ep, err := NewUDPEndpoint("127.0.0.1:0", sw, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewUDPEndpoint: %v", err)
	}
	defer ep.Close()

	client, err := net.DialUDP("udp", nil, ep.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// ping -> pong (handled locally by the endpoint, not bridged).
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 16)
	n, err := client.Read(reply)
	if err != nil || !bytes.Equal(reply[:n], pongMsg) {
		t.Fatalf("expected pong, got %q err=%v", reply[:n], err)
	}

	// A frame from the udpt client (src macA) is learned and bridged up to the
	// switch, which floods it to the uplink (macB unknown).
	if _, err := client.Write(frame(macB, macA, 0x0800, make([]byte, 20))); err != nil {
		t.Fatal(err)
	}
	if !waitCount(uplink, 1) {
		t.Fatalf("frame not bridged to uplink: got %d", uplink.count())
	}

	// A frame arriving from the uplink destined to macA must be unicast back to
	// the udpt client over UDP (the endpoint learned macA -> client addr).
	sw.Inject(uplinkPort, frame(macA, macB, 0x0800, make([]byte, 20)))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	rbuf := make([]byte, MaxEtherFrame)
	rn, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("client did not receive bridged frame: %v", err)
	}
	var gotDst MAC
	copy(gotDst[:], rbuf[0:6])
	if gotDst != macA {
		t.Fatalf("wrong dst delivered to client: %v", gotDst)
	}
	_ = rn
}

// TestUDPEndpointIntraSwitch verifies that two udpt clients on the same
// endpoint are switched locally (A->B) and that such traffic does NOT leak up
// to the uplink (it stays on this host, off the carrier).
func TestUDPEndpointIntraSwitch(t *testing.T) {
	sw := New(nil, log.New(io.Discard, "", 0))
	uplink := &collector{}
	_ = sw.AddPort(uplink.send, PortConfig{Name: "uplink"})

	ep, err := NewUDPEndpoint("127.0.0.1:0", sw, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewUDPEndpoint: %v", err)
	}
	defer ep.Close()
	epAddr := ep.conn.LocalAddr().(*net.UDPAddr)

	clientA, err := net.DialUDP("udp", nil, epAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.DialUDP("udp", nil, epAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	// B announces itself with a broadcast so the switch learns macB -> portB.
	if _, err := clientB.Write(frame(bcast, macB, 0x0800, make([]byte, 20))); err != nil {
		t.Fatal(err)
	}
	if !waitCount(uplink, 1) { // broadcast floods to uplink too
		t.Fatalf("broadcast not seen on uplink: %d", uplink.count())
	}
	uplinkAfterBroadcast := uplink.count()

	// A sends a unicast to macB. It must be delivered to B over UDP and must NOT
	// be sent up the uplink (B lives on this host).
	if _, err := clientA.Write(frame(macB, macA, 0x0800, make([]byte, 20))); err != nil {
		t.Fatal(err)
	}
	_ = clientB.SetReadDeadline(time.Now().Add(2 * time.Second))
	rbuf := make([]byte, MaxEtherFrame)
	if _, err := clientB.Read(rbuf); err != nil {
		t.Fatalf("B did not receive A's unicast locally: %v", err)
	}
	var dst, src MAC
	copy(dst[:], rbuf[0:6])
	copy(src[:], rbuf[6:12])
	if dst != macB || src != macA {
		t.Fatalf("B received wrong frame: dst=%v src=%v", dst, src)
	}
	// The unicast A->B must not have leaked onto the uplink.
	time.Sleep(50 * time.Millisecond)
	if uplink.count() != uplinkAfterBroadcast {
		t.Fatalf("intra-client unicast leaked to uplink: before=%d after=%d", uplinkAfterBroadcast, uplink.count())
	}
}
