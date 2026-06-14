package l2

import (
	"bufio"
	"io"
	"log"
	"net"
	"sync"
	"testing"
)

// wireStreamPort attaches conn to sw as a port (the pattern used by both the
// server hub and the client uplink): frames sent out go through WritePacket,
// and a reader goroutine injects inbound frames.
func wireStreamPort(sw *Switch, conn net.Conn, name string) {
	var wmu sync.Mutex
	bw := bufio.NewWriter(conn)
	port := sw.AddPort(func(f []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		if err := WritePacket(bw, f); err != nil {
			return err
		}
		return bw.Flush()
	}, PortConfig{Name: name})
	go func() {
		buf := make([]byte, MaxEtherFrame)
		for {
			n, err := ReadPacket(conn, buf)
			if err != nil {
				return
			}
			sw.Inject(port, buf[:n])
		}
	}()
}

// TestEndToEndBridgeOverStream connects a client switch and a server switch
// over a single framed stream (as the carrier yamux stream would) and verifies
// frames bridge across, with learning enabling a unicast reply.
func TestEndToEndBridgeOverStream(t *testing.T) {
	srvEnd, cliEnd := net.Pipe()
	defer srvEnd.Close()
	defer cliEnd.Close()
	discard := log.New(io.Discard, "", 0)

	cliSW := New(nil, discard)
	wireStreamPort(cliSW, cliEnd, "cli-uplink")
	cliLocal := &collector{}
	cliPort := cliSW.AddPort(cliLocal.send, PortConfig{Name: "cli-local"})

	srvSW := New(nil, discard)
	wireStreamPort(srvSW, srvEnd, "srv-uplink")
	srvLocal := &collector{}
	srvPort := srvSW.AddPort(srvLocal.send, PortConfig{Name: "srv-local"})

	// A broadcast from a client-local node must reach the server-local node
	// across the stream, and teaches the server that macA lives via the stream.
	cliSW.Inject(cliPort, frame(bcast, macA, 0x0800, make([]byte, 20)))
	if !waitCount(srvLocal, 1) {
		t.Fatalf("broadcast did not bridge to server: got %d", srvLocal.count())
	}

	// A reply from a server-local node to macA must travel back over the stream
	// and be delivered to the client-local node (which the client switch learned
	// macB on, but more importantly the server unicasts to its uplink port).
	srvSW.Inject(srvPort, frame(macA, macB, 0x0800, make([]byte, 20)))
	if !waitCount(cliLocal, 1) {
		t.Fatalf("unicast reply did not bridge back to client: got %d", cliLocal.count())
	}
}
