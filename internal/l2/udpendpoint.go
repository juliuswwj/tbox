package l2

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
)

// UDPEndpoint fronts external udpt.py clients over a local UDP socket. Each
// distinct udpt peer (by UDP address) becomes its own port on the shared
// Switch, so the switch forwards between local udpt clients directly — A->B
// traffic is switched on this host and never traverses the carrier to the
// server — while still bridging to the uplink/TAP for destinations that live
// elsewhere. This mirrors the reference udpt.py server, which switches between
// clients on its single UDP socket. Unmodified udpt.py clients join with
// `--target <listen> --ip ...`.
type UDPEndpoint struct {
	conn   *net.UDPConn
	sw     *Switch
	logger *log.Logger

	mu    sync.Mutex
	peers map[string]*Port // UDP address -> switch port
}

// ping/pong are the reference bridge's keepalive control datagrams; like
// udpt.py we treat any datagram shorter than 20 bytes as control, not a frame.
var (
	pingMsg = []byte("ping")
	pongMsg = []byte("pong")
)

const minFrameLen = 20

// NewUDPEndpoint binds listen (host:port) and starts serving udpt peers.
func NewUDPEndpoint(listen string, sw *Switch, logger *log.Logger) (*UDPEndpoint, error) {
	if logger == nil {
		logger = log.Default()
	}
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %q: %w", listen, err)
	}
	ep := &UDPEndpoint{conn: conn, sw: sw, logger: logger, peers: make(map[string]*Port)}
	go ep.readLoop()
	return ep, nil
}

func (ep *UDPEndpoint) readLoop() {
	buf := make([]byte, MaxEtherFrame)
	for {
		n, addr, err := ep.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed
		}
		if n < minFrameLen {
			// Control datagram (udpt.py ping/pong/hello). Answer ping locally.
			if bytes.Equal(buf[:n], pingMsg) {
				_, _ = ep.conn.WriteToUDP(pongMsg, addr)
			}
			continue
		}
		ep.sw.Inject(ep.peerPort(addr), buf[:n])
	}
}

// peerPort returns the switch port for a udpt peer address, creating it on
// first sight. The port's send delivers a frame to that specific peer.
func (ep *UDPEndpoint) peerPort(addr *net.UDPAddr) *Port {
	key := addr.String()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if p, ok := ep.peers[key]; ok {
		return p
	}
	peer := *addr // capture by value for the closure
	p := ep.sw.AddPort(func(frame []byte) error {
		_, err := ep.conn.WriteToUDP(frame, &peer)
		return err
	}, PortConfig{Name: "udpt:" + key})
	ep.peers[key] = p
	ep.logger.Printf("l2: udpt peer %s joined", key)
	return p
}

// Close detaches all peer ports and closes the socket.
func (ep *UDPEndpoint) Close() error {
	ep.mu.Lock()
	for _, p := range ep.peers {
		ep.sw.RemovePort(p)
	}
	ep.peers = make(map[string]*Port)
	ep.mu.Unlock()
	return ep.conn.Close()
}
