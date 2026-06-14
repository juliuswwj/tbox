package control

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/juliuswwj/tbox/internal/l2"
)

// TunHub is the server-side L2 tunnel hub. It owns the Switch (whose ports are
// the local TAP and each client's carrier data stream) and assigns stable
// virtual IPv4 addresses to native-TAP clients from a pool. External udpt.py
// clients self-configure and do not draw from the pool.
type TunHub struct {
	sw           *l2.Switch
	gateway      string
	mtu          int
	pool         *net.IPNet
	offerDefault bool
	serverRealIP string
	logger       *log.Logger

	mu       sync.Mutex
	assigned map[string]string // clientID -> assigned IPv4 (no mask)
	used     map[string]bool   // IPv4 -> in use
}

// NewTunHub creates a hub around an already-running Switch.
func NewTunHub(sw *l2.Switch, gateway string, pool *net.IPNet, mtu int, offerDefault bool, serverRealIP string, logger *log.Logger) *TunHub {
	if logger == nil {
		logger = log.Default()
	}
	return &TunHub{
		sw: sw, gateway: gateway, mtu: mtu, pool: pool,
		offerDefault: offerDefault, serverRealIP: serverRealIP, logger: logger,
		assigned: make(map[string]string), used: make(map[string]bool),
	}
}

// Assign returns a stable virtual-network assignment for clientID, allocating a
// new pool address on first use. Returns nil if the pool is exhausted.
func (h *TunHub) Assign(clientID string) *TunAssignment {
	h.mu.Lock()
	defer h.mu.Unlock()
	ip := h.assigned[clientID]
	if ip == "" {
		ip = h.allocLocked()
		if ip == "" {
			h.logger.Printf("control: tun pool exhausted, no address for %s", shortID(clientID))
			return nil
		}
		h.assigned[clientID] = ip
		h.used[ip] = true
	}
	ones, _ := h.pool.Mask.Size()
	return &TunAssignment{
		IPv4CIDR:     fmt.Sprintf("%s/%d", ip, ones),
		Gateway:      h.gateway,
		MTU:          h.mtu,
		SubnetRoute:  h.pool.String(),
		DefaultRoute: h.offerDefault,
		ServerRealIP: h.serverRealIP,
	}
}

// allocLocked returns the next free host address (skipping network, gateway,
// and broadcast). Caller holds h.mu.
func (h *TunHub) allocLocked() string {
	network := h.pool.IP.Mask(h.pool.Mask)
	bcast := broadcast(h.pool)
	ip := make(net.IP, len(network))
	copy(ip, network)
	for {
		incIP(ip)
		if !h.pool.Contains(ip) || ip.Equal(bcast) {
			return ""
		}
		s := ip.String()
		if s == h.gateway || h.used[s] {
			continue
		}
		return s
	}
}

// ServeClient attaches a client's data stream as a switch port and pumps frames
// until the stream closes.
func (h *TunHub) ServeClient(clientID string, stream net.Conn) {
	var wmu sync.Mutex
	bw := bufio.NewWriterSize(stream, 4096)
	send := func(frame []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		if err := l2.WritePacket(bw, frame); err != nil {
			return err
		}
		return bw.Flush()
	}
	port := h.sw.AddPort(send, l2.PortConfig{Name: "client:" + shortID(clientID)})
	defer h.sw.RemovePort(port)
	h.logger.Printf("control: tun client %s attached", shortID(clientID))
	defer h.logger.Printf("control: tun client %s detached", shortID(clientID))

	buf := make([]byte, l2.MaxEtherFrame)
	for {
		n, err := l2.ReadPacket(stream, buf)
		if err != nil {
			return
		}
		h.sw.Inject(port, buf[:n])
	}
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func broadcast(n *net.IPNet) net.IP {
	ip := n.IP.Mask(n.Mask)
	b := make(net.IP, len(ip))
	for i := range ip {
		b[i] = ip[i] | ^n.Mask[i]
	}
	return b
}
