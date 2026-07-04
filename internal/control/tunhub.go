package control

import (
	"bufio"
	"log"
	"net"
	"sync"

	"github.com/juliuswwj/tbox/internal/l2"
)

// TunHub is the server-side L2 tunnel hub. It owns the Switch (whose ports are
// the local TAP and each client's carrier data stream) and bridges Ethernet
// frames between them. Virtual IPv4 addresses are no longer assigned by the
// hub: an embedded DHCPv4 server (internal/dhcpserver) listens on the TAP and
// hands out leases from the configured pool, so any L2 peer — native tbox
// client or unmodified udpt.py — gets an address the same way.
type TunHub struct {
	sw     *l2.Switch
	logger *log.Logger
}

// NewTunHub creates a hub around an already-running Switch.
func NewTunHub(sw *l2.Switch, logger *log.Logger) *TunHub {
	if logger == nil {
		logger = log.Default()
	}
	return &TunHub{sw: sw, logger: logger}
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
