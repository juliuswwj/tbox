package l2

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sync"
)

// Route is an extra route to install on the TAP/bridge device. Gw == "" means a
// link-scoped route via the device; otherwise the route is via Gw.
type Route struct {
	Dst string // CIDR
	Gw  string // optional gateway
}

// ClientTAP describes an optional native TAP attachment on the client, making
// the client itself a node on the tunnel's L2 segment.
type ClientTAP struct {
	Name          string
	Bridge        string   // if set, enslave the TAP to this bridge and put the IP on it
	BridgeMembers []string // extra local NICs to also enslave to the bridge
	IPv4CIDR      string   // CIDR; "" leaves the interface address-less
	IPv6          string   // CIDR; optional
	Routes        []Route  // extra routes installed on the TAP/bridge device
	DefaultRoute  bool
	Gateway       string
	SubnetRoute   string
	ServerRealIP  string // pinned to the current default route when DefaultRoute is set
}

// ClientOptions configures a client-side L2 node.
type ClientOptions struct {
	MTU       int
	TAP       *ClientTAP // nil = no native TAP
	UDPListen string     // "" = no UDP endpoint for external udpt clients
}

// ClientNode bridges an uplink data stream (to the server hub) with local
// endpoints: an optional native TAP and an optional UDP endpoint fronting
// unmodified udpt.py clients. All share one client-side Switch.
type ClientNode struct {
	sw            *Switch
	stream        net.Conn
	dev           *Device
	udp           *UDPEndpoint
	createdBridge string   // bridge tbox created and must remove on close ("" = none)
	bridgeMembers []string // local NICs tbox enslaved, to detach on close
	logger        *log.Logger

	closeOnce sync.Once
}

// StartClient wires the uplink stream into a Switch and attaches the configured
// local endpoints. stream must already carry the tun stream tag (the caller
// writes the tunnel frame before calling).
func StartClient(stream net.Conn, opts ClientOptions, logger *log.Logger) (*ClientNode, error) {
	if logger == nil {
		logger = log.Default()
	}
	sw := New(nil, logger)
	n := &ClientNode{sw: sw, stream: stream, logger: logger}

	// Uplink port over the carrier stream.
	var wmu sync.Mutex
	bw := bufio.NewWriterSize(stream, 4096)
	send := func(frame []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		if err := WritePacket(bw, frame); err != nil {
			return err
		}
		return bw.Flush()
	}
	uplink := sw.AddPort(send, PortConfig{Name: "uplink"})
	go func() {
		buf := make([]byte, MaxEtherFrame)
		for {
			m, err := ReadPacket(stream, buf)
			if err != nil {
				n.Close()
				return
			}
			sw.Inject(uplink, buf[:m])
		}
	}()

	if opts.TAP != nil {
		if err := n.startTAP(opts.TAP, opts.MTU); err != nil {
			n.Close()
			return nil, err
		}
	}
	if opts.UDPListen != "" {
		ep, err := NewUDPEndpoint(opts.UDPListen, sw, logger)
		if err != nil {
			n.Close()
			return nil, err
		}
		n.udp = ep
		logger.Printf("l2: udpt endpoint listening on %s", opts.UDPListen)
	}
	return n, nil
}

func (n *ClientNode) startTAP(t *ClientTAP, mtu int) error {
	dev, err := Open(t.Name)
	if err != nil {
		return err
	}
	n.dev = dev
	name := dev.Name()
	if err := SetUp(name, mtu); err != nil {
		return err
	}

	// When bridging, the TAP becomes a bridge port (no L3 address); the IP and
	// routes go on the bridge. tbox creates the bridge if it does not exist.
	ipDev := name
	if t.Bridge != "" {
		created, err := EnsureBridge(t.Bridge)
		if err != nil {
			return err
		}
		if created {
			n.createdBridge = t.Bridge
		}
		if err := AddToBridge(name, t.Bridge); err != nil {
			return err
		}
		if err := SetUp(t.Bridge, mtu); err != nil {
			return err
		}
		// Enslave any extra local NICs so their segment is bridged in too.
		for _, m := range t.BridgeMembers {
			if err := AddToBridge(m, t.Bridge); err != nil {
				return fmt.Errorf("enslave %q to %q: %w", m, t.Bridge, err)
			}
			n.bridgeMembers = append(n.bridgeMembers, m)
		}
		ipDev = t.Bridge
	}

	if t.IPv4CIDR != "" {
		if err := AddAddr(ipDev, t.IPv4CIDR); err != nil {
			return err
		}
	}
	if t.IPv6 != "" {
		if err := AddAddr(ipDev, t.IPv6); err != nil {
			return err
		}
	}
	if t.SubnetRoute != "" {
		if err := AddRoute(ipDev, t.SubnetRoute); err != nil {
			return err
		}
	}
	if t.DefaultRoute && t.Gateway != "" {
		if t.ServerRealIP != "" {
			if err := AddHostRouteViaCurrentGateway(t.ServerRealIP); err != nil {
				n.logger.Printf("l2: pin carrier host route %s: %v", t.ServerRealIP, err)
			}
		}
		if err := AddDefaultRoute(ipDev, t.Gateway); err != nil {
			return err
		}
	}
	// Custom user-specified routes (link-scoped or via a gateway).
	for _, rt := range t.Routes {
		if rt.Gw != "" {
			if err := AddRouteVia(ipDev, rt.Dst, rt.Gw); err != nil {
				return err
			}
		} else if err := AddRoute(ipDev, rt.Dst); err != nil {
			return err
		}
	}

	port := n.sw.AddPort(func(frame []byte) error {
		_, werr := dev.Write(frame)
		return werr
	}, PortConfig{Name: "tap:" + name})
	go func() {
		buf := make([]byte, MaxEtherFrame)
		for {
			m, err := dev.Read(buf)
			if err != nil {
				return
			}
			n.sw.Inject(port, buf[:m])
		}
	}()
	if t.Bridge != "" {
		n.logger.Printf("l2: native TAP %s up (mtu %d), bridged to %s", name, mtu, t.Bridge)
	} else {
		n.logger.Printf("l2: native TAP %s up (mtu %d)", name, mtu)
	}
	return nil
}

// Close tears down the node: closes the UDP endpoint, the TAP (removing its
// interface, addresses, and routes), and the uplink stream.
func (n *ClientNode) Close() error {
	n.closeOnce.Do(func() {
		if n.udp != nil {
			_ = n.udp.Close()
		}
		if n.dev != nil {
			_ = n.dev.Close() // removes the TAP, auto-detaching it from any bridge
		}
		for _, m := range n.bridgeMembers {
			_ = RemoveFromBridge(m) // return enslaved NICs to standalone
		}
		if n.createdBridge != "" {
			_ = DelLink(n.createdBridge) // remove the bridge tbox created
		}
		_ = n.stream.Close()
	})
	return nil
}
