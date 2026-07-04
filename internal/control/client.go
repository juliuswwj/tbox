//go:build !android

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/juliuswwj/tbox/internal/destallow"
	"github.com/juliuswwj/tbox/internal/dhcpclient"
	"github.com/juliuswwj/tbox/internal/l2"
	"github.com/juliuswwj/tbox/internal/socks5"
	"github.com/juliuswwj/tbox/internal/tunnel"
)

// ClientTunParams configures the client-side L2 tunnel data plane. It is nil
// when the tunnel is disabled.
type ClientTunParams struct {
	TAPEnable          bool
	TAPName            string
	TAPBridge          string   // "" = no bridge; else enslave TAP to this (auto-created) bridge
	TAPBridgeMembers   []string // extra local NICs to enslave to the bridge
	TAPv4              string   // manual CIDR override; "" uses DHCP
	TAPv6              string
	TAPDHCP            bool       // when true and TAPv4 == "", obtain IP via DHCPv4
	TAPRoutes          []l2.Route // extra routes on the TAP/bridge device
	UDPListen          string     // "" disables the udpt UDP endpoint
	AcceptDefaultRoute bool
	MTU                int
}

// DialFunc opens a carrier connection to the server's control address, tunneled
// through the VLESS-REALITY outbound (typically via the local SOCKS inbound).
type DialFunc func(ctx context.Context) (net.Conn, error)

// Client maintains the control-plane connection from the local machine: it
// authenticates, registers published services, serves reverse streams by
// dialing local upstreams, and supports runtime whitelist updates.
type Client struct {
	uuid         string
	dial         DialFunc
	certs        []CertReg
	services     []ServiceReg
	tun          *ClientTunParams // nil = tunnel disabled
	serverRealIP string           // carrier's real host (or IP) — used to pin default-route exception
	logger       *log.Logger

	serviceByID map[string]ServiceReg
	destSets    map[string]*destallow.Set // socks5 service id -> allowed destinations

	mu         sync.Mutex
	whitelists map[string][]string // service id -> current allow list
	enc        *json.Encoder
	dec        *json.Decoder
	connected  bool
	sendMu     sync.Mutex // serializes request+ack on the control stream
}

// NewClient builds a control client. certs are the (optional) client-provided
// certificates; services are the published services with initial allow lists.
// serverRealIP is the carrier's real host (hostname or IP) used by the tun
// default-route pin so the encrypted TCP connection to the server is not
// captured by the tunnel's own default route. Pass "" to disable the pin.
func NewClient(uuid string, certs []CertReg, services []ServiceReg, tun *ClientTunParams, serverRealIP string, dial DialFunc, logger *log.Logger) *Client {
	if logger == nil {
		logger = log.Default()
	}
	byID := make(map[string]ServiceReg)
	destSets := make(map[string]*destallow.Set)
	whitelists := make(map[string][]string)
	for _, s := range services {
		id := s.ID()
		byID[id] = s
		whitelists[id] = s.Allow
		if s.Mode == "socks5" {
			set, err := destallow.New(s.AllowDest)
			if err != nil {
				logger.Printf("control: %s: invalid allow_dest, denying all: %v", id, err)
				set, _ = destallow.New(nil)
			}
			destSets[id] = set
		}
	}
	return &Client{
		uuid:         uuid,
		dial:         dial,
		certs:        certs,
		services:     services,
		tun:          tun,
		serverRealIP: serverRealIP,
		logger:       logger,
		serviceByID:  byID,
		destSets:     destSets,
		whitelists:   whitelists,
	}
}

// Run keeps a control session alive, reconnecting with backoff until ctx is
// cancelled.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for ctx.Err() == nil {
		err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.logger.Printf("control: session ended: %v (retry in %s)", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if err == nil {
			backoff = time.Second
		} else if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

func (c *Client) session(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("dial control: %w", err)
	}
	sess, err := tunnel.Client(conn)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("yamux client: %w", err)
	}
	defer sess.Close()

	control, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	c.mu.Lock()
	c.enc = json.NewEncoder(control)
	c.dec = json.NewDecoder(control)
	c.connected = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
	}()

	if err := c.request(Message{Type: TypeAuth, UUID: c.uuid}); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if err := c.request(Message{Type: TypeRegister, Certs: c.certs, Services: c.currentServices()}); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	c.logger.Printf("control: connected, registered %d cert(s), %d service(s)", len(c.certs), len(c.services))

	go c.acceptLoop(sess)

	if c.tun != nil {
		node, err := c.startTun(sess)
		if err != nil {
			c.logger.Printf("control: tun setup failed: %v", err)
		} else {
			defer node.Close()
		}
	}

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sess.CloseChan():
			return errors.New("carrier closed")
		case <-ticker.C:
			if err := c.request(Message{Type: TypeHeartbeat}); err != nil {
				return fmt.Errorf("heartbeat: %w", err)
			}
		}
	}
}

func (c *Client) acceptLoop(sess *yamux.Session) {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go c.handleReverse(stream)
	}
}

func (c *Client) handleReverse(stream net.Conn) {
	f, err := tunnel.ReadFrame(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	svc, ok := c.serviceByID[f.Service]
	if !ok {
		c.logger.Printf("control: refusing reverse stream for unknown service %q", f.Service)
		_ = stream.Close()
		return
	}
	if svc.Mode == "socks5" {
		set := c.destSets[f.Service]
		if err := socks5.Serve(stream, set.Allowed, nil); err != nil {
			c.logger.Printf("control: socks5 %s: %v", f.Service, err)
		}
		return
	}
	// http / ws / tcp: dial the service's own upstream and pipe.
	local, err := net.DialTimeout("tcp", svc.Upstream, 10*time.Second)
	if err != nil {
		c.logger.Printf("control: dial local %s for %s: %v", svc.Upstream, f.Service, err)
		_ = stream.Close()
		return
	}
	tunnel.Pipe(stream, local)
}

// UpdateWhitelist sets a service's allow list (by service id, e.g.
// "https://app.example.com/loc/") and pushes it to the server if connected.
// The new list persists locally and is replayed on reconnect.
func (c *Client) UpdateWhitelist(serviceID string, allow []string) error {
	c.mu.Lock()
	if _, ok := c.whitelists[serviceID]; !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown service %q", serviceID)
	}
	c.whitelists[serviceID] = allow
	connected := c.connected
	c.mu.Unlock()
	if !connected {
		return nil // will be replayed on reconnect
	}
	return c.request(Message{Type: TypeUpdateWhitelist, ServiceID: serviceID, Allow: allow})
}

// Whitelist returns the current allow list for a service id.
func (c *Client) Whitelist(serviceID string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.whitelists[serviceID]
	return v, ok
}

// Services returns the published service ids.
func (c *Client) Services() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.whitelists))
	for id := range c.whitelists {
		out = append(out, id)
	}
	return out
}

func (c *Client) currentServices() []ServiceReg {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ServiceReg, len(c.services))
	copy(out, c.services)
	for i := range out {
		if wl, ok := c.whitelists[out[i].ID()]; ok {
			out[i].Allow = wl
		}
	}
	return out
}

// request sends a message and waits for the server's ack, discarding the body.
func (c *Client) request(m Message) error {
	_, err := c.requestResp(m)
	return err
}

// requestResp sends a message and returns the server's ack (so callers can read
// fields such as the tun assignment).
func (c *Client) requestResp(m Message) (Message, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.mu.Lock()
	enc, dec := c.enc, c.dec
	c.mu.Unlock()
	if enc == nil || dec == nil {
		return Message{}, errors.New("not connected")
	}
	if err := enc.Encode(m); err != nil {
		return Message{}, err
	}
	var resp Message
	if err := dec.Decode(&resp); err != nil {
		return Message{}, err
	}
	if resp.Type != TypeAck || !resp.OK {
		return resp, fmt.Errorf("server rejected %s: %s", m.Type, resp.Error)
	}
	return resp, nil
}

// startTun opens the L2 data stream, applies the client's L2 configuration
// (native TAP and/or UDP endpoint), and — when native TAP is enabled without a
// manual IPv4 — obtains an address via DHCPv4 from the server's embedded DHCP
// server. It never relies on any in-protocol IP assignment: the register ack
// carries only the certs/services ack.
func (c *Client) startTun(sess *yamux.Session) (*l2.ClientNode, error) {
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open tun stream: %w", err)
	}
	if err := tunnel.WriteFrame(stream, tunnel.Frame{Service: TunService}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("tag tun stream: %w", err)
	}

	opts := l2.ClientOptions{MTU: c.tun.MTU, UDPListen: c.tun.UDPListen}
	if c.tun.TAPEnable {
		tap := &l2.ClientTAP{
			Name:          c.tun.TAPName,
			Bridge:        c.tun.TAPBridge,
			BridgeMembers: c.tun.TAPBridgeMembers,
			IPv6:          c.tun.TAPv6,
			Routes:        c.tun.TAPRoutes,
		}
		switch {
		case c.tun.TAPv4 != "":
			tap.IPv4CIDR = c.tun.TAPv4
		case c.tun.TAPDHCP:
			// Leave IPv4CIDR empty; DHCPv4 will assign it after the TAP is up.
		default:
			// No static IP and DHCP disabled: only useful when bridging a
			// local segment (pure L2).
		}
		// An address-less TAP is fine when bridging (pure L2 bridge of a local
		// segment); otherwise we need an address to be useful.
		if tap.IPv4CIDR == "" && !c.tun.TAPDHCP && tap.Bridge == "" {
			c.logger.Printf("control: tun TAP enabled but no IPv4, no DHCP, and no bridge; skipping native TAP")
		} else {
			opts.TAP = tap
		}
	}
	if opts.TAP == nil && opts.UDPListen == "" {
		_ = stream.Close()
		return nil, errors.New("tun enabled but neither TAP nor UDP is usable")
	}

	node, err := l2.StartClient(stream, opts, c.logger)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}

	// If we have a native TAP and the user wants DHCP, run DORA now (after the
	// TAP is up and bridged, so the OS can speak DHCP on the right device).
	if c.tun.TAPEnable && c.tun.TAPv4 == "" && c.tun.TAPDHCP && opts.TAP != nil {
		ipDev := opts.TAP.Name
		if opts.TAP.Bridge != "" {
			ipDev = opts.TAP.Bridge
		}
		if err := c.runDHCP(ipDev, opts.TAP); err != nil {
			c.logger.Printf("control: tun DHCP on %s failed: %v", ipDev, err)
		}
	}

	return node, nil
}

// runDHCP performs a one-shot DHCPv4 DORA on ipDev and installs the leased
// IPv4, subnet route, and (when AcceptDefaultRoute is set) a default route via
// the offered gateway. If the server's DHCP ACK provides a router option, we
// also pin the carrier's real host route so the encrypted TCP to the server is
// not captured by the tunnel's own default route.
func (c *Client) runDHCP(ipDev string, tap *l2.ClientTAP) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lease, err := dhcpclient.Discover(ctx, ipDev, c.logger)
	if err != nil {
		return err
	}
	ones, _ := lease.SubnetMask.Size()
	if ones == 0 {
		return fmt.Errorf("DHCP ACK missing subnet mask")
	}
	cidr := fmt.Sprintf("%s/%d", lease.IPv4.String(), ones)
	if err := l2.AddAddr(ipDev, cidr); err != nil {
		return fmt.Errorf("apply leased addr %s: %w", cidr, err)
	}
	// Subnet route (link-scoped) for the assigned prefix.
	subnet := &net.IPNet{IP: lease.IPv4.Mask(lease.SubnetMask), Mask: lease.SubnetMask}
	if err := l2.AddRoute(ipDev, subnet.String()); err != nil {
		c.logger.Printf("control: tun DHCP subnet route %s: %v", subnet.String(), err)
	}
	// Default route via the carrier, if the user opted in and the ACK offered a router.
	if c.tun.AcceptDefaultRoute && lease.Gateway != nil && lease.DefaultRoute {
		if c.serverRealIP != "" {
			if err := l2.AddHostRouteViaCurrentGateway(c.serverRealIP); err != nil {
				c.logger.Printf("control: pin carrier host route %s: %v", c.serverRealIP, err)
			}
		}
		if err := l2.AddDefaultRoute(ipDev, lease.Gateway.String()); err != nil {
			return fmt.Errorf("default route via %s: %w", lease.Gateway.String(), err)
		}
	}
	c.logger.Printf("control: tun DHCP applied %s on %s", cidr, ipDev)
	return nil
}
