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
	"github.com/juliuswwj/tbox/internal/socks5"
	"github.com/juliuswwj/tbox/internal/tunnel"
)

// DialFunc opens a carrier connection to the server's control address, tunneled
// through the VLESS-REALITY outbound (typically via the local SOCKS inbound).
type DialFunc func(ctx context.Context) (net.Conn, error)

// Client maintains the control-plane connection from the local machine: it
// authenticates, registers published services, serves reverse streams by
// dialing local upstreams, and supports runtime whitelist updates.
type Client struct {
	uuid     string
	dial     DialFunc
	certs    []CertReg
	services []ServiceReg
	logger   *log.Logger

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
func NewClient(uuid string, certs []CertReg, services []ServiceReg, dial DialFunc, logger *log.Logger) *Client {
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
		uuid:        uuid,
		dial:        dial,
		certs:       certs,
		services:    services,
		logger:      logger,
		serviceByID: byID,
		destSets:    destSets,
		whitelists:  whitelists,
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

// request sends a message and waits for the server's ack.
func (c *Client) request(m Message) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.mu.Lock()
	enc, dec := c.enc, c.dec
	c.mu.Unlock()
	if enc == nil || dec == nil {
		return errors.New("not connected")
	}
	if err := enc.Encode(m); err != nil {
		return err
	}
	var resp Message
	if err := dec.Decode(&resp); err != nil {
		return err
	}
	if resp.Type != TypeAck || !resp.OK {
		return fmt.Errorf("server rejected %s: %s", m.Type, resp.Error)
	}
	return nil
}
