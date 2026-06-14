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
	services []ServiceReg
	logger   *log.Logger

	allowedTargets map[string]bool

	mu         sync.Mutex
	whitelists map[string][]string // domain -> current allow list
	enc        *json.Encoder
	dec        *json.Decoder
	connected  bool
	sendMu     sync.Mutex // serializes request+ack on the control stream
}

// NewClient builds a control client. services are the published services
// (already populated with cert/key PEM and initial allow lists).
func NewClient(uuid string, services []ServiceReg, dial DialFunc, logger *log.Logger) *Client {
	if logger == nil {
		logger = log.Default()
	}
	targets := make(map[string]bool)
	whitelists := make(map[string][]string)
	for _, s := range services {
		whitelists[s.Domain] = s.Allow
		for _, r := range s.Routes {
			if r.Upstream != "" {
				targets[r.Upstream] = true
			}
		}
		if s.WSUpstream != "" {
			targets[s.WSUpstream] = true
		}
	}
	return &Client{
		uuid:           uuid,
		dial:           dial,
		services:       services,
		logger:         logger,
		allowedTargets: targets,
		whitelists:     whitelists,
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
	if err := c.request(Message{Type: TypeRegister, Services: c.currentServices()}); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	c.logger.Printf("control: connected and registered %d service(s)", len(c.services))

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
	if !c.allowedTargets[f.Target] {
		c.logger.Printf("control: refusing reverse stream to unregistered target %q", f.Target)
		_ = stream.Close()
		return
	}
	local, err := net.DialTimeout("tcp", f.Target, 10*time.Second)
	if err != nil {
		c.logger.Printf("control: dial local %s: %v", f.Target, err)
		_ = stream.Close()
		return
	}
	tunnel.Pipe(stream, local)
}

// UpdateWhitelist sets a domain's allow list and pushes it to the server if
// connected. The new list persists locally and is replayed on reconnect.
func (c *Client) UpdateWhitelist(domain string, allow []string) error {
	c.mu.Lock()
	if _, ok := c.whitelists[domain]; !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown domain %q", domain)
	}
	c.whitelists[domain] = allow
	connected := c.connected
	c.mu.Unlock()
	if !connected {
		return nil // will be replayed on reconnect
	}
	return c.request(Message{Type: TypeUpdateWhitelist, Domain: domain, Allow: allow})
}

// Whitelist returns the current allow list for a domain.
func (c *Client) Whitelist(domain string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.whitelists[domain]
	return v, ok
}

// Domains returns the published domains.
func (c *Client) Domains() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.whitelists))
	for d := range c.whitelists {
		out = append(out, d)
	}
	return out
}

func (c *Client) currentServices() []ServiceReg {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ServiceReg, len(c.services))
	copy(out, c.services)
	for i := range out {
		if wl, ok := c.whitelists[out[i].Domain]; ok {
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
