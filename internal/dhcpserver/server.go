// Package dhcpserver embeds a minimal DHCPv4 server that hands out addresses
// from a configured pool over a L2 segment. It is the sole IP-allocation
// authority for the tbox virtual network, replacing the legacy in-protocol
// TunAssignment scheme so that both native tbox clients and unmodified udpt.py
// peers obtain addresses through the standard DORA exchange.
package dhcpserver

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
)

// Config describes the pool and per-lease options the server offers.
type Config struct {
	// Iface is the L2 device the server listens on (e.g. "tbox0"). The DHCP
	// socket is bound to it via SO_BINDTODEVICE so traffic stays on the
	// virtual segment.
	Iface string
	// Pool is the subnet to allocate from (e.g. 10.42.0.0/24).
	Pool *net.IPNet
	// Gateway is the router address handed to clients (also the server's own
	// address on the segment).
	Gateway net.IP
	// LeaseTime is the duration offered. Defaults to 1 hour when zero.
	LeaseTime time.Duration
	// OfferDefaultRoute, when true, makes the DHCP ACK include the default
	// route option (option 3 with 0.0.0.0/0 semantics via gateway) so clients
	// install a default route through the tunnel.
	OfferDefaultRoute bool
}

// Server is a running embedded DHCPv4 server. Close stops serving and releases
// the bound UDP socket.
type Server struct {
	cfg    Config
	srv    *server4.Server
	logger *log.Logger

	mu     sync.Mutex
	used   map[string]bool      // leased IPv4 (string form) -> in use
	byChid map[string]string    // client identifier (chaddr) -> leased IPv4
	expiry map[string]time.Time // leased IPv4 -> lease expiry
}

// New constructs (but does not start) a server. Call Start to begin serving.
func New(cfg Config, logger *log.Logger) (*Server, error) {
	if cfg.Pool == nil {
		return nil, fmt.Errorf("dhcpserver: nil pool")
	}
	if cfg.Gateway == nil {
		return nil, fmt.Errorf("dhcpserver: nil gateway")
	}
	if cfg.LeaseTime == 0 {
		cfg.LeaseTime = time.Hour
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		cfg:    cfg,
		logger: logger,
		used:   make(map[string]bool),
		byChid: make(map[string]string),
		expiry: make(map[string]time.Time),
	}, nil
}

// Start binds the DHCP socket (UDP/67) on the configured interface and begins
// serving requests in a background goroutine. Returns an error if the bind
// fails. The server runs until Close is called or the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ServerPort}
	srv, err := server4.NewServer(s.cfg.Iface, laddr, s.handle)
	if err != nil {
		return fmt.Errorf("dhcpserver: bind %s:67: %w", s.cfg.Iface, err)
	}
	s.srv = srv
	go func() {
		if err := srv.Serve(); err != nil {
			s.logger.Printf("dhcpserver: serve ended: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	s.logger.Printf("dhcpserver: listening on %s:67, pool %s, gw %s, lease %s, default-route=%v",
		s.cfg.Iface, s.cfg.Pool, s.cfg.Gateway, s.cfg.LeaseTime, s.cfg.OfferDefaultRoute)
	return nil
}

// Close stops serving and closes the socket. Safe to call multiple times.
func (s *Server) Close() error {
	if s.srv == nil {
		return nil
	}
	err := s.srv.Close()
	s.srv = nil
	return err
}

func (s *Server) handle(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	reply, logErr := s.buildReply(req)
	if logErr != nil {
		s.logger.Printf("dhcpserver: %v", logErr)
		return
	}
	if reply == nil {
		return
	}
	if _, err := conn.WriteTo(reply.ToBytes(), peer); err != nil {
		s.logger.Printf("dhcpserver: write reply: %v", err)
	}
}

// buildReply dispatches on message type to produce a DHCPv4 reply (or nil for
// "no answer", such as an exhausted pool on DISCOVER).
func (s *Server) buildReply(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		offer, err := s.buildOffer(req)
		if err != nil {
			return nil, err
		}
		return offer, nil
	case dhcpv4.MessageTypeRequest:
		return s.buildACK(req)
	case dhcpv4.MessageTypeRelease:
		s.release(req.ClientHWAddr)
		return nil, nil
	case dhcpv4.MessageTypeDecline:
		if ip := req.RequestedIPAddress(); ip != nil {
			s.releaseIP(ip.String())
		}
		return nil, nil
	default:
		return nil, nil
	}
}

// buildOffer picks a candidate IP and returns an OFFER. Reservation is
// committed immediately: the candidate IP is marked used (with the full lease
// duration) and recorded against the client's chaddr, so repeated DISCOVERs
// from the same client return the same address and a different client never
// sees it as available until expiry. ACK just reaffirms; RELEASE/DECLINE or
// lease expiry clears it.
func (s *Server) buildOffer(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	ip := s.allocFor(req.ClientHWAddr.String(), req.RequestedIPAddress())
	if ip == nil {
		// Pool exhausted: stay silent per RFC 2131.
		return nil, nil
	}
	reply, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithYourIP(ip),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.cfg.Gateway)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(s.cfg.Pool.Mask)),
		dhcpv4.WithLeaseTime(uint32(s.cfg.LeaseTime.Seconds())),
	)
	if err != nil {
		return nil, err
	}
	if s.cfg.OfferDefaultRoute {
		reply.UpdateOption(dhcpv4.OptRouter(s.cfg.Gateway))
	}
	return reply, nil
}

// buildACK confirms the offered lease and returns an ACK. If the client asks
// for an address we didn't offer and it's not free, we NAK. A REQUEST with no
// prior OFFER (INIT-REBOOT style) is honored iff the requested IP is free and
// in-pool.
func (s *Server) buildACK(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	chid := req.ClientHWAddr.String()
	want := req.RequestedIPAddress()
	if want == nil {
		want = req.ClientIPAddr
	}

	s.mu.Lock()
	current := s.byChid[chid]
	if want != nil && want.To4() != nil && !s.cfg.Pool.Contains(want) {
		s.mu.Unlock()
		return s.nak(req, "requested IP out of pool")
	}
	if current == "" {
		// No prior OFFER: allocate a fresh one (or honor the requested IP if free).
		if want != nil && want.To4() != nil && !s.used[want.String()] {
			current = want.String()
		} else {
			ip := s.allocLocked()
			if ip == nil {
				s.mu.Unlock()
				return s.nak(req, "pool exhausted")
			}
			current = ip.String()
		}
	} else if want != nil && want.To4() != nil && !net.ParseIP(current).Equal(want) {
		// Client asked for something other than what we offered.
		if s.used[want.String()] && !s.expired(want.String()) {
			s.mu.Unlock()
			return s.nak(req, "requested IP unavailable")
		}
		// Reassign to the requested address.
		delete(s.used, current)
		delete(s.expiry, current)
		current = want.String()
	}
	s.used[current] = true
	s.byChid[chid] = current
	s.expiry[current] = time.Now().Add(s.cfg.LeaseTime)
	ip := net.ParseIP(current)
	s.mu.Unlock()

	reply, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(ip),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.cfg.Gateway)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(s.cfg.Pool.Mask)),
		dhcpv4.WithLeaseTime(uint32(s.cfg.LeaseTime.Seconds())),
	)
	if err != nil {
		return nil, err
	}
	if s.cfg.OfferDefaultRoute {
		reply.UpdateOption(dhcpv4.OptRouter(s.cfg.Gateway))
	}
	return reply, nil
}

func (s *Server) nak(req *dhcpv4.DHCPv4, msg string) (*dhcpv4.DHCPv4, error) {
	return dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.cfg.Gateway)),
		dhcpv4.WithOption(dhcpv4.OptMessage(msg)),
	)
}

// allocFor is the offer-time picker: reuse the same client's previous lease if
// it has one; otherwise pick a fresh address and COMMIT it (mark used + bind to
// chaddr + set expiry to the full lease duration). Returns nil if the pool is
// exhausted. Committing at OFFER time gives stable DISCOVERs and prevents two
// clients from being offered the same address.
func (s *Server) allocFor(chid string, requested net.IP) net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.byChid[chid]; old != "" {
		if !s.expired(old) {
			return net.ParseIP(old)
		}
		// Stale: clear before reallocating.
		delete(s.used, old)
		delete(s.expiry, old)
		delete(s.byChid, chid)
	}
	var ip net.IP
	if requested != nil && requested.To4() != nil && s.cfg.Pool.Contains(requested) && !s.used[requested.String()] {
		ip = requested
	} else {
		ip = s.allocLocked()
	}
	if ip == nil {
		return nil
	}
	sip := ip.String()
	now := time.Now()
	s.used[sip] = true
	s.byChid[chid] = sip
	s.expiry[sip] = now.Add(s.cfg.LeaseTime)
	return ip
}

// allocLocked scans the pool upward for the next free host address, skipping the
// network, gateway, and broadcast. Caller holds s.mu.
func (s *Server) allocLocked() net.IP {
	network := s.cfg.Pool.IP.Mask(s.cfg.Pool.Mask)
	bcast := broadcast(s.cfg.Pool)
	ip := make(net.IP, len(network))
	copy(ip, network)
	for {
		incIP(ip)
		if !s.cfg.Pool.Contains(ip) || ip.Equal(bcast) {
			return nil
		}
		sip := ip.String()
		if sip == s.cfg.Gateway.String() {
			continue
		}
		if s.used[sip] && !s.expired(sip) {
			continue
		}
		if s.used[sip] {
			// stale lease — reclaim
			delete(s.used, sip)
			delete(s.expiry, sip)
			for c, v := range s.byChid {
				if v == sip {
					delete(s.byChid, c)
				}
			}
		}
		return ip
	}
}

func (s *Server) expired(ip string) bool {
	t, ok := s.expiry[ip]
	return !ok || time.Now().After(t)
}

func (s *Server) release(hwaddr net.HardwareAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	chid := hwaddr.String()
	ip := s.byChid[chid]
	if ip == "" {
		return
	}
	delete(s.used, ip)
	delete(s.byChid, chid)
	delete(s.expiry, ip)
}

func (s *Server) releaseIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.used[ip] {
		return
	}
	delete(s.used, ip)
	delete(s.expiry, ip)
	for c, v := range s.byChid {
		if v == ip {
			delete(s.byChid, c)
		}
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
