package control

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/yamux"

	"github.com/juliuswwj/tbox/internal/ipallow"
	"github.com/juliuswwj/tbox/internal/tunnel"
)

// Service is one published service (http location, ws endpoint, or whole-host
// tcp), owned by the client that registered it and forwarded over its session.
type Service struct {
	Mode     string // http | ws | tcp
	Host     string
	Path     string // http/ws only
	Upstream string

	// http rewrite
	StripPrefix     bool
	AddPrefix       string
	SetHost         string
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string

	ClientID string
	Session  *yamux.Session
	Allow    *ipallow.Set
}

// ID returns the canonical identifier for the service.
func (s *Service) ID() string { return ServiceID(s.Mode, s.Host, s.Path) }

// OpenStream opens a reverse stream to the owning client and writes the frame
// naming this service. The client resolves what to do from its own config.
func (s *Service) OpenStream() (net.Conn, error) {
	stream, err := s.Session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open reverse stream: %w", err)
	}
	if err := tunnel.WriteFrame(stream, tunnel.Frame{Service: s.ID()}); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

// Dial returns a connection to the service upstream. For a client-owned service
// it opens a reverse stream to that client (which dials the upstream locally);
// for a server-owned service (no session) it dials the upstream directly.
func (s *Service) Dial() (net.Conn, error) {
	if s.Session == nil {
		return net.Dial("tcp", s.Upstream)
	}
	return s.OpenStream()
}

// isRaw reports whether a mode is a whole-host, TLS-terminate-then-raw service.
func isRaw(mode string) bool { return mode == "tcp" || mode == "socks5" }

type parsedCert struct {
	cert     tls.Certificate
	names    []string // lower-case SAN DNS names (may include *.example.com)
	clientID string   // "" for server-provided
	session  *yamux.Session
}

// Registry holds the certificates and services published across all clients.
// Certificates are decoupled from services: a service only needs some cert
// (server- or client-provided) whose SAN matches its host.
type Registry struct {
	mu      sync.RWMutex
	certs   []*parsedCert
	raw     map[string]*Service   // host -> whole-host tcp/socks5 service
	http    map[string][]*Service // host -> http/ws services
	version atomic.Uint64
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{raw: make(map[string]*Service), http: make(map[string][]*Service)}
}

// Version changes whenever certs/services change; used to invalidate caches.
func (r *Registry) Version() uint64 { return r.version.Load() }

func parseCert(certPEM, keyPEM string) (*parsedCert, error) {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid cert/key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	cert.Leaf = leaf
	names := append([]string(nil), leaf.DNSNames...)
	if len(names) == 0 && leaf.Subject.CommonName != "" {
		names = []string{leaf.Subject.CommonName}
	}
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	return &parsedCert{cert: cert, names: names}, nil
}

// AddServerCert registers a permanent, server-provided certificate.
func (r *Registry) AddServerCert(certPEM, keyPEM string) error {
	pc, err := parseCert(certPEM, keyPEM)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.certs = append(r.certs, pc)
	r.version.Add(1)
	r.mu.Unlock()
	return nil
}

// LookupCert returns the certificate whose SAN matches sni (exact preferred,
// then wildcard).
func (r *Registry) LookupCert(sni string) (*tls.Certificate, bool) {
	host := strings.ToLower(strings.TrimSpace(sni))
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, pc := range r.certs {
		for _, n := range pc.names {
			if n == host {
				return &pc.cert, true
			}
		}
	}
	for _, pc := range r.certs {
		for _, n := range pc.names {
			if wildcardMatch(n, host) {
				return &pc.cert, true
			}
		}
	}
	return nil, false
}

// ServerOwnerID identifies services published by the server itself (dialed
// directly, no client session). The NUL byte cannot occur in a client UUID, so
// it never collides with a real client.
const ServerOwnerID = "\x00server"

// RegisterServer registers services the server publishes directly: they have no
// client session (Service.Dial dials the upstream itself) and are permanent for
// the process lifetime. Conflict checks run against any client services, so a
// client cannot later take over a host/path the server owns.
func (r *Registry) RegisterServer(services []ServiceReg) error {
	return r.Register(ServerOwnerID, nil, nil, services)
}

// Register replaces a client's certs and services. Hosts/paths are
// first-come-first-served across clients; a host cannot be both tcp and http.
func (r *Registry) Register(clientID string, sess *yamux.Session, certs []CertReg, services []ServiceReg) error {
	// Parse everything up front so a bad entry doesn't partially mutate state.
	pcs := make([]*parsedCert, 0, len(certs))
	for _, c := range certs {
		pc, err := parseCert(c.CertPEM, c.KeyPEM)
		if err != nil {
			return err
		}
		pc.clientID = clientID
		pc.session = sess
		pcs = append(pcs, pc)
	}
	svcs := make([]*Service, 0, len(services))
	for _, sr := range services {
		allow, err := ipallow.New(sr.Allow)
		if err != nil {
			return fmt.Errorf("invalid allow list for %s: %w", sr.ID(), err)
		}
		host := strings.ToLower(sr.Host)
		path := ""
		if !isRaw(sr.Mode) {
			path = normPath(sr.Path)
		}
		svcs = append(svcs, &Service{
			Mode: sr.Mode, Host: host, Path: path, Upstream: sr.Upstream,
			StripPrefix: sr.StripPrefix, AddPrefix: sr.AddPrefix, SetHost: sr.SetHost,
			RequestHeaders: sr.RequestHeaders, ResponseHeaders: sr.ResponseHeaders,
			ClientID: clientID, Session: sess, Allow: allow,
		})
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Replace: drop this client's existing certs/services first.
	r.removeClientLocked(clientID)

	// Conflict checks against other clients' remaining services.
	for _, s := range svcs {
		switch {
		case isRaw(s.Mode):
			if ex, ok := r.raw[s.Host]; ok && ex.ClientID != clientID {
				return fmt.Errorf("host %s already used (%s) by another client", s.Host, ex.Mode)
			}
			if len(r.http[s.Host]) > 0 {
				return fmt.Errorf("host %s already used for http/ws; cannot also be %s", s.Host, s.Mode)
			}
		case s.Mode == "http" || s.Mode == "ws":
			if ex, ok := r.raw[s.Host]; ok {
				return fmt.Errorf("host %s already used as %s; cannot also serve http/ws", s.Host, ex.Mode)
			}
			for _, ex := range r.http[s.Host] {
				if samePath(ex.Path, s.Path) {
					return fmt.Errorf("path %s on %s already registered by another client", s.Path, s.Host)
				}
			}
		default:
			return fmt.Errorf("unknown mode %q for %s", s.Mode, s.Host)
		}
	}

	// Commit.
	r.certs = append(r.certs, pcs...)
	for _, s := range svcs {
		if isRaw(s.Mode) {
			r.raw[s.Host] = s
		} else {
			r.http[s.Host] = append(r.http[s.Host], s)
		}
	}
	r.version.Add(1)
	return nil
}

// removeClientLocked drops all certs/services owned by clientID (caller holds mu).
func (r *Registry) removeClientLocked(clientID string) {
	r.certs = filterCerts(r.certs, func(pc *parsedCert) bool { return pc.clientID != clientID })
	for host, s := range r.raw {
		if s.ClientID == clientID {
			delete(r.raw, host)
		}
	}
	for host, list := range r.http {
		kept := list[:0:0]
		for _, s := range list {
			if s.ClientID != clientID {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			delete(r.http, host)
		} else {
			r.http[host] = kept
		}
	}
}

// UpdateWhitelist atomically replaces a service's allow list.
func (r *Registry) UpdateWhitelist(clientID, serviceID string, allow []string) error {
	r.mu.RLock()
	s := r.findServiceLocked(serviceID)
	r.mu.RUnlock()
	if s == nil {
		return fmt.Errorf("service %s not registered", serviceID)
	}
	if s.ClientID != clientID {
		return fmt.Errorf("service %s not owned by this client", serviceID)
	}
	if err := s.Allow.Replace(allow); err != nil {
		return err
	}
	r.version.Add(1)
	return nil
}

func (r *Registry) findServiceLocked(serviceID string) *Service {
	for _, s := range r.raw {
		if s.ID() == serviceID {
			return s
		}
	}
	for _, list := range r.http {
		for _, s := range list {
			if s.ID() == serviceID {
				return s
			}
		}
	}
	return nil
}

// RawService returns the whole-host tcp/socks5 service for a host.
func (r *Registry) RawService(host string) (*Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.raw[strings.ToLower(host)]
	return s, ok
}

// HTTPServices returns a snapshot of the http/ws services for a host.
func (r *Registry) HTTPServices(host string) []*Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := r.http[strings.ToLower(host)]
	out := make([]*Service, len(list))
	copy(out, list)
	return out
}

// HasHTTPHost reports whether any http/ws service exists for a host.
func (r *Registry) HasHTTPHost(host string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.http[strings.ToLower(host)]) > 0
}

// HTTPHostAllowed reports whether remote is admitted by any http/ws service on
// the host (coarse L4 gate; precise per-service checks happen at HTTP).
func (r *Registry) HTTPHostAllowed(host string, remote net.Addr) bool {
	addr, ok := addrOf(remote)
	if !ok {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := r.http[strings.ToLower(host)]
	if len(list) == 0 {
		return false
	}
	for _, s := range list {
		if s.Allow.Allowed(addr) {
			return true
		}
	}
	return false
}

// RemoveSession removes all certs/services owned by a session (on disconnect).
func (r *Registry) RemoveSession(sess *yamux.Session) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var affected []string
	before := len(r.certs)
	r.certs = filterCerts(r.certs, func(pc *parsedCert) bool { return pc.session != sess })
	changed := len(r.certs) != before
	for host, s := range r.raw {
		if s.Session == sess {
			delete(r.raw, host)
			affected = append(affected, s.ID())
			changed = true
		}
	}
	for host, list := range r.http {
		kept := list[:0:0]
		for _, s := range list {
			if s.Session == sess {
				affected = append(affected, s.ID())
				changed = true
			} else {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			delete(r.http, host)
		} else {
			r.http[host] = kept
		}
	}
	if changed {
		r.version.Add(1)
	}
	return affected
}

func filterCerts(in []*parsedCert, keep func(*parsedCert) bool) []*parsedCert {
	out := in[:0:0]
	for _, pc := range in {
		if keep(pc) {
			out = append(out, pc)
		}
	}
	return out
}

func addrOf(remote net.Addr) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		host = remote.String()
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// wildcardMatch reports whether a cert name (possibly *.example.com) matches host.
func wildcardMatch(name, host string) bool {
	if name == host {
		return true
	}
	if strings.HasPrefix(name, "*.") {
		suffix := name[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) {
			label := host[:len(host)-len(suffix)]
			return label != "" && !strings.Contains(label, ".")
		}
	}
	return false
}

func samePath(a, b string) bool { return normPath(a) == normPath(b) }
