package control

import (
	"crypto/tls"
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

// RouteEntry is one location (path prefix) on a domain, owned by a single
// client. Multiple clients may contribute different locations to the same
// domain; each location forwards to its owner's local upstream.
type RouteEntry struct {
	Path     string // public path prefix ("/" = whole site / default)
	Mode     string // http | ws
	Upstream string // owner's local target

	// http rewrite
	StripPrefix     bool
	AddPrefix       string
	SetHost         string
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string

	// owner
	ClientID string
	Session  *yamux.Session
	Allow    *ipallow.Set // shared per (domain, client)
}

// OpenStream opens a reverse stream to this route's owning client and writes
// the frame naming the local target the client must dial.
func (e *RouteEntry) OpenStream(mode tunnel.Mode, target string) (net.Conn, error) {
	stream, err := e.Session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open reverse stream: %w", err)
	}
	if err := tunnel.WriteFrame(stream, tunnel.Frame{Mode: mode, Target: target}); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

// Domain is the server-side state for one published domain. Its TLS cert is
// supplied by the first registrant that provides one (the "cert owner"); other
// clients may add cert-free locations.
type Domain struct {
	Name string

	mu            sync.RWMutex
	cert          tls.Certificate
	hasCert       bool
	certClient    string
	routes        []*RouteEntry
	allowByClient map[string]*ipallow.Set
	version       atomic.Uint64
}

// Cert returns the domain's TLS certificate.
func (d *Domain) Cert() (tls.Certificate, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cert, d.hasCert
}

// Routes returns a snapshot of the domain's routes.
func (d *Domain) Routes() []*RouteEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*RouteEntry, len(d.routes))
	copy(out, d.routes)
	return out
}

// Version changes whenever the domain's routes/cert change; used to invalidate
// cached handlers.
func (d *Domain) Version() uint64 { return d.version.Load() }

// AllowedConn reports whether addr is permitted by at least one route's
// whitelist (coarse L4 gate; precise per-route enforcement happens at HTTP).
func (d *Domain) AllowedConn(remote net.Addr) bool {
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		host = remote.String()
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.allowByClient) == 0 {
		return true
	}
	for _, set := range d.allowByClient {
		if set.Allowed(addr) {
			return true
		}
	}
	return false
}

// Registry tracks published domains across all connected clients.
type Registry struct {
	mu      sync.RWMutex
	domains map[string]*Domain
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{domains: make(map[string]*Domain)}
}

// Register adds (or replaces) a client's locations on a domain. Locations are
// first-come-first-served at the path level across distinct clients; a client
// re-registering replaces its own locations. The domain's cert is set from the
// first registration that carries one.
func (r *Registry) Register(clientID string, sess *yamux.Session, reg ServiceReg) error {
	name := strings.ToLower(reg.Domain)

	allow, err := ipallow.New(reg.Allow)
	if err != nil {
		return fmt.Errorf("invalid allow list for %s: %w", name, err)
	}

	var cert tls.Certificate
	hasCert := false
	if reg.CertPEM != "" {
		cert, err = tls.X509KeyPair([]byte(reg.CertPEM), []byte(reg.KeyPEM))
		if err != nil {
			return fmt.Errorf("invalid cert/key for %s: %w", name, err)
		}
		hasCert = true
	}

	newRoutes, err := buildRoutes(clientID, sess, allow, reg)
	if err != nil {
		return err
	}

	r.mu.Lock()
	d := r.domains[name]
	if d == nil {
		d = &Domain{Name: name, allowByClient: make(map[string]*ipallow.Set)}
		r.domains[name] = d
	}
	r.mu.Unlock()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Path conflicts against OTHER clients' locations.
	for _, nr := range newRoutes {
		for _, ex := range d.routes {
			if ex.ClientID != clientID && samePath(ex.Path, nr.Path) {
				return fmt.Errorf("path %q on domain %s already registered by another client", nr.Path, name)
			}
		}
	}

	// Replace this client's existing locations (handles reconnect/re-register).
	kept := d.routes[:0:0]
	for _, ex := range d.routes {
		if ex.ClientID != clientID {
			kept = append(kept, ex)
		}
	}
	d.routes = append(kept, newRoutes...)
	d.allowByClient[clientID] = allow

	if hasCert && (!d.hasCert || d.certClient == clientID) {
		d.cert = cert
		d.hasCert = true
		d.certClient = clientID
	}
	d.version.Add(1)
	return nil
}

func buildRoutes(clientID string, sess *yamux.Session, allow *ipallow.Set, reg ServiceReg) ([]*RouteEntry, error) {
	switch reg.Mode {
	case "http":
		if len(reg.Routes) == 0 {
			return nil, fmt.Errorf("http registration for %s has no routes", reg.Domain)
		}
		out := make([]*RouteEntry, 0, len(reg.Routes))
		for _, rt := range reg.Routes {
			out = append(out, &RouteEntry{
				Path:            normPath(rt.Path),
				Mode:            "http",
				Upstream:        rt.Upstream,
				StripPrefix:     rt.StripPrefix,
				AddPrefix:       rt.AddPrefix,
				SetHost:         rt.SetHost,
				RequestHeaders:  rt.RequestHeaders,
				ResponseHeaders: rt.ResponseHeaders,
				ClientID:        clientID,
				Session:         sess,
				Allow:           allow,
			})
		}
		return out, nil
	case "ws":
		return []*RouteEntry{{
			Path:     normPath(reg.WSPath),
			Mode:     "ws",
			Upstream: reg.WSUpstream,
			ClientID: clientID,
			Session:  sess,
			Allow:    allow,
		}}, nil
	default:
		return nil, fmt.Errorf("unknown mode %q for %s", reg.Mode, reg.Domain)
	}
}

// UpdateWhitelist atomically replaces the allow list for a client's locations
// on a domain.
func (r *Registry) UpdateWhitelist(clientID, domain string, allow []string) error {
	d, ok := r.Lookup(domain)
	if !ok {
		return fmt.Errorf("domain %s not registered", domain)
	}
	d.mu.RLock()
	set, ok := d.allowByClient[clientID]
	d.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no locations on %s owned by this client", domain)
	}
	if err := set.Replace(allow); err != nil {
		return err
	}
	d.version.Add(1)
	return nil
}

// Lookup returns the domain state.
func (r *Registry) Lookup(domain string) (*Domain, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.domains[strings.ToLower(domain)]
	return d, ok
}

// Has reports whether a domain is registered (has at least one route).
func (r *Registry) Has(domain string) bool {
	_, ok := r.Lookup(domain)
	return ok
}

// RemoveSession removes all locations owned by the given session and drops any
// domain left with no routes. Returns the affected domain names.
func (r *Registry) RemoveSession(sess *yamux.Session) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var affected []string
	for name, d := range r.domains {
		d.mu.Lock()
		changed := false
		kept := d.routes[:0:0]
		for _, e := range d.routes {
			if e.Session == sess {
				changed = true
			} else {
				kept = append(kept, e)
			}
		}
		if changed {
			d.routes = kept
			// Drop allow sets for clients with no remaining routes.
			live := make(map[string]bool)
			for _, e := range d.routes {
				live[e.ClientID] = true
			}
			for cid := range d.allowByClient {
				if !live[cid] {
					delete(d.allowByClient, cid)
				}
			}
			d.version.Add(1)
			affected = append(affected, name)
		}
		empty := len(d.routes) == 0
		d.mu.Unlock()
		if empty {
			delete(r.domains, name)
		}
	}
	return affected
}

func samePath(a, b string) bool { return normPath(a) == normPath(b) }

func normPath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}
