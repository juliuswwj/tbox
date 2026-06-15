// Package config defines the on-disk YAML configuration for the tbox server
// and client roles.
package config

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/juliuswwj/tbox/internal/destallow"
)

// ParseTunRoute parses a tun route spec: "CIDR" (link-scoped via the device) or
// "CIDR via GATEWAY". It returns the destination CIDR and an optional gateway.
func ParseTunRoute(s string) (dst, gw string, err error) {
	f := strings.Fields(s)
	switch {
	case len(f) == 1:
		dst = f[0]
	case len(f) == 3 && f[1] == "via":
		dst, gw = f[0], f[2]
	default:
		return "", "", fmt.Errorf("route %q: want \"CIDR\" or \"CIDR via GATEWAY\"", s)
	}
	if _, _, err := net.ParseCIDR(dst); err != nil {
		return "", "", fmt.Errorf("route %q: %w", s, err)
	}
	if gw != "" && net.ParseIP(gw) == nil {
		return "", "", fmt.Errorf("route %q: bad gateway %q", s, gw)
	}
	return dst, gw, nil
}

// CertFile points at a TLS certificate + key on disk. The covered domain names
// are read from the certificate's SAN (so wildcards just work); they are not
// repeated in config.
type CertFile struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

// ServerConfig is the VPS-side configuration.
type ServerConfig struct {
	// Listen is the public L4 SNI router address (e.g. ":443").
	Listen string `yaml:"listen"`
	// ServerAddr is the public host clients dial; baked into emitted tokens.
	ServerAddr string `yaml:"server_addr"`
	// Mimic is the REALITY handshake server, host:port (e.g. www.microsoft.com:443).
	Mimic string `yaml:"mimic"`
	// RealityPrivateKey / RealityPublicKey / ShortID are the REALITY parameters.
	RealityPrivateKey string `yaml:"reality_private_key"`
	RealityPublicKey  string `yaml:"reality_public_key"`
	ShortID           string `yaml:"short_id"`
	// ControlAddr is the localhost control-plane listener (e.g. 127.0.0.1:8443).
	ControlAddr string `yaml:"control_addr"`
	// RealityInboundAddr is where the embedded sing-box VLESS-REALITY inbound
	// binds, fronted by the L4 router (e.g. 127.0.0.1:8444).
	RealityInboundAddr string       `yaml:"reality_inbound_addr"`
	LogLevel           string       `yaml:"log_level"`
	Clients            []ClientCred `yaml:"clients"`
	// Certs are TLS certificates the server provides for published domains, so
	// clients need not ship their own (avoids client-side cert dependencies).
	Certs []CertFile `yaml:"certs"`
	// Tun enables the L2 (TAP) tunnel data plane on the server (the hub).
	Tun ServerTun `yaml:"tun"`
	// Ban enables fail2ban-style throttling of the HTTP publishing path.
	Ban ServerBan `yaml:"ban"`
}

// ServerBan configures fail2ban-style banning on the HTTP publishing path: it
// counts auth failures (by default POST responses with 401/403) per source IP
// and bans an IP, escalating to its /24, when thresholds are crossed.
type ServerBan struct {
	Enable          bool     `yaml:"enable"`
	Methods         []string `yaml:"methods"`          // default ["POST"]
	Statuses        []int    `yaml:"statuses"`         // default [401, 403]
	Path            string   `yaml:"path"`             // optional request-path prefix filter
	Window          string   `yaml:"window"`           // default "10m"
	Threshold       int      `yaml:"threshold"`        // default 5
	BanDuration     string   `yaml:"ban_duration"`     // default "1h"
	SubnetThreshold *int     `yaml:"subnet_threshold"` // default 2; 0 disables /24 escalation
	Exempt          []string `yaml:"exempt"`           // CIDRs never counted or blocked
}

// ClientCred is a single authorized client (one VLESS user).
type ClientCred struct {
	Name string `yaml:"name"`
	UUID string `yaml:"uuid"`
}

// ServerTun configures the server-side L2 tunnel hub: a TAP device on the VPS,
// MAC-learning forwarding across client carrier streams, optional NAT egress
// for the v4 pool, and optional IPv6 transparent passthrough via ndppd.
type ServerTun struct {
	Enable            bool   `yaml:"enable"`
	TapName           string `yaml:"tap_name"`           // default tbox0
	PoolV4            string `yaml:"pool_v4"`            // e.g. 10.42.0.0/24
	Gateway           string `yaml:"gateway"`            // default: first host of pool
	IPv6Prefix        string `yaml:"ipv6_prefix"`        // optional, e.g. 2001:db8::/80
	MTU               int    `yaml:"mtu"`                // default 1448
	EnableNAT         bool   `yaml:"enable_nat"`         // MASQUERADE pool_v4 out wan_interface
	WANInterface      string `yaml:"wan_interface"`      // required when enable_nat
	EnablePassthrough bool   `yaml:"enable_passthrough"` // IPv6 /80 routes + ndppd
}

// ClientTunTAP optionally makes the client itself a node on the L2 segment.
type ClientTunTAP struct {
	Name          string   `yaml:"name"`           // default tbox0
	Bridge        string   `yaml:"bridge"`         // optional: enslave TAP to this bridge (auto-created), put IP on it
	BridgeMembers []string `yaml:"bridge_members"` // optional: extra local NICs to enslave to the bridge
	IPv4CIDR      string   `yaml:"ipv4_cidr"`      // optional manual address (else server-assigned)
	IPv6          string   `yaml:"ipv6"`           // optional manual address
	// Routes are extra routes installed on the TAP/bridge device. Each is a CIDR,
	// optionally "CIDR via GATEWAY" (e.g. "192.168.9.0/24 via 10.42.0.1").
	Routes []string `yaml:"routes"`
}

// ClientTunUDP optionally exposes a local UDP socket so external udpt.py
// clients can join the tunnel's L2 segment unmodified.
type ClientTunUDP struct {
	Listen string `yaml:"listen"` // e.g. 127.0.0.1:3390
}

// ClientTun configures the client-side L2 tunnel leaf. At least one of TAP or
// UDP must be set when Enable is true.
type ClientTun struct {
	Enable             bool          `yaml:"enable"`
	TAP                *ClientTunTAP `yaml:"tap"`
	UDP                *ClientTunUDP `yaml:"udp"`
	AcceptDefaultRoute bool          `yaml:"accept_default_route"`
	MTU                int           `yaml:"mtu"` // default 1448
}

// ClientConfig is the local-side configuration.
type ClientConfig struct {
	Token       string `yaml:"token"`
	SocksListen string `yaml:"socks_listen"`
	AdminListen string `yaml:"admin_listen"`
	LogLevel    string `yaml:"log_level"`
	// Certs are TLS certificates this client uploads (optional; the server may
	// provide the cert instead).
	Certs   []CertFile `yaml:"certs"`
	Publish []Publish  `yaml:"publish"`
	// Tun enables the L2 (TAP) tunnel data plane on the client (a leaf).
	Tun ClientTun `yaml:"tun"`
}

// Publish describes one local service exposed via the server. The service is
// identified by a URL whose scheme selects the mode:
//
//	https://host/path   -> HTTP reverse proxy (with optional rewriting)
//	wss://host/path     -> WebSocket bridged to a raw TCP upstream
//	tcp://host          -> TLS terminated by SNI, then raw TCP to the upstream
//
// The host must be covered by some registered certificate (server- or
// client-provided); the cert is matched by SNI, so wildcards work.
type Publish struct {
	URL      string   `yaml:"url"`
	Upstream string   `yaml:"upstream"`
	Allow    []string `yaml:"allow"` // source-IP whitelist (CIDRs); empty = allow all

	// socks5 mode: allowed CONNECT destinations (empty = deny all).
	AllowDest []string `yaml:"allow_dest"`

	// HTTP mode rewriting (ignored for ws/tcp/socks5):
	StripPrefix     bool              `yaml:"strip_prefix"`
	AddPrefix       string            `yaml:"add_prefix"`
	SetHost         string            `yaml:"set_host"`
	RequestHeaders  map[string]string `yaml:"request_headers"`
	ResponseHeaders map[string]string `yaml:"response_headers"`
}

// Parse splits the publish URL into mode (http|ws|tcp), host, and path.
func (p Publish) Parse() (mode, host, path string, err error) {
	u, err := url.Parse(p.URL)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid url %q: %w", p.URL, err)
	}
	host = u.Hostname()
	if host == "" {
		return "", "", "", fmt.Errorf("url %q has no host", p.URL)
	}
	switch u.Scheme {
	case "https", "http":
		mode = "http"
	case "wss", "ws":
		mode = "ws"
	case "tcp", "tls":
		mode = "tcp"
	case "socks5", "socks":
		mode = "socks5"
	default:
		return "", "", "", fmt.Errorf("url %q: unsupported scheme (use https/wss/tcp/socks5)", p.URL)
	}
	path = u.Path
	if mode == "tcp" || mode == "socks5" {
		if path != "" && path != "/" {
			return "", "", "", fmt.Errorf("url %q: %s services cover a whole host and must not have a path", p.URL, mode)
		}
		path = ""
	} else if path == "" {
		path = "/"
	}
	return mode, host, path, nil
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*ServerConfig, error) {
	var c ServerConfig
	if err := loadYAML(path, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if c.ControlAddr == "" {
		c.ControlAddr = "127.0.0.1:8443"
	}
	if c.RealityInboundAddr == "" {
		c.RealityInboundAddr = "127.0.0.1:8444"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Mimic == "" {
		return nil, fmt.Errorf("mimic is required")
	}
	if c.RealityPrivateKey == "" || c.ShortID == "" {
		return nil, fmt.Errorf("reality_private_key and short_id are required (run: tbox gen-keypair)")
	}
	if len(c.Clients) == 0 {
		return nil, fmt.Errorf("at least one client is required")
	}
	if c.Tun.Enable {
		if err := validateServerTun(&c.Tun); err != nil {
			return nil, fmt.Errorf("tun: %w", err)
		}
	}
	if c.Ban.Enable {
		if err := validateServerBan(&c.Ban); err != nil {
			return nil, fmt.Errorf("ban: %w", err)
		}
	}
	return &c, nil
}

// validateServerBan fills defaults and validates the ban block.
func validateServerBan(b *ServerBan) error {
	if len(b.Methods) == 0 {
		b.Methods = []string{"POST"}
	}
	if len(b.Statuses) == 0 {
		b.Statuses = []int{401, 403}
	}
	if b.Window == "" {
		b.Window = "10m"
	}
	if b.BanDuration == "" {
		b.BanDuration = "1h"
	}
	if b.Threshold <= 0 {
		b.Threshold = 5
	}
	if b.SubnetThreshold == nil {
		def := 2
		b.SubnetThreshold = &def
	}
	if _, err := time.ParseDuration(b.Window); err != nil {
		return fmt.Errorf("invalid window %q: %w", b.Window, err)
	}
	if _, err := time.ParseDuration(b.BanDuration); err != nil {
		return fmt.Errorf("invalid ban_duration %q: %w", b.BanDuration, err)
	}
	for _, c := range b.Exempt {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("invalid exempt CIDR %q: %w", c, err)
		}
	}
	return nil
}

// validateServerTun fills defaults and validates the server tun block.
func validateServerTun(t *ServerTun) error {
	if t.TapName == "" {
		t.TapName = "tbox0"
	}
	if t.MTU == 0 {
		t.MTU = 1448
	}
	if t.PoolV4 == "" {
		return fmt.Errorf("pool_v4 is required")
	}
	_, ipnet, err := net.ParseCIDR(t.PoolV4)
	if err != nil {
		return fmt.Errorf("invalid pool_v4 %q: %w", t.PoolV4, err)
	}
	if t.Gateway == "" {
		gw := firstHost(ipnet)
		if gw == nil {
			return fmt.Errorf("cannot derive gateway from pool_v4 %q", t.PoolV4)
		}
		t.Gateway = gw.String()
	} else if net.ParseIP(t.Gateway) == nil {
		return fmt.Errorf("invalid gateway %q", t.Gateway)
	}
	if t.IPv6Prefix != "" {
		if _, _, err := net.ParseCIDR(t.IPv6Prefix); err != nil {
			return fmt.Errorf("invalid ipv6_prefix %q: %w", t.IPv6Prefix, err)
		}
	}
	if t.EnableNAT && t.WANInterface == "" {
		return fmt.Errorf("wan_interface is required when enable_nat is set")
	}
	return nil
}

// firstHost returns the first usable host address of an IPv4 network (network
// address + 1), used as the default tunnel gateway.
func firstHost(ipnet *net.IPNet) net.IP {
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil
	}
	host := make(net.IP, len(ip))
	copy(host, ip)
	host[3]++
	if !ipnet.Contains(host) {
		return nil
	}
	return host
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*ClientConfig, error) {
	var c ClientConfig
	if err := loadYAML(path, &c); err != nil {
		return nil, err
	}
	if c.SocksListen == "" {
		c.SocksListen = "127.0.0.1:1080"
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:9090"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Token == "" {
		return nil, fmt.Errorf("token is required")
	}
	for i := range c.Publish {
		p := &c.Publish[i]
		mode, _, _, err := p.Parse()
		if err != nil {
			return nil, fmt.Errorf("publish[%d]: %w", i, err)
		}
		if mode == "socks5" {
			if _, err := destallow.New(p.AllowDest); err != nil {
				return nil, fmt.Errorf("publish[%d] (%s): %w", i, p.URL, err)
			}
		} else if p.Upstream == "" {
			return nil, fmt.Errorf("publish[%d] (%s): upstream is required", i, p.URL)
		}
	}
	if c.Tun.Enable {
		if c.Tun.TAP == nil && c.Tun.UDP == nil {
			return nil, fmt.Errorf("tun: enable requires at least one of tap or udp")
		}
		if c.Tun.MTU == 0 {
			c.Tun.MTU = 1448
		}
		if c.Tun.TAP != nil {
			if c.Tun.TAP.Name == "" {
				c.Tun.TAP.Name = "tbox0"
			}
			if c.Tun.TAP.IPv4CIDR != "" {
				if _, _, err := net.ParseCIDR(c.Tun.TAP.IPv4CIDR); err != nil {
					return nil, fmt.Errorf("tun.tap.ipv4_cidr %q: %w", c.Tun.TAP.IPv4CIDR, err)
				}
			}
			if len(c.Tun.TAP.BridgeMembers) > 0 && c.Tun.TAP.Bridge == "" {
				return nil, fmt.Errorf("tun.tap.bridge_members requires tun.tap.bridge")
			}
			for _, r := range c.Tun.TAP.Routes {
				if _, _, err := ParseTunRoute(r); err != nil {
					return nil, fmt.Errorf("tun.tap.routes: %w", err)
				}
			}
		}
		if c.Tun.UDP != nil && c.Tun.UDP.Listen == "" {
			return nil, fmt.Errorf("tun.udp.listen is required when udp is set")
		}
	}
	return &c, nil
}

// MimicHost returns the host portion of the mimic address.
func (c *ServerConfig) MimicHost() string {
	host, _, err := net.SplitHostPort(c.Mimic)
	if err != nil {
		return c.Mimic
	}
	return host
}

// MimicPort returns the port portion of the mimic address (default 443).
func (c *ServerConfig) MimicPort() uint16 {
	_, portStr, err := net.SplitHostPort(c.Mimic)
	if err != nil {
		return 443
	}
	p, _ := strconv.ParseUint(portStr, 10, 16)
	if p == 0 {
		return 443
	}
	return uint16(p)
}

// PublicPort returns the port of the public listener (default 443).
func (c *ServerConfig) PublicPort() uint16 {
	_, portStr, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return 443
	}
	p, _ := strconv.ParseUint(portStr, 10, 16)
	if p == 0 {
		return 443
	}
	return uint16(p)
}

// SaveServer writes a server config to disk (0640, creating parent dirs). It
// rewrites the file from the struct, so hand-added comments are not preserved.
func SaveServer(path string, c *ServerConfig) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal server config: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

func loadYAML(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}
