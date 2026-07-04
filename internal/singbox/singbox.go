// Package singbox embeds sing-box as a library to provide the VLESS-REALITY
// encrypted carrier for tbox. We build configs as JSON and load them through
// sing-box's documented JSON schema (UnmarshalJSONContext), which is far more
// stable across sing-box releases than reaching into the typed option structs
// or the inbound/outbound managers.
package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// Instance wraps a running sing-box Box together with the context it was
// created with.
type Instance struct {
	box *box.Box
	ctx context.Context
}

// New builds a sing-box instance from a raw JSON config document.
func New(rawConfig []byte) (*Instance, error) {
	ctx := include.Context(context.Background())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, rawConfig); err != nil {
		return nil, fmt.Errorf("parse sing-box config: %w", err)
	}
	b, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, fmt.Errorf("create sing-box: %w", err)
	}
	return &Instance{box: b, ctx: ctx}, nil
}

// Start starts the embedded sing-box.
func (i *Instance) Start() error { return i.box.Start() }

// Close stops the embedded sing-box.
func (i *Instance) Close() error { return i.box.Close() }

// --- config models (subset of the sing-box JSON schema we use) ---

type logOpts struct {
	Level     string `json:"level,omitempty"`
	Timestamp bool   `json:"timestamp"`
}

type realityHandshake struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

type inboundReality struct {
	Enabled    bool             `json:"enabled"`
	Handshake  realityHandshake `json:"handshake"`
	PrivateKey string           `json:"private_key"`
	ShortID    []string         `json:"short_id"`
}

type outboundReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type utlsOpts struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type inboundTLS struct {
	Enabled    bool            `json:"enabled"`
	ServerName string          `json:"server_name,omitempty"`
	Reality    *inboundReality `json:"reality,omitempty"`
}

type outboundTLS struct {
	Enabled    bool             `json:"enabled"`
	ServerName string           `json:"server_name,omitempty"`
	UTLS       *utlsOpts        `json:"utls,omitempty"`
	Reality    *outboundReality `json:"reality,omitempty"`
}

type vlessUser struct {
	Name string `json:"name,omitempty"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

type inbound struct {
	Type       string      `json:"type"`
	Tag        string      `json:"tag,omitempty"`
	Listen     string      `json:"listen,omitempty"`
	ListenPort uint16      `json:"listen_port,omitempty"`
	Users      []vlessUser `json:"users,omitempty"`
	TLS        *inboundTLS `json:"tls,omitempty"`
}

type outbound struct {
	Type       string       `json:"type"`
	Tag        string       `json:"tag,omitempty"`
	Server     string       `json:"server,omitempty"`
	ServerPort uint16       `json:"server_port,omitempty"`
	UUID       string       `json:"uuid,omitempty"`
	Flow       string       `json:"flow,omitempty"`
	TLS        *outboundTLS `json:"tls,omitempty"`
	// TCPFastOpen makes the DialerOptions non-zero so sing-box does not reject
	// the direct outbound as "empty" when used as a DNS detour. Harmless for
	// UDP DNS queries, keeps IsEmpty() == false.
	TCPFastOpen bool `json:"tcp_fast_open,omitempty"`
}

type routeOpts struct {
	Final string `json:"final,omitempty"`
}

type config struct {
	Log       *logOpts   `json:"log,omitempty"`
	Inbounds  []inbound  `json:"inbounds,omitempty"`
	Outbounds []outbound `json:"outbounds,omitempty"`
	Route     *routeOpts `json:"route,omitempty"`
}

// ServerParams configures the server-side sing-box (VLESS-REALITY inbound).
type ServerParams struct {
	ListenAddr string // host the reality inbound binds (e.g. 127.0.0.1)
	ListenPort uint16 // reality inbound port (behind the L4 SNI router)
	MimicHost  string // REALITY handshake server host (e.g. www.microsoft.com)
	MimicPort  uint16 // REALITY handshake server port (usually 443)
	PrivateKey string // REALITY private key
	ShortID    string // REALITY short id
	Users      []User // allowed clients
	LogLevel   string
}

// User is a VLESS user (one per tbox client).
type User struct {
	Name string
	UUID string
}

// ServerConfigJSON renders the server sing-box config as JSON.
func ServerConfigJSON(p ServerParams) ([]byte, error) {
	users := make([]vlessUser, 0, len(p.Users))
	for _, u := range p.Users {
		users = append(users, vlessUser{Name: u.Name, UUID: u.UUID})
	}
	cfg := config{
		Log: &logOpts{Level: orDefault(p.LogLevel, "info")},
		Inbounds: []inbound{{
			Type:       "vless",
			Tag:        "vless-in",
			Listen:     orDefault(p.ListenAddr, "127.0.0.1"),
			ListenPort: p.ListenPort,
			Users:      users,
			TLS: &inboundTLS{
				Enabled:    true,
				ServerName: p.MimicHost,
				Reality: &inboundReality{
					Enabled:    true,
					Handshake:  realityHandshake{Server: p.MimicHost, ServerPort: orDefaultPort(p.MimicPort, 443)},
					PrivateKey: p.PrivateKey,
					ShortID:    []string{p.ShortID},
				},
			},
		}},
		Outbounds: []outbound{{Type: "direct", Tag: "direct"}},
		Route:     &routeOpts{Final: "direct"},
	}
	return json.Marshal(cfg)
}

// ClientParams configures the client-side sing-box.
type ClientParams struct {
	SocksListen string // host:port of the local SOCKS5H/mixed inbound
	ServerAddr  string // VPS host
	ServerPort  uint16 // VPS port (443)
	UUID        string
	SNI         string // REALITY server_name (mimic host)
	PublicKey   string // REALITY public key
	ShortID     string
	Fingerprint string // utls fingerprint, default chrome
	LogLevel    string
}

// ClientConfigJSON renders the client sing-box config as JSON.
func ClientConfigJSON(p ClientParams) ([]byte, error) {
	host, port, err := splitHostPort(p.SocksListen)
	if err != nil {
		return nil, fmt.Errorf("socks_listen: %w", err)
	}
	cfg := config{
		Log: &logOpts{Level: orDefault(p.LogLevel, "info")},
		Inbounds: []inbound{{
			Type:       "mixed",
			Tag:        "socks-in",
			Listen:     host,
			ListenPort: port,
		}},
		Outbounds: []outbound{
			{
				Type:       "vless",
				Tag:        "vless-out",
				Server:     p.ServerAddr,
				ServerPort: p.ServerPort,
				UUID:       p.UUID,
				TLS: &outboundTLS{
					Enabled:    true,
					ServerName: p.SNI,
					UTLS:       &utlsOpts{Enabled: true, Fingerprint: orDefault(p.Fingerprint, "chrome")},
					Reality:    &outboundReality{Enabled: true, PublicKey: p.PublicKey, ShortID: p.ShortID},
				},
			},
			{Type: "direct", Tag: "direct"},
		},
		Route: &routeOpts{Final: "vless-out"},
	}
	return json.Marshal(cfg)
}

// --- tun (Android VpnService) client config ---
//
// The Android client runs the same VLESS-REALITY outbound as the desktop
// client, but fronts it with a sing-box "tun" inbound instead of a local
// SOCKS listener so it can capture all device traffic. sing-box's libbox
// runtime turns the tun inbound into a VpnService callback (OpenTun) and honors
// route.auto_detect_interface to protect the underlying carrier socket, so the
// connection to the server does not loop back through the tunnel.

type dnsServer struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort uint16 `json:"server_port,omitempty"`
	Detour     string `json:"detour,omitempty"`
}

type dnsOpts struct {
	Servers []dnsServer `json:"servers"`
	Final   string      `json:"final,omitempty"`
}

type domainResolver struct {
	Server string `json:"server"`
}

type tunInbound struct {
	Type        string   `json:"type"`
	Tag         string   `json:"tag,omitempty"`
	Address     []string `json:"address,omitempty"`
	MTU         uint32   `json:"mtu,omitempty"`
	AutoRoute   bool     `json:"auto_route"`
	StrictRoute bool     `json:"strict_route"`
	Stack       string   `json:"stack,omitempty"`
}

type routeRule struct {
	Action   string `json:"action,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type tunRouteOpts struct {
	Rules                 []routeRule     `json:"rules,omitempty"`
	AutoDetectInterface   bool            `json:"auto_detect_interface"`
	OverrideAndroidVPN    bool            `json:"override_android_vpn,omitempty"`
	DefaultDomainResolver *domainResolver `json:"default_domain_resolver,omitempty"`
	Final                 string          `json:"final,omitempty"`
}

type tunConfig struct {
	Log       *logOpts      `json:"log,omitempty"`
	DNS       *dnsOpts      `json:"dns,omitempty"`
	Inbounds  []tunInbound  `json:"inbounds,omitempty"`
	Outbounds []outbound    `json:"outbounds,omitempty"`
	Route     *tunRouteOpts `json:"route,omitempty"`
}

// TunClientParams configures the Android tun client. The REALITY fields mirror
// ClientParams; the tun fields describe the virtual interface addresses.
type TunClientParams struct {
	ServerAddr  string // VPS host
	ServerPort  uint16 // VPS port (443)
	UUID        string
	SNI         string // REALITY server_name (mimic host)
	PublicKey   string // REALITY public key (base64url)
	ShortID     string // REALITY short id (hex)
	Fingerprint string // utls fingerprint, default chrome
	LogLevel    string

	MTU        uint32 // tun MTU, default 9000
	IPv6       bool   // include an IPv6 tun address / route
	DNSAddress string // upstream DNS resolved through the tunnel, default 8.8.8.8
}

const (
	tunInet4Address = "198.18.0.1/15"
	tunInet6Address = "fdfe:dcba:9876::1/126"
)

// TunAddress returns the IPv4 TUN address (without mask).
func TunAddress() string {
	return tunInet4Address
}

// TunClientConfigJSON renders the Android tun client sing-box config as JSON.
func TunClientConfigJSON(p TunClientParams) ([]byte, error) {
	if p.ServerAddr == "" || p.UUID == "" || p.PublicKey == "" {
		return nil, fmt.Errorf("tun client: server address, uuid and public key are required")
	}
	addrs := []string{tunInet4Address}
	if p.IPv6 {
		addrs = append(addrs, tunInet6Address)
	}
	cfg := tunConfig{
		Log: &logOpts{Level: orDefault(p.LogLevel, "info")},
		// remote-dns answers hijacked app queries through the tunnel as UDP;
		// direct-dns resolves the carrier server's own domain over the underlying
		// network (via route.default_domain_resolver) so the tunnel can be
		// established without looping DNS back through itself.
		DNS: &dnsOpts{
			Servers: []dnsServer{
				{Type: "udp", Tag: "remote-dns", Server: orDefault(p.DNSAddress, "8.8.8.8"), Detour: "vless-out"},
				{Type: "udp", Tag: "direct-dns", Server: "223.5.5.5", Detour: "direct"},
			},
			Final: "remote-dns",
		},
		Inbounds: []tunInbound{{
			Type:        "tun",
			Tag:         "tun-in",
			Address:     addrs,
			MTU:         orDefaultUint32(p.MTU, 9000),
			AutoRoute:   true,
			StrictRoute: true,
			Stack:       "system",
		}},
		Outbounds: []outbound{
			{
				Type:       "vless",
				Tag:        "vless-out",
				Server:     p.ServerAddr,
				ServerPort: p.ServerPort,
				UUID:       p.UUID,
				TLS: &outboundTLS{
					Enabled:    true,
					ServerName: p.SNI,
					UTLS:       &utlsOpts{Enabled: true, Fingerprint: orDefault(p.Fingerprint, "chrome")},
					Reality:    &outboundReality{Enabled: true, PublicKey: p.PublicKey, ShortID: p.ShortID},
				},
			},
			{Type: "direct", Tag: "direct", TCPFastOpen: true},
		},
		Route: &tunRouteOpts{
			Rules: []routeRule{
				{Action: "sniff"},
				{Protocol: "dns", Action: "hijack-dns"},
			},
			AutoDetectInterface:   true,
			DefaultDomainResolver: &domainResolver{Server: "direct-dns"},
			Final:                 "vless-out",
		},
	}
	return json.Marshal(cfg)
}

func orDefaultUint32(v, d uint32) uint32 {
	if v == 0 {
		return d
	}
	return v
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func orDefaultPort(v, d uint16) uint16 {
	if v == 0 {
		return d
	}
	return v
}

func splitHostPort(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host, uint16(port), nil
}
