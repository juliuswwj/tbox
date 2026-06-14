// Package config defines the on-disk YAML configuration for the tbox server
// and client roles.
package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

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
}

// ClientCred is a single authorized client (one VLESS user).
type ClientCred struct {
	Name string `yaml:"name"`
	UUID string `yaml:"uuid"`
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

	// HTTP mode rewriting (ignored for ws/tcp):
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
	default:
		return "", "", "", fmt.Errorf("url %q: unsupported scheme (use https/wss/tcp)", p.URL)
	}
	path = u.Path
	if mode == "tcp" {
		if path != "" && path != "/" {
			return "", "", "", fmt.Errorf("url %q: tcp services cover a whole host and must not have a path", p.URL)
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
	return &c, nil
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
		if _, _, _, err := p.Parse(); err != nil {
			return nil, fmt.Errorf("publish[%d]: %w", i, err)
		}
		if p.Upstream == "" {
			return nil, fmt.Errorf("publish[%d] (%s): upstream is required", i, p.URL)
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
