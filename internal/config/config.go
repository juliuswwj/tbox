// Package config defines the on-disk YAML configuration for the tbox server
// and client roles.
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

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
}

// ClientCred is a single authorized client (one VLESS user).
type ClientCred struct {
	Name string `yaml:"name"`
	UUID string `yaml:"uuid"`
}

// ClientConfig is the local-side configuration.
type ClientConfig struct {
	Token       string    `yaml:"token"`
	SocksListen string    `yaml:"socks_listen"`
	AdminListen string    `yaml:"admin_listen"`
	LogLevel    string    `yaml:"log_level"`
	Publish     []Publish `yaml:"publish"`
}

// Publish describes one local service exposed via the server as HTTPS.
type Publish struct {
	Domain string `yaml:"domain"`
	// CertPath/KeyPath are optional: a client that only adds locations to a
	// domain another client already serves (with its cert) can leave them empty.
	CertPath string   `yaml:"cert_path"`
	KeyPath  string   `yaml:"key_path"`
	Mode     string   `yaml:"mode"`  // "http" or "ws"
	Allow    []string `yaml:"allow"` // initial source-IP whitelist (CIDRs); empty = allow all

	// http mode:
	Routes []Route `yaml:"routes,omitempty"`

	// ws mode:
	Path     string `yaml:"path,omitempty"`     // public WS path
	Upstream string `yaml:"upstream,omitempty"` // local raw TCP target
}

// Route is one HTTP reverse-proxy rule (longest path prefix wins).
type Route struct {
	Path            string            `yaml:"path"`             // public path prefix
	Upstream        string            `yaml:"upstream"`         // local HTTP target host:port
	StripPrefix     bool              `yaml:"strip_prefix"`     // strip Path before forwarding
	AddPrefix       string            `yaml:"add_prefix"`       // prepend to upstream path
	SetHost         string            `yaml:"set_host"`         // override Host header
	RequestHeaders  map[string]string `yaml:"request_headers"`  // set/replace; "" value deletes
	ResponseHeaders map[string]string `yaml:"response_headers"` // set/replace; "" value deletes
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
		if p.Domain == "" {
			return nil, fmt.Errorf("publish[%d]: domain is required", i)
		}
		switch p.Mode {
		case "http":
			if len(p.Routes) == 0 {
				return nil, fmt.Errorf("publish[%d] (%s): http mode requires routes", i, p.Domain)
			}
		case "ws":
			if p.Upstream == "" {
				return nil, fmt.Errorf("publish[%d] (%s): ws mode requires upstream", i, p.Domain)
			}
			if p.Path == "" {
				p.Path = "/"
			}
		default:
			return nil, fmt.Errorf("publish[%d] (%s): mode must be http or ws", i, p.Domain)
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
