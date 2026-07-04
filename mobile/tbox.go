// Package mobile is the gomobile entry point for the tbox Android client.
//
// It is bound with `gomobile bind` (see `make android`) together with
// sing-box's experimental/libbox package. The Android app decodes a tbox
// token, builds a sing-box "tun" config (VLESS-REALITY outbound + tun inbound)
// and runs it through libbox. All of the tbox-specific logic — the token
// format and the exact REALITY field mapping — lives here in Go so it stays in
// lockstep with the server, while the Kotlin side only implements
// libbox.PlatformInterface (the VpnService tun + protect callbacks).
package mobile

import (
	"fmt"

	"github.com/sagernet/sing-box/experimental/libbox"

	"github.com/juliuswwj/tbox/internal/singbox"
	"github.com/juliuswwj/tbox/internal/token"
)

// Options tunes the tun client. All fields are optional; zero values fall back
// to sensible defaults. Kept to gomobile-friendly scalar types.
type Options struct {
	LogLevel string // sing-box log level, default "info"
	MTU      int    // tun MTU, default 9000
	IPv6     bool   // include an IPv6 tun address / route
	DNS      string // upstream DNS resolved through the tunnel, default 8.8.8.8

	// BasePath/WorkingPath/TempPath are handed to libbox.Setup. On Android
	// pass Context.getFilesDir()/getCacheDir() paths. If empty, Setup is
	// skipped (fine for a stateless forward-proxy VPN).
	BasePath    string
	WorkingPath string
	TempPath    string
}

// TokenInfo is a gomobile-friendly view of a decoded token, for the UI to
// confirm what a pasted token points at before connecting.
type TokenInfo struct {
	ServerAddr string
	ServerPort int
	SNI        string
	UUID       string
}

// ParseToken decodes and validates a tbox:// token, returning a summary for
// display. It returns an error if the token is malformed.
func ParseToken(tokenStr string) (*TokenInfo, error) {
	tok, err := token.Decode(tokenStr)
	if err != nil {
		return nil, err
	}
	return &TokenInfo{
		ServerAddr: tok.ServerAddr,
		ServerPort: int(tok.ServerPort),
		SNI:        tok.SNI,
		UUID:       tok.UUID,
	}, nil
}

// TokenSummary returns a short human-readable description of a token, e.g.
// "vps.example.com:443 (SNI www.microsoft.com)".
func TokenSummary(tokenStr string) (string, error) {
	info, err := ParseToken(tokenStr)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d (SNI %s)", info.ServerAddr, info.ServerPort, info.SNI), nil
}

// DefaultTunAddress returns the TUN IPv4 address used by the Android client.
func DefaultTunAddress() string {
	return singbox.TunAddress()
}

// BuildConfig decodes a token and renders the sing-box tun config JSON. Exposed
// mainly for debugging/inspection from the app; Start uses it internally.
func BuildConfig(tokenStr string, opts *Options) (string, error) {
	if opts == nil {
		opts = &Options{}
	}
	tok, err := token.Decode(tokenStr)
	if err != nil {
		return "", err
	}
	raw, err := singbox.TunClientConfigJSON(singbox.TunClientParams{
		ServerAddr: tok.ServerAddr,
		ServerPort: tok.ServerPort,
		UUID:       tok.UUID,
		SNI:        tok.SNI,
		PublicKey:  tok.PublicKey,
		ShortID:    tok.ShortID,
		LogLevel:   opts.LogLevel,
		MTU:        uint32(opts.MTU),
		IPv6:       opts.IPv6,
		DNSAddress: opts.DNS,
	})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Service is a running tbox tun client. Close it to tear the VPN down.
type Service struct {
	box *libbox.BoxService
}

// Start decodes the token, builds the tun config and starts the embedded
// sing-box via libbox. The platform argument is implemented on the Kotlin side
// (the VpnService): its OpenTun builds the tun interface and returns the fd,
// and AutoDetectInterfaceControl maps to VpnService.protect so the carrier
// socket to the server bypasses the tunnel.
func Start(tokenStr string, opts *Options, platform libbox.PlatformInterface) (*Service, error) {
	if opts == nil {
		opts = &Options{}
	}
	if platform == nil {
		return nil, fmt.Errorf("platform interface is required")
	}
	if opts.WorkingPath != "" || opts.TempPath != "" || opts.BasePath != "" {
		if err := libbox.Setup(&libbox.SetupOptions{
			BasePath:        opts.BasePath,
			WorkingPath:     opts.WorkingPath,
			TempPath:        opts.TempPath,
			FixAndroidStack: true,
		}); err != nil {
			return nil, fmt.Errorf("libbox setup: %w", err)
		}
	}
	configJSON, err := BuildConfig(tokenStr, opts)
	if err != nil {
		return nil, err
	}
	bs, err := libbox.NewService(configJSON, platform)
	if err != nil {
		return nil, fmt.Errorf("create service: %w", err)
	}
	if err := bs.Start(); err != nil {
		bs.Close()
		return nil, fmt.Errorf("start service: %w", err)
	}
	return &Service{box: bs}, nil
}

// Close stops the running service and tears down the tun.
func (s *Service) Close() error {
	if s == nil || s.box == nil {
		return nil
	}
	err := s.box.Close()
	s.box = nil
	return err
}
