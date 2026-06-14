package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/proxy"

	"github.com/juliuswwj/tbox/internal/config"
	"github.com/juliuswwj/tbox/internal/control"
	"github.com/juliuswwj/tbox/internal/singbox"
	"github.com/juliuswwj/tbox/internal/token"
)

// RunClient starts the local-side client: the embedded sing-box (SOCKS5H
// inbound + VLESS-REALITY outbound), the control-plane connection that
// registers published services and serves reverse streams, and the local admin
// listener for runtime whitelist changes.
func RunClient(cfg *config.ClientConfig) error {
	logger := log.New(os.Stderr, "[tbox-client] ", log.LstdFlags|log.Lmsgprefix)

	tok, err := token.Decode(cfg.Token)
	if err != nil {
		return err
	}
	if tok.ControlAddr == "" {
		return fmt.Errorf("token missing control_addr; regenerate it with this tbox version")
	}

	raw, err := singbox.ClientConfigJSON(singbox.ClientParams{
		SocksListen: cfg.SocksListen,
		ServerAddr:  tok.ServerAddr,
		ServerPort:  tok.ServerPort,
		UUID:        tok.UUID,
		SNI:         tok.SNI,
		PublicKey:   tok.PublicKey,
		ShortID:     tok.ShortID,
		LogLevel:    cfg.LogLevel,
	})
	if err != nil {
		return fmt.Errorf("build sing-box config: %w", err)
	}
	inst, err := singbox.New(raw)
	if err != nil {
		return err
	}
	if err := inst.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	defer inst.Close()
	logger.Printf("SOCKS5H proxy on %s, VLESS-REALITY outbound to %s:%d", cfg.SocksListen, tok.ServerAddr, tok.ServerPort)

	services, err := buildServices(cfg.Publish)
	if err != nil {
		return err
	}

	dial, err := makeControlDialer(cfg.SocksListen, tok.ControlAddr)
	if err != nil {
		return err
	}

	cc := control.NewClient(tok.UUID, services, dial, logger)

	if cfg.AdminListen != "" {
		adminLn, err := net.Listen("tcp", cfg.AdminListen)
		if err != nil {
			return fmt.Errorf("listen admin %s: %w", cfg.AdminListen, err)
		}
		defer adminLn.Close()
		go serveAdmin(adminLn, cc, logger)
		logger.Printf("admin API on %s", cfg.AdminListen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cc.Run(ctx)
	logger.Printf("shutting down")
	return nil
}

// buildServices converts publish config into wire registrations, reading the
// cert/key files from disk.
func buildServices(pubs []config.Publish) ([]control.ServiceReg, error) {
	out := make([]control.ServiceReg, 0, len(pubs))
	for _, p := range pubs {
		// Cert/key are optional: omit them when only adding a location to a
		// domain whose cert another client already provides.
		var certPEM, keyPEM string
		if p.CertPath != "" || p.KeyPath != "" {
			cert, err := os.ReadFile(p.CertPath)
			if err != nil {
				return nil, fmt.Errorf("read cert for %s: %w", p.Domain, err)
			}
			key, err := os.ReadFile(p.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("read key for %s: %w", p.Domain, err)
			}
			certPEM, keyPEM = string(cert), string(key)
		}
		svc := control.ServiceReg{
			Domain:  p.Domain,
			Mode:    p.Mode,
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
			Allow:   p.Allow,
		}
		switch p.Mode {
		case "http":
			for _, r := range p.Routes {
				svc.Routes = append(svc.Routes, control.RouteReg{
					Path:            r.Path,
					Upstream:        r.Upstream,
					StripPrefix:     r.StripPrefix,
					AddPrefix:       r.AddPrefix,
					SetHost:         r.SetHost,
					RequestHeaders:  r.RequestHeaders,
					ResponseHeaders: r.ResponseHeaders,
				})
			}
		case "ws":
			svc.WSPath = p.Path
			svc.WSUpstream = p.Upstream
		}
		out = append(out, svc)
	}
	return out, nil
}

// makeControlDialer returns a DialFunc that reaches the server's control
// address by tunneling a SOCKS5 CONNECT through the local sing-box inbound.
func makeControlDialer(socksAddr, controlAddr string) (control.DialFunc, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	ctxDialer, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks dialer does not support contexts")
	}
	return func(ctx context.Context) (net.Conn, error) {
		return ctxDialer.DialContext(ctx, "tcp", controlAddr)
	}, nil
}
