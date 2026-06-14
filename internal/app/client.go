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

	certs, err := buildCerts(cfg.Certs)
	if err != nil {
		return err
	}
	services, err := buildServices(cfg.Publish)
	if err != nil {
		return err
	}

	dial, err := makeControlDialer(cfg.SocksListen, tok.ControlAddr)
	if err != nil {
		return err
	}

	cc := control.NewClient(tok.UUID, certs, services, dial, logger)

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

// buildCerts reads the client-provided certificate files into wire form.
func buildCerts(files []config.CertFile) ([]control.CertReg, error) {
	out := make([]control.CertReg, 0, len(files))
	for i, cf := range files {
		certPEM, err := os.ReadFile(cf.CertPath)
		if err != nil {
			return nil, fmt.Errorf("certs[%d]: %w", i, err)
		}
		keyPEM, err := os.ReadFile(cf.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("certs[%d]: %w", i, err)
		}
		out = append(out, control.CertReg{CertPEM: string(certPEM), KeyPEM: string(keyPEM)})
	}
	return out, nil
}

// buildServices converts publish config (URL form) into wire registrations.
func buildServices(pubs []config.Publish) ([]control.ServiceReg, error) {
	out := make([]control.ServiceReg, 0, len(pubs))
	for _, p := range pubs {
		mode, host, path, err := p.Parse()
		if err != nil {
			return nil, err
		}
		svc := control.ServiceReg{
			Mode:      mode,
			Host:      host,
			Path:      path,
			Upstream:  p.Upstream,
			Allow:     p.Allow,
			AllowDest: p.AllowDest,
		}
		if mode == "http" {
			svc.StripPrefix = p.StripPrefix
			svc.AddPrefix = p.AddPrefix
			svc.SetHost = p.SetHost
			svc.RequestHeaders = p.RequestHeaders
			svc.ResponseHeaders = p.ResponseHeaders
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
