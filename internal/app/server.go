// Package app wires the tbox server and client roles together from config.
package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/juliuswwj/tbox/internal/config"
	"github.com/juliuswwj/tbox/internal/control"
	"github.com/juliuswwj/tbox/internal/l4router"
	"github.com/juliuswwj/tbox/internal/singbox"
)

// RunServer starts the VPS-side server: the embedded sing-box VLESS-REALITY
// inbound, the control-plane listener, and the public :443 SNI router.
func RunServer(cfg *config.ServerConfig) error {
	logger := log.New(os.Stderr, "[tbox-server] ", log.LstdFlags|log.Lmsgprefix)

	rHost, rPort, err := splitHostPort(cfg.RealityInboundAddr)
	if err != nil {
		return fmt.Errorf("reality_inbound_addr: %w", err)
	}

	users := make([]singbox.User, 0, len(cfg.Clients))
	clientMap := make(map[string]string, len(cfg.Clients))
	for _, c := range cfg.Clients {
		users = append(users, singbox.User{Name: c.Name, UUID: c.UUID})
		clientMap[c.UUID] = c.Name
	}

	raw, err := singbox.ServerConfigJSON(singbox.ServerParams{
		ListenAddr: rHost,
		ListenPort: rPort,
		MimicHost:  cfg.MimicHost(),
		MimicPort:  cfg.MimicPort(),
		PrivateKey: cfg.RealityPrivateKey,
		ShortID:    cfg.ShortID,
		Users:      users,
		LogLevel:   cfg.LogLevel,
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
	logger.Printf("sing-box VLESS-REALITY inbound on %s (mimic %s)", cfg.RealityInboundAddr, cfg.Mimic)

	reg := control.NewRegistry()
	for i, cf := range cfg.Certs {
		certPEM, err := os.ReadFile(cf.CertPath)
		if err != nil {
			return fmt.Errorf("certs[%d]: %w", i, err)
		}
		keyPEM, err := os.ReadFile(cf.KeyPath)
		if err != nil {
			return fmt.Errorf("certs[%d]: %w", i, err)
		}
		if err := reg.AddServerCert(string(certPEM), string(keyPEM)); err != nil {
			return fmt.Errorf("certs[%d]: %w", i, err)
		}
	}
	if len(cfg.Certs) > 0 {
		logger.Printf("loaded %d server-provided certificate(s)", len(cfg.Certs))
	}
	csrv := control.NewServer(reg, clientMap, logger)
	ctrlLn, err := net.Listen("tcp", cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("listen control %s: %w", cfg.ControlAddr, err)
	}
	defer ctrlLn.Close()
	go func() {
		if err := csrv.Serve(ctrlLn); err != nil {
			logger.Printf("control server stopped: %v", err)
		}
	}()
	logger.Printf("control plane on %s (%d client credential(s))", cfg.ControlAddr, len(clientMap))

	router := l4router.New(reg, cfg.RealityInboundAddr, logger)

	errc := make(chan error, 1)
	go func() { errc <- router.ListenAndServe(cfg.Listen) }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		logger.Printf("shutting down")
		return nil
	case err := <-errc:
		return fmt.Errorf("l4 router: %w", err)
	}
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
