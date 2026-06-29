// Package app wires the tbox server and client roles together from config.
package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/juliuswwj/tbox/internal/ban"
	"github.com/juliuswwj/tbox/internal/config"
	"github.com/juliuswwj/tbox/internal/control"
	"github.com/juliuswwj/tbox/internal/l2"
	"github.com/juliuswwj/tbox/internal/l4router"
	"github.com/juliuswwj/tbox/internal/singbox"
)

// RunServer starts the VPS-side server: the embedded sing-box VLESS-REALITY
// inbound, the control-plane listener, and the public :443 SNI router.
func RunServer(cfg *config.ServerConfig) error {
	logger := newLogger("[tbox-server] ")

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
	if len(cfg.Publish) > 0 {
		svcs, err := buildServices(cfg.Publish)
		if err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		if err := reg.RegisterServer(svcs); err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		logger.Printf("published %d server-side service(s)", len(svcs))
	}
	hub, tunCleanup, err := setupTunHub(cfg, logger)
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	defer tunCleanup()

	csrv := control.NewServer(reg, clientMap, hub, logger)
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

	banner, err := setupBanner(cfg, logger)
	if err != nil {
		return fmt.Errorf("ban: %w", err)
	}
	router := l4router.New(reg, cfg.RealityInboundAddr, banner, logger)

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

// setupBanner builds the fail2ban-style HTTP throttle when enabled. Durations
// and CIDRs are already validated by LoadServer.
func setupBanner(cfg *config.ServerConfig, logger *log.Logger) (*ban.Banner, error) {
	if !cfg.Ban.Enable {
		return nil, nil
	}
	b := cfg.Ban
	window, _ := time.ParseDuration(b.Window)
	banDur, _ := time.ParseDuration(b.BanDuration)
	subnet := 2
	if b.SubnetThreshold != nil {
		subnet = *b.SubnetThreshold
	}
	exempt := make([]netip.Prefix, 0, len(b.Exempt))
	for _, c := range b.Exempt {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("exempt %q: %w", c, err)
		}
		exempt = append(exempt, p)
	}
	logger.Printf("http ban: %d failures/%s -> ban %s (subnet escalation: %d IPs/24); methods=%v statuses=%v",
		b.Threshold, b.Window, b.BanDuration, subnet, b.Methods, b.Statuses)
	return ban.New(ban.Config{
		Methods:         b.Methods,
		Statuses:        b.Statuses,
		PathPrefix:      b.Path,
		Window:          window,
		Threshold:       b.Threshold,
		BanDuration:     banDur,
		SubnetThreshold: subnet,
		Exempt:          exempt,
	}), nil
}

// setupTunHub starts the server-side L2 tunnel hub when enabled: it creates the
// TAP device, brings it up with the gateway address, optionally enables NAT
// egress and IPv6 passthrough, and starts the local TAP read loop. It returns
// the hub (nil when disabled) and a cleanup to run at shutdown.
func setupTunHub(cfg *config.ServerConfig, logger *log.Logger) (*control.TunHub, func(), error) {
	noop := func() {}
	if !cfg.Tun.Enable {
		return nil, noop, nil
	}

	_, poolNet, err := net.ParseCIDR(cfg.Tun.PoolV4)
	if err != nil {
		return nil, noop, fmt.Errorf("pool_v4: %w", err)
	}

	dev, err := l2.Open(cfg.Tun.TapName)
	if err != nil {
		return nil, noop, fmt.Errorf("open tap: %w", err)
	}
	name := dev.Name()
	if err := l2.SetUp(name, cfg.Tun.MTU); err != nil {
		_ = dev.Close()
		return nil, noop, err
	}
	ones, _ := poolNet.Mask.Size()
	if err := l2.AddAddr(name, fmt.Sprintf("%s/%d", cfg.Tun.Gateway, ones)); err != nil {
		_ = dev.Close()
		return nil, noop, fmt.Errorf("gateway addr: %w", err)
	}

	var onIPv6 func(net.IP)
	if cfg.Tun.EnablePassthrough {
		onIPv6 = l2.NewPassthrough(name, logger).OnIPv6
	}
	sw := l2.New(onIPv6, logger)
	tapPort := sw.AddPort(func(f []byte) error { _, e := dev.Write(f); return e }, l2.PortConfig{Name: "tap:" + name})
	go func() {
		buf := make([]byte, l2.MaxEtherFrame)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			sw.Inject(tapPort, buf[:n])
		}
	}()

	natCleanup := noop
	if cfg.Tun.EnableNAT {
		if err := l2.EnableIPForward(); err != nil {
			logger.Printf("tun: enable forwarding: %v", err)
		}
		cleanup, err := l2.EnsureMasquerade(cfg.Tun.PoolV4, cfg.Tun.WANInterface)
		if err != nil {
			_ = dev.Close()
			return nil, noop, fmt.Errorf("nat: %w", err)
		}
		natCleanup = func() { _ = cleanup() }
	}

	hub := control.NewTunHub(sw, cfg.Tun.Gateway, poolNet, cfg.Tun.MTU, cfg.Tun.EnableNAT, cfg.ServerAddr, logger)
	logger.Printf("tun hub: TAP %s, gateway %s, pool %s (nat=%v, passthrough=%v)",
		name, cfg.Tun.Gateway, cfg.Tun.PoolV4, cfg.Tun.EnableNAT, cfg.Tun.EnablePassthrough)

	cleanup := func() {
		natCleanup()
		_ = dev.Close()
	}
	return hub, cleanup, nil
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
