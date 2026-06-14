// Command tbox is a VLESS-REALITY tunnel that publishes local services as HTTPS
// on a VPS and provides a local SOCKS5H proxy. It has two roles, server and
// client, plus helpers to generate REALITY keys and client tokens.
package main

import (
	"fmt"
	"os"

	"github.com/juliuswwj/tbox/internal/app"
	"github.com/juliuswwj/tbox/internal/config"
	"github.com/juliuswwj/tbox/internal/token"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = cmdServer(os.Args[2:])
	case "client":
		err = cmdClient(os.Args[2:])
	case "gen-keypair":
		err = cmdGenKeypair()
	case "gen-token":
		err = cmdGenToken(os.Args[2:])
	case "whitelist":
		err = cmdWhitelist(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("tbox %s\n", version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tbox — VLESS-REALITY service publishing + SOCKS5H proxy

Usage:
  tbox server   -c server.yaml
  tbox client   -c client.yaml
  tbox gen-keypair
  tbox gen-token -c server.yaml --client <name>
  tbox whitelist -c client.yaml show
  tbox whitelist -c client.yaml set    <domain> <cidr>...
  tbox whitelist -c client.yaml add    <domain> <cidr>...
  tbox whitelist -c client.yaml remove <domain> <cidr>...
  tbox version
`)
}

func cmdServer(args []string) error {
	path, err := flagConfig(args)
	if err != nil {
		return err
	}
	cfg, err := config.LoadServer(path)
	if err != nil {
		return err
	}
	return app.RunServer(cfg)
}

func cmdClient(args []string) error {
	path, err := flagConfig(args)
	if err != nil {
		return err
	}
	cfg, err := config.LoadClient(path)
	if err != nil {
		return err
	}
	return app.RunClient(cfg)
}

func cmdGenKeypair() error {
	kp, err := token.GenerateKeypair()
	if err != nil {
		return err
	}
	sid, err := token.GenerateShortID()
	if err != nil {
		return err
	}
	uuid, err := token.GenerateUUID()
	if err != nil {
		return err
	}
	fmt.Println("# Paste these into your server.yaml:")
	fmt.Printf("reality_private_key: %q\n", kp.PrivateKey)
	fmt.Printf("reality_public_key:  %q\n", kp.PublicKey)
	fmt.Printf("short_id:            %q\n", sid)
	fmt.Println("# Example client credential:")
	fmt.Printf("# clients:\n#   - name: client-1\n#     uuid: %q\n", uuid)
	return nil
}

func cmdGenToken(args []string) error {
	var cfgPath, clientName string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for %s", args[i])
			}
			cfgPath = args[i+1]
			i++
		case "--client":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for --client")
			}
			clientName = args[i+1]
			i++
		}
	}
	if cfgPath == "" {
		return fmt.Errorf("-c server.yaml is required")
	}
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return err
	}

	pub := cfg.RealityPublicKey
	if pub == "" {
		pub, err = token.PublicKeyFromPrivate(cfg.RealityPrivateKey)
		if err != nil {
			return fmt.Errorf("derive public key: %w", err)
		}
	}
	if cfg.ServerAddr == "" {
		return fmt.Errorf("server_addr must be set in server config to emit tokens")
	}

	emit := func(c config.ClientCred) error {
		t := token.Token{
			ServerAddr:  cfg.ServerAddr,
			ServerPort:  cfg.PublicPort(),
			UUID:        c.UUID,
			PublicKey:   pub,
			ShortID:     cfg.ShortID,
			SNI:         cfg.MimicHost(),
			ControlAddr: cfg.ControlAddr,
		}
		s, err := token.Encode(t)
		if err != nil {
			return err
		}
		fmt.Printf("# token for client %q:\n%s\n", c.Name, s)
		return nil
	}

	if clientName != "" {
		for _, c := range cfg.Clients {
			if c.Name == clientName {
				return emit(c)
			}
		}
		return fmt.Errorf("client %q not found in config", clientName)
	}
	for _, c := range cfg.Clients {
		if err := emit(c); err != nil {
			return err
		}
	}
	return nil
}

func cmdWhitelist(args []string) error {
	// tbox whitelist -c client.yaml <show|set|add|remove> [domain] [cidr...]
	var cfgPath string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" || args[i] == "--config" {
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for %s", args[i])
			}
			cfgPath = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	if cfgPath == "" {
		return fmt.Errorf("-c client.yaml is required")
	}
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("missing subcommand: show|set|add|remove")
	}
	admin := cfg.AdminListen
	switch rest[0] {
	case "show":
		return app.WhitelistShow(admin)
	case "set", "add", "remove":
		if len(rest) < 2 {
			return fmt.Errorf("usage: tbox whitelist -c client.yaml %s <domain> <cidr>...", rest[0])
		}
		domain, cidrs := rest[1], rest[2:]
		switch rest[0] {
		case "set":
			return app.WhitelistSet(admin, domain, cidrs)
		case "add":
			return app.WhitelistAdd(admin, domain, cidrs)
		case "remove":
			return app.WhitelistRemove(admin, domain, cidrs)
		}
	}
	return fmt.Errorf("unknown subcommand %q", rest[0])
}

func flagConfig(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" || args[i] == "--config" {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", args[i])
			}
			return args[i+1], nil
		}
	}
	return "", fmt.Errorf("-c <config.yaml> is required")
}
