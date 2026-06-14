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
	case "init-server":
		err = cmdInitServer(os.Args[2:])
	case "add-client":
		err = cmdAddClient(os.Args[2:])
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

Quick start (server):
  tbox init-server -c server.yaml --addr <vps-host>   # writes config + keys, prints first token
  tbox add-client  -c server.yaml <name>              # adds a client, prints its token
  tbox server      -c server.yaml

Usage:
  tbox init-server -c server.yaml --addr <host> [--mimic www.microsoft.com:443] [--listen :443] [--client <name>] [--force]
  tbox add-client  -c server.yaml <name>
  tbox server      -c server.yaml
  tbox client      -c client.yaml
  tbox gen-token   -c server.yaml [--client <name>]   # re-print token(s) for existing client(s)
  tbox gen-keypair                                    # low-level: just print keys
  tbox whitelist   -c client.yaml show
  tbox whitelist   -c client.yaml set    <service-url> <cidr>...
  tbox whitelist   -c client.yaml add    <service-url> <cidr>...
  tbox whitelist   -c client.yaml remove <service-url> <cidr>...
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

func cmdInitServer(args []string) error {
	var cfgPath, addr string
	mimic := "www.microsoft.com:443"
	listen := ":443"
	client := "default"
	force := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			cfgPath, i = nextArg(args, i)
		case "--addr":
			addr, i = nextArg(args, i)
		case "--mimic":
			mimic, i = nextArg(args, i)
		case "--listen":
			listen, i = nextArg(args, i)
		case "--client":
			client, i = nextArg(args, i)
		case "--force":
			force = true
		default:
			return fmt.Errorf("unexpected argument %q", args[i])
		}
	}
	if cfgPath == "" || addr == "" {
		return fmt.Errorf("usage: tbox init-server -c server.yaml --addr <vps-host> [--mimic ...] [--listen ...] [--client <name>] [--force]")
	}
	tok, err := app.InitServer(cfgPath, addr, mimic, listen, client, force)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s (mimic %s, client %q)\n", cfgPath, mimic, client)
	fmt.Printf("\n# token for client %q (put this in the client's client.yaml):\n%s\n", client, tok)
	fmt.Printf("\nNext: add more clients with `tbox add-client -c %s <name>`, then run `tbox server -c %s`.\n", cfgPath, cfgPath)
	return nil
}

func cmdAddClient(args []string) error {
	var cfgPath string
	var name string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			cfgPath, i = nextArg(args, i)
		default:
			if name == "" {
				name = args[i]
			} else {
				return fmt.Errorf("unexpected argument %q", args[i])
			}
		}
	}
	if cfgPath == "" || name == "" {
		return fmt.Errorf("usage: tbox add-client -c server.yaml <name>")
	}
	tok, err := app.AddClient(cfgPath, name)
	if err != nil {
		return err
	}
	fmt.Printf("# token for client %q (put this in the client's client.yaml):\n%s\n", name, tok)
	return nil
}

func cmdGenToken(args []string) error {
	var cfgPath, clientName string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			cfgPath, i = nextArg(args, i)
		case "--client":
			clientName, i = nextArg(args, i)
		}
	}
	if cfgPath == "" {
		return fmt.Errorf("-c server.yaml is required")
	}
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return err
	}
	names := []string{clientName}
	if clientName == "" {
		names = names[:0]
		for _, c := range cfg.Clients {
			names = append(names, c.Name)
		}
	}
	for _, n := range names {
		tok, err := app.TokenFor(cfg, n)
		if err != nil {
			return err
		}
		fmt.Printf("# token for client %q:\n%s\n", n, tok)
	}
	return nil
}

// nextArg returns the value following a flag at index i, and the advanced index.
func nextArg(args []string, i int) (string, int) {
	if i+1 >= len(args) {
		return "", i
	}
	return args[i+1], i + 1
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
