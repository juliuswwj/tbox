package app

import (
	"fmt"
	"os"

	"github.com/juliuswwj/tbox/internal/config"
	"github.com/juliuswwj/tbox/internal/token"
)

// TokenFor builds the connection token for a named client in a server config.
func TokenFor(cfg *config.ServerConfig, name string) (string, error) {
	if cfg.ServerAddr == "" {
		return "", fmt.Errorf("server_addr must be set in the server config to emit tokens")
	}
	pub := cfg.RealityPublicKey
	if pub == "" {
		var err error
		pub, err = token.PublicKeyFromPrivate(cfg.RealityPrivateKey)
		if err != nil {
			return "", fmt.Errorf("derive public key: %w", err)
		}
	}
	var uuid string
	for _, c := range cfg.Clients {
		if c.Name == name {
			uuid = c.UUID
		}
	}
	if uuid == "" {
		return "", fmt.Errorf("client %q not found in config", name)
	}
	return token.Encode(token.Token{
		ServerAddr:  cfg.ServerAddr,
		ServerPort:  cfg.PublicPort(),
		UUID:        uuid,
		PublicKey:   pub,
		ShortID:     cfg.ShortID,
		SNI:         cfg.MimicHost(),
		ControlAddr: cfg.ControlAddr,
	})
}

// InitServer generates a fresh, complete server config (REALITY keypair +
// short id) with one initial client, writes it to path, and returns that
// client's token. It refuses to overwrite an existing file unless force is set.
func InitServer(path, serverAddr, mimic, listen, firstClient string, force bool) (string, error) {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return "", fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}
	kp, err := token.GenerateKeypair()
	if err != nil {
		return "", err
	}
	shortID, err := token.GenerateShortID()
	if err != nil {
		return "", err
	}
	uuid, err := token.GenerateUUID()
	if err != nil {
		return "", err
	}
	cfg := &config.ServerConfig{
		Listen:             listen,
		ServerAddr:         serverAddr,
		Mimic:              mimic,
		RealityPrivateKey:  kp.PrivateKey,
		RealityPublicKey:   kp.PublicKey,
		ShortID:            shortID,
		ControlAddr:        "127.0.0.1:8443",
		RealityInboundAddr: "127.0.0.1:8444",
		LogLevel:           "info",
		Clients:            []config.ClientCred{{Name: firstClient, UUID: uuid}},
	}
	if err := config.SaveServer(path, cfg); err != nil {
		return "", err
	}
	return TokenFor(cfg, firstClient)
}

// AddClient generates a new client credential, appends it to the server config
// on disk, and returns its token.
func AddClient(path, name string) (string, error) {
	cfg, err := config.LoadServer(path)
	if err != nil {
		return "", err
	}
	for _, c := range cfg.Clients {
		if c.Name == name {
			return "", fmt.Errorf("client %q already exists", name)
		}
	}
	uuid, err := token.GenerateUUID()
	if err != nil {
		return "", err
	}
	cfg.Clients = append(cfg.Clients, config.ClientCred{Name: name, UUID: uuid})
	if err := config.SaveServer(path, cfg); err != nil {
		return "", err
	}
	return TokenFor(cfg, name)
}
