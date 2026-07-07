package app

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/juliuswwj/tbox/internal/config"
	"github.com/juliuswwj/tbox/internal/token"
)

// $XBH_AI_PATCH_START
// // TokenFor builds the connection token for a named client in a server config.
//
//	func TokenFor(cfg *config.ServerConfig, name string) (string, error) {
//		if cfg.ServerAddr == "" {
//			return "", fmt.Errorf("server_addr must be set in the server config to emit tokens")
//		}
//		pub := cfg.RealityPublicKey
//		if pub == "" {
//			var err error
//			pub, err = token.PublicKeyFromPrivate(cfg.RealityPrivateKey)
//			if err != nil {
//				return "", fmt.Errorf("derive public key: %w", err)
//			}
//		}
//		var uuid string
//		for _, c := range cfg.Clients {
//			if c.Name == name {
//				uuid = c.UUID
//			}
//		}
//		if uuid == "" {
//			return "", fmt.Errorf("client %q not found in config", name)
//		}
//		return token.Encode(token.Token{
//			ServerAddr:  cfg.ServerAddr,
//			ServerPort:  cfg.PublicPort(),
//			UUID:        uuid,
//			PublicKey:   pub,
//			ShortID:     cfg.ShortID,
//			SNI:         cfg.MimicHost(),
//			ControlAddr: cfg.ControlAddr,
//		})
//	}
//
// $XBH_AI_PATCH_MODIFY
// TokenFor builds the connection token for a named client, selecting the carrier
// ("reality" or "tuic"). The carrier decides which credential set is baked in;
// the token's Protocol field records the choice so the client renders the
// matching outbound. An empty carrier defaults to "reality" (legacy behavior).
func TokenFor(cfg *config.ServerConfig, name, carrier string) (string, error) {
	if cfg.ServerAddr == "" {
		return "", fmt.Errorf("server_addr must be set in the server config to emit tokens")
	}
	if carrier == "" {
		carrier = "reality"
	}
	var uuid, tuicPw string
	for _, c := range cfg.Clients {
		if c.Name == name {
			uuid = c.UUID
			tuicPw = c.TuicPassword
		}
	}
	if uuid == "" {
		return "", fmt.Errorf("client %q not found in config", name)
	}
	if tuicPw == "" {
		tuicPw = uuid // backward-compatible default: UUID doubles as TUIC password
	}
	tok := token.Token{
		ServerAddr:  cfg.ServerAddr,
		ServerPort:  cfg.PublicPort(),
		UUID:        uuid,
		ControlAddr: cfg.ControlAddr,
	}
	switch carrier {
	case "tuic":
		if !cfg.Tuic.Enable {
			return "", fmt.Errorf("tuic carrier requested but server tuic is not enabled")
		}
		_, portStr, err := net.SplitHostPort(cfg.Tuic.Listen)
		if err != nil {
			return "", fmt.Errorf("tuic.listen: %w", err)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return "", fmt.Errorf("tuic.listen: invalid port %q: %w", portStr, err)
		}
		tok.TuicPort = uint16(port)
		tok.TuicPassword = tuicPw
		tok.TuicSNI = cfg.Tuic.SNI
		tok.TuicCongestion = cfg.Tuic.CongestionControl
		tok.Protocol = "tuic"
	default:
		pub := cfg.RealityPublicKey
		if pub == "" {
			var err error
			pub, err = token.PublicKeyFromPrivate(cfg.RealityPrivateKey)
			if err != nil {
				return "", fmt.Errorf("derive public key: %w", err)
			}
		}
		tok.PublicKey = pub
		tok.ShortID = cfg.ShortID
		tok.SNI = cfg.MimicHost()
		tok.Protocol = "reality"
	}
	return token.Encode(tok)
}

//$XBH_AI_PATCH_END

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
	return TokenFor(cfg, firstClient, "reality")
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
	return TokenFor(cfg, name, "reality")
}
