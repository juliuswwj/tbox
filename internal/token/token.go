// Package token encodes the credential a tbox client needs to connect to a
// tbox server: the VLESS UUID plus the REALITY parameters and server address.
// A token is a self-contained, base64url-encoded JSON blob handed to a client.
package token

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Token carries everything a client needs to dial the server's VLESS-REALITY
// inbound and to authenticate on the control plane.
type Token struct {
	ServerAddr  string `json:"server_addr"`  // host clients dial (public)
	ServerPort  uint16 `json:"server_port"`  // usually 443
	UUID        string `json:"uuid"`         // VLESS user id == client_id on control plane
	PublicKey   string `json:"public_key"`   // REALITY public key (base64url)
	ShortID     string `json:"short_id"`     // REALITY short id (hex)
	SNI         string `json:"sni"`          // REALITY server_name (mimic host)
	ControlAddr string `json:"control_addr"` // server-side control listener (e.g. 127.0.0.1:8443)
	Flow        string `json:"flow,omitempty"`
}

// Encode renders a token as a base64url string with a "tbox://" scheme prefix.
func Encode(t Token) (string, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return "tbox://" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decode parses a token string produced by Encode.
func Decode(s string) (Token, error) {
	const scheme = "tbox://"
	if len(s) > len(scheme) && s[:len(scheme)] == scheme {
		s = s[len(scheme):]
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Token{}, fmt.Errorf("decode token: %w", err)
	}
	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return Token{}, fmt.Errorf("parse token: %w", err)
	}
	if t.UUID == "" || t.ServerAddr == "" || t.PublicKey == "" {
		return Token{}, fmt.Errorf("token missing required fields")
	}
	return t, nil
}

// Keypair is a REALITY X25519 keypair, base64url-encoded.
type Keypair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeypair creates a fresh REALITY X25519 keypair.
func GenerateKeypair() (Keypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// PublicKeyFromPrivate derives the REALITY public key from a private key.
func PublicKeyFromPrivate(privB64 string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// GenerateShortID returns a random REALITY short id (8 hex chars / 4 bytes).
func GenerateShortID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// GenerateUUID returns a random RFC 4122 version 4 UUID string.
func GenerateUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
