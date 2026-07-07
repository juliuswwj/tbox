package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSelfSignedCert writes a self-signed cert+key pair whose SAN covers
// domain, returning the cert and key paths.
func writeSelfSignedCert(t *testing.T, dir, domain string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	cp := filepath.Join(dir, "cert.pem")
	kp := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cp, kp
}

func TestValidateServerTuic(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeSelfSignedCert(t, dir, "tuic.example.com")
	certs := []CertFile{{CertPath: cert, KeyPath: key}}

	t.Run("requires sni", func(t *testing.T) {
		tuic := ServerTuic{Enable: true, Listen: ":443"}
		if err := validateServerTuic(&tuic, certs); err == nil || !strings.Contains(err.Error(), "sni") {
			t.Fatalf("want sni-required error, got %v", err)
		}
	})

	t.Run("rejects when no cert covers sni", func(t *testing.T) {
		tuic := ServerTuic{Enable: true, Listen: ":443", SNI: "other.example.com"}
		if err := validateServerTuic(&tuic, certs); err == nil || !strings.Contains(err.Error(), "no cert") {
			t.Fatalf("want no-cert-covers error, got %v", err)
		}
	})

	t.Run("requires at least one cert", func(t *testing.T) {
		tuic := ServerTuic{Enable: true, SNI: "tuic.example.com"}
		if err := validateServerTuic(&tuic, nil); err == nil || !strings.Contains(err.Error(), "cert") {
			t.Fatalf("want cert-required error, got %v", err)
		}
	})

	t.Run("accepts and fills defaults when cert covers sni", func(t *testing.T) {
		tuic := ServerTuic{Enable: true, SNI: "tuic.example.com"}
		if err := validateServerTuic(&tuic, certs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tuic.Listen != ":443" {
			t.Errorf("Listen default = %q, want :443", tuic.Listen)
		}
		if tuic.CongestionControl != "cubic" {
			t.Errorf("CongestionControl default = %q, want cubic", tuic.CongestionControl)
		}
	})
}

func TestFindCertForSAN(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeSelfSignedCert(t, dir, "tuic.example.com")
	certs := []CertFile{{CertPath: cert, KeyPath: key}}

	if cf, ok := FindCertForSAN(certs, "tuic.example.com"); !ok || cf.CertPath != cert {
		t.Fatalf("FindCertForSAN(tuic.example.com) = %+v ok=%v, want %s", cf, ok, cert)
	}
	if _, ok := FindCertForSAN(certs, "nomatch.example.com"); ok {
		t.Fatal("FindCertForSAN should not match an uncovered SNI")
	}
}
