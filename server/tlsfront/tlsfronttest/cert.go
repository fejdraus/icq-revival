// Package tlsfronttest makes self-signed certificates for tests of the TLS
// listener.
package tlsfronttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// Cert is a self-signed certificate and its key, in PEM.
type Cert struct {
	CertPEM []byte
	KeyPEM  []byte
	// Serial tells two certificates apart.
	Serial *big.Int
	// Pool trusts the certificate, for a client's RootCAs.
	Pool *x509.CertPool
}

// NewCert makes a self-signed ECDSA certificate for names, which may be DNS
// names or IP addresses, valid for an hour.
func NewCert(t testing.TB, names ...string) Cert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return Cert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Serial:  serial,
		Pool:    pool,
	}
}

// Write puts the certificate and the key in their files.
func (c Cert) Write(t testing.TB, certFile, keyFile string) {
	t.Helper()
	WriteFile(t, certFile, c.CertPEM)
	WriteFile(t, keyFile, c.KeyPEM)
}

// WriteFile writes data to path and moves its modification time a little
// ahead, so a change is seen even where the clock is coarse.
func WriteFile(t testing.TB, path string, data []byte) {
	t.Helper()
	var prev time.Time
	if fi, err := os.Stat(path); err == nil {
		prev = fi.ModTime()
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	next := time.Now()
	if !next.After(prev) {
		next = prev.Add(time.Second)
	}
	if err := os.Chtimes(path, next, next); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}
