// Package tlsfront holds the parts of the server's own TLS 1.3 listener that
// do not depend on a protocol: the certificate that is reloaded when its
// files change, the TLS configuration with ALPN, a listener that hands
// already accepted connections to an HTTP server, and the channel binding
// (RFC 9266 tls-exporter) that SCRAM will bind its sign-in to.
package tlsfront

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// fileStamp tells whether a file changed since it was last read.
type fileStamp struct {
	modTime time.Time
	size    int64
}

func stampOf(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{modTime: fi.ModTime(), size: fi.Size()}, nil
}

// CertReloader serves a certificate from a pair of PEM files and reads them
// again when either changes, so a certificate renewed on disk (certbot) is
// served on the next handshake without a restart.
//
// A pair that does not load, such as a certificate already copied while the
// key is not yet, leaves the previous certificate in service. The pair is
// tried again once either file changes again.
type CertReloader struct {
	certFile string
	keyFile  string
	logger   *slog.Logger

	mu        sync.Mutex
	cert      *tls.Certificate
	certStamp fileStamp
	keyStamp  fileStamp
	// failedCert and failedKey are the stamps of a pair that did not load,
	// so it is not tried, and logged, on every handshake.
	failedCert fileStamp
	failedKey  fileStamp
}

// NewCertReloader loads the certificate in certFile and its key in keyFile.
// It fails when the pair does not load, so a server is not started without a
// certificate to serve.
func NewCertReloader(certFile, keyFile string, logger *slog.Logger) (*CertReloader, error) {
	r := &CertReloader{certFile: certFile, keyFile: keyFile, logger: logger}
	certStamp, keyStamp, err := r.stamps()
	if err != nil {
		return nil, err
	}
	if err := r.load(certStamp, keyStamp); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate returns the current certificate, reading the files again
// when they changed. It is meant for tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	certStamp, keyStamp, err := r.stamps()
	switch {
	case err != nil:
		// The files are being replaced, or are gone: keep what is loaded.
		r.logger.Warn("TLS certificate files unreadable, serving the loaded certificate", "err", err.Error())
	case certStamp == r.certStamp && keyStamp == r.keyStamp:
	case certStamp == r.failedCert && keyStamp == r.failedKey:
	default:
		if err := r.load(certStamp, keyStamp); err != nil {
			r.failedCert, r.failedKey = certStamp, keyStamp
			r.logger.Warn("TLS certificate files changed but do not load, serving the loaded certificate", "err", err.Error())
		}
	}
	return r.cert, nil
}

func (r *CertReloader) stamps() (cert, key fileStamp, err error) {
	if cert, err = stampOf(r.certFile); err != nil {
		return fileStamp{}, fileStamp{}, fmt.Errorf("TLS certificate file: %w", err)
	}
	if key, err = stampOf(r.keyFile); err != nil {
		return fileStamp{}, fileStamp{}, fmt.Errorf("TLS key file: %w", err)
	}
	return cert, key, nil
}

// load reads the pair; the caller holds mu, or owns r alone.
func (r *CertReloader) load(certStamp, keyStamp fileStamp) error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate %s with key %s: %w", r.certFile, r.keyFile, err)
	}
	r.cert = &cert
	r.certStamp, r.keyStamp = certStamp, keyStamp
	attrs := []any{"cert_file", r.certFile}
	if cert.Leaf != nil {
		attrs = append(attrs, "subject", cert.Leaf.Subject.String(), "names", cert.Leaf.DNSNames, "not_after", cert.Leaf.NotAfter)
	}
	r.logger.Info("TLS certificate loaded", attrs...)
	return nil
}
