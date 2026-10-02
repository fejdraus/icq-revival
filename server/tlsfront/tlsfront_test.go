package tlsfront

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/server/tlsfront/tlsfronttest"
)

// servedSerial runs a handshake against the reloader's current certificate and
// returns the serial number of the certificate the client was shown.
func servedSerial(t *testing.T, r *CertReloader) string {
	t.Helper()
	cert, err := r.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	return leaf.SerialNumber.String()
}

func TestCertReloader(t *testing.T) {
	cases := []struct {
		name string
		// change alters the files after the first certificate was loaded.
		change func(t *testing.T, certFile, keyFile string, next tlsfronttest.Cert)
		// wantNext is whether the next certificate is served afterwards.
		wantNext bool
	}{
		{
			name:     "files unchanged, the loaded certificate is served",
			change:   func(*testing.T, string, string, tlsfronttest.Cert) {},
			wantNext: false,
		},
		{
			name: "both files replaced, the new certificate is served without a restart",
			change: func(t *testing.T, certFile, keyFile string, next tlsfronttest.Cert) {
				next.Write(t, certFile, keyFile)
			},
			wantNext: true,
		},
		{
			name: "only the certificate replaced so far, the old pair stays in service",
			change: func(t *testing.T, certFile, _ string, next tlsfronttest.Cert) {
				tlsfronttest.WriteFile(t, certFile, next.CertPEM)
			},
			wantNext: false,
		},
		{
			name: "certificate file garbled, the old pair stays in service",
			change: func(t *testing.T, certFile, _ string, _ tlsfronttest.Cert) {
				tlsfronttest.WriteFile(t, certFile, []byte("not a certificate"))
			},
			wantNext: false,
		},
		{
			name: "key file removed, the old pair stays in service",
			change: func(t *testing.T, _ string, keyFile string, _ tlsfronttest.Cert) {
				require.NoError(t, os.Remove(keyFile))
			},
			wantNext: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "ts-cert.pem"), filepath.Join(dir, "ts-key.pem")
			first := tlsfronttest.NewCert(t, "localhost")
			next := tlsfronttest.NewCert(t, "localhost")
			first.Write(t, certFile, keyFile)

			r, err := NewCertReloader(certFile, keyFile, slog.Default())
			require.NoError(t, err)
			assert.Equal(t, first.Serial.String(), servedSerial(t, r))

			tc.change(t, certFile, keyFile, next)

			want := first.Serial.String()
			if tc.wantNext {
				want = next.Serial.String()
			}
			assert.Equal(t, want, servedSerial(t, r))
		})
	}
}

func TestCertReloader_SecondHalfOfAPairCompletesIt(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "ts-cert.pem"), filepath.Join(dir, "ts-key.pem")
	first := tlsfronttest.NewCert(t, "localhost")
	next := tlsfronttest.NewCert(t, "localhost")
	first.Write(t, certFile, keyFile)

	r, err := NewCertReloader(certFile, keyFile, slog.Default())
	require.NoError(t, err)

	// certbot's hook copies the certificate, then the key
	tlsfronttest.WriteFile(t, certFile, next.CertPEM)
	assert.Equal(t, first.Serial.String(), servedSerial(t, r))
	tlsfronttest.WriteFile(t, keyFile, next.KeyPEM)
	assert.Equal(t, next.Serial.String(), servedSerial(t, r))
}

func TestNewCertReloader_FailsWithoutALoadablePair(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, certFile, keyFile string)
	}{
		{
			name:  "files missing",
			setup: func(*testing.T, string, string) {},
		},
		{
			name: "key does not match the certificate",
			setup: func(t *testing.T, certFile, keyFile string) {
				tlsfronttest.WriteFile(t, certFile, tlsfronttest.NewCert(t, "localhost").CertPEM)
				tlsfronttest.WriteFile(t, keyFile, tlsfronttest.NewCert(t, "localhost").KeyPEM)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
			tc.setup(t, certFile, keyFile)
			_, err := NewCertReloader(certFile, keyFile, slog.Default())
			assert.Error(t, err)
		})
	}
}

// handshakeResult is what each side of a real loopback handshake saw.
type handshakeResult struct {
	clientErr   error
	serverErr   error
	clientState tls.ConnectionState
	serverState tls.ConnectionState
}

// handshake runs a TLS handshake over a loopback TCP connection between the
// server configuration and the client configuration.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) handshakeResult {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	serverDone := make(chan handshakeResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- handshakeResult{serverErr: err}
			return
		}
		defer conn.Close()
		tc := tls.Server(conn, serverCfg)
		err = Handshake(context.Background(), tc)
		serverDone <- handshakeResult{serverErr: err, serverState: tc.ConnectionState()}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	client := tls.Client(conn, clientCfg)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	clientErr := client.Handshake()

	res := <-serverDone
	res.clientErr = clientErr
	res.clientState = client.ConnectionState()
	return res
}

func TestNewServerConfig_Handshake(t *testing.T) {
	cert := tlsfronttest.NewCert(t, "localhost")
	pair, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	require.NoError(t, err)
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &pair, nil }

	cases := []struct {
		name      string
		withHTTP  bool
		client    *tls.Config
		wantErr   bool
		wantProto string
	}{
		{
			name:      "TLS 1.3 with ALPN oscar",
			client:    &tls.Config{NextProtos: []string{ALPNOSCAR}},
			wantProto: ALPNOSCAR,
		},
		{
			name:      "TLS 1.3 without ALPN, as a native TLS client",
			client:    &tls.Config{},
			wantProto: "",
		},
		{
			name:      "TLS 1.3 with ALPN http/1.1 when the WebAPI is on",
			withHTTP:  true,
			client:    &tls.Config{NextProtos: []string{ALPNHTTP}},
			wantProto: ALPNHTTP,
		},
		{
			name:     "ALPN http/1.1 is refused when the WebAPI is off",
			client:   &tls.Config{NextProtos: []string{ALPNHTTP}},
			wantErr:  true,
			withHTTP: false,
		},
		{
			name:     "an unknown ALPN protocol is refused",
			withHTTP: true,
			client:   &tls.Config{NextProtos: []string{"h2"}},
			wantErr:  true,
		},
		{
			name:     "a TLS 1.2 client is refused",
			withHTTP: true,
			client:   &tls.Config{MaxVersion: tls.VersionTLS12, NextProtos: []string{ALPNOSCAR}},
			wantErr:  true,
		},
		{
			name:     "a TLS 1.0-1.2 client without ALPN is refused",
			client:   &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12},
			wantErr:  true,
			withHTTP: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.client.Clone()
			client.RootCAs = cert.Pool
			client.ServerName = "localhost"

			res := handshake(t, NewServerConfig(getCert, tc.withHTTP), client)
			if tc.wantErr {
				assert.Error(t, res.serverErr)
				assert.Error(t, res.clientErr)
				return
			}
			require.NoError(t, res.serverErr)
			require.NoError(t, res.clientErr)
			assert.Equal(t, uint16(tls.VersionTLS13), res.serverState.Version)
			assert.Equal(t, tc.wantProto, res.serverState.NegotiatedProtocol)
			assert.Equal(t, tc.wantProto, res.clientState.NegotiatedProtocol)
		})
	}
}

func TestChannelBinding_SameOnBothEnds(t *testing.T) {
	cert := tlsfronttest.NewCert(t, "localhost")
	pair, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	require.NoError(t, err)
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &pair, nil }

	first := handshake(t, NewServerConfig(getCert, false), &tls.Config{RootCAs: cert.Pool, ServerName: "localhost"})
	require.NoError(t, first.serverErr)
	require.NoError(t, first.clientErr)

	serverCB, err := ChannelBinding(first.serverState)
	require.NoError(t, err)
	clientCB, err := ChannelBinding(first.clientState)
	require.NoError(t, err)
	assert.Len(t, serverCB, 32)
	assert.Equal(t, serverCB, clientCB)

	// another connection binds to another value
	second := handshake(t, NewServerConfig(getCert, false), &tls.Config{RootCAs: cert.Pool, ServerName: "localhost"})
	require.NoError(t, second.serverErr)
	otherCB, err := ChannelBinding(second.serverState)
	require.NoError(t, err)
	assert.NotEqual(t, serverCB, otherCB)
}

func TestConnectionStateContext(t *testing.T) {
	_, ok := ConnectionStateFromContext(context.Background())
	assert.False(t, ok)

	ctx := WithConnectionState(context.Background(), tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: ALPNOSCAR})
	cs, ok := ConnectionStateFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, uint16(tls.VersionTLS13), cs.Version)
	assert.Equal(t, ALPNOSCAR, cs.NegotiatedProtocol)
}

func TestConnListener(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5194}
	l := NewConnListener(addr)
	assert.Equal(t, addr, l.Addr())

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	delivered := make(chan error, 1)
	go func() { delivered <- l.Deliver(a) }()

	got, err := l.Accept()
	require.NoError(t, err)
	assert.Equal(t, a, got)
	assert.NoError(t, <-delivered)

	assert.NoError(t, l.Close())
	assert.NoError(t, l.Close(), "closing twice is fine")

	_, err = l.Accept()
	assert.ErrorIs(t, err, net.ErrClosed)
	assert.ErrorIs(t, l.Deliver(b), net.ErrClosed)
}
