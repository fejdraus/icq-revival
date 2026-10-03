package oscar

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/tlsfront"
	"github.com/mk6i/open-oscar-server/server/tlsfront/tlsfronttest"
	"github.com/mk6i/open-oscar-server/server/webapi"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// noKeyDirectory leaves the WebAPI without the E2E key directory.
type noKeyDirectory struct{}

func (noKeyDirectory) Register(*http.ServeMux) {}

// freeAddr returns a loopback address with a port nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// tlsFixture is an OSCAR server with a TLS 1.3 listener, ALPN http/1.1
// handed to a real WebAPI server, and the certificate files on disk.
type tlsFixture struct {
	addr     string
	certFile string
	keyFile  string
	cert     tlsfronttest.Cert
}

// startTLSServer starts the OSCAR server, whose connection handler is
// handler (nil for the real one), and the WebAPI behind its TLS listener.
func startTLSServer(t *testing.T, handler func(ctx context.Context, conn net.Conn, endpointCfg config.Endpoint) error) tlsFixture {
	t.Helper()

	dir := t.TempDir()
	fx := tlsFixture{
		addr:     freeAddr(t),
		certFile: filepath.Join(dir, "ts-cert.pem"),
		keyFile:  filepath.Join(dir, "ts-key.pem"),
		cert:     tlsfronttest.NewCert(t, "localhost", "127.0.0.1"),
	}
	fx.cert.Write(t, fx.certFile, fx.keyFile)

	groups := []config.ListenerGroup{
		{
			Name:                   "lan",
			BOSListenAddress:       freeAddr(t),
			BOSAdvertisedHostPlain: "icq.example.org:5190",
			BOSListenAddressTLS:    fx.addr,
			BOSAdvertisedHostTLS:   "icq.example.org:5194",
		},
	}

	server := NewServer(
		nil,
		nil,
		nil,
		nil,
		slog.Default(),
		nil,
		nil,
		nil,
		wire.DefaultSNACRateLimits(),
		nil,
		groups,
		func(ctx context.Context, instance *state.SessionInstance) error { return nil },
		func(ctx context.Context, instance *state.SessionInstance) {},
	)
	if handler != nil {
		server.handler = handler
	}

	web := webapi.NewServer(nil, slog.Default(), webapi.Handler{Logger: slog.Default(), E2EKeyDirectory: noKeyDirectory{}}, webapi.NewSessionManager())
	httpConns := tlsfront.NewConnListener(&net.TCPAddr{})
	web.ServeListener(httpConns)

	certs, err := tlsfront.NewCertReloader(fx.certFile, fx.keyFile, slog.Default())
	require.NoError(t, err)
	server.EnableTLS(tlsfront.NewServerConfig(certs.GetCertificate, true), httpConns)

	oscarDone := make(chan error, 1)
	go func() { oscarDone <- server.ListenAndServe() }()
	webDone := make(chan error, 1)
	go func() { webDone <- web.ListenAndServe() }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, server.Shutdown(ctx))
		assert.NoError(t, web.Shutdown(ctx))
		assert.NoError(t, <-oscarDone)
		assert.NoError(t, <-webDone)
	})

	// wait until the TLS port accepts
	for attempt := 0; ; attempt++ {
		conn, err := net.Dial("tcp", fx.addr)
		if err == nil {
			_ = conn.Close()
			break
		}
		if attempt == 50 {
			t.Fatalf("TLS listener not ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fx
}

// dialTLS opens a client connection to the fixture.
func (fx tlsFixture) dialTLS(cfg *tls.Config) (*tls.Conn, error) {
	cfg.ServerName = "localhost"
	if cfg.RootCAs == nil {
		cfg.RootCAs = fx.cert.Pool
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fx.addr, cfg)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, nil
}

func TestServer_TLSListener_ALPN(t *testing.T) {
	fx := startTLSServer(t, nil)

	cases := []struct {
		name string
		// client is the client's TLS configuration
		client *tls.Config
		// wantHandshakeErr is whether the handshake is refused
		wantHandshakeErr bool
		// wantFLAPHello is whether the OSCAR server greets with a FLAP
		// sign-on frame
		wantFLAPHello bool
		// wantHTTP is whether GET / reaches the WebAPI
		wantHTTP bool
	}{
		{
			name:          "ALPN oscar gets the FLAP hello",
			client:        &tls.Config{NextProtos: []string{tlsfront.ALPNOSCAR}},
			wantFLAPHello: true,
		},
		{
			name:          "no ALPN gets the FLAP hello, as a native TLS client",
			client:        &tls.Config{},
			wantFLAPHello: true,
		},
		{
			name:     "ALPN http/1.1 reaches the WebAPI",
			client:   &tls.Config{NextProtos: []string{tlsfront.ALPNHTTP}},
			wantHTTP: true,
		},
		{
			name:             "a TLS 1.2 client is refused",
			client:           &tls.Config{MaxVersion: tls.VersionTLS12},
			wantHandshakeErr: true,
		},
		{
			name:             "an unknown ALPN protocol is refused",
			client:           &tls.Config{NextProtos: []string{"h2"}},
			wantHandshakeErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.client.Clone()
			conn, err := fx.dialTLS(client)
			if tc.wantHandshakeErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			assert.Equal(t, uint16(tls.VersionTLS13), conn.ConnectionState().Version)

			if tc.wantFLAPHello {
				flap := wire.FLAPFrame{}
				require.NoError(t, wire.UnmarshalBE(&flap, conn))
				assert.Equal(t, uint8(0x2a), flap.StartMarker)
				assert.Equal(t, wire.FLAPFrameSignon, flap.FrameType)
			}

			if tc.wantHTTP {
				_, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
				require.NoError(t, err)
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				require.NoError(t, err)
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.True(t, strings.HasPrefix(string(body), "WebAPI Server Running\n"), "body: %q", body)
			}
		})
	}
}

func TestServer_TLSListener_EndpointAndChannelBinding(t *testing.T) {
	type seen struct {
		endpoint config.Endpoint
		binding  []byte
		ok       bool
	}
	seenCh := make(chan seen, 1)
	fx := startTLSServer(t, func(ctx context.Context, conn net.Conn, endpointCfg config.Endpoint) error {
		s := seen{endpoint: endpointCfg}
		if cs, ok := tlsfront.ConnectionStateFromContext(ctx); ok {
			s.binding, _ = tlsfront.ChannelBinding(cs)
			s.ok = true
		}
		seenCh <- s
		_, _ = conn.Write([]byte{0})
		return nil
	})

	conn, err := fx.dialTLS(&tls.Config{NextProtos: []string{tlsfront.ALPNOSCAR}})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, _ = conn.Read(make([]byte, 1)) // the handler ran

	got := <-seenCh
	assert.Equal(t, config.TransportTLS13, got.endpoint.Transport)
	assert.Equal(t, "icq.example.org:5194", got.endpoint.AdvertisedHost())
	require.True(t, got.ok, "the handler's context carries the TLS state")

	clientBinding, err := tlsfront.ChannelBinding(conn.ConnectionState())
	require.NoError(t, err)
	assert.Len(t, got.binding, 32)
	assert.Equal(t, clientBinding, got.binding, "tls-exporter is the same on both ends")
}

func TestServer_TLSListener_CertificateReload(t *testing.T) {
	fx := startTLSServer(t, nil)

	servedSerial := func(cfg *tls.Config) string {
		conn, err := fx.dialTLS(cfg)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}

	assert.Equal(t, fx.cert.Serial.String(), servedSerial(&tls.Config{}))

	renewed := tlsfronttest.NewCert(t, "localhost", "127.0.0.1")
	renewed.Write(t, fx.certFile, fx.keyFile)

	assert.Equal(t, renewed.Serial.String(), servedSerial(&tls.Config{RootCAs: renewed.Pool}),
		"a replaced certificate file is served without a restart")
}

func TestServer_TLSListener_SilentClientTimesOut(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the handshake deadline")
	}
	fx := startTLSServer(t, nil)

	conn, err := net.Dial("tcp", fx.addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// say nothing: the server gives up after the handshake deadline
	_ = conn.SetReadDeadline(time.Now().Add(tlsfront.HandshakeTimeout + 5*time.Second))
	start := time.Now()
	_, err = conn.Read(make([]byte, 1))
	assert.Error(t, err)
	assert.Less(t, time.Since(start), tlsfront.HandshakeTimeout+4*time.Second)
}
