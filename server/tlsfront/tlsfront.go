package tlsfront

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// ALPN protocol names offered on the TLS listener.
const (
	// ALPNOSCAR selects the OSCAR (FLAP) connection handler. A client that
	// offers no ALPN at all gets OSCAR too, so a native TLS client such as
	// Miranda needs nothing new.
	ALPNOSCAR = "oscar"
	// ALPNHTTP selects the WebAPI: sign-in, startOSCARSession and the rest.
	ALPNHTTP = "http/1.1"
)

// HandshakeTimeout bounds the TLS handshake, so a slow or silent client does
// not hold a connection, and its goroutine, forever.
const HandshakeTimeout = 10 * time.Second

// channelBindingLabel and channelBindingLength are the RFC 9266 tls-exporter
// parameters: the exporter label and a 32-byte output, no context.
const (
	channelBindingLabel  = "EXPORTER-Channel-Binding"
	channelBindingLength = 32
)

// NewServerConfig returns the TLS configuration of the listener: TLS 1.3 and
// nothing older, the certificate from getCertificate, and ALPN offering
// "oscar", plus "http/1.1" when withHTTP. A client that offers ALPN but none
// of these is refused in the handshake.
func NewServerConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), withHTTP bool) *tls.Config {
	protos := []string{ALPNOSCAR}
	if withHTTP {
		protos = append(protos, ALPNHTTP)
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
		GetCertificate: getCertificate,
		NextProtos:     protos,
	}
}

// Handshake runs the server side of the TLS handshake on conn within
// HandshakeTimeout, or sooner if ctx ends, and clears the deadline after.
func Handshake(ctx context.Context, conn *tls.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(HandshakeTimeout)); err != nil {
		return err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}

// ChannelBinding returns the RFC 9266 tls-exporter channel binding of a
// TLS 1.3 connection, the value SCRAM-SHA-256-PLUS binds its sign-in to.
func ChannelBinding(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(channelBindingLabel, nil, channelBindingLength)
}

type connStateKey struct{}

// WithConnectionState returns ctx carrying the TLS state of the connection
// it serves, for code that needs the channel binding later.
func WithConnectionState(ctx context.Context, cs tls.ConnectionState) context.Context {
	return context.WithValue(ctx, connStateKey{}, cs)
}

// ConnectionStateFromContext returns the TLS state put on ctx by
// WithConnectionState. ok is false for a connection without the server's own
// TLS.
func ConnectionStateFromContext(ctx context.Context) (cs tls.ConnectionState, ok bool) {
	cs, ok = ctx.Value(connStateKey{}).(tls.ConnectionState)
	return cs, ok
}

// ConnListener is a net.Listener of connections accepted elsewhere: the TLS
// listener hands it the connections that negotiated ALPN http/1.1, and an
// http.Server serves them from it.
type ConnListener struct {
	addr      net.Addr
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

// NewConnListener returns a listener that reports addr as its address.
func NewConnListener(addr net.Addr) *ConnListener {
	return &ConnListener{
		addr:  addr,
		conns: make(chan net.Conn),
		done:  make(chan struct{}),
	}
}

// Deliver hands conn to the next Accept. It returns net.ErrClosed, and leaves
// conn to the caller, when the listener is closed.
func (l *ConnListener) Deliver(conn net.Conn) error {
	select {
	case l.conns <- conn:
		return nil
	case <-l.done:
		return net.ErrClosed
	}
}

// Accept waits for a delivered connection.
func (l *ConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept and Deliver. It is safe to call more than once.
func (l *ConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

// Addr returns the address given to NewConnListener.
func (l *ConnListener) Addr() net.Addr {
	return l.addr
}
