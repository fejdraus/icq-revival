package oscar

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	// proxyHeaderTimeout bounds the wait for the PROXY header nginx sends
	// the moment it connects. OSCAR clients wait for the server to speak
	// first, so a connection without the header just sends nothing.
	proxyHeaderTimeout = 2 * time.Second
	// maxProxyHeaderV1 is the longest a PROXY protocol v1 line can be,
	// "\r\n" included.
	maxProxyHeaderV1 = 107
)

// proxiedConn is a connection accepted from an SSL terminator that told us,
// in a PROXY protocol header, which client it carries: RemoteAddr is that
// client's address, and reads start after the header.
type proxiedConn struct {
	net.Conn
	r      io.Reader
	remote net.Addr
}

func (c *proxiedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *proxiedConn) RemoteAddr() net.Addr { return c.remote }

// withProxyHeader returns conn with the client address an SSL terminator
// such as nginx (with proxy_protocol on) put in a PROXY protocol v1 header,
// "PROXY TCP4 <client> <server> <client port> <server port>\r\n", so that
// the server sees the real address of a client connecting over SSL: it
// hands that address to the other side of a direct connection, such as a
// file transfer, and tells clients on the same network apart by it.
//
// Only a connection from the loopback interface is trusted with a header,
// since nothing else can reach the terminator's listener. A connection
// without one is returned as it is, with any bytes read while looking for
// it still to be read.
func withProxyHeader(conn net.Conn) net.Conn {
	peer, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil || !peer.Addr().Unmap().IsLoopback() {
		return conn
	}

	_ = conn.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	// read one byte at a time, so that nothing after the header is taken
	var line []byte
	one := make([]byte, 1)
	for len(line) < maxProxyHeaderV1 {
		n, err := conn.Read(one)
		if n == 1 {
			line = append(line, one[0])
			if !bytes.HasPrefix([]byte("PROXY "), line) && !bytes.HasPrefix(line, []byte("PROXY ")) {
				break // not a PROXY header
			}
			if bytes.HasSuffix(line, []byte("\r\n")) {
				if remote, ok := parseProxyV1(string(line[:len(line)-2])); ok {
					return &proxiedConn{Conn: conn, r: conn, remote: remote}
				}
				break
			}
		}
		if err != nil {
			break
		}
	}
	return &proxiedConn{Conn: conn, r: io.MultiReader(bytes.NewReader(line), conn), remote: conn.RemoteAddr()}
}

// parseProxyV1 returns the client address of a PROXY protocol v1 line
// without its "\r\n", and reports whether the line names one: "PROXY
// UNKNOWN" and malformed lines don't.
func parseProxyV1(line string) (net.Addr, bool) {
	f := strings.Fields(line)
	if len(f) != 6 || f[0] != "PROXY" || (f[1] != "TCP4" && f[1] != "TCP6") {
		return nil, false
	}
	ip, err := netip.ParseAddr(f[2])
	if err != nil || (f[1] == "TCP4") != ip.Is4() {
		return nil, false
	}
	port, err := strconv.ParseUint(f[4], 10, 16)
	if err != nil {
		return nil, false
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port))), true
}
