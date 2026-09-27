package oscar

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// pipeFrom returns the server end of a connection whose client end writes
// sent (unless it is nil) and then waits; the server end reports remote as
// its RemoteAddr.
func pipeFrom(t *testing.T, remote string, sent []byte) net.Conn {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	if sent != nil {
		go func() { _, _ = client.Write(sent) }()
	}
	addr, err := net.ResolveTCPAddr("tcp", remote)
	assert.NoError(t, err)
	return addrConn{Conn: server, remote: addr}
}

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

func TestWithProxyHeader(t *testing.T) {
	tests := []struct {
		name       string
		peer       string
		sent       string
		wantRemote string
		// wantRest is what reads return after the header, of what was sent
		wantRest string
	}{
		{
			name:       "IPv4 client behind nginx",
			peer:       "127.0.0.1:40000",
			sent:       "PROXY TCP4 203.0.113.7 10.0.0.2 51311 5193\r\n*\x01",
			wantRemote: "203.0.113.7:51311",
			wantRest:   "*\x01",
		},
		{
			name:       "IPv6 client behind nginx",
			peer:       "[::1]:40000",
			sent:       "PROXY TCP6 2001:db8::5 2001:db8::1 443 5193\r\n",
			wantRemote: "[2001:db8::5]:443",
		},
		{
			name:       "a header from anything but loopback is not trusted",
			peer:       "198.51.100.9:40000",
			sent:       "PROXY TCP4 203.0.113.7 10.0.0.2 51311 5193\r\n",
			wantRemote: "198.51.100.9:40000",
			wantRest:   "PROXY TCP4 203.0.113.7 10.0.0.2 51311 5193\r\n",
		},
		{
			name:       "no header: what was read is read again",
			peer:       "127.0.0.1:40000",
			sent:       "*\x01\x00\x01",
			wantRemote: "127.0.0.1:40000",
			wantRest:   "*\x01\x00\x01",
		},
		{
			name:       "PROXY UNKNOWN keeps the terminator's address",
			peer:       "127.0.0.1:40000",
			sent:       "PROXY UNKNOWN\r\n",
			wantRemote: "127.0.0.1:40000",
			wantRest:   "PROXY UNKNOWN\r\n",
		},
		{
			name:       "an address of the wrong family",
			peer:       "127.0.0.1:40000",
			sent:       "PROXY TCP4 2001:db8::5 10.0.0.2 1 2\r\n",
			wantRemote: "127.0.0.1:40000",
			wantRest:   "PROXY TCP4 2001:db8::5 10.0.0.2 1 2\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := withProxyHeader(pipeFrom(t, tt.peer, []byte(tt.sent)))
			assert.Equal(t, tt.wantRemote, conn.RemoteAddr().String())

			got := make([]byte, len(tt.wantRest))
			if len(got) > 0 {
				_, err := io.ReadFull(conn, got)
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantRest, string(got))
		})
	}

	t.Run("a client that sends nothing is let through after the timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("waits for the header timeout")
		}
		start := time.Now()
		conn := withProxyHeader(pipeFrom(t, "127.0.0.1:40000", nil))
		assert.Equal(t, "127.0.0.1:40000", conn.RemoteAddr().String())
		assert.Less(t, time.Since(start), proxyHeaderTimeout+time.Second)
	})
}
