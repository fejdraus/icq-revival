package stun

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedIn is a SignedIn that knows a fixed set of addresses.
type signedIn map[netip.Addr]bool

func (s signedIn) SignedInFrom(ip netip.Addr) bool { return s[ip] }

var (
	publicIP = netip.MustParseAddr("127.0.0.1")
	alice    = netip.MustParseAddrPort("127.0.0.2:40000")
	bob      = netip.MustParseAddrPort("127.0.0.3:40000")
	stranger = netip.MustParseAddrPort("127.0.0.9:40000")
)

func testRelay(t *testing.T, cfg RelayConfig) *relay {
	t.Helper()
	cfg.PublicIP = publicIP
	if cfg.PortMin == 0 {
		cfg.PortMin, cfg.PortMax = 45160, 45199
	}
	if cfg.MaxPerIP == 0 {
		cfg.MaxPerIP = 8
	}
	if cfg.Kbps == 0 {
		cfg.Kbps = 2000
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = time.Minute
	}
	r := newRelay(cfg, "127.0.0.1", signedIn{alice.Addr(): true, bob.Addr(): true}, slog.Default())
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	r.conn = conn // no sweeper: the tests sweep themselves, at the time they set
	t.Cleanup(func() {
		r.stop()
		_ = conn.Close()
	})
	return r
}

func allocateReq(lifetime uint32) turnMsg {
	m, _ := parseTURN(encodeTURN(turnAllocate, classicID, turnU32(attrLifetime, lifetime)))
	return m
}

// answer reads what a reply says: its type, the MAPPED-ADDRESS and LIFETIME
// of an Allocate response, and the code of an error.
func answer(t *testing.T, reply []byte) (typ uint16, mapped netip.AddrPort, lifetime uint32, code int) {
	t.Helper()
	m, ok := parseTURN(reply)
	require.True(t, ok, "the client would not take this for TURN")
	mapped, _ = m.address(attrMappedAddress)
	lifetime, _ = m.lifetime()
	if v, ok := m.get(attrErrorCode); ok {
		code = int(v[2])*100 + int(v[3])
	}
	return m.typ, mapped, lifetime, code
}

func TestRelayAllocate(t *testing.T) {
	tests := []struct {
		name         string
		from         netip.AddrPort
		lifetime     uint32
		omitLifetime bool
		wantType     uint16
		wantLifetime uint32
		wantCode     int
	}{
		{name: "ICQ's 56 seconds are granted", from: alice, lifetime: 56, wantType: turnAllocateResponse, wantLifetime: 56},
		{name: "too short a lifetime is raised", from: alice, lifetime: 5, wantType: turnAllocateResponse, wantLifetime: minLifetime},
		{name: "too long a lifetime is cut", from: alice, lifetime: 86400, wantType: turnAllocateResponse, wantLifetime: maxLifetime},
		{name: "no lifetime gets the default", from: alice, omitLifetime: true, wantType: turnAllocateResponse, wantLifetime: defaultLifetime},
		{name: "nobody signed in from there", from: stranger, lifetime: 56, wantType: turnAllocateError, wantCode: 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testRelay(t, RelayConfig{})
			req := allocateReq(tt.lifetime)
			if tt.omitLifetime {
				req, _ = parseTURN(encodeTURN(turnAllocate, classicID))
			}
			typ, mapped, lifetime, code := answer(t, r.handle(req, tt.from))
			assert.Equal(t, tt.wantType, typ)
			assert.Equal(t, tt.wantCode, code)
			if tt.wantType != turnAllocateResponse {
				assert.Nil(t, r.find(tt.from))
				return
			}
			assert.Equal(t, tt.wantLifetime, lifetime)
			assert.Equal(t, publicIP, mapped.Addr())
			assert.True(t, mapped.Port() >= 45160 && mapped.Port() <= 45199)
		})
	}
}

func TestRelayAllocationLifecycle(t *testing.T) {
	r := testRelay(t, RelayConfig{IdleTimeout: time.Hour})
	now := time.Now()
	r.now = func() time.Time { return now }

	_, first, _, _ := answer(t, r.handle(allocateReq(56), alice))
	_, again, _, _ := answer(t, r.handle(allocateReq(56), alice))
	assert.Equal(t, first, again, "a refresh keeps the relayed address")

	now = now.Add(50 * time.Second)
	r.sweep()
	assert.NotNil(t, r.find(alice), "refreshed within its lifetime")

	now = now.Add(10 * time.Second)
	r.sweep()
	assert.Nil(t, r.find(alice), "not refreshed in time")

	_, _, _, _ = answer(t, r.handle(allocateReq(56), alice))
	typ, _, lifetime, _ := answer(t, r.handle(allocateReq(0), alice))
	assert.Equal(t, uint16(turnAllocateResponse), typ)
	assert.Equal(t, uint32(0), lifetime)
	assert.Nil(t, r.find(alice), "released with a lifetime of 0")

	_, _, _, _ = answer(t, r.handle(allocateReq(56), alice))
	typ, _, _, _ = answer(t, r.handle(func() turnMsg { m, _ := parseTURN(encodeTURN(turnCloseBinding, classicID)); return m }(), alice))
	assert.Equal(t, uint16(turnCloseBindingResp), typ)
	assert.Nil(t, r.find(alice), "closed with Close Binding")
}

func TestRelayIdle(t *testing.T) {
	r := testRelay(t, RelayConfig{IdleTimeout: 2 * time.Minute})
	now := time.Now()
	r.now = func() time.Time { return now }
	_, _, _, _ = answer(t, r.handle(allocateReq(maxLifetime), alice))
	now = now.Add(time.Minute)
	r.sweep()
	assert.NotNil(t, r.find(alice))
	now = now.Add(2 * time.Minute)
	r.sweep()
	assert.Nil(t, r.find(alice), "nothing relayed for longer than the idle timeout")
}

func TestRelayLimits(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RelayConfig
		clients []netip.AddrPort
		want    []int // error code of each Allocate, 0 for success
	}{
		{
			name:    "allocations per address",
			cfg:     RelayConfig{MaxPerIP: 2},
			clients: []netip.AddrPort{alice, netip.AddrPortFrom(alice.Addr(), 40001), netip.AddrPortFrom(alice.Addr(), 40002), bob},
			want:    []int{0, 0, 486, 0},
		},
		{
			name:    "the port range is the total",
			cfg:     RelayConfig{PortMin: 45200, PortMax: 45201},
			clients: []netip.AddrPort{alice, bob, netip.AddrPortFrom(alice.Addr(), 40001)},
			want:    []int{0, 0, 486},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testRelay(t, tt.cfg)
			for i, c := range tt.clients {
				_, _, _, code := answer(t, r.handle(allocateReq(56), c))
				assert.Equal(t, tt.want[i], code, "client %d", i)
			}
		})
	}
}

func TestRelayRequestsWithoutAllocation(t *testing.T) {
	r := testRelay(t, RelayConfig{})
	send, _ := parseTURN(encodeTURN(turnSend, classicID, turnAddr(attrDestinationAddress, bob), stunAttr{attrData, []byte("x")}))
	typ, _, _, code := answer(t, r.handle(send, alice))
	assert.Equal(t, uint16(turnSendError), typ)
	assert.Equal(t, 437, code)
	dest, _ := parseTURN(encodeTURN(turnSetActiveDest, classicID, turnAddr(attrDestinationAddress, bob)))
	typ, _, _, code = answer(t, r.handle(dest, alice))
	assert.Equal(t, uint16(turnSetActiveDestErr), typ)
	assert.Equal(t, 437, code)
}

func TestRelayPeerAllowed(t *testing.T) {
	onInternet := &relay{cfg: RelayConfig{PublicIP: netip.MustParseAddr("192.0.2.1"), PortMin: 49160, PortMax: 49199}}
	onLAN := &relay{cfg: RelayConfig{PublicIP: netip.MustParseAddr("192.168.1.10"), PortMin: 49160, PortMax: 49199}}
	tests := []struct {
		name  string
		relay *relay
		dst   string
		want  bool
	}{
		{name: "an address on the Internet", relay: onInternet, dst: "198.51.100.7:50000", want: true},
		{name: "another relayed port of the server", relay: onInternet, dst: "192.0.2.1:49170", want: true},
		{name: "another service of the server", relay: onInternet, dst: "192.0.2.1:3478", want: false},
		{name: "a private address from the Internet", relay: onInternet, dst: "192.168.1.5:50000", want: false},
		{name: "a carrier-grade NAT address from the Internet", relay: onInternet, dst: "100.100.1.1:50000", want: false},
		{name: "loopback", relay: onInternet, dst: "127.0.0.1:8080", want: false},
		{name: "link-local", relay: onInternet, dst: "169.254.169.254:80", want: false},
		{name: "multicast", relay: onInternet, dst: "239.1.1.1:5000", want: false},
		{name: "broadcast", relay: onInternet, dst: "255.255.255.255:5000", want: false},
		{name: "port 0", relay: onInternet, dst: "198.51.100.7:0", want: false},
		{name: "a private address from a relay on a LAN", relay: onLAN, dst: "192.168.1.5:50000", want: true},
		{name: "loopback from a relay on a LAN", relay: onLAN, dst: "127.0.0.1:8080", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.relay.peerAllowed(netip.MustParseAddrPort(tt.dst)))
		})
	}
}

func TestIsServerRequest(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		want bool
	}{
		{name: "an Allocate", msg: icqAllocate(classicID), want: true},
		{name: "a Binding request", msg: request(0x0001, classicID, nil), want: true},
		{name: "a Binding response for the peer", msg: message(0x0101, classicID, nil), want: false},
		{name: "RTP", msg: append([]byte{0x80, 0x60, 0, 1}, make([]byte, 30)...), want: false},
		{name: "a CRLF keepalive", msg: []byte("\r\n"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isServerRequest(tt.msg))
		})
	}
}

// udpAt opens a UDP socket on a loopback address other than the server's.
func udpAt(t *testing.T, a netip.AddrPort) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.Addr(), 0)))
	if err != nil {
		t.Skipf("cannot bind %s here: %v", a.Addr(), err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func recv(t *testing.T, c *net.UDPConn) ([]byte, netip.AddrPort, bool) {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	buf := make([]byte, 2048)
	n, from, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, netip.AddrPort{}, false
	}
	return buf[:n], from, true
}

func mustRecv(t *testing.T, c *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	msg, from, ok := recv(t, c)
	require.True(t, ok, "nothing arrived")
	return msg, from
}

// TestRelayForwarding runs the server with a relay on loopback: two clients
// signed in from 127.0.0.2 and 127.0.0.3 and a peer on the Internet side at
// 127.0.0.4.
func TestRelayForwarding(t *testing.T) {
	s, err := NewServerWithRelay("127.0.0.1:0", slog.Default(),
		RelayConfig{PublicIP: publicIP, PortMin: 45300, PortMax: 45339, MaxPerIP: 8, Kbps: 2000, IdleTimeout: time.Minute},
		signedIn{alice.Addr(): true, bob.Addr(): true})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe() }()
	var server netip.AddrPort
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.conn != nil {
			server = s.conn.LocalAddr().(*net.UDPAddr).AddrPort()
		}
		return server.IsValid()
	}, time.Second, 10*time.Millisecond)
	defer func() {
		assert.NoError(t, s.Shutdown(context.Background()))
		assert.NoError(t, <-done)
	}()

	a := udpAt(t, alice)
	b := udpAt(t, bob)
	p := udpAt(t, netip.MustParseAddrPort("127.0.0.4:0"))
	peerAddr := p.LocalAddr().(*net.UDPAddr).AddrPort()

	ask := func(c *net.UDPConn, msg []byte) turnMsg {
		t.Helper()
		_, err := c.WriteToUDPAddrPort(msg, server)
		require.NoError(t, err)
		reply, _ := mustRecv(t, c)
		m, ok := parseTURN(reply)
		require.True(t, ok)
		return m
	}
	relayedOf := func(c *net.UDPConn) netip.AddrPort {
		m := ask(c, icqAllocate(classicID))
		require.Equal(t, uint16(turnAllocateResponse), m.typ)
		relayed, ok := m.address(attrMappedAddress)
		require.True(t, ok)
		return relayed
	}
	relayedA := relayedOf(a)

	// a stranger's packet to the relayed address goes nowhere
	_, err = p.WriteToUDPAddrPort([]byte("knock"), relayedA)
	require.NoError(t, err)
	_, _, got := recv(t, a)
	assert.False(t, got, "a peer the client never sent to cannot reach it")

	// Send: the DATA leaves the relayed address, the client gets a response
	m := ask(a, encodeTURN(turnSend, classicID, turnAddr(attrDestinationAddress, peerAddr), stunAttr{attrData, []byte("\r\n")}))
	assert.Equal(t, uint16(turnSendResponse), m.typ)
	data, from := mustRecv(t, p)
	assert.Equal(t, []byte("\r\n"), data)
	assert.Equal(t, relayedA, from)

	// now the peer may send back, and it comes in a Data Indication
	_, err = p.WriteToUDPAddrPort([]byte("probe"), relayedA)
	require.NoError(t, err)
	di, _ := mustRecv(t, a)
	m, ok := parseTURN(di)
	require.True(t, ok)
	assert.Equal(t, uint16(turnDataIndication), m.typ)
	remote, _ := m.address(attrRemoteAddress)
	assert.Equal(t, peerAddr, remote)
	payload, _ := m.get(attrData)
	assert.Equal(t, []byte("probe"), payload)

	// Set Active Destination: media goes both ways as it is
	m = ask(a, encodeTURN(turnSetActiveDest, classicID, turnAddr(attrDestinationAddress, peerAddr)))
	assert.Equal(t, uint16(turnSetActiveDestResp), m.typ)
	rtp := append([]byte{0x80, 0x60, 0x00, 0x01}, make([]byte, 160)...)
	_, err = a.WriteToUDPAddrPort(rtp, server)
	require.NoError(t, err)
	data, from = mustRecv(t, p)
	assert.Equal(t, rtp, data)
	assert.Equal(t, relayedA, from)
	_, err = p.WriteToUDPAddrPort(rtp, relayedA)
	require.NoError(t, err)
	data, from = mustRecv(t, a)
	assert.Equal(t, rtp, data)
	assert.Equal(t, server, from)

	// a Binding request from the client is still answered by the server
	_, err = a.WriteToUDPAddrPort(request(0x0001, classicID, nil), server)
	require.NoError(t, err)
	data, _ = mustRecv(t, a)
	assert.Equal(t, uint16(0x0101), binary.BigEndian.Uint16(data[0:2]))

	// relay to relay: Bob lets Alice's relayed address in, then Alice sends
	// to Bob's relayed address, which this server hands over directly
	relayedB := relayedOf(b)
	m = ask(b, encodeTURN(turnSend, classicID, turnAddr(attrDestinationAddress, relayedA), stunAttr{attrData, []byte("\r\n")}))
	assert.Equal(t, uint16(turnSendResponse), m.typ)
	_, _, _ = recv(t, a) // the priming, in a Data Indication or dropped
	m = ask(a, encodeTURN(turnSend, classicID, turnAddr(attrDestinationAddress, relayedB), stunAttr{attrData, []byte("hi bob")}))
	assert.Equal(t, uint16(turnSendResponse), m.typ)
	di, _ = mustRecv(t, b)
	m, ok = parseTURN(di)
	require.True(t, ok)
	remote, _ = m.address(attrRemoteAddress)
	assert.Equal(t, relayedA, remote)
	payload, _ = m.get(attrData)
	assert.Equal(t, []byte("hi bob"), payload)
}

func TestServerWithoutRelayRefusesTURN(t *testing.T) {
	s := NewServer("127.0.0.1:0", slog.Default())
	m, _ := parseTURN(icqAllocate(classicID))
	typ, _, _, code := answer(t, s.turnReply(m, alice))
	assert.Equal(t, uint16(turnAllocateError), typ)
	assert.Equal(t, 403, code)
}
