package stun

import (
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RelayConfig says how the TURN relay runs.
type RelayConfig struct {
	// PublicIP is the address clients are told their relayed ports are on:
	// the server's address on the Internet.
	PublicIP netip.Addr
	// PortMin and PortMax bound the UDP ports relayed addresses are on. One
	// port serves one allocation, so the range also caps how many there are.
	PortMin, PortMax uint16
	// MaxPerIP caps the allocations clients behind one IP address hold.
	MaxPerIP int
	// Kbps caps the traffic one allocation relays, both ways together.
	Kbps int
	// IdleTimeout closes an allocation that has relayed nothing for so long.
	IdleTimeout time.Duration
}

// SignedIn tells whether a user is signed in from an IP address. The relay
// serves only such addresses: the TURN of ICQ 6.5 has no password to check.
type SignedIn interface {
	SignedInFrom(ip netip.Addr) bool
}

const (
	// lifetimes an allocation is granted: ICQ 6.5 asks for 56 seconds and
	// asks again every 28
	minLifetime     = 30
	defaultLifetime = 300
	maxLifetime     = 600
	// permissionLifetime is how long a peer the client sent to may send back.
	permissionLifetime = 5 * time.Minute
	// packetsPerSecond caps the packets one allocation relays, both ways.
	packetsPerSecond = 500
	// sweepEvery is how often expired and idle allocations are closed.
	sweepEvery = 5 * time.Second
)

// relay is a TURN server in the dialect of ICQ 6.5 (see turn.go). A client
// allocates a UDP port on the server's public address, a relayed address,
// which it offers its peer as one more way to reach it. From then on:
//
//   - a Send request asks for its DATA to go from the relayed address to its
//     DESTINATION-ADDRESS, and lets that address send back;
//   - a Set Active Destination request names the peer that packets the
//     client sends the server without TURN framing go to, and whose packets
//     come back to the client as they are;
//   - what other permitted peers send the relayed address reaches the
//     client in a Data Indication that says who sent it.
//
// The client keeps an allocation by sending Allocate again from the same
// address and port before its lifetime runs out, and gives it up with a
// LIFETIME of 0.
type relay struct {
	cfg      RelayConfig
	bindIP   string // the interface relayed ports are opened on
	signedIn SignedIn
	logger   *slog.Logger
	now      func() time.Time

	mu     sync.Mutex
	conn   net.PacketConn // the server's socket, which clients talk to
	allocs map[netip.AddrPort]*allocation
	byPort map[uint16]*allocation
	perIP  map[netip.Addr]int
	closed bool
	done   chan struct{}
	wg     sync.WaitGroup
}

// allocation is one relayed address and the client it belongs to.
type allocation struct {
	client  netip.AddrPort
	relayed netip.AddrPort
	sock    *net.UDPConn
	created time.Time
	bytes   *rate.Limiter
	packets *rate.Limiter

	mu       sync.Mutex
	expires  time.Time
	lastData time.Time
	active   netip.AddrPort // the peer of Set Active Destination, if any
	perms    map[netip.Addr]time.Time
	in, out  int64 // bytes relayed to and from the client
}

func newRelay(cfg RelayConfig, bindIP string, signedIn SignedIn, logger *slog.Logger) *relay {
	return &relay{
		cfg:      cfg,
		bindIP:   bindIP,
		signedIn: signedIn,
		logger:   logger,
		now:      time.Now,
		allocs:   make(map[netip.AddrPort]*allocation),
		byPort:   make(map[uint16]*allocation),
		perIP:    make(map[netip.Addr]int),
		done:     make(chan struct{}),
	}
}

// start serves allocations through conn, the server's socket, and closes
// expired and idle ones until stop.
func (r *relay) start(conn net.PacketConn) {
	r.mu.Lock()
	r.conn = conn
	r.mu.Unlock()
	r.logger.Info("starting TURN relay", "public_ip", r.cfg.PublicIP.String(),
		"ports", r.cfg.PortMin, "to", r.cfg.PortMax, "per_ip", r.cfg.MaxPerIP, "kbps", r.cfg.Kbps)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(sweepEvery)
		defer t.Stop()
		for {
			select {
			case <-r.done:
				return
			case <-t.C:
				r.sweep()
			}
		}
	}()
}

// stop closes every allocation and waits for their readers.
func (r *relay) stop() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.done)
	var all []*allocation
	for _, a := range r.allocs {
		all = append(all, a)
	}
	r.mu.Unlock()
	for _, a := range all {
		r.remove(a, "shutdown")
	}
	r.wg.Wait()
}

// handle answers a TURN request the client at from sent the server.
func (r *relay) handle(m turnMsg, from netip.AddrPort) []byte {
	switch m.typ {
	case turnAllocate:
		return r.allocate(m, from)
	case turnSend:
		return r.send(m, from)
	case turnSetActiveDest:
		return r.setActiveDestination(m, from)
	case turnCloseBinding:
		if a := r.find(from); a != nil {
			r.remove(a, "closed by the client")
		}
		return encodeTURN(turnCloseBindingResp, m.id)
	}
	return nil
}

// fromClient relays a packet the client at from sent the server without
// TURN framing - media - to its active destination. It returns false, and
// does nothing, for a packet the server itself must answer: a STUN or TURN
// request, or anything from an address with no allocation.
func (r *relay) fromClient(msg []byte, from netip.AddrPort) bool {
	if isServerRequest(msg) {
		return false
	}
	a := r.find(from)
	if a == nil {
		return false
	}
	a.mu.Lock()
	dst := a.active
	a.mu.Unlock()
	if dst.IsValid() && a.allow(len(msg)) {
		r.sendTo(a, dst, msg)
	}
	return true
}

// isServerRequest tells a STUN or TURN request, which the server answers,
// from what a client sends to be relayed. Media never starts with two zero
// bits; a STUN response or indication for the peer is relayed.
func isServerRequest(msg []byte) bool {
	if len(msg) < headerLen || msg[0]&0xC0 != 0 {
		return false
	}
	typ := uint16(msg[0])<<8 | uint16(msg[1])
	length := int(msg[2])<<8 | int(msg[3])
	return headerLen+length == len(msg) && typ&0x0110 == classRequest
}

func (r *relay) find(client netip.AddrPort) *allocation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allocs[client]
}

func (r *relay) allocate(m turnMsg, from netip.AddrPort) []byte {
	lifetime, ok := m.lifetime()
	if !ok {
		lifetime = defaultLifetime
	}
	a := r.find(from)
	if lifetime == 0 {
		if a != nil {
			r.remove(a, "released by the client")
		}
		return encodeTURN(turnAllocateResponse, m.id, turnU32(attrLifetime, 0))
	}
	if !r.signedIn.SignedInFrom(from.Addr()) {
		r.logger.Info("TURN allocation refused: nobody is signed in from there", "from", from.String())
		return encodeTURN(turnAllocateError, m.id, turnError(403, "Forbidden"))
	}
	lifetime = min(max(lifetime, minLifetime), maxLifetime)
	if a == nil {
		var err error
		if a, err = r.open(from); err != nil {
			r.logger.Warn("TURN allocation refused", "from", from.String(), "err", err)
			return encodeTURN(turnAllocateError, m.id, turnError(486, "Allocation Quota Reached"))
		}
	}
	a.mu.Lock()
	a.expires = r.now().Add(time.Duration(lifetime) * time.Second)
	a.mu.Unlock()
	return encodeTURN(turnAllocateResponse, m.id,
		turnAddr(attrMappedAddress, a.relayed), turnU32(attrLifetime, lifetime))
}

var (
	errPerIP = errors.New("too many allocations from this address")
	errPorts = errors.New("no relay port left")
)

// open makes an allocation for a client on a free port of the range.
func (r *relay) open(client netip.AddrPort) (*allocation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if r.perIP[client.Addr()] >= r.cfg.MaxPerIP {
		return nil, errPerIP
	}
	span := int(r.cfg.PortMax) - int(r.cfg.PortMin) + 1
	first := rand.IntN(span)
	for i := range span {
		port := uint16(int(r.cfg.PortMin) + (first+i)%span)
		if r.byPort[port] != nil {
			continue
		}
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(r.bindIP), Port: int(port)})
		if err != nil {
			continue // something else has it
		}
		now := r.now()
		bytesPerSec := r.cfg.Kbps * 1000 / 8
		a := &allocation{
			client:   client,
			relayed:  netip.AddrPortFrom(r.cfg.PublicIP, port),
			sock:     sock,
			created:  now,
			lastData: now,
			bytes:    rate.NewLimiter(rate.Limit(bytesPerSec), max(bytesPerSec, 65535)),
			packets:  rate.NewLimiter(packetsPerSecond, packetsPerSecond),
			perms:    make(map[netip.Addr]time.Time),
		}
		r.allocs[client] = a
		r.byPort[port] = a
		r.perIP[client.Addr()]++
		r.wg.Add(1)
		go r.readPeers(a)
		r.logger.Info("TURN allocation", "client", client.String(), "relayed", a.relayed.String(), "allocations", len(r.allocs))
		return a, nil
	}
	return nil, errPorts
}

// remove closes an allocation.
func (r *relay) remove(a *allocation, why string) {
	r.mu.Lock()
	if r.allocs[a.client] != a {
		r.mu.Unlock()
		return
	}
	delete(r.allocs, a.client)
	delete(r.byPort, a.relayed.Port())
	if r.perIP[a.client.Addr()]--; r.perIP[a.client.Addr()] <= 0 {
		delete(r.perIP, a.client.Addr())
	}
	left := len(r.allocs)
	r.mu.Unlock()
	_ = a.sock.Close()
	a.mu.Lock()
	in, out := a.in, a.out
	a.mu.Unlock()
	r.logger.Info("TURN allocation closed", "client", a.client.String(), "relayed", a.relayed.String(),
		"why", why, "bytes_to_client", in, "bytes_from_client", out,
		"lasted", r.now().Sub(a.created).Round(time.Second).String(), "allocations", left)
}

// sweep closes allocations whose lifetime ran out and those idle too long,
// and forgets expired permissions.
func (r *relay) sweep() {
	now := r.now()
	r.mu.Lock()
	var all []*allocation
	for _, a := range r.allocs {
		all = append(all, a)
	}
	r.mu.Unlock()
	for _, a := range all {
		a.mu.Lock()
		expired := now.After(a.expires)
		idle := now.Sub(a.lastData) > r.cfg.IdleTimeout
		for ip, until := range a.perms {
			if now.After(until) {
				delete(a.perms, ip)
			}
		}
		a.mu.Unlock()
		switch {
		case expired:
			r.remove(a, "not refreshed")
		case idle:
			r.remove(a, "idle")
		}
	}
}

func (r *relay) send(m turnMsg, from netip.AddrPort) []byte {
	a := r.find(from)
	if a == nil {
		return encodeTURN(turnSendError, m.id, turnError(437, "No Binding"))
	}
	dst, ok := m.address(attrDestinationAddress)
	if !ok {
		return encodeTURN(turnSendError, m.id, turnError(400, "Bad Request"))
	}
	if !r.peerAllowed(dst) {
		return encodeTURN(turnSendError, m.id, turnError(403, "Forbidden"))
	}
	a.permit(dst.Addr(), r.now())
	if data, ok := m.get(attrData); ok && len(data) > 0 && a.allow(len(data)) {
		r.sendTo(a, dst, data)
	}
	return encodeTURN(turnSendResponse, m.id)
}

func (r *relay) setActiveDestination(m turnMsg, from netip.AddrPort) []byte {
	a := r.find(from)
	if a == nil {
		return encodeTURN(turnSetActiveDestErr, m.id, turnError(437, "No Binding"))
	}
	dst, ok := m.address(attrDestinationAddress)
	if ok && !r.peerAllowed(dst) {
		return encodeTURN(turnSetActiveDestErr, m.id, turnError(403, "Forbidden"))
	}
	a.mu.Lock()
	a.active = netip.AddrPort{}
	if ok {
		a.active = dst
	}
	a.mu.Unlock()
	if ok {
		a.permit(dst.Addr(), r.now())
	}
	return encodeTURN(turnSetActiveDestResp, m.id)
}

// peerAllowed tells whether the relay may send to an address. It never
// sends to loopback, link-local, multicast or broadcast addresses, and to
// private ones only when its own address is private too - a relay on the
// Internet must not reach into the network it runs in. Of its own address
// it reaches only the relayed ports.
func (r *relay) peerAllowed(dst netip.AddrPort) bool {
	ip := dst.Addr().Unmap()
	if !ip.Is4() || dst.Port() == 0 {
		return false
	}
	if ip == r.cfg.PublicIP {
		return dst.Port() >= r.cfg.PortMin && dst.Port() <= r.cfg.PortMax
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	return scope(ip) <= scope(r.cfg.PublicIP)
}

// scope ranks how far an address reaches: the Internet, a private network,
// the machine itself.
func scope(ip netip.Addr) int {
	switch {
	case ip.IsLoopback():
		return 2
	case ip.IsPrivate() || cgnat.Contains(ip):
		return 1
	}
	return 0
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// sendTo sends what the client of a relays to dst from its relayed address.
// Another allocation of this server is handed the packet directly: a cloud
// network may not bring a packet sent to the server's own public address
// back to it.
func (r *relay) sendTo(a *allocation, dst netip.AddrPort, data []byte) {
	a.mu.Lock()
	a.out += int64(len(data))
	a.lastData = r.now()
	a.mu.Unlock()
	if dst.Addr() == r.cfg.PublicIP {
		r.mu.Lock()
		b := r.byPort[dst.Port()]
		r.mu.Unlock()
		if b != nil {
			r.fromPeer(b, a.relayed, data)
		}
		return
	}
	if _, err := a.sock.WriteToUDPAddrPort(data, dst); err != nil && !errors.Is(err, net.ErrClosed) {
		r.logger.Debug("TURN relay send failed", "relayed", a.relayed.String(), "to", dst.String(), "err", err)
	}
}

// readPeers takes what peers send to a relayed address until it is closed.
func (r *relay) readPeers(a *allocation) {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := a.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		r.fromPeer(a, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), buf[:n])
	}
}

// fromPeer hands the client of a what a peer sent its relayed address: as
// it is from the active destination, in a Data Indication from another peer
// the client sent to, and not at all from anyone else.
func (r *relay) fromPeer(a *allocation, src netip.AddrPort, data []byte) {
	now := r.now()
	a.mu.Lock()
	raw := a.active == src
	until, permitted := a.perms[src.Addr()]
	ok := raw || (permitted && !now.After(until))
	if ok {
		a.in += int64(len(data))
		a.lastData = now
	}
	a.mu.Unlock()
	if !ok || !a.allow(len(data)) {
		return
	}
	out := data
	if !raw {
		out = dataIndication(src, data)
	}
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()
	_, _ = conn.WriteTo(out, net.UDPAddrFromAddrPort(a.client))
}

// permit lets a peer's address send to the relayed address.
func (a *allocation) permit(ip netip.Addr, now time.Time) {
	a.mu.Lock()
	a.perms[ip.Unmap()] = now.Add(permissionLifetime)
	a.mu.Unlock()
}

// allow tells whether a packet of n bytes fits the allocation's caps.
func (a *allocation) allow(n int) bool {
	return a.packets.Allow() && a.bytes.AllowN(time.Now(), n)
}
