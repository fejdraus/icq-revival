// Package stun answers STUN Binding requests: it tells a client the address
// and port its UDP packets come from, as seen from the Internet.
//
// ICQ 6 asks for that before a voice or video call, to offer its peer an
// address that reaches it through its router. It asks turn.oscar.aol.com on
// UDP 3478 - a host that no longer exists, so without an answer the call
// fails as soon as it is picked up. The ICQ 6.5 patch points the client here.
//
// Both the classic STUN of RFC 3489, which that client speaks, and RFC 5389
// are answered. Only the Binding method is served; other requests, such as
// a TURN Allocate, get an error at once so the client does not wait on them.
package stun

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"sync"
)

const (
	headerLen   = 20
	magicCookie = 0x2112A442

	methodBinding = 0x0001

	classRequest       = 0x0000
	classSuccess       = 0x0100
	classErrorResponse = 0x0110

	attrMappedAddress    = 0x0001
	attrChangeRequest    = 0x0003
	attrErrorCode        = 0x0009
	attrXORMappedAddress = 0x0020
)

// Server is a STUN server on one UDP address.
type Server struct {
	addr   string
	logger *slog.Logger

	mu   sync.Mutex
	conn net.PacketConn
}

// NewServer returns a server that listens on addr, e.g. "0.0.0.0:3478".
func NewServer(addr string, logger *slog.Logger) *Server {
	return &Server{addr: addr, logger: logger}
}

// ListenAndServe answers requests until Shutdown.
func (s *Server) ListenAndServe() error {
	conn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	s.logger.Info("starting STUN server", "addr", s.addr)

	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		reply, method := Reply(buf[:n], udp)
		if reply == nil {
			continue
		}
		s.logger.Info("STUN request", "from", udp.String(), "method", method)
		if _, err := conn.WriteTo(reply, from); err != nil {
			s.logger.Warn("STUN reply failed", "to", udp.String(), "err", err)
		}
	}
}

// Shutdown stops the server.
func (s *Server) Shutdown(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// Reply returns the response to a STUN message that came from the given
// address, and the method it asked for. It returns nil for anything that is
// not a request to answer.
func Reply(msg []byte, from *net.UDPAddr) ([]byte, uint16) {
	if len(msg) < headerLen || msg[0]&0xC0 != 0 {
		return nil, 0
	}
	typ := binary.BigEndian.Uint16(msg[0:2])
	length := int(binary.BigEndian.Uint16(msg[2:4]))
	if length%4 != 0 || headerLen+length > len(msg) {
		return nil, 0
	}
	class := typ & 0x0110
	method := typ &^ 0x0110
	if class != classRequest {
		return nil, 0
	}
	id := msg[4:headerLen] // the magic cookie and transaction ID, or a classic 16-byte ID
	modern := binary.BigEndian.Uint32(msg[4:8]) == magicCookie

	if method != methodBinding {
		return message(method|classErrorResponse, id, errorCode(400, "Bad Request")), method
	}

	// A classic client asks for the answer to come from another address or
	// port to learn what kind of NAT it is behind. This server has only one,
	// and an answer from the same one would tell it wrongly; no answer is
	// what such a test expects when the NAT lets nothing else in.
	if flags, ok := attribute(msg[headerLen:headerLen+length], attrChangeRequest); ok && len(flags) == 4 && binary.BigEndian.Uint32(flags)&0x6 != 0 {
		return nil, 0
	}

	ip := from.IP.To4()
	family := byte(0x01)
	if ip == nil {
		ip = from.IP.To16()
		family = 0x02
	}
	if ip == nil {
		return nil, 0
	}
	attrs := addressAttr(attrMappedAddress, family, uint16(from.Port), ip)
	if modern {
		x := make([]byte, len(ip))
		for i := range ip {
			x[i] = ip[i] ^ id[i%len(id)] // the cookie, then the transaction ID
		}
		attrs = append(attrs, addressAttr(attrXORMappedAddress, family, uint16(from.Port)^uint16(magicCookie>>16), x)...)
	}
	return message(methodBinding|classSuccess, id, attrs), method
}

func message(typ uint16, id []byte, attrs []byte) []byte {
	out := make([]byte, headerLen, headerLen+len(attrs))
	binary.BigEndian.PutUint16(out[0:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(attrs)))
	copy(out[4:], id)
	return append(out, attrs...)
}

func addressAttr(typ uint16, family byte, port uint16, ip []byte) []byte {
	v := make([]byte, 4+len(ip))
	v[1] = family
	binary.BigEndian.PutUint16(v[2:4], port)
	copy(v[4:], ip)
	return attr(typ, v)
}

func errorCode(code int, reason string) []byte {
	v := []byte{0, 0, byte(code / 100), byte(code % 100)}
	return attr(attrErrorCode, append(v, reason...))
}

func attr(typ uint16, v []byte) []byte {
	out := make([]byte, 4, 4+len(v)+3)
	binary.BigEndian.PutUint16(out[0:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(v)))
	out = append(out, v...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

// attribute finds an attribute among the ones of a message.
func attribute(attrs []byte, typ uint16) ([]byte, bool) {
	for len(attrs) >= 4 {
		t := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+l > len(attrs) {
			return nil, false
		}
		if t == typ {
			return attrs[4 : 4+l], true
		}
		padded := 4 + (l+3)&^3
		if padded > len(attrs) {
			return nil, false
		}
		attrs = attrs[padded:]
	}
	return nil, false
}
