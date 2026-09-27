package stun

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
)

// The TURN that ICQ 6.5 speaks is the one of draft-rosenberg-midcom-turn-08
// (2005), as the sipXtapi voice engine in sipXtapi.dll implements it, with
// AOL's changes. It is not the TURN of RFC 5766, which gives the same method
// numbers other meanings. Every TURN message begins with a MAGIC-COOKIE
// attribute, which is how the client tells it from STUN and from media: a
// TURN reply without it is not a reply to the client.
//
// The client builds its messages the RFC 3489 way: a 16-byte transaction ID
// with no RFC 5389 cookie, and attributes one after the other with no
// padding after a value, so the DATA attribute holds the exact bytes. It
// reads replies the same way and refuses a message with bytes to spare, so
// the replies here are built exactly like that too.
const (
	turnAllocate          = 0x0003
	turnAllocateResponse  = 0x0103
	turnAllocateError     = 0x0113
	turnSend              = 0x0004
	turnSendResponse      = 0x0104
	turnSendError         = 0x0114
	turnDataIndication    = 0x0115
	turnSetActiveDest     = 0x0006
	turnSetActiveDestResp = 0x0106
	turnSetActiveDestErr  = 0x0116
	turnCloseBinding      = 0x0009
	turnCloseBindingResp  = 0x0109
	turnCloseBindingError = 0x0119

	attrUsername           = 0x0006
	attrLifetime           = 0x000D
	attrTURNMagicCookie    = 0x000F
	attrBandwidth          = 0x0010
	attrDestinationAddress = 0x0011
	attrRemoteAddress      = 0x0012
	attrData               = 0x0013

	turnMagicCookie = 0x72C64BC6
)

// stunAttr is one attribute of a message.
type stunAttr struct {
	typ   uint16
	value []byte
}

// walk splits the attributes of a message body. With exact, a value is
// followed at once by the next attribute, as in the messages of ICQ 6.5;
// otherwise it is padded to a multiple of four bytes, as RFC 5389 has it.
// ok is false when the attributes do not fill the body exactly.
func walk(body []byte, exact bool) (attrs []stunAttr, ok bool) {
	for len(body) >= 4 {
		t := binary.BigEndian.Uint16(body[0:2])
		l := int(binary.BigEndian.Uint16(body[2:4]))
		if 4+l > len(body) {
			return attrs, false
		}
		attrs = append(attrs, stunAttr{typ: t, value: body[4 : 4+l]})
		step := 4 + l
		if !exact {
			step = 4 + (l+3)&^3
		}
		if step > len(body) {
			return attrs, false
		}
		body = body[step:]
	}
	return attrs, len(body) == 0
}

// isAOLTURN tells whether a message with these attributes is in the TURN of
// ICQ 6.5: its first attribute is the TURN MAGIC-COOKIE.
func isAOLTURN(attrs []stunAttr) bool {
	return len(attrs) > 0 && attrs[0].typ == attrTURNMagicCookie &&
		len(attrs[0].value) == 4 && binary.BigEndian.Uint32(attrs[0].value) == turnMagicCookie
}

// turnMsg is a message in the TURN of ICQ 6.5.
type turnMsg struct {
	typ   uint16
	id    []byte // the 16 bytes after the length: a classic transaction ID
	attrs []stunAttr
}

// parseTURN reads a message in the TURN of ICQ 6.5. ok is false for
// anything else, such as STUN, RFC 5766 TURN or media.
func parseTURN(msg []byte) (m turnMsg, ok bool) {
	if len(msg) < headerLen || msg[0]&0xC0 != 0 {
		return m, false
	}
	if headerLen+int(binary.BigEndian.Uint16(msg[2:4])) != len(msg) {
		return m, false
	}
	modern := binary.BigEndian.Uint32(msg[4:8]) == magicCookie
	attrs, ok := walk(msg[headerLen:], !modern)
	if !ok || !isAOLTURN(attrs) {
		return m, false
	}
	return turnMsg{typ: binary.BigEndian.Uint16(msg[0:2]), id: msg[4:headerLen], attrs: attrs}, true
}

// get returns the value of the first attribute of a type.
func (m turnMsg) get(typ uint16) ([]byte, bool) {
	for _, a := range m.attrs {
		if a.typ == typ {
			return a.value, true
		}
	}
	return nil, false
}

// address reads an address attribute: IPv4 only, as the client has it.
func (m turnMsg) address(typ uint16) (netip.AddrPort, bool) {
	v, ok := m.get(typ)
	if !ok || len(v) != 8 || v[1] != 0x01 {
		return netip.AddrPort{}, false
	}
	ip := netip.AddrFrom4([4]byte(v[4:8]))
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(v[2:4])), true
}

// lifetime reads the LIFETIME attribute.
func (m turnMsg) lifetime() (uint32, bool) {
	v, ok := m.get(attrLifetime)
	if !ok || len(v) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(v), true
}

// encodeTURN builds a message in the TURN of ICQ 6.5: the MAGIC-COOKIE, then
// the attributes given. For a classic ID values are not padded, which the
// client needs; only the last attribute may then have a length that is not
// a multiple of four, and every caller puts DATA last.
func encodeTURN(typ uint16, id []byte, attrs ...stunAttr) []byte {
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, turnMagicCookie)
	attrs = append([]stunAttr{{attrTURNMagicCookie, cookie}}, attrs...)
	pad := binary.BigEndian.Uint32(id[0:4]) == magicCookie

	out := make([]byte, headerLen, 256)
	binary.BigEndian.PutUint16(out[0:2], typ)
	copy(out[4:], id)
	for _, a := range attrs {
		out = binary.BigEndian.AppendUint16(out, a.typ)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.value)))
		out = append(out, a.value...)
		for pad && len(out)%4 != 0 {
			out = append(out, 0)
		}
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-headerLen))
	return out
}

func turnAddr(typ uint16, a netip.AddrPort) stunAttr {
	ip := a.Addr().Unmap().As4()
	v := []byte{0, 0x01, 0, 0, ip[0], ip[1], ip[2], ip[3]}
	binary.BigEndian.PutUint16(v[2:4], a.Port())
	return stunAttr{typ, v}
}

func turnU32(typ uint16, n uint32) stunAttr {
	return stunAttr{typ, binary.BigEndian.AppendUint32(nil, n)}
}

// turnError is an ERROR-CODE attribute. The reason is padded with spaces to
// a multiple of four bytes, as RFC 3489 wants, so that nothing needs
// padding after it.
func turnError(code int, reason string) stunAttr {
	for (len(reason))%4 != 0 {
		reason += " "
	}
	return stunAttr{attrErrorCode, append([]byte{0, 0, byte(code / 100), byte(code % 100)}, reason...)}
}

// dataIndication wraps what a peer sent to the relayed address for the
// client: REMOTE-ADDRESS says who sent it, DATA holds it.
func dataIndication(from netip.AddrPort, data []byte) []byte {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	if binary.BigEndian.Uint32(id[0:4]) == magicCookie {
		id[0] ^= 0xFF // keep it a classic ID, so DATA is not padded
	}
	return encodeTURN(turnDataIndication, id, turnAddr(attrRemoteAddress, from), stunAttr{attrData, data})
}
