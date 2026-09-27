package stun

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// cookieAttr is the MAGIC-COOKIE every TURN message of ICQ 6.5 starts with.
var cookieAttr = []byte{0x00, 0x0F, 0x00, 0x04, 0x72, 0xC6, 0x4B, 0xC6}

func TestParseTURN(t *testing.T) {
	tests := []struct {
		name     string
		msg      []byte
		wantOK   bool
		wantType uint16
		wantAttr []uint16
	}{
		{
			name:     "an Allocate as ICQ 6.5 sends it",
			msg:      icqAllocate(classicID),
			wantOK:   true,
			wantType: turnAllocate,
			wantAttr: []uint16{attrTURNMagicCookie, attrLifetime, 0x0021, attrUsername, 0x0008},
		},
		{
			name: "a Send whose DATA is followed at once by the next attribute",
			msg: append(append(append([]byte{0x00, 0x04, 0x00, 0x1A}, classicID...), cookieAttr...),
				0x00, 0x13, 0x00, 0x02, '\r', '\n', // DATA, not padded
				0x00, 0x06, 0x00, 0x04, 'a', 'b', 'c', 'd', // USERNAME
				0x00, 0x21, 0x00, 0x00), // XOR-ONLY
			wantOK:   true,
			wantType: turnSend,
			wantAttr: []uint16{attrTURNMagicCookie, attrData, attrUsername, 0x0021},
		},
		{
			name: "with an RFC 5389 ID the values are padded",
			msg: append(append(append([]byte{0x00, 0x04, 0x00, 0x14}, modernID...), cookieAttr...),
				0x00, 0x13, 0x00, 0x02, '\r', '\n', 0, 0,
				0x00, 0x21, 0x00, 0x00),
			wantOK:   true,
			wantType: turnSend,
			wantAttr: []uint16{attrTURNMagicCookie, attrData, 0x0021},
		},
		{
			name: "an RFC 5766 Allocate has no TURN cookie",
			msg:  request(0x0003, modernID, attr(0x0019, []byte{17, 0, 0, 0})),
		},
		{
			name: "the cookie must come first",
			msg:  request(0x0003, classicID, append(attr(attrLifetime, []byte{0, 0, 0, 56}), cookieAttr...)),
		},
		{
			name: "a wrong cookie",
			msg:  request(0x0003, classicID, []byte{0x00, 0x0F, 0x00, 0x04, 0x21, 0x12, 0xA4, 0x42}),
		},
		{
			name: "a length that is not the packet's",
			msg:  append(append([]byte{0x00, 0x03, 0x00, 0x0C}, classicID...), cookieAttr...),
		},
		{
			name: "bytes left over",
			msg:  append(append(append([]byte{0x00, 0x03, 0x00, 0x0A}, classicID...), cookieAttr...), 0, 0),
		},
		{
			name: "media",
			msg:  append([]byte{0x80, 0x60, 0x00, 0x01}, make([]byte, 40)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := parseTURN(tt.msg)
			assert.Equal(t, tt.wantOK, ok)
			if !ok {
				return
			}
			assert.Equal(t, tt.wantType, m.typ)
			var types []uint16
			for _, a := range m.attrs {
				types = append(types, a.typ)
			}
			assert.Equal(t, tt.wantAttr, types)
		})
	}
}

func TestTURNAttributes(t *testing.T) {
	m, ok := parseTURN(encodeTURN(turnSend, classicID,
		turnU32(attrLifetime, 56),
		turnAddr(attrDestinationAddress, netip.MustParseAddrPort("198.51.100.7:50000")),
		stunAttr{attrData, []byte("abc")}))
	assert.True(t, ok)
	lifetime, ok := m.lifetime()
	assert.True(t, ok)
	assert.Equal(t, uint32(56), lifetime)
	dst, ok := m.address(attrDestinationAddress)
	assert.True(t, ok)
	assert.Equal(t, netip.MustParseAddrPort("198.51.100.7:50000"), dst)
	data, ok := m.get(attrData)
	assert.True(t, ok)
	assert.Equal(t, []byte("abc"), data)
	_, ok = m.address(attrRemoteAddress)
	assert.False(t, ok)
}

func TestEncodeTURN(t *testing.T) {
	relayed := netip.MustParseAddrPort("192.0.2.1:49160")
	tests := []struct {
		name string
		got  []byte
		want []byte
	}{
		{
			name: "a Send response is the cookie alone",
			got:  encodeTURN(turnSendResponse, classicID),
			want: append(append([]byte{0x01, 0x04, 0x00, 0x08}, classicID...), cookieAttr...),
		},
		{
			name: "an Allocate response gives the relayed address as MAPPED-ADDRESS",
			got:  encodeTURN(turnAllocateResponse, classicID, turnAddr(attrMappedAddress, relayed), turnU32(attrLifetime, 56)),
			want: append(append(append([]byte{0x01, 0x03, 0x00, 0x1C}, classicID...), cookieAttr...),
				0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0xC0, 0x08, 192, 0, 2, 1,
				0x00, 0x0D, 0x00, 0x04, 0, 0, 0, 56),
		},
		{
			name: "DATA of odd length is not padded for a classic ID",
			got:  encodeTURN(turnDataIndication, classicID, turnAddr(attrRemoteAddress, relayed), stunAttr{attrData, []byte("hey")}),
			want: append(append(append([]byte{0x01, 0x15, 0x00, 0x1B}, classicID...), cookieAttr...),
				0x00, 0x12, 0x00, 0x08, 0x00, 0x01, 0xC0, 0x08, 192, 0, 2, 1,
				0x00, 0x13, 0x00, 0x03, 'h', 'e', 'y'),
		},
		{
			name: "but is padded for an RFC 5389 ID",
			got:  encodeTURN(turnDataIndication, modernID, stunAttr{attrData, []byte("hey")}),
			want: append(append(append([]byte{0x01, 0x15, 0x00, 0x10}, modernID...), cookieAttr...),
				0x00, 0x13, 0x00, 0x03, 'h', 'e', 'y', 0),
		},
		{
			name: "an error's reason is padded with spaces to a multiple of four",
			got:  encodeTURN(turnSendError, classicID, turnError(437, "No Binding")),
			want: append(append(append([]byte{0x01, 0x14, 0x00, 0x1C}, classicID...), cookieAttr...),
				append([]byte{0x00, 0x09, 0x00, 0x10, 0, 0, 4, 37}, "No Binding  "...)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.got)
		})
	}
}

// The client reads a Data Indication with exact lengths and wants the
// cookie first: that is what one must look like.
func TestDataIndication(t *testing.T) {
	from := netip.MustParseAddrPort("198.51.100.7:50000")
	msg := dataIndication(from, []byte{0x80, 0x00, 0x01})
	assert.Equal(t, uint16(turnDataIndication), binary.BigEndian.Uint16(msg[0:2]))
	assert.NotEqual(t, uint32(magicCookie), binary.BigEndian.Uint32(msg[4:8]))
	m, ok := parseTURN(msg)
	assert.True(t, ok)
	remote, ok := m.address(attrRemoteAddress)
	assert.True(t, ok)
	assert.Equal(t, from, remote)
	data, _ := m.get(attrData)
	assert.Equal(t, []byte{0x80, 0x00, 0x01}, data)
}
