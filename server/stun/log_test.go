package stun

import (
	"bytes"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var peer = netip.MustParseAddrPort("198.51.100.7:50000")

// icqAllocate is an Allocate the way ICQ 6.5 sends it: the TURN cookie, a
// LIFETIME of twice its 28-second keepalive, XOR-ONLY, a USERNAME padded
// with spaces and a MESSAGE-INTEGRITY, with no padding anywhere.
func icqAllocate(id []byte) []byte {
	return encodeTURN(turnAllocate, id,
		turnU32(attrLifetime, 56),
		stunAttr{0x0021, nil},
		stunAttr{attrUsername, []byte("123456  ")},
		stunAttr{0x0008, make([]byte, 20)})
}

func TestDescribe(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		want []any
	}{
		{
			name: "an ICQ 6.5 Allocate",
			msg:  icqAllocate(classicID),
			want: []any{"type", "0x0003", "len", 76, "body", 56, "id", "classic",
				"method", "Allocate", "class", "request", "dialect", "draft TURN",
				"attrs", "0x000f/4 0x000d/4 0x0021/0 0x0006/8 0x0008/20"},
		},
		{
			name: "a Send with a DATA that is not a multiple of four",
			msg: encodeTURN(turnSend, classicID,
				turnAddr(attrDestinationAddress, peer), stunAttr{attrData, []byte("\r\n")},
				stunAttr{attrUsername, []byte("abcd")}),
			want: []any{"type", "0x0004", "len", 54, "body", 34, "id", "classic",
				"method", "Send", "class", "request", "dialect", "draft TURN",
				"attrs", "0x000f/4 0x0011/8 0x0013/2 0x0006/4"},
		},
		{
			name: "an RFC 5389 Binding",
			msg:  request(0x0001, modernID, nil),
			want: []any{"type", "0x0001", "len", 20, "body", 0, "id", "rfc5389",
				"method", "Binding", "class", "request", "dialect", "STUN/RFC TURN", "attrs", ""},
		},
		{
			name: "an RFC 5766 Refresh is named as such",
			msg:  request(0x0004, modernID, attr(attrLifetime, []byte{0, 0, 2, 0x58})),
			want: []any{"type", "0x0004", "len", 28, "body", 8, "id", "rfc5389",
				"method", "Refresh", "class", "request", "dialect", "STUN/RFC TURN", "attrs", "0x000d/4"},
		},
		{
			name: "media is not STUN",
			msg:  []byte{0x80, 0x00, 0, 1, 2, 3},
			want: []any{"kind", "not STUN", "len", 6},
		},
		{
			name: "a length past the packet",
			msg:  append([]byte{0, 1, 0, 8}, classicID...),
			want: []any{"type", "0x0001", "len", 20, "body", 8, "id", "classic", "kind", "length does not match the packet"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, describe(tt.msg))
		})
	}
}

func TestRequestLogLimit(t *testing.T) {
	var out bytes.Buffer
	l := newRequestLog(slog.New(slog.NewTextHandler(&out, nil)))
	from := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 40000}
	for i := 0; i < requestLogBurst+10; i++ {
		l.log(icqAllocate(classicID), from)
	}
	assert.Equal(t, requestLogBurst, strings.Count(out.String(), "STUN/TURN message"))
	assert.NotContains(t, out.String(), "123456", "no contents are logged")
	assert.Equal(t, 10, l.skipped)
}
