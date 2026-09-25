package stun

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func request(typ uint16, id []byte, attrs []byte) []byte {
	return message(typ, id, attrs)
}

var (
	classicID = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	modernID  = append([]byte{0x21, 0x12, 0xA4, 0x42}, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
	client    = &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 40000}
)

func TestReply(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		want []byte
	}{
		{
			name: "a classic Binding request gets the mapped address",
			msg:  request(0x0001, classicID, nil),
			want: message(0x0101, classicID,
				attr(attrMappedAddress, []byte{0, 1, 0x9C, 0x40, 203, 0, 113, 5})),
		},
		{
			name: "an RFC 5389 Binding request gets the XOR-mapped address too",
			msg:  request(0x0001, modernID, nil),
			want: message(0x0101, modernID, append(
				attr(attrMappedAddress, []byte{0, 1, 0x9C, 0x40, 203, 0, 113, 5}),
				attr(attrXORMappedAddress, []byte{0, 1, 0x9C ^ 0x21, 0x40 ^ 0x12, 203 ^ 0x21, 0 ^ 0x12, 113 ^ 0xA4, 5 ^ 0x42})...)),
		},
		{
			name: "a request to answer from another address goes unanswered",
			msg:  request(0x0001, classicID, attr(attrChangeRequest, []byte{0, 0, 0, 6})),
		},
		{
			name: "a change request asking for no change is answered",
			msg:  request(0x0001, classicID, attr(attrChangeRequest, []byte{0, 0, 0, 0})),
			want: message(0x0101, classicID,
				attr(attrMappedAddress, []byte{0, 1, 0x9C, 0x40, 203, 0, 113, 5})),
		},
		{
			name: "a TURN Allocate gets an error at once",
			msg:  request(0x0003, classicID, nil),
			want: message(0x0113, classicID, attr(attrErrorCode, append([]byte{0, 0, 4, 0}, "Bad Request"...))),
		},
		{
			name: "a response is not answered",
			msg:  message(0x0101, classicID, nil),
		},
		{
			name: "a short packet is not answered",
			msg:  []byte{0, 1, 0, 0},
		},
		{
			name: "a length past the packet is not answered",
			msg:  append([]byte{0, 1, 0, 8}, classicID...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := Reply(tt.msg, client)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestServer(t *testing.T) {
	s := NewServer("127.0.0.1:0", slog.Default())
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe() }()

	var addr net.Addr
	assert.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.conn != nil {
			addr = s.conn.LocalAddr()
		}
		return addr != nil
	}, time.Second, 10*time.Millisecond)

	conn, err := net.Dial("udp", addr.String())
	assert.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write(request(0x0001, classicID, nil))
	assert.NoError(t, err)

	assert.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, uint16(0x0101), binary.BigEndian.Uint16(buf[0:2]))
	mapped, ok := attribute(buf[headerLen:n], attrMappedAddress)
	assert.True(t, ok)
	local := conn.LocalAddr().(*net.UDPAddr)
	assert.Equal(t, uint16(local.Port), binary.BigEndian.Uint16(mapped[2:4]))
	assert.Equal(t, []byte{127, 0, 0, 1}, mapped[4:8])

	assert.NoError(t, s.Shutdown(context.Background()))
	assert.NoError(t, <-done)
}
