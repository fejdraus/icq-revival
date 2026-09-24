package foodgroup

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestICBMService_addExternalIP(t *testing.T) {
	lan := []byte{192, 168, 1, 10}
	tests := []struct {
		name          string
		senderAddr    string
		recipAddr     string
		wantRequester []byte
	}{
		{
			name:          "a peer on another network gets the address the server sees",
			senderAddr:    "203.0.113.5:40000",
			recipAddr:     "198.51.100.7:40001",
			wantRequester: []byte{203, 0, 113, 5},
		},
		{
			name:          "a peer behind the same router keeps the LAN address",
			senderAddr:    "203.0.113.5:40000",
			recipAddr:     "203.0.113.5:40001",
			wantRequester: lan,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := newTestInstance("100001")
			sa := netip.MustParseAddrPort(tt.senderAddr)
			sender.SetRemoteAddr(&sa)
			recip := newTestInstance("100002")
			ra := netip.MustParseAddrPort(tt.recipAddr)
			recip.SetRemoteAddr(&ra)

			frag := wire.ICBMCh2Fragment{Type: wire.ICBMRdvMessagePropose}
			frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, lan))
			frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, uint16(5000)))

			s := &ICBMService{logger: slog.Default()}
			out, err := s.addExternalIP(context.Background(), sender, recip.Session(), wire.NewTLVBE(wire.ICBMTLVData, frag))
			assert.NoError(t, err)

			got := wire.ICBMCh2Fragment{}
			assert.NoError(t, wire.UnmarshalBE(&got, bytes.NewReader(out.Value)))
			requester, _ := got.Bytes(wire.ICBMRdvTLVTagsRequesterIP)
			verified, _ := got.Bytes(wire.ICBMRdvTLVTagsVerifiedIP)
			assert.Equal(t, tt.wantRequester, requester)
			assert.Equal(t, []byte{203, 0, 113, 5}, verified)
		})
	}
}
