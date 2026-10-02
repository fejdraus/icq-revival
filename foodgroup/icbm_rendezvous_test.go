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

func TestICBMService_addExternalIP_logsNothingIdentifying(t *testing.T) {
	// File transfer service data: multiple-files flag, file count 3, total
	// size 0x00ABCDEF, then the name.
	svc := append([]byte{0x00, 0x02, 0x00, 0x03, 0x00, 0xAB, 0xCD, 0xEF}, []byte("holiday-photos.zip\x00")...)
	tests := []struct {
		name    string
		frag    func() wire.ICBMCh2Fragment
		want    []string
		notWant []string
	}{
		{
			name: "a file offer is logged by its tags and counts only",
			frag: func() wire.ICBMCh2Fragment {
				f := wire.ICBMCh2Fragment{
					Type:       wire.ICBMRdvMessagePropose,
					Cookie:     [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04},
					Capability: wire.CapFileTransfer,
				}
				f.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsRdvIP, []byte{192, 168, 1, 10}))
				f.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, []byte{192, 168, 1, 10}))
				f.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, uint16(5190)))
				f.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(1)))
				f.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, svc))
				return f
			},
			want: []string{"rendezvous proposal", "seq=1", "files=3", "proposed_addr=private",
				"service_data_bytes=27", "use_ars=false", `tags="0002 0003 0005 000A 2711"`},
			notWant: []string{"holiday", "686F6C69646179", "192.168", "C0A8010A", "203.0.113",
				"5190", "DEADBEEF", "deadbeef", "ABCDEF", "abcdef", "11259375"},
		},
		{
			name: "a proxied offer says so",
			frag: func() wire.ICBMCh2Fragment {
				f := wire.ICBMCh2Fragment{Type: wire.ICBMRdvMessagePropose, Capability: wire.CapFileTransfer}
				f.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, []byte{10, 0, 0, 2}))
				f.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsUseARS, []byte{}))
				return f
			},
			want:    []string{"use_ars=true", "service_data_bytes=0"},
			notWant: []string{"10.0.0.2", "files="},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := newTestInstance("100001")
			sa := netip.MustParseAddrPort("203.0.113.5:40000")
			sender.SetRemoteAddr(&sa)
			recip := newTestInstance("100002")
			ra := netip.MustParseAddrPort("198.51.100.7:40001")
			recip.SetRemoteAddr(&ra)

			buf := &bytes.Buffer{}
			logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			s := &ICBMService{logger: logger}
			_, err := s.addExternalIP(context.Background(), sender, recip.Session(), wire.NewTLVBE(wire.ICBMTLVData, tt.frag()))
			assert.NoError(t, err)

			out := buf.String()
			for _, w := range tt.want {
				assert.Contains(t, out, w)
			}
			for _, nw := range tt.notWant {
				assert.NotContains(t, out, nw)
			}
		})
	}
}

func TestSipLogAttrs(t *testing.T) {
	sdp := "v=0\r\no=- 1 1 IN IP4 192.168.1.10\r\nc=IN IP4 203.0.113.5\r\nm=audio 40000 RTP/AVP 0\r\n"
	tests := []struct {
		name string
		sip  string
		want []any
	}{
		{
			name: "a request is logged by its method",
			sip:  "INVITE sip:100002@203.0.113.5 SIP/2.0\r\nFrom: <sip:100001@192.168.1.10>\r\n\r\n" + sdp,
			want: []any{"what", "INVITE", "sdp_bytes", len(sdp)},
		},
		{
			name: "a response is logged by its status",
			sip:  "SIP/2.0 200 OK\r\nContact: <sip:100002@198.51.100.7>\r\n\r\n",
			want: []any{"what", "200 OK", "sdp_bytes", 0},
		},
		{
			name: "an empty message",
			sip:  "",
			want: []any{"what", "", "sdp_bytes", 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []any{tt.want[0], tt.want[1], "bytes", len(tt.sip), tt.want[2], tt.want[3]}
			assert.Equal(t, want, sipLogAttrs([]byte(tt.sip)))
		})
	}
}
