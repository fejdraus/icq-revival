package foodgroup

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// tzerSvcData builds the service data (TLV 0x2711) of a tZer as ICQ 6.5 sends
// it: the extended message header, a plugin message with an empty text, the
// plugin header naming the tZer plugin's "Send Tzer" function, and doc.
func tzerSvcData(doc string) []byte {
	b := &bytes.Buffer{}
	le := func(v any) { _ = binary.Write(b, binary.LittleEndian, v) }
	le(uint16(0x1B))
	le(uint16(9))
	b.Write(make([]byte, 16+2+4+1)) // plugin GUID (none), unknown, caps, unknown
	le(uint16(0x64))
	le(uint16(0x0E))
	le(uint16(0x64))
	b.Write(make([]byte, 12))
	b.Write([]byte{0x1A, 0}) // MTYPE_PLUGIN, flags
	le(uint16(0))            // status
	le(uint16(1))            // priority
	le(uint16(0))            // the message text: none
	le(uint16(0x30))
	b.Write(tzerPluginGUID)
	le(uint16(0))
	le(uint32(len(tzerFunction)))
	b.Write(tzerFunction)
	b.Write(make([]byte, 17))
	le(uint32(len(doc) + 4))
	le(uint32(len(doc)))
	b.WriteString(doc)
	return b.Bytes()
}

// tzerProposal returns the TLV 0x0005 of a channel 2 message carrying the
// service data svc under capability capability.
func tzerProposal(t *testing.T, capability [16]byte, svc []byte) wire.TLV {
	frag := wire.ICBMCh2Fragment{
		Type:       wire.ICBMRdvMessagePropose,
		Capability: capability,
	}
	frag.Append(wire.NewTLVBE(0x000A, uint16(1)))
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, svc))
	buf := bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(frag, &buf))
	return wire.NewTLVBE(wire.ICBMTLVData, buf.Bytes())
}

const tzerDoc = `<tzerRoot id="cantH" url="http://example.com:8101/icq/tzers/canthearu.swf" ` +
	`thumb="http://example.com:8101/icq/tzers/canthearu.png" name=" Вас не чути" freeData=""/>` + "\r\n"

func TestTzerText(t *testing.T) {
	tzer := tzerProposal(t, wire.CapICQCh2Extended, tzerSvcData(tzerDoc))

	withTLVs := func(channel uint16, tlvs ...wire.TLV) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
		return wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			ChannelID:    channel,
			ScreenName:   "100002",
			TLVRestBlock: wire.TLVRestBlock{TLVList: tlvs},
		}
	}
	plainRecipient := newTestInstance("100002", sessOptMirandaICQ).Session()
	tzerRecipient := newTestInstance("100002", sessOptICQ6).Session()

	tests := []struct {
		name     string
		inBody   wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
		recip    *state.Session
		wantText string
		wantTzer bool
	}{
		{
			name:     "a tZer to a client that can't play it",
			inBody:   withTLVs(wire.ICBMChannelRendezvous, tzer),
			recip:    plainRecipient,
			wantText: "tZer: Вас не чути",
			wantTzer: true,
		},
		{
			name:   "a tZer to a client that plays tZers",
			inBody: withTLVs(wire.ICBMChannelRendezvous, tzer),
			recip:  tzerRecipient,
		},
		{
			name:     "a tZer without a name",
			inBody:   withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapICQCh2Extended, tzerSvcData(`<tzerRoot id="boo"/>`))),
			recip:    plainRecipient,
			wantText: "tZer",
			wantTzer: true,
		},
		{
			name:     "a name with an entity",
			inBody:   withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapICQCh2Extended, tzerSvcData(`<tzerRoot name="Tom &amp; Jerry"/>`))),
			recip:    plainRecipient,
			wantText: "tZer: Tom & Jerry",
			wantTzer: true,
		},
		{
			name:   "another plugin message",
			inBody: withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapICQCh2Extended, bytes.ReplaceAll(tzerSvcData(tzerDoc), tzerFunction, []byte("Send Xtraz")))),
			recip:  plainRecipient,
		},
		{
			name:   "another rendezvous",
			inBody: withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapFileTransfer, tzerSvcData(tzerDoc))),
			recip:  plainRecipient,
		},
		{
			name:   "not a rendezvous",
			inBody: withTLVs(wire.ICBMChannelIM, tzer),
			recip:  plainRecipient,
		},
		{
			name:   "a rendezvous without data",
			inBody: withTLVs(wire.ICBMChannelRendezvous),
			recip:  plainRecipient,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, isTzer := tzerText(tt.inBody, tt.recip)
			assert.Equal(t, tt.wantTzer, isTzer)
			assert.Equal(t, tt.wantText, text)
		})
	}
}

func TestTextFragments(t *testing.T) {
	for _, text := range []string{"tZer: Kisses", "tZer: Вас не чути"} {
		frags, err := textFragments(text)
		assert.NoError(t, err)
		b, err := wire.MarshalICBMFragmentList(frags)
		assert.NoError(t, err)
		got, err := wire.UnmarshalICBMMessageText(b)
		assert.NoError(t, err)
		assert.Equal(t, text, got)
	}
}

// A tZer sent to a client that can't play it arrives as a channel 1 message,
// and the sender still gets the acknowledgement it asked for.
func TestICBMService_ChannelMsgToHost_TzerAsText(t *testing.T) {
	sender := newTestInstance("100001", sessOptICQ6)
	recipSess := newTestInstance("100002", sessOptMirandaICQ, sessOptSignonComplete).Session()

	relationshipFetcher := newMockRelationshipFetcher(t)
	relationshipFetcher.EXPECT().
		Relationship(matchContext(), state.NewIdentScreenName("100001"), state.NewIdentScreenName("100002")).
		Return(state.Relationship{User: state.NewIdentScreenName("100002")}, nil)
	sessionRetriever := newMockSessionRetriever(t)
	sessionRetriever.EXPECT().
		RetrieveSession(state.NewIdentScreenName("100002")).
		Return(recipSess)

	frags, err := textFragments("tZer: Вас не чути")
	assert.NoError(t, err)
	messageRelayer := newMockMessageRelayer(t)
	messageRelayer.EXPECT().
		RelayToScreenNameActiveOnly(mock.Anything, state.NewIdentScreenName("100002"), wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
				Cookie:      0x0102030405060708,
				ChannelID:   wire.ICBMChannelIM,
				TLVUserInfo: recipSess.UserInfoFor(sender.Session().TLVUserInfo()),
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags)},
				},
			},
		})

	svc := ICBMService{
		relationshipFetcher: relationshipFetcher,
		messageRelayer:      messageRelayer,
		sessionRetriever:    sessionRetriever,
		convoTracker:        newConvoTracker(),
		logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	inBody := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:     0x0102030405060708,
		ChannelID:  wire.ICBMChannelRendezvous,
		ScreenName: "100002",
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				tzerProposal(t, wire.CapICQCh2Extended, tzerSvcData(tzerDoc)),
				wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
			},
		},
	}

	out, err := svc.ChannelMsgToHost(context.Background(), sender, wire.SNACFrame{RequestID: 7}, inBody)
	assert.NoError(t, err)
	assert.Equal(t, &wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMHostAck, RequestID: 7},
		Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
			Cookie:     inBody.Cookie,
			ChannelID:  wire.ICBMChannelRendezvous,
			ScreenName: "100002",
		},
	}, out)
}
