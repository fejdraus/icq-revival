package foodgroup

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
	"time"
	"unicode/utf16"

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

// tzerPluginHeader is the service data of the tZer ICQ 6.5 sent in a live
// capture, up to the lengths of its document.
const tzerPluginHeader = "1b000900" + "00000000000000000000000000000000" + "0000" + "00000000" + "00" + "6400" +
	"0e00" + "6400" + "000000000000000000000000" +
	"1a00" + "0000" + "0100" + "0000" +
	"3000" + "4fa6f34c09b7fd4892087e857ae07330" + "0000" + "09000000" + "53656e6420547a6572" +
	"0000000000000000000000000000000000"

// tzerIMPrefix is the message data of the tZer ICQ 7.2 sent in a live
// capture, up to its text fragment: the features fragment and the tZer
// fragment.
const tzerIMPrefix = "0501000101" + "10010010" + "b2ec8f167c6f451bbd79dc58497888b9"

// tzerIMData builds the message data (TLV 0x0002) of a tZer as ICQ 7.2 sends
// it: tzerIMPrefix, then the text fragment with doc in UCS-2BE.
func tzerIMData(t *testing.T, doc string) []byte {
	b := &bytes.Buffer{}
	prefix, err := hex.DecodeString(tzerIMPrefix)
	assert.NoError(t, err)
	b.Write(prefix)
	units := utf16.Encode([]rune(doc))
	be := func(v uint16) { _ = binary.Write(b, binary.BigEndian, v) }
	b.Write([]byte{0x01, 0x01})
	be(uint16(4 + 2*len(units)))
	be(0x0002) // UCS-2BE
	be(0x002D)
	for _, u := range units {
		be(u)
	}
	return b.Bytes()
}

// tzerCookie is the cookie of the tZers in these tests.
const tzerCookie uint64 = 0x33A0D30342E98ABC

// tzerIMMessage returns a channel 1 tZer from ICQ 7.2 with the document doc
// and the TLVs it sends along: a host ack request, the offline store
// directive and its icon's hash.
func tzerIMMessage(t *testing.T, doc string) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
	return wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:     tzerCookie,
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: "100002",
		TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
			wire.NewTLVBE(wire.ICBMTLVAOLIMData, tzerIMData(t, doc)),
			wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
			wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
			wire.NewTLVBE(wire.ICBMTLVBART, append([]byte{0x00, 0x01, 0x01, 0x10}, make([]byte, 16)...)),
		}},
	}
}

// tzerPluginTLV returns the TLV 0x0005 ICQ 6.5 sends a tZer with the document
// doc in, under the rendezvous cookie cookie.
func tzerPluginTLV(t *testing.T, cookie uint64, doc string) wire.TLV {
	frag := wire.ICBMCh2Fragment{
		Type:       wire.ICBMRdvMessagePropose,
		Capability: wire.CapICQCh2Extended,
	}
	binary.BigEndian.PutUint64(frag.Cookie[:], cookie)
	frag.Append(wire.NewTLVBE(0x000A, uint16(1)))
	frag.Append(wire.NewTLVBE(0x000F, []byte{}))
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, tzerSvcData(doc)))
	buf := bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(frag, &buf))
	return wire.NewTLVBE(wire.ICBMTLVData, buf.Bytes())
}

func TestTzerLayouts(t *testing.T) {
	svc := tzerPluginSvcData(tzerDoc)
	assert.Equal(t, tzerSvcData(tzerDoc), svc)
	assert.Equal(t, tzerPluginHeader, hex.EncodeToString(svc[:len(tzerPluginHeader)/2]))

	frags, err := tzerIMFragments(tzerDoc)
	assert.NoError(t, err)
	b, err := wire.MarshalICBMFragmentList(frags)
	assert.NoError(t, err)
	assert.Equal(t, tzerIMData(t, tzerDoc), b)
}

func TestTzerForRecipient(t *testing.T) {
	withTLVs := func(channel uint16, tlvs ...wire.TLV) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
		return wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			Cookie:       tzerCookie,
			ChannelID:    channel,
			ScreenName:   "100002",
			TLVRestBlock: wire.TLVRestBlock{TLVList: tlvs},
		}
	}
	textTLV := func(text string) wire.TLV {
		frags, err := textFragments(text)
		assert.NoError(t, err)
		return wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags)
	}
	imTLV := func(doc string) wire.TLV {
		return wire.NewTLVBE(wire.ICBMTLVAOLIMData, tzerIMData(t, doc))
	}
	latin1IM := func(doc string) wire.TLV {
		msg := wire.ICBMCh1Message{Charset: wire.ICBMMessageEncodingLatin1, Text: []byte(doc)}
		buf := bytes.Buffer{}
		assert.NoError(t, wire.MarshalBE(msg, &buf))
		return wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
			{ID: 5, Version: 1, Payload: []byte{1}},
			{ID: 0x10, Version: 1, Payload: wire.CapICQTZers[:]},
			{ID: 1, Version: 1, Payload: buf.Bytes()},
		})
	}

	plugin := withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapICQCh2Extended, tzerSvcData(tzerDoc)))
	im := tzerIMMessage(t, tzerDoc)
	truncated := tzerSvcData(tzerDoc)
	truncated = truncated[:len(truncated)-10]

	plain := newTestInstance("100002", sessOptMirandaICQ).Session()
	icq6 := newTestInstance("100002", sessOptICQ6).Session()
	icq7 := newTestInstance("100002", sessOptICQ7).Session()
	miranda := newTestInstance("100002", sessOptMirandaICQ, func(instance *state.SessionInstance) {
		instance.SetCaps(append(instance.Caps(), wire.CapICQTZers))
	}).Session()

	tests := []struct {
		name        string
		msg         wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
		recip       *state.Session
		wantRebuilt bool
		wantChannel uint16
		wantTLV     wire.TLV
	}{
		{
			name:        "plugin tZer to a client that plays none",
			msg:         plugin,
			recip:       plain,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelIM,
			wantTLV:     textTLV("tZer: Вас не чути"),
		},
		{
			name:  "plugin tZer to ICQ 6.5",
			msg:   plugin,
			recip: icq6,
		},
		{
			name:  "plugin tZer to Miranda that plays tZers",
			msg:   plugin,
			recip: miranda,
		},
		{
			name:        "plugin tZer to ICQ 7.2",
			msg:         plugin,
			recip:       icq7,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelIM,
			wantTLV:     imTLV(tzerDoc),
		},
		{
			name:        "IM tZer to a client that plays none",
			msg:         im,
			recip:       plain,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelIM,
			wantTLV:     textTLV("tZer: Вас не чути"),
		},
		{
			name:        "IM tZer to ICQ 6.5",
			msg:         im,
			recip:       icq6,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelRendezvous,
			wantTLV:     tzerPluginTLV(t, tzerCookie, tzerDoc),
		},
		{
			name:        "IM tZer to Miranda that plays tZers",
			msg:         im,
			recip:       miranda,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelRendezvous,
			wantTLV:     tzerPluginTLV(t, tzerCookie, tzerDoc),
		},
		{
			name:  "IM tZer to ICQ 7.2",
			msg:   im,
			recip: icq7,
		},
		{
			name:        "Latin-1 IM tZer to ICQ 6.5",
			msg:         withTLVs(wire.ICBMChannelIM, latin1IM("<tzerRoot name=\"Caf\xe9\"/>")),
			recip:       icq6,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelRendezvous,
			wantTLV:     tzerPluginTLV(t, tzerCookie, `<tzerRoot name="Café"/>`),
		},
		{
			name:        "a tZer without a name",
			msg:         withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapICQCh2Extended, tzerSvcData(`<tzerRoot id="boo"/>`))),
			recip:       plain,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelIM,
			wantTLV:     textTLV("tZer"),
		},
		{
			name:        "a name with an entity",
			msg:         withTLVs(wire.ICBMChannelIM, imTLV(`<tzerRoot name="Tom &amp; Jerry"/>`)),
			recip:       plain,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelIM,
			wantTLV:     textTLV("tZer: Tom & Jerry"),
		},
		{
			name:        "a plugin tZer whose document can't be read, to a client that plays none",
			msg:         withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapICQCh2Extended, truncated)),
			recip:       plain,
			wantRebuilt: true,
			wantChannel: wire.ICBMChannelIM,
			wantTLV:     textTLV("tZer"),
		},
		{
			name:  "a plugin tZer whose document can't be read, to ICQ 7.2",
			msg:   withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapICQCh2Extended, truncated)),
			recip: icq7,
		},
		{
			name:  "another plugin message",
			msg:   withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapICQCh2Extended, bytes.ReplaceAll(tzerSvcData(tzerDoc), tzerFunction, []byte("Send Xtraz")))),
			recip: icq7,
		},
		{
			name:  "another rendezvous",
			msg:   withTLVs(wire.ICBMChannelRendezvous, tzerProposal(t, wire.CapFileTransfer, tzerSvcData(tzerDoc))),
			recip: plain,
		},
		{
			name:  "a plain IM",
			msg:   withTLVs(wire.ICBMChannelIM, textTLV(tzerDoc)),
			recip: icq6,
		},
		{
			name:  "an IM with a fragment 0x10 of another capability",
			msg:   withTLVs(wire.ICBMChannelIM, wire.NewTLVBE(wire.ICBMTLVAOLIMData, bytes.Replace(tzerIMData(t, tzerDoc), wire.CapICQTZers[:], wire.CapICQ6HTML[:], 1))),
			recip: plain,
		},
		{
			name:  "a plugin tZer on channel 1",
			msg:   withTLVs(wire.ICBMChannelIM, tzerProposal(t, wire.CapICQCh2Extended, tzerSvcData(tzerDoc))),
			recip: plain,
		},
		{
			name:  "a rendezvous without data",
			msg:   withTLVs(wire.ICBMChannelRendezvous),
			recip: plain,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			channel, tlv, rebuilt, err := tzerForRecipient(tt.msg, tt.recip)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantRebuilt, rebuilt)
			assert.Equal(t, tt.wantChannel, channel)
			assert.Equal(t, tt.wantTLV, tlv)
		})
	}
}

// A tZer from ICQ 7.2 reaches ICQ 6.5 as the plugin message ICQ 6.5 sends, and
// ICQ 7.2 gets the acknowledgement it asked for on channel 1.
func TestICBMService_ChannelMsgToHost_TzerIMToPlugin(t *testing.T) {
	sender := newTestInstance("100001", sessOptICQ7)
	sender.Session().SetTypingEventsEnabled(true)
	recipSess := newTestInstance("100002", sessOptICQ6, sessOptSignonComplete).Session()

	relationshipFetcher := newMockRelationshipFetcher(t)
	relationshipFetcher.EXPECT().
		Relationship(matchContext(), state.NewIdentScreenName("100001"), state.NewIdentScreenName("100002")).
		Return(state.Relationship{User: state.NewIdentScreenName("100002")}, nil)
	sessionRetriever := newMockSessionRetriever(t)
	sessionRetriever.EXPECT().
		RetrieveSession(state.NewIdentScreenName("100002")).
		Return(recipSess)

	inBody := tzerIMMessage(t, tzerDoc)
	messageRelayer := newMockMessageRelayer(t)
	messageRelayer.EXPECT().
		RelayToScreenNameActiveOnly(mock.Anything, state.NewIdentScreenName("100002"), wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
				Cookie:      inBody.Cookie,
				ChannelID:   wire.ICBMChannelRendezvous,
				TLVUserInfo: recipSess.UserInfoFor(sender.Session().TLVUserInfo()),
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{tzerPluginTLV(t, inBody.Cookie, tzerDoc)},
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

	out, err := svc.ChannelMsgToHost(context.Background(), sender, wire.SNACFrame{RequestID: 7}, inBody)
	assert.NoError(t, err)
	assert.Equal(t, &wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMHostAck, RequestID: 7},
		Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
			Cookie:     inBody.Cookie,
			ChannelID:  wire.ICBMChannelIM,
			ScreenName: "100002",
		},
	}, out)
}

// A tZer ICQ 7.2 left offline is replayed in the form the recipient plays.
func TestICBMService_OfflineRetrieve_Tzer(t *testing.T) {
	recip := newTestInstance("100002", sessOptICQ6)
	sent := time.Unix(1700000000, 0).UTC()

	offlineMessageManager := newMockOfflineMessageManager(t)
	offlineMessageManager.EXPECT().
		RetrieveMessages(matchContext(), state.NewIdentScreenName("100002")).
		Return([]state.OfflineMessage{{
			Message:   tzerIMMessage(t, tzerDoc),
			Recipient: state.NewIdentScreenName("100002"),
			Sender:    state.NewIdentScreenName("100001"),
			Sent:      sent,
		}}, nil)
	offlineMessageManager.EXPECT().
		DeleteMessages(matchContext(), state.NewIdentScreenName("100002")).
		Return(nil)

	messageRelayer := newMockMessageRelayer(t)
	messageRelayer.EXPECT().
		RelayToSelf(mock.Anything, matchSession(state.NewIdentScreenName("100002")), wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
				Cookie:      tzerCookie,
				ChannelID:   wire.ICBMChannelRendezvous,
				TLVUserInfo: wire.TLVUserInfo{ScreenName: "100001"},
				TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
					tzerPluginTLV(t, tzerCookie, tzerDoc),
					wire.NewTLVBE(wire.ICBMTLVSendTime, uint32(sent.Unix())),
				}},
			},
		})

	svc := ICBMService{
		messageRelayer:        messageRelayer,
		offlineMessageManager: offlineMessageManager,
	}
	_, err := svc.OfflineRetrieve(context.Background(), recip, wire.SNACFrame{RequestID: 1})
	assert.NoError(t, err)
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
