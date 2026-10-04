package icq_legacy

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/charmap"

	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ICQ 7.2 sends its messages so: HTML, in UCS-2.
const icq72HTML = `<HTML><BODY dir="ltr"><B><FONT color="#000000" size="2" face="Arial">Привет</FONT></B></BODY></HTML>`

// win1251 returns s, UTF-8, in the bytes of windows-1251.
func win1251(t *testing.T, s string) string {
	t.Helper()
	out, err := charmap.Windows1251.NewEncoder().String(s)
	require.NoError(t, err)
	return out
}

func newTestLegacyText(t *testing.T, codePage string) legacyText {
	t.Helper()
	ct, err := foodgroup.NewClassicText(codePage)
	require.NoError(t, err)
	return legacyText{cp: ct}
}

// ucs2 returns s, UTF-8, as UCS-2BE bytes.
func ucs2(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r>>8), byte(r))
	}
	return b
}

// ch1Payload returns the value of TLV 0x0002 of a channel 1 message with
// text in charset.
func ch1Payload(t *testing.T, charset uint16, text []byte) []byte {
	t.Helper()
	msgBuf := bytes.Buffer{}
	require.NoError(t, wire.MarshalBE(wire.ICBMCh1Message{Charset: charset, Text: text}, &msgBuf))
	b, err := wire.MarshalICBMFragmentList([]wire.ICBMCh1Fragment{
		{ID: 5, Version: 1, Payload: []byte{1, 1, 2}},
		{ID: 1, Version: 1, Payload: msgBuf.Bytes()},
	})
	require.NoError(t, err)
	return b
}

func TestLegacyMessageBridge_extractChannel1Text(t *testing.T) {
	tests := []struct {
		name     string
		codePage string
		charset  uint16
		text     func(t *testing.T) []byte
		want     func(t *testing.T) string
	}{
		{
			name:     "UCS-2 Cyrillic HTML from ICQ 7.2 becomes plain cp1251",
			codePage: "windows-1251",
			charset:  wire.ICBMMessageEncodingUnicode,
			text:     func(t *testing.T) []byte { return ucs2(icq72HTML) },
			want:     func(t *testing.T) string { return win1251(t, "Привет") },
		},
		{
			name:     "entities, line breaks and nested tags",
			codePage: "windows-1251",
			charset:  wire.ICBMMessageEncodingUnicode,
			text: func(t *testing.T) []byte {
				return ucs2(`<HTML><BODY><B>Да &amp; нет<BR>a &lt;b&gt;<FONT><I>&quot;ё&quot;</I></FONT></B></BODY></HTML>`)
			},
			want: func(t *testing.T) string { return win1251(t, "Да & нет\r\na <b>\"ё\"") },
		},
		{
			name:     "code page bytes from a classic client stay",
			codePage: "windows-1251",
			charset:  wire.ICBMMessageEncodingASCII,
			text:     func(t *testing.T) []byte { return []byte(win1251(t, "Привет")) },
			want:     func(t *testing.T) string { return win1251(t, "Привет") },
		},
		{
			name:     "ASCII unchanged",
			codePage: "windows-1251",
			charset:  wire.ICBMMessageEncodingASCII,
			text:     func(t *testing.T) []byte { return []byte("hello <3") },
			want:     func(t *testing.T) string { return "hello <3" },
		},
		{
			name:     "a character the code page lacks becomes ?",
			codePage: "windows-1251",
			charset:  wire.ICBMMessageEncodingUnicode,
			text:     func(t *testing.T) []byte { return ucs2("Да 中") },
			want:     func(t *testing.T) string { return win1251(t, "Да ?") },
		},
		{
			name:    "no code page passes bytes through",
			charset: wire.ICBMMessageEncodingASCII,
			text:    func(t *testing.T) []byte { return []byte("\xcf\xf0\xe8") },
			want:    func(t *testing.T) string { return "\xcf\xf0\xe8" },
		},
		{
			name:    "no code page sends UCS-2 as Latin-1",
			charset: wire.ICBMMessageEncodingUnicode,
			text:    func(t *testing.T) []byte { return ucs2("<B>café</B>") },
			want:    func(t *testing.T) string { return "caf\xe9" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &LegacyMessageBridge{text: newTestLegacyText(t, tt.codePage)}
			msg := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{ChannelID: wire.ICBMChannelIM}
			msg.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, ch1Payload(t, tt.charset, tt.text(t))))
			assert.Equal(t, tt.want(t), b.extractChannel1Text(msg))
		})
	}
}

func TestLegacyText_ch4ToLegacy(t *testing.T) {
	tests := []struct {
		name     string
		codePage string
		msg      wire.ICBMCh4Message
		want     func(t *testing.T) string
	}{
		{
			name:     "auth request fields in UTF-8 become cp1251",
			codePage: "windows-1251",
			msg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeAuthReq,
				Message:     "Вася\xFEВасилий\xFE\xFEv@x\xFE1\xFEДобавь меня",
			},
			want: func(t *testing.T) string {
				return win1251(t, "Вася") + "\xFE" + win1251(t, "Василий") + "\xFE\xFEv@x\xFE1\xFE" + win1251(t, "Добавь меня")
			},
		},
		{
			name:     "auth deny reason in cp1251 stays",
			codePage: "windows-1251",
			msg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeAuthDeny,
				Message:     "\xcd\xe5\xf2",
			},
			want: func(t *testing.T) string { return "\xcd\xe5\xf2" },
		},
		{
			name:     "plain message: HTML stripped, CRLF",
			codePage: "windows-1251",
			msg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypePlain,
				Message:     "<B>Да</B><BR>нет",
			},
			want: func(t *testing.T) string { return win1251(t, "Да\r\nнет") },
		},
		{
			name: "no code page passes bytes through",
			msg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeUrl,
				Message:     "\xcf\xf0\xe8\xFEhttp://x",
			},
			want: func(t *testing.T) string { return "\xcf\xf0\xe8\xFEhttp://x" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want(t), newTestLegacyText(t, tt.codePage).ch4ToLegacy(tt.msg))
		})
	}
}

func TestLegacyMessageBridge_buildLegacyAuthFields(t *testing.T) {
	finder := newMockICQUserFinder(t)
	user := state.User{}
	user.ICQInfo.Basic.Nickname = "Вася"
	user.ICQInfo.Basic.FirstName = "Василий"
	finder.EXPECT().FindByUIN(matchContext(), uint32(100002)).Return(user, nil)

	b := &LegacyMessageBridge{userFinder: finder, text: newTestLegacyText(t, "windows-1251")}
	nick, first, last, email := b.buildLegacyAuthFields(100002)
	assert.Equal(t, win1251(t, "Вася"), nick)
	assert.Equal(t, win1251(t, "Василий"), first)
	assert.Equal(t, "", last)
	assert.Equal(t, "", email)
}

// newTextTestService returns a legacy service whose code page is codePage.
func newTextTestService(t *testing.T, codePage string, icbm *mockICBMService, retriever *mockSessionRetriever,
	offline *mockOfflineMessageManager, users *mockUserManager, updater *mockICQUserUpdater) *ICQLegacyService {
	t.Helper()
	svc := NewICQLegacyService(
		newMockAuthService(t),
		users,
		newMockAccountManager(t),
		retriever,
		newMockMessageRelayer(t),
		newMockBuddyBroadcaster(t),
		offline,
		newMockICQUserFinder(t),
		updater,
		newMockFeedbagManager(t),
		newMockRelationshipFetcher(t),
		newMockBuddyListRegistry(t),
		newMockBuddyService(t),
		icbm,
		&LegacySessionManager{sessions: map[uint32]*LegacySession{}},
		slog.Default(),
	)
	ct, err := foodgroup.NewClassicText(codePage)
	require.NoError(t, err)
	svc.SetClassicText(ct)
	return svc
}

func TestICQLegacyService_ProcessMessage_Text(t *testing.T) {
	ch4 := func(msgType uint8, text string) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
		return wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			ChannelID:  wire.ICBMChannelICQ,
			ScreenName: "100002",
			TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{UIN: 100001, MessageType: msgType, Message: text}),
				wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
			}},
		}
	}
	ch1 := func(t *testing.T, text string) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
		frags, err := foodgroup.ICBMTextFragments(text)
		require.NoError(t, err)
		payload, err := wire.MarshalICBMFragmentList(frags)
		require.NoError(t, err)
		return wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			ChannelID:  wire.ICBMChannelIM,
			ScreenName: "100002",
			TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICBMTLVAOLIMData, payload),
				wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
			}},
		}
	}
	icq7 := func() *state.Session {
		sess := state.NewSession()
		sess.AddInstance().SetCaps([][16]byte{wire.CapXHTMLIM})
		return sess
	}

	tests := []struct {
		name      string
		codePage  string
		msgType   uint16
		message   func(t *testing.T) string
		recipient *state.Session // nil: RetrieveSession not expected
		lookedUp  bool
		want      func(t *testing.T) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
	}{
		{
			name:     "cp1251 text goes to OSCAR as UCS-2 on channel 1",
			codePage: "windows-1251",
			msgType:  ICQLegacyMsgText,
			message:  func(t *testing.T) string { return win1251(t, "Привет") },
			want: func(t *testing.T) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
				snac := ch1(t, "Привет")
				// the text really is UCS-2
				b, _ := snac.Bytes(wire.ICBMTLVAOLIMData)
				var frags []wire.ICBMCh1Fragment
				require.NoError(t, wire.UnmarshalBE(&frags, bytes.NewReader(b)))
				m := wire.ICBMCh1Message{}
				require.NoError(t, wire.UnmarshalBE(&m, bytes.NewReader(frags[1].Payload)))
				require.Equal(t, wire.ICBMMessageEncodingUnicode, m.Charset)
				require.Equal(t, ucs2("Привет"), m.Text)
				return snac
			},
		},
		{
			name:     "ASCII text goes as ASCII",
			codePage: "windows-1251",
			msgType:  ICQLegacyMsgText,
			message:  func(t *testing.T) string { return "hello" },
			want:     func(t *testing.T) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost { return ch1(t, "hello") },
		},
		{
			name:     "auth reason to an ICQ 7 reader goes in UTF-8",
			codePage: "windows-1251",
			msgType:  ICQLegacyMsgAuthReq,
			message: func(t *testing.T) string {
				return win1251(t, "Вася") + "\xFE\xFE\xFE\xFE1\xFE" + win1251(t, "Пусти")
			},
			recipient: icq7(),
			lookedUp:  true,
			want: func(t *testing.T) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
				return ch4(wire.ICBMMsgTypeAuthReq, "Вася\xFE\xFE\xFE\xFE1\xFEПусти")
			},
		},
		{
			name:     "auth reason to a classic client stays in its code page",
			codePage: "windows-1251",
			msgType:  ICQLegacyMsgAuthReq,
			message:  func(t *testing.T) string { return win1251(t, "Пусти") },
			lookedUp: true,
			want: func(t *testing.T) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
				return ch4(wire.ICBMMsgTypeAuthReq, win1251(t, "Пусти"))
			},
		},
		{
			name:    "no code page passes bytes through on channel 4",
			msgType: ICQLegacyMsgText,
			message: func(t *testing.T) string { return "\xcf\xf0\xe8" },
			want: func(t *testing.T) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
				return ch4(wire.ICBMMsgTypePlain, "\xcf\xf0\xe8")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icbm := newMockICBMService(t)
			icbm.EXPECT().
				ChannelMsgToHost(matchContext(), matchSession(state.NewIdentScreenName("100001")),
					wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}, tt.want(t)).
				Return(nil, nil)
			retriever := newMockSessionRetriever(t)
			if tt.lookedUp {
				retriever.EXPECT().RetrieveSession(state.NewIdentScreenName("100002")).Return(tt.recipient)
			}
			svc := newTextTestService(t, tt.codePage, icbm, retriever, newMockOfflineMessageManager(t),
				newMockUserManager(t), newMockICQUserUpdater(t))

			_, err := svc.ProcessMessage(context.Background(), newTestLegacySession(100001, legacySessionOptOSCARSess),
				MessageRequest{FromUIN: 100001, ToUIN: 100002, MsgType: tt.msgType, Message: tt.message(t)})
			assert.NoError(t, err)
		})
	}
}

// TestICQLegacyService_ProcessMessage_LegacyToLegacy checks that a message
// between two legacy clients is left to the handler as it is: no ICBM.
func TestICQLegacyService_ProcessMessage_LegacyToLegacy(t *testing.T) {
	svc := newTextTestService(t, "windows-1251", newMockICBMService(t), newMockSessionRetriever(t),
		newMockOfflineMessageManager(t), newMockUserManager(t), newMockICQUserUpdater(t))
	svc.legacySessionManager = &LegacySessionManager{sessions: map[uint32]*LegacySession{
		100002: newTestLegacySession(100002),
	}}
	req := MessageRequest{FromUIN: 100001, ToUIN: 100002, MsgType: ICQLegacyMsgText, Message: win1251(t, "Привет")}

	got, err := svc.ProcessMessage(context.Background(), newTestLegacySession(100001), req)
	assert.NoError(t, err)
	assert.True(t, got.Delivered)
	assert.Equal(t, win1251(t, "Привет"), req.Message)
}

func TestICQLegacyService_GetOfflineMessages_Text(t *testing.T) {
	sent := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		codePage string
		message  func(t *testing.T, svc *ICQLegacyService) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
		wantType uint16
		wantText func(t *testing.T) string
	}{
		{
			name:     "UCS-2 HTML from ICQ 7.2 becomes plain cp1251",
			codePage: "windows-1251",
			message: func(t *testing.T, _ *ICQLegacyService) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
				snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{ChannelID: wire.ICBMChannelIM}
				snac.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, ch1Payload(t, wire.ICBMMessageEncodingUnicode, ucs2(icq72HTML+"<BR>!"))))
				return snac
			},
			wantType: ICQLegacyMsgText,
			wantText: func(t *testing.T) string { return win1251(t, "Привет\r\n!") },
		},
		{
			name:     "auth request on channel 4, fields in UTF-8",
			codePage: "windows-1251",
			message: func(t *testing.T, _ *ICQLegacyService) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
				snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{ChannelID: wire.ICBMChannelICQ}
				snac.Append(wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
					UIN: 100002, MessageType: wire.ICBMMsgTypeAuthReq, Message: "Вася\xFE\xFE\xFE\xFE1\xFEПусти",
				}))
				return snac
			},
			wantType: ICQLegacyMsgAuthReq,
			wantText: func(t *testing.T) string {
				return win1251(t, "Вася") + "\xFE\xFE\xFE\xFE1\xFE" + win1251(t, "Пусти")
			},
		},
		{
			name:     "a legacy client's offline message comes back as written",
			codePage: "windows-1251",
			message: func(t *testing.T, svc *ICQLegacyService) wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
				return svc.messageToOSCAR(state.NewIdentScreenName("100002"), state.NewIdentScreenName("100001"),
					MessageRequest{MsgType: ICQLegacyMsgText, Message: win1251(t, "Привет, мир")})
			},
			wantType: ICQLegacyMsgText,
			wantText: func(t *testing.T) string { return win1251(t, "Привет, мир") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offline := newMockOfflineMessageManager(t)
			svc := newTextTestService(t, tt.codePage, newMockICBMService(t), newMockSessionRetriever(t),
				offline, newMockUserManager(t), newMockICQUserUpdater(t))
			offline.EXPECT().RetrieveMessages(matchContext(), state.NewIdentScreenName("100001")).
				Return([]state.OfflineMessage{{
					Sender:    state.NewIdentScreenName("100002"),
					Recipient: state.NewIdentScreenName("100001"),
					Sent:      sent,
					Message:   tt.message(t, svc),
				}}, nil)

			got, err := svc.GetOfflineMessages(context.Background(), 100001)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tt.wantType, got[0].MsgType)
			assert.Equal(t, tt.wantText(t), got[0].Message)
		})
	}
}

func TestICQLegacyService_ProfileText(t *testing.T) {
	t.Run("user info goes out in cp1251", func(t *testing.T) {
		users := newMockUserManager(t)
		u := &state.User{}
		u.ICQInfo.Basic.Nickname = "Вася"
		u.ICQInfo.Basic.City = "Київ"
		u.ICQInfo.Notes.Notes = "Обо мне"
		users.EXPECT().User(matchContext(), state.NewIdentScreenName("100002")).Return(u, nil)
		retriever := newMockSessionRetriever(t)
		retriever.EXPECT().RetrieveSession(state.NewIdentScreenName("100002")).Return(nil)
		svc := newTextTestService(t, "windows-1251", newMockICBMService(t), retriever,
			newMockOfflineMessageManager(t), users, newMockICQUserUpdater(t))

		got, err := svc.GetUserInfoForProtocol(context.Background(), 100002)
		require.NoError(t, err)
		assert.Equal(t, win1251(t, "Вася"), got.Nickname)
		assert.Equal(t, win1251(t, "Київ"), got.City)
		assert.Equal(t, win1251(t, "Обо мне"), got.About)
		assert.Equal(t, "Вася", u.ICQInfo.Basic.Nickname, "the stored user is left as it was")
	})

	t.Run("basic info comes in as UTF-8", func(t *testing.T) {
		updater := newMockICQUserUpdater(t)
		updater.EXPECT().SetBasicInfo(matchContext(), state.NewIdentScreenName("100001"),
			state.ICQBasicInfo{Nickname: "Вася", City: "Москва", EmailAddress: "v@x"}).Return(nil)
		svc := newTextTestService(t, "windows-1251", newMockICBMService(t), newMockSessionRetriever(t),
			newMockOfflineMessageManager(t), newMockUserManager(t), updater)

		err := svc.UpdateBasicInfo(context.Background(), 100001,
			state.ICQBasicInfo{Nickname: win1251(t, "Вася"), City: win1251(t, "Москва"), EmailAddress: "v@x"})
		assert.NoError(t, err)
	})

	t.Run("no code page passes bytes through", func(t *testing.T) {
		updater := newMockICQUserUpdater(t)
		updater.EXPECT().SetBasicInfo(matchContext(), state.NewIdentScreenName("100001"),
			state.ICQBasicInfo{Nickname: "\xc2\xe0\xf1\xff"}).Return(nil)
		svc := newTextTestService(t, "", newMockICBMService(t), newMockSessionRetriever(t),
			newMockOfflineMessageManager(t), newMockUserManager(t), updater)

		assert.NoError(t, svc.UpdateBasicInfo(context.Background(), 100001, state.ICQBasicInfo{Nickname: "\xc2\xe0\xf1\xff"}))
	})
}
