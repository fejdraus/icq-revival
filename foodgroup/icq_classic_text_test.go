package foodgroup

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// "Сергій" as ICQ 2003b sends it on a Cyrillic Windows.
const sergeyCP1251 = "\xd1\xe5\xf0\xe3\xb3\xe9"

func TestClassicText(t *testing.T) {
	tests := []struct {
		name     string
		codePage string
		in       string
		wantIn   string
		out      string
		wantOut  string
	}{
		{
			name:     "code page text becomes UTF-8 and back",
			codePage: "windows-1251",
			in:       sergeyCP1251,
			wantIn:   "Сергій",
			out:      "Сергій",
			wantOut:  sergeyCP1251,
		},
		{
			name:     "UTF-8 from a newer client is kept as it is",
			codePage: "windows-1251",
			in:       "Олексій",
			wantIn:   "Олексій",
		},
		{
			name:     "ASCII is the same both ways",
			codePage: "windows-1251",
			in:       "John",
			wantIn:   "John",
			out:      "John",
			wantOut:  "John",
		},
		{
			name:     "a character the code page lacks becomes a question mark",
			codePage: "windows-1251",
			out:      "Ann 日本",
			wantOut:  "Ann ??",
		},
		{
			name:     "bytes kept from before are sent as they are",
			codePage: "windows-1251",
			out:      sergeyCP1251,
			wantOut:  sergeyCP1251,
		},
		{
			name:     "no code page passes everything through",
			codePage: "",
			in:       sergeyCP1251,
			wantIn:   sergeyCP1251,
			out:      "Сергій",
			wantOut:  "Сергій",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := newClassicText(tt.codePage)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantIn, ct.in(tt.in))
			assert.Equal(t, tt.wantOut, ct.out(tt.out))
		})
	}
}

func TestClassicText_UnknownCodePage(t *testing.T) {
	_, err := newClassicText("no-such-code-page")
	assert.Error(t, err)
}

func TestClassicText_Structs(t *testing.T) {
	ct, err := newClassicText("windows-1251")
	assert.NoError(t, err)

	// A request: every text field converted in place.
	req := wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo{FirstName: sergeyCP1251, Nickname: "Serg", CountryCode: 804}
	ct.inAll(&req)
	assert.Equal(t, "Сергій", req.FirstName)
	assert.Equal(t, "Serg", req.Nickname)
	assert.Equal(t, uint16(804), req.CountryCode)

	// Search criteria are pointers to strings.
	first := sergeyCP1251
	criteria := state.ICQUserSearchCriteria{FirstName: &first}
	ct.inAll(&criteria)
	assert.Equal(t, "Сергій", *criteria.FirstName)

	// A reply: a converted copy, the original left alone.
	reply := wire.ICQ_0x07DA_0x00C8_DBQueryMetaReplyBasicInfo{FirstName: "Сергій", City: "Kyiv"}
	got := ct.outAll(reply).(wire.ICQ_0x07DA_0x00C8_DBQueryMetaReplyBasicInfo)
	assert.Equal(t, sergeyCP1251, got.FirstName)
	assert.Equal(t, "Kyiv", got.City)
	assert.Equal(t, "Сергій", reply.FirstName)
}

func TestICQService_ClassicCodePage(t *testing.T) {
	updater := newMockICQUserUpdater(t)
	updater.EXPECT().
		SetBasicInfo(mock.Anything, state.NewIdentScreenName("100003"), mock.MatchedBy(func(d state.ICQBasicInfo) bool {
			return d.FirstName == "Сергій" && d.Nickname == "Serg"
		})).
		Return(nil)
	relayer := newMockMessageRelayer(t)
	relayer.EXPECT().RelayToScreenName(mock.Anything, mock.Anything, mock.Anything).Return()

	s := NewICQService(relayer, nil, updater, slog.Default(), nil, nil)
	assert.NoError(t, s.SetClassicCodePage("windows-1251"))

	err := s.SetBasicInfo(context.Background(), newTestInstance("100003", sessOptUIN(100003)),
		wire.SNACFrame{RequestID: 1234},
		wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo{FirstName: sergeyCP1251, Nickname: "Serg", ZIP: "18000"}, 1)
	assert.NoError(t, err)
}

func TestClassicZIP(t *testing.T) {
	tests := []struct {
		zip  string
		want string
	}{
		{zip: "18000", want: "18000"},
		{zip: "1", want: "1"},
		{zip: "99999", want: "99999"},
		{zip: "180000", want: ""}, // a six-digit postcode
		{zip: "0", want: ""},
		{zip: "SW1A 1AA", want: ""},
		{zip: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.zip, func(t *testing.T) {
			assert.Equal(t, tt.want, classicZIP(tt.zip))
		})
	}
}

func TestICQService_keptZIP(t *testing.T) {
	tests := []struct {
		name   string
		sent   string
		stored string
		want   string
	}{
		{name: "a code sent is saved", sent: "18000", stored: "180000", want: "18000"},
		{name: "empty keeps a code the client could not show", sent: "", stored: "180000", want: "180000"},
		{name: "empty clears a code the client did show", sent: "", stored: "18000", want: ""},
		{name: "empty stays empty", sent: "", stored: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := newMockICQUserFinder(t)
			if tt.sent == "" {
				finder.EXPECT().FindByUIN(mock.Anything, uint32(100003)).
					Return(state.User{ICQInfo: state.ICQInfo{Basic: state.ICQBasicInfo{ZIPCode: tt.stored}}}, nil)
			}
			s := NewICQService(nil, finder, nil, slog.Default(), nil, nil)
			got := s.keptZIP(context.Background(), newTestInstance("100003", sessOptUIN(100003)), tt.sent,
				func(u state.User) string { return u.ICQInfo.Basic.ZIPCode })
			assert.Equal(t, tt.want, got)
		})
	}
}
