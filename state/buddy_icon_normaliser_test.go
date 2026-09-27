package state

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

// fakeNormalisedBuddyIcons is a NormalisedBuddyIconFinder with a copy ready
// for each buddy icon hash in ready. It records who it was asked about.
type fakeNormalisedBuddyIcons struct {
	ready map[string]wire.BARTID
	asked []IdentScreenName
}

func (f *fakeNormalisedBuddyIcons) NormalisedBuddyIcon(owner IdentScreenName, icon wire.BARTID) (wire.BARTID, bool) {
	f.asked = append(f.asked, owner)
	normalised, ok := f.ready[string(icon.Hash)]
	return normalised, ok
}

func TestSession_UserInfoFor_NormalisedBuddyIcon(t *testing.T) {
	big := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("big")}}
	small := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("small")}}
	pending := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("pending")}}
	cleared := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: wire.GetClearIconHash()}}
	status := wire.BARTID{Type: wire.BARTTypesStatusStr, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsData, Hash: []byte("status")}}
	flash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("devil")}}
	noStillFlash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("foreign")}}
	still := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("still")}}
	infoWith := func(ids ...wire.BARTID) wire.TLVUserInfo {
		return wire.TLVUserInfo{
			ScreenName: "Owner",
			TLVBlock:   wire.TLVBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, ids)}},
		}
	}

	icq6 := wire.FlashAvatarCaps
	qip := [][16]byte{wire.CapICQCh2Extended, wire.CapUTF8Messages, wire.CapSupportICQ}
	aim := [][16]byte{wire.CapChat, wire.CapFileTransfer}
	miranda := [][16]byte{wire.CapUTF8Messages, wire.CapXHTMLIM}
	mirandaFlash := [][16]byte{wire.CapUTF8Messages, wire.CapXHTMLIM, wire.CapFlashAvatarPlayer}
	owner := NewIdentScreenName("owner")

	tests := []struct {
		name string
		caps [][16]byte
		// noFinder leaves the recipient without a NormalisedBuddyIconFinder
		noFinder  bool
		info      wire.TLVUserInfo
		want      wire.TLVUserInfo
		wantAsked []IdentScreenName
	}{
		{
			name: "ICQ 6 gets the original",
			caps: icq6,
			info: infoWith(big, status),
			want: infoWith(big, status),
		},
		{
			name:      "QIP gets the copy",
			caps:      qip,
			info:      infoWith(big, status),
			want:      infoWith(small, status),
			wantAsked: []IdentScreenName{owner},
		},
		{
			name:      "AIM gets the copy",
			caps:      aim,
			info:      infoWith(big, status),
			want:      infoWith(small, status),
			wantAsked: []IdentScreenName{owner},
		},
		{
			name:      "Miranda gets the copy",
			caps:      miranda,
			info:      infoWith(big, status),
			want:      infoWith(small, status),
			wantAsked: []IdentScreenName{owner},
		},
		{
			name:      "Miranda with the Flash plugin gets the copy and the Flash avatar",
			caps:      mirandaFlash,
			info:      infoWith(big, noStillFlash),
			want:      infoWith(small, noStillFlash),
			wantAsked: []IdentScreenName{owner},
		},
		{
			name:      "the original is sent while the copy isn't ready",
			caps:      qip,
			info:      infoWith(pending, status),
			want:      infoWith(pending, status),
			wantAsked: []IdentScreenName{owner},
		},
		{
			name: "a cleared icon is not asked about",
			caps: qip,
			info: infoWith(cleared, status),
			want: infoWith(cleared, status),
		},
		{
			name: "the still of a Flash avatar wins, and is not normalised",
			caps: qip,
			info: infoWith(big, flash),
			want: infoWith(still),
		},
		{
			name:      "a Flash avatar without a still leaves the copy of the owner's icon",
			caps:      qip,
			info:      infoWith(big, noStillFlash),
			want:      infoWith(small),
			wantAsked: []IdentScreenName{owner},
		},
		{
			name:     "a session without a finder sends the original",
			caps:     qip,
			noFinder: true,
			info:     infoWith(big, status),
			want:     infoWith(big, status),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icons := &fakeNormalisedBuddyIcons{ready: map[string]wire.BARTID{string(big.Hash): small}}
			recipient := NewSession()
			instance := recipient.AddInstance()
			instance.SetCaps(tt.caps)
			recipient.SetFlashAvatarStills(&fakeFlashAvatarStills{stills: map[string]wire.BARTID{string(flash.Hash): still}})
			if !tt.noFinder {
				recipient.SetNormalisedBuddyIcons(icons)
			}

			assert.Equal(t, tt.want, recipient.UserInfoFor(tt.info))
			assert.Equal(t, tt.want, instance.UserInfoFor(tt.info))
			if tt.wantAsked != nil {
				// once by the session, once by the instance
				tt.wantAsked = append(tt.wantAsked, tt.wantAsked...)
			}
			assert.Equal(t, tt.wantAsked, icons.asked)
		})
	}
}

func TestInMemorySessionManager_SetNormalisedBuddyIcons(t *testing.T) {
	icons := &fakeNormalisedBuddyIcons{}
	sm := NewInMemorySessionManager(nil)
	sm.SetNormalisedBuddyIcons(icons)

	instance, err := sm.AddSession(t.Context(), "Owner", false)
	assert.NoError(t, err)
	assert.Equal(t, icons, instance.Session().normalisedBuddyIconFinder())
}
