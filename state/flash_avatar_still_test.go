package state

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

// fakeFlashAvatarStills is a FlashAvatarStillFinder with a still ready for
// each Flash avatar hash it holds. It records who it was asked about.
type fakeFlashAvatarStills struct {
	stills map[string]wire.BARTID
	asked  []IdentScreenName
}

func (f *fakeFlashAvatarStills) FlashAvatarStill(owner IdentScreenName, flash wire.BARTID) (wire.BARTID, bool) {
	f.asked = append(f.asked, owner)
	still, ok := f.stills[string(flash.Hash)]
	return still, ok
}

func TestSession_UserInfoFor_FlashAvatarStill(t *testing.T) {
	icon := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("icon")}}
	still := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("still")}}
	flash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("devil")}}
	otherFlash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("other")}}
	infoWith := func(ids ...wire.BARTID) wire.TLVUserInfo {
		return wire.TLVUserInfo{
			ScreenName: "Owner",
			TLVBlock:   wire.TLVBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, ids)}},
		}
	}
	noBART := wire.TLVUserInfo{ScreenName: "Owner", TLVBlock: wire.TLVBlock{TLVList: wire.TLVList{}}}

	tests := []struct {
		name string
		// icq6 makes the recipient an ICQ 6 client
		icq6 bool
		// noFinder leaves the recipient without a FlashAvatarStillFinder
		noFinder  bool
		info      wire.TLVUserInfo
		want      wire.TLVUserInfo
		wantAsked []IdentScreenName
	}{
		{
			name:      "the still stands in for the Flash avatar",
			info:      infoWith(flash),
			want:      infoWith(still),
			wantAsked: []IdentScreenName{NewIdentScreenName("owner")},
		},
		{
			name: "ICQ 6 gets the Flash avatar",
			icq6: true,
			info: infoWith(flash),
			want: infoWith(flash),
		},
		{
			name: "the owner's own icon stays and no still is asked for",
			info: infoWith(icon, flash),
			want: infoWith(icon),
		},
		{
			name:      "a still that isn't ready is left out",
			info:      infoWith(otherFlash),
			want:      noBART,
			wantAsked: []IdentScreenName{NewIdentScreenName("owner")},
		},
		{
			name: "a removed Flash avatar has no still",
			info: infoWith(wire.BARTID{Type: wire.BARTTypesFlashAvatar}),
			want: noBART,
		},
		{
			name:     "a session without a finder sends no still",
			noFinder: true,
			info:     infoWith(flash),
			want:     noBART,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stills := &fakeFlashAvatarStills{stills: map[string]wire.BARTID{string(flash.Hash): still}}
			recipient := NewSession()
			instance := recipient.AddInstance()
			if tt.icq6 {
				instance.SetCaps(wire.FlashAvatarCaps)
			}
			if !tt.noFinder {
				recipient.SetFlashAvatarStills(stills)
			}

			assert.Equal(t, tt.want, recipient.UserInfoFor(tt.info))
			assert.Equal(t, tt.want, instance.UserInfoFor(tt.info))
			if tt.wantAsked != nil {
				// once by the session, once by the instance
				tt.wantAsked = append(tt.wantAsked, tt.wantAsked...)
			}
			assert.Equal(t, tt.wantAsked, stills.asked)
		})
	}
}

func TestInMemorySessionManager_SetFlashAvatarStills(t *testing.T) {
	stills := &fakeFlashAvatarStills{}
	sm := NewInMemorySessionManager(nil)
	sm.SetFlashAvatarStills(stills)

	instance, err := sm.AddSession(t.Context(), "Owner", false)
	assert.NoError(t, err)
	assert.Equal(t, stills, instance.Session().flashAvatarStillFinder())
}
