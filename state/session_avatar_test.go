package state

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestSession_AvatarItems(t *testing.T) {
	flashHash := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	bigHash := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}
	flash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: flashHash}}
	big := wire.BARTID{Type: wire.BARTTypesBuddyIconBig, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: bigHash}}

	tests := []struct {
		name string
		// set is applied to the session in order
		set []wire.BARTID
		// wantItems is what AvatarItems returns
		wantItems []wire.BARTID
		// wantFlash is what AvatarItem(BARTTypesFlashAvatar) reports
		wantFlash bool
	}{
		{
			name:      "nothing set",
			wantItems: nil,
		},
		{
			name:      "items come back in allow-list order",
			set:       []wire.BARTID{big, flash},
			wantItems: []wire.BARTID{flash, big},
			wantFlash: true,
		},
		{
			name:      "a later item replaces the earlier one of its type",
			set:       []wire.BARTID{{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Hash: bigHash}}, flash},
			wantItems: []wire.BARTID{flash},
			wantFlash: true,
		},
		{
			name:      "types outside the allow-list are ignored",
			set:       []wire.BARTID{{Type: wire.BARTTypesArriveSound, BARTInfo: wire.BARTInfo{Hash: flashHash}}},
			wantItems: nil,
		},
		{
			name:      "an empty hash leaves a removal notice",
			set:       []wire.BARTID{flash, {Type: wire.BARTTypesFlashAvatar}},
			wantItems: []wire.BARTID{{Type: wire.BARTTypesFlashAvatar}},
		},
		{
			name:      "an all-zero hash leaves a removal notice",
			set:       []wire.BARTID{flash, {Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: make([]byte, 16)}}},
			wantItems: []wire.BARTID{{Type: wire.BARTTypesFlashAvatar}},
		},
		{
			name:      "the clear icon hash leaves a removal notice",
			set:       []wire.BARTID{flash, {Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Hash: wire.GetClearIconHash()}}},
			wantItems: []wire.BARTID{{Type: wire.BARTTypesFlashAvatar}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := NewSession()
			for _, item := range tt.set {
				sess.SetAvatarItem(item)
			}
			assert.Equal(t, tt.wantItems, sess.AvatarItems())
			got, ok := sess.AvatarItem(wire.BARTTypesFlashAvatar)
			assert.Equal(t, tt.wantFlash, ok)
			if tt.wantFlash {
				assert.Equal(t, flash, got)
			}
		})
	}
}

func TestSession_TLVUserInfo_AvatarItems(t *testing.T) {
	icon := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte{1, 2, 3, 4}}}
	mood := wire.BARTID{Type: wire.BARTTypesMood, BARTInfo: wire.BARTInfo{Hash: []byte("0icqmood65")}}
	flash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte{5, 6, 7, 8}}}
	big := wire.BARTID{Type: wire.BARTTypesBuddyIconBig, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte{9, 10, 11, 12}}}
	var status wire.BARTID
	assert.NoError(t, status.SetStatusText("hello"))

	tests := []struct {
		name    string
		prepare func(sess *Session)
		want    []wire.BARTID
	}{
		{
			name: "existing items keep their place, avatar items are appended",
			prepare: func(sess *Session) {
				sess.SetAvatarItem(big)
				sess.SetAvatarItem(flash)
				sess.SetBuddyIcon(icon)
				sess.SetStatus(status)
				sess.SetStatusMood(mood)
			},
			want: []wire.BARTID{icon, status, mood, flash, big},
		},
		{
			name: "no avatar items, the tag is unchanged",
			prepare: func(sess *Session) {
				sess.SetBuddyIcon(icon)
				sess.SetStatus(status)
			},
			want: []wire.BARTID{icon, status},
		},
		{
			name: "a removed avatar item is sent as an empty item",
			prepare: func(sess *Session) {
				sess.SetBuddyIcon(icon)
				sess.SetAvatarItem(flash)
				sess.SetAvatarItem(wire.BARTID{Type: wire.BARTTypesFlashAvatar})
			},
			want: []wire.BARTID{icon, {Type: wire.BARTTypesFlashAvatar}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := NewSession()
			tt.prepare(sess)

			info := sess.TLVUserInfo()
			blob, ok := info.Bytes(wire.OServiceUserInfoBARTInfo)
			assert.True(t, ok)
			want := wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, tt.want)
			assert.Equal(t, want.Value, blob)
		})
	}
}
