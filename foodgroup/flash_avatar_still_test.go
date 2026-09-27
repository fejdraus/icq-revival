package foodgroup

import (
	"bytes"
	"crypto/md5"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestFlashAvatarStills_UserInfoFor(t *testing.T) {
	galleryDoc := []byte(`<DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>http://icq.example.com:8101/icq/avatars/pirate.swf</URL></RESSET></DOCUMENT>`)
	foreignDoc := []byte(`<DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>http://example.com/devils/pirate.swf</URL></RESSET></DOCUMENT>`)
	stillJPEG := []byte("\xff\xd8\xff\xe0 the pirate, standing still")
	stillHash := md5.Sum(stillJPEG)
	still := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: stillHash[:]}}

	flashHash := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	flash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: flashHash}}
	ownIcon := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("the owner's own icon")}}

	tests := []struct {
		name string
		// ownerOpts set up the owner, an ICQ 6 user
		ownerOpts []func(*state.SessionInstance)
		// recipientOpts set up the buddy the owner's user info is sent to
		recipientOpts []func(*state.SessionInstance)
		// doc is the owner's Flash avatar document in the BART store
		doc []byte
		// stillStatus is what the legacy web answers for the still
		stillStatus int
		// wantIcon is the buddy icon the recipient is sent, if any
		wantIcon *wire.BARTID
		// wantFlash is whether the recipient is sent the Flash avatar item
		wantFlash bool
		// wantFetches is how many times the legacy web is asked for a still
		wantFetches int32
		// wantStored is whether the still goes into the BART store and the
		// owner's buddies are told about it
		wantStored bool
	}{
		{
			name:          "a client that can't play Flash gets the gallery avatar's still",
			ownerOpts:     []func(*state.SessionInstance){sessOptAvatarItem(flash)},
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaICQ},
			doc:           galleryDoc,
			stillStatus:   http.StatusOK,
			wantIcon:      &still,
			wantFetches:   1,
			wantStored:    true,
		},
		{
			name:          "ICQ 6 gets the Flash avatar and no still",
			ownerOpts:     []func(*state.SessionInstance){sessOptAvatarItem(flash)},
			recipientOpts: []func(*state.SessionInstance){sessOptICQ6},
			doc:           galleryDoc,
			stillStatus:   http.StatusOK,
			wantFlash:     true,
		},
		{
			// ICQ 6 shows the Flash avatar over the owner's own icon
			name:          "the still takes the place of the owner's own buddy icon",
			ownerOpts:     []func(*state.SessionInstance){sessOptAvatarItem(flash), sessOptBuddyIcon(ownIcon)},
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaICQ},
			doc:           galleryDoc,
			stillStatus:   http.StatusOK,
			wantIcon:      &still,
			wantFetches:   1,
			wantStored:    true,
		},
		{
			name:          "the owner's own buddy icon stays when the Flash avatar has no still",
			ownerOpts:     []func(*state.SessionInstance){sessOptAvatarItem(flash), sessOptBuddyIcon(ownIcon)},
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaICQ},
			doc:           foreignDoc,
			stillStatus:   http.StatusOK,
			wantIcon:      &ownIcon,
		},
		{
			// ICQ 6.5 clears the Flash avatar when a static picture is chosen
			name: "the owner's own buddy icon shows again once the Flash avatar is cleared",
			ownerOpts: []func(*state.SessionInstance){
				sessOptAvatarItem(flash),
				sessOptBuddyIcon(ownIcon),
				sessOptAvatarItem(wire.BARTID{Type: wire.BARTTypesFlashAvatar}),
			},
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaICQ},
			doc:           galleryDoc,
			stillStatus:   http.StatusOK,
			wantIcon:      &ownIcon,
		},
		{
			name:          "ICQ 6 gets the owner's own buddy icon and the Flash avatar",
			ownerOpts:     []func(*state.SessionInstance){sessOptAvatarItem(flash), sessOptBuddyIcon(ownIcon)},
			recipientOpts: []func(*state.SessionInstance){sessOptICQ6},
			doc:           galleryDoc,
			stillStatus:   http.StatusOK,
			wantIcon:      &ownIcon,
			wantFlash:     true,
		},
		{
			name:          "a Flash avatar from elsewhere has no still",
			ownerOpts:     []func(*state.SessionInstance){sessOptAvatarItem(flash)},
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaICQ},
			doc:           foreignDoc,
			stillStatus:   http.StatusOK,
		},
		{
			name:          "a still the legacy web doesn't have is not sent",
			ownerOpts:     []func(*state.SessionInstance){sessOptAvatarItem(flash)},
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaICQ},
			doc:           galleryDoc,
			stillStatus:   http.StatusNotFound,
			wantFetches:   1,
		},
		{
			name: "a cleared Flash avatar has no still",
			ownerOpts: []func(*state.SessionInstance){
				sessOptAvatarItem(flash),
				sessOptAvatarItem(wire.BARTID{Type: wire.BARTTypesFlashAvatar}),
			},
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaICQ},
			doc:           galleryDoc,
			stillStatus:   http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fetches atomic.Int32
			legacyWeb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fetches.Add(1)
				if r.URL.Path != "/icq/avatars/pirate-still.jpg" || tt.stillStatus != http.StatusOK {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(stillJPEG)
			}))
			defer legacyWeb.Close()

			owner := newTestInstance("owner", append([]func(*state.SessionInstance){sessOptICQ6}, tt.ownerOpts...)...)
			recipient := newTestInstance("buddy", tt.recipientOpts...)

			bartItemManager := newMockBARTItemManager(t)
			bartItemManager.EXPECT().BARTItem(mock.Anything, flashHash).Return(tt.doc, nil).Maybe()
			broadcaster := newMockbuddyBroadcaster(t)
			if tt.wantStored {
				bartItemManager.EXPECT().
					InsertBARTItem(mock.Anything, stillHash[:], stillJPEG, wire.BARTTypesBuddyIcon).
					Return(nil)
				broadcaster.EXPECT().
					BroadcastBuddyArrived(mock.Anything, owner.IdentScreenName(), mock.Anything).
					Return(nil)
			}
			sessionRetriever := newMockSessionRetriever(t)
			sessionRetriever.EXPECT().RetrieveSession(owner.IdentScreenName()).Return(owner.Session()).Maybe()

			stills := NewFlashAvatarStills(legacyWeb.URL+"/", bartItemManager, nil, nil, sessionRetriever, slog.Default())
			stills.buddyBroadcaster = broadcaster
			recipient.Session().SetFlashAvatarStills(stills)

			// the first user info goes out before the still is ready
			first := recipient.UserInfoFor(owner.Session().TLVUserInfo())
			stills.fetches.Wait()
			if tt.wantStored {
				firstIcon, _ := first.BuddyIconItem()
				assert.False(t, bytes.Equal(firstIcon.Hash, stillHash[:]), "the still is not ready yet")
			}

			got := userInfoBARTIDs(t, recipient.UserInfoFor(owner.Session().TLVUserInfo()))
			icon, hasIcon := findBARTID(got, wire.BARTTypesBuddyIcon)
			if tt.wantIcon == nil {
				assert.False(t, hasIcon, "no buddy icon expected, got %v", icon)
			} else {
				assert.Equal(t, *tt.wantIcon, icon)
			}
			_, hasFlash := findBARTID(got, wire.BARTTypesFlashAvatar)
			assert.Equal(t, tt.wantFlash, hasFlash)
			assert.Equal(t, tt.wantFetches, fetches.Load())

			// the owner's own client is never sent the still as its own icon
			self := userInfoBARTIDs(t, sessionUserInfo(owner, false))
			selfIcon, hasSelfIcon := findBARTID(self, wire.BARTTypesBuddyIcon)
			if hasSelfIcon {
				assert.Equal(t, ownIcon, selfIcon)
			}
			assert.False(t, bytes.Equal(selfIcon.Hash, stillHash[:]))
		})
	}
}

func TestFlashAvatarStills_Off(t *testing.T) {
	flash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("flash")}}
	// no expectations: nothing is read, stored or announced
	stills := NewFlashAvatarStills("", newMockBARTItemManager(t), nil, nil, newMockSessionRetriever(t), slog.Default())

	_, ok := stills.FlashAvatarStill(state.NewIdentScreenName("owner"), flash)
	stills.fetches.Wait()
	assert.False(t, ok)
}

func TestFlashAvatarStills_RetriesAfterFailure(t *testing.T) {
	doc := []byte(`<DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>http://127.0.0.1:8101/icq/avatars/pirate.swf</URL></RESSET></DOCUMENT>`)
	flash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("flash")}}
	owner := state.NewIdentScreenName("owner")

	var fetches atomic.Int32
	legacyWeb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer legacyWeb.Close()

	bartItemManager := newMockBARTItemManager(t)
	bartItemManager.EXPECT().BARTItem(mock.Anything, flash.Hash).Return(doc, nil)
	stills := NewFlashAvatarStills(legacyWeb.URL, bartItemManager, nil, nil, newMockSessionRetriever(t), slog.Default())
	now := stills.nowFn()
	stills.nowFn = func() time.Time { return now }

	_, ok := stills.FlashAvatarStill(owner, flash)
	stills.fetches.Wait()
	assert.False(t, ok)
	assert.Equal(t, int32(1), fetches.Load())

	// not tried again right away
	_, ok = stills.FlashAvatarStill(owner, flash)
	stills.fetches.Wait()
	assert.False(t, ok)
	assert.Equal(t, int32(1), fetches.Load())

	// but once the wait is over
	now = now.Add(flashStillRetryAfter)
	_, ok = stills.FlashAvatarStill(owner, flash)
	stills.fetches.Wait()
	assert.False(t, ok)
	assert.Equal(t, int32(2), fetches.Load())
}

func TestGalleryAvatarName(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		wantName string
		wantOK   bool
	}{
		{
			name:     "a gallery avatar",
			doc:      `<DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>http://icq.example.com:8101/icq/avatars/2308koshak.swf</URL></RESSET></DOCUMENT>`,
			wantName: "2308koshak",
			wantOK:   true,
		},
		{
			name:     "a gallery avatar with a query and spaces around the address",
			doc:      "<document><resset><url>\n http://h/icq/avatars/avatar_10522.swf?emotion=stam </url></resset></document>",
			wantName: "avatar_10522",
			wantOK:   true,
		},
		{
			name: "a movie elsewhere",
			doc:  `<DOCUMENT><RESSET><URL>http://example.com/devil.swf</URL></RESSET></DOCUMENT>`,
		},
		{
			name: "a path below the gallery",
			doc:  `<DOCUMENT><RESSET><URL>http://h/icq/avatars/../secret/x.swf</URL></RESSET></DOCUMENT>`,
		},
		{
			name: "a name with characters a gallery name doesn't have",
			doc:  `<DOCUMENT><RESSET><URL>http://h/icq/avatars/pi.rate.swf</URL></RESSET></DOCUMENT>`,
		},
		{
			name: "not a movie",
			doc:  `<DOCUMENT><RESSET><URL>http://h/icq/avatars/pirate.png</URL></RESSET></DOCUMENT>`,
		},
		{
			name: "no address",
			doc:  `<DOCUMENT></DOCUMENT>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ok := galleryAvatarName([]byte(tt.doc))
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantName, name)
		})
	}
}

// findBARTID returns the first of ids of type itemType.
func findBARTID(ids []wire.BARTID, itemType uint16) (wire.BARTID, bool) {
	for _, id := range ids {
		if id.Type == itemType {
			return id, true
		}
	}
	return wire.BARTID{}, false
}

// fakeFlashAvatarStills is a state.FlashAvatarStillFinder with a still ready
// for each Flash avatar hash it holds.
type fakeFlashAvatarStills map[string]wire.BARTID

func (f fakeFlashAvatarStills) FlashAvatarStill(_ state.IdentScreenName, flash wire.BARTID) (wire.BARTID, bool) {
	still, ok := f[string(flash.Hash)]
	return still, ok
}

// sessOptFlashAvatarStill makes still the one the session is sent in place
// of the Flash avatar item flash.
func sessOptFlashAvatarStill(flash wire.BARTID, still wire.BARTID) func(instance *state.SessionInstance) {
	return func(instance *state.SessionInstance) {
		instance.Session().SetFlashAvatarStills(fakeFlashAvatarStills{string(flash.Hash): still})
	}
}
