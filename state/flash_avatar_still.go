package state

import "github.com/mk6i/open-oscar-server/wire"

// FlashAvatarStillFinder finds the still picture the server shows in place of
// a Flash avatar to the clients that can't play one (see
// Session.SupportsFlashAvatars).
type FlashAvatarStillFinder interface {
	// FlashAvatarStill returns the buddy icon (wire.BARTTypesBuddyIcon)
	// standing in for owner's Flash avatar item flash and reports whether one
	// is ready. It never blocks on the network: a still that isn't ready yet
	// reports false, and owner's buddies hear about it once it is.
	FlashAvatarStill(owner IdentScreenName, flash wire.BARTID) (wire.BARTID, bool)
}

// SetFlashAvatarStills sets where UserInfoFor finds the still pictures that
// stand in for Flash avatars. A session without one sends no such stills.
func (s *Session) SetFlashAvatarStills(stills FlashAvatarStillFinder) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.flashAvatarStills = stills
}

// SetFlashAvatarStills sets where the sessions created from now on find the
// still pictures that stand in for Flash avatars, see
// Session.SetFlashAvatarStills.
func (s *InMemorySessionManager) SetFlashAvatarStills(stills FlashAvatarStillFinder) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	s.flashAvatarStills = stills
}

// userInfoWithoutFlash returns info as a client that can't play Flash avatars
// is sent it: without the Flash avatar and big icon items and, when info's
// owner has a Flash avatar but no buddy icon of their own, with the still
// that stills finds for the avatar as the buddy icon. stills may be nil.
func userInfoWithoutFlash(info wire.TLVUserInfo, stills FlashAvatarStillFinder) wire.TLVUserInfo {
	plain := info.WithoutRelayedAvatarItems()
	if stills == nil || plain.HasBuddyIcon() {
		return plain
	}
	flash, ok := info.FlashAvatarItem()
	if !ok {
		return plain
	}
	still, ok := stills.FlashAvatarStill(NewIdentScreenName(info.ScreenName), flash)
	if !ok {
		return plain
	}
	return plain.WithBuddyIcon(still)
}
