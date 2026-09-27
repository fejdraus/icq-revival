package state

import "github.com/mk6i/open-oscar-server/wire"

// FlashAvatarStillFinder finds the still picture the server shows in place of
// a Flash avatar to the clients that show a buddy icon instead (see
// Session.NeedsFlashAvatarStill). The still takes the place of the owner's
// own buddy icon too, since ICQ 6 shows the Flash avatar over it.
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

// flashAvatarStill returns the still that stills finds for the Flash avatar
// listed in info and reports whether one is ready. It reports false when
// info lists no Flash avatar that is set. stills may be nil.
func flashAvatarStill(info wire.TLVUserInfo, stills FlashAvatarStillFinder) (wire.BARTID, bool) {
	if stills == nil {
		return wire.BARTID{}, false
	}
	flash, ok := info.FlashAvatarItem()
	if !ok {
		return wire.BARTID{}, false
	}
	return stills.FlashAvatarStill(NewIdentScreenName(info.ScreenName), flash)
}
