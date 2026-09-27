package state

import "github.com/mk6i/open-oscar-server/wire"

// NormalisedBuddyIconFinder finds the copy of a buddy icon the server sends
// in place of the owner's own to the clients that can't show every picture
// ICQ 6 uploads (see Session.NeedsFlashAvatarStill): a buddy icon of at most
// 64x64 pixels and 7 KB in a format the old clients take.
type NormalisedBuddyIconFinder interface {
	// NormalisedBuddyIcon returns the buddy icon (wire.BARTTypesBuddyIcon)
	// to send in place of owner's buddy icon icon and reports whether there
	// is one ready. It reports false for an icon the old clients already
	// take and for one it can't make a copy of. It never blocks: a copy
	// that isn't ready yet reports false, and owner's buddies hear about it
	// once it is.
	NormalisedBuddyIcon(owner IdentScreenName, icon wire.BARTID) (wire.BARTID, bool)
}

// SetNormalisedBuddyIcons sets where UserInfoFor finds the copies of the
// buddy icons that stand in for the ones the session's clients may not show.
// A session without one sends every buddy icon as it is.
func (s *Session) SetNormalisedBuddyIcons(icons NormalisedBuddyIconFinder) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.normalisedBuddyIcons = icons
}

// SetNormalisedBuddyIcons sets where the sessions created from now on find
// the copies of the buddy icons that stand in for the ones their clients may
// not show, see Session.SetNormalisedBuddyIcons.
func (s *InMemorySessionManager) SetNormalisedBuddyIcons(icons NormalisedBuddyIconFinder) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	s.normalisedBuddyIcons = icons
}

// normalisedBuddyIconFinder returns the session's NormalisedBuddyIconFinder,
// nil when it has none.
func (s *Session) normalisedBuddyIconFinder() NormalisedBuddyIconFinder {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.normalisedBuddyIcons
}

// userInfoFor returns info as a recipient is sent it. An ICQ 6 recipient
// (needsStill false) gets it as it is. Any other gets it without the Flash
// avatar and big icon items unless playsFlash, and with one buddy icon: the
// still that stills finds for the owner's Flash avatar when there is one
// ready, in place of the owner's own icon too, since ICQ 6 shows the Flash
// avatar over it; otherwise the owner's own icon, or the normalised copy
// that icons finds for it. A still, already a small JPEG, is never
// normalised. stills and icons may be nil.
func userInfoFor(info wire.TLVUserInfo, playsFlash, needsStill bool, stills FlashAvatarStillFinder, icons NormalisedBuddyIconFinder) wire.TLVUserInfo {
	if !needsStill {
		return info
	}
	to := info
	if !playsFlash {
		to = info.WithoutRelayedAvatarItems()
	}
	if still, ok := flashAvatarStill(info, stills); ok {
		return to.ReplacingBuddyIcon(still)
	}
	return withNormalisedBuddyIcon(to, icons)
}

// withNormalisedBuddyIcon returns info with the copy that icons finds in
// place of the buddy icon info lists, when there is one ready. icons may be
// nil.
func withNormalisedBuddyIcon(info wire.TLVUserInfo, icons NormalisedBuddyIconFinder) wire.TLVUserInfo {
	if icons == nil {
		return info
	}
	icon, ok := info.BuddyIconItem()
	if !ok {
		return info
	}
	normalised, ok := icons.NormalisedBuddyIcon(NewIdentScreenName(info.ScreenName), icon)
	if !ok {
		return info
	}
	return info.ReplacingBuddyIcon(normalised)
}
