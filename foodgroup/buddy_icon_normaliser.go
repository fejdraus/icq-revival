package foodgroup

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

const (
	// buddyIconNormaliseTimeout bounds one attempt to make a normalised copy
	// of a buddy icon: reading the icon and storing the copy.
	buddyIconNormaliseTimeout = 10 * time.Second
	// buddyIconNormaliseRetryAfter is how long a buddy icon that could not be
	// read or decoded is not tried again.
	buddyIconNormaliseRetryAfter = time.Minute
)

// NewBuddyIconNormaliser creates a BuddyIconNormaliser.
func NewBuddyIconNormaliser(
	bartItemManager BARTItemManager,
	relationshipFetcher RelationshipFetcher,
	messageRelayer MessageRelayer,
	sessionRetriever SessionRetriever,
	logger *slog.Logger,
) *BuddyIconNormaliser {
	return &BuddyIconNormaliser{
		messageRelayer:   messageRelayer,
		bartItemManager:  bartItemManager,
		buddyBroadcaster: newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		sessionRetriever: sessionRetriever,
		logger:           logger,
		nowFn:            time.Now,
		byIcon:           make(map[string]*normalisedIcon),
	}
}

// BuddyIconNormaliser makes the copies of buddy icons the server sends in
// place of the owner's own to the clients other than ICQ 6 (see
// state.Session.NeedsFlashAvatarStill). ICQ 6 uploads pictures of any size
// and kind, such as a 360x360 progressive JPEG, while the old clients (QIP,
// AIM, older ICQ and the like) take a GIF, JPEG or BMP of at most 64x64
// pixels and 7 KB and show nothing for anything else.
//
// A buddy icon that doesn't conform gets a copy: a baseline JPEG scaled to
// fit within 64x64, laid on white where the picture is transparent, stored
// in the BART store as a buddy icon under its MD5 hash so that any client can
// download it. Copies are made in the background, the first time one is
// asked for, and kept in memory with what is known about each icon; once one
// is ready, the buddies of the users who were sent their user info without
// it are told again.
//
// BuddyIconNormaliser implements state.NormalisedBuddyIconFinder and is safe
// for concurrent use.
type BuddyIconNormaliser struct {
	messageRelayer   MessageRelayer
	bartItemManager  BARTItemManager
	buddyBroadcaster buddyBroadcaster
	sessionRetriever SessionRetriever
	logger           *slog.Logger
	nowFn            func() time.Time

	mutex sync.Mutex
	// byIcon holds what is known of each buddy icon asked about, keyed by
	// the icon's hash.
	byIcon map[string]*normalisedIcon
	// jobs tracks the copies being made, so tests can wait for them.
	jobs sync.WaitGroup
}

// normalisedIcon is what BuddyIconNormaliser knows about one buddy icon.
type normalisedIcon struct {
	// normalised is the icon sent in place of the original, once ready.
	normalised wire.BARTID
	ready      bool
	// conforming is set for an original the old clients take as it is.
	conforming bool
	// working is set while the icon is being looked at.
	working bool
	// failed is set for an icon that could not be read or decoded, which is
	// sent as it is and not tried again before retryAt.
	failed  bool
	retryAt time.Time
	// owners are the users sent their user info with the original while the
	// copy wasn't ready, whose buddies are told again once it is.
	owners map[state.IdentScreenName]struct{}
}

// NormalisedBuddyIcon returns the copy of owner's buddy icon icon that the
// old clients take and reports whether one is ready. It reports false for an
// icon they already take, one that can't be decoded and one whose copy isn't
// ready yet. A copy is made in the background, and owner's buddies are sent
// owner's user info again once it is ready. It never blocks.
func (n *BuddyIconNormaliser) NormalisedBuddyIcon(owner state.IdentScreenName, icon wire.BARTID) (wire.BARTID, bool) {
	// a cleared icon, or one the client has yet to upload
	if icon.Type != wire.BARTTypesBuddyIcon || icon.IsCleared() || icon.Flags&wire.BARTFlagsUnknown != 0 {
		return wire.BARTID{}, false
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	key := string(icon.Hash)
	entry, ok := n.byIcon[key]
	if !ok {
		entry = &normalisedIcon{owners: make(map[state.IdentScreenName]struct{})}
		n.byIcon[key] = entry
	}
	switch {
	case entry.ready:
		return entry.normalised, true
	case entry.conforming:
		return wire.BARTID{}, false
	case entry.failed && n.nowFn().Before(entry.retryAt):
		return wire.BARTID{}, false
	}
	entry.owners[owner] = struct{}{}
	if !entry.working {
		entry.working = true
		n.jobs.Add(1)
		go n.normalise(bytes.Clone(icon.Hash))
	}
	return wire.BARTID{}, false
}

// normalise looks at the buddy icon whose hash is iconHash, makes its copy
// when it doesn't conform and, once the copy is ready, tells the buddies of
// the users waiting for it.
func (n *BuddyIconNormaliser) normalise(iconHash []byte) {
	defer n.jobs.Done()

	ctx, cancel := context.WithTimeout(context.Background(), buddyIconNormaliseTimeout)
	defer cancel()

	normalised, conforming, err := n.makeCopy(ctx, iconHash)

	n.mutex.Lock()
	entry := n.byIcon[string(iconHash)]
	entry.working = false
	owners := entry.owners
	entry.owners = make(map[state.IdentScreenName]struct{})
	switch {
	case err != nil:
		entry.failed, entry.retryAt = true, n.nowFn().Add(buddyIconNormaliseRetryAfter)
	case conforming:
		entry.failed, entry.conforming = false, true
	default:
		entry.failed, entry.ready, entry.normalised = false, true, normalised
	}
	n.mutex.Unlock()

	switch {
	case err != nil:
		n.logger.WarnContext(ctx, "unable to make a normalised copy of a buddy icon", "hash", fmt.Sprintf("%x", iconHash), "err", err.Error())
		return
	case conforming:
		return
	}
	n.logger.DebugContext(ctx, "made a normalised copy of a buddy icon", "hash", fmt.Sprintf("%x", iconHash), "copy", fmt.Sprintf("%x", normalised.Hash))

	// the announcements get their own time: the copy may have used up ctx's
	for owner := range owners {
		n.announce(context.Background(), owner, iconHash)
	}
}

// makeCopy reads the buddy icon whose hash is iconHash from the BART store
// and, unless it conforms, stores a normalised copy of it there. It returns
// the copy, or reports that the icon conforms.
func (n *BuddyIconNormaliser) makeCopy(ctx context.Context, iconHash []byte) (wire.BARTID, bool, error) {
	data, err := n.bartItemManager.BARTItem(ctx, iconHash)
	if err != nil {
		return wire.BARTID{}, false, fmt.Errorf("BARTItem: %w", err)
	}
	if len(data) == 0 {
		return wire.BARTID{}, false, errors.New("the buddy icon is not in the BART store")
	}

	conforming, err := buddyIconConforms(data)
	if err != nil {
		return wire.BARTID{}, false, err
	}
	if conforming {
		return wire.BARTID{}, true, nil
	}

	normalised, err := normaliseBuddyIcon(data)
	if err != nil {
		return wire.BARTID{}, false, err
	}
	hash := md5.Sum(normalised)
	if err := n.bartItemManager.InsertBARTItem(ctx, hash[:], normalised, wire.BARTTypesBuddyIcon); err != nil && !errors.Is(err, state.ErrBARTItemExists) {
		return wire.BARTID{}, false, fmt.Errorf("InsertBARTItem: %w", err)
	}

	return wire.BARTID{
		Type: wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{
			Flags: wire.BARTFlagsCustom,
			Hash:  hash[:],
		},
	}, false, nil
}

// announce tells owner's buddies about owner's user info again, now that the
// copy of the buddy icon whose hash is iconHash is ready, unless owner has
// gone offline or set another icon since.
func (n *BuddyIconNormaliser) announce(ctx context.Context, owner state.IdentScreenName, iconHash []byte) {
	sess := n.sessionRetriever.RetrieveSession(owner)
	if sess == nil {
		return
	}
	if icon, ok := sess.BuddyIcon(); !ok || !bytes.Equal(icon.Hash, iconHash) || icon.Flags&wire.BARTFlagsUnknown != 0 {
		return
	}
	if err := n.buddyBroadcaster.BroadcastBuddyArrived(ctx, owner, sess.TLVUserInfo()); err != nil {
		n.logger.WarnContext(ctx, "unable to announce the normalised copy of a buddy icon", "owner", owner.String(), "err", err.Error())
	}
	// the owner's own clients learn it too (see sendOwnBuddyIcon)
	for _, instance := range sess.Instances() {
		sendOwnBuddyIcon(ctx, n.messageRelayer, instance)
	}
}
