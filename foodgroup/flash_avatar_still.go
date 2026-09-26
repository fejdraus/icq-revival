package foodgroup

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

const (
	// flashStillFetchTimeout bounds one attempt to make a still: reading the
	// Flash avatar document and downloading the picture.
	flashStillFetchTimeout = 10 * time.Second
	// flashStillRetryAfter is how long a still that could not be made is not
	// tried again.
	flashStillRetryAfter = time.Minute
	// maxFlashStillSize is the largest still picture taken from the legacy
	// web. The gallery's are 52x64 JPEGs of a few KB.
	maxFlashStillSize = 256 << 10
)

var (
	// flashAvatarDocURL finds the address in a Flash avatar document:
	// <DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>...</URL></RESSET></DOCUMENT>.
	flashAvatarDocURL = regexp.MustCompile(`(?is)<URL>\s*([^<]*?)\s*</URL>`)
	// galleryAvatarPath is the path of an animated avatar of the legacy web's
	// gallery; its one group is the avatar's name.
	galleryAvatarPath = regexp.MustCompile(`^/icq/avatars/([A-Za-z0-9_-]+)\.swf$`)

	errNotGalleryAvatar = errors.New("the Flash avatar is not one of the gallery's")
)

// NewFlashAvatarStills creates a FlashAvatarStills that takes the still
// pictures from the legacy web at legacyWebURL, such as
// http://127.0.0.1:8101. An empty legacyWebURL turns the stills off.
func NewFlashAvatarStills(
	legacyWebURL string,
	bartItemManager BARTItemManager,
	relationshipFetcher RelationshipFetcher,
	messageRelayer MessageRelayer,
	sessionRetriever SessionRetriever,
	logger *slog.Logger,
) *FlashAvatarStills {
	return &FlashAvatarStills{
		legacyWebURL:     strings.TrimRight(legacyWebURL, "/"),
		httpClient:       &http.Client{Timeout: flashStillFetchTimeout},
		bartItemManager:  bartItemManager,
		buddyBroadcaster: newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		sessionRetriever: sessionRetriever,
		logger:           logger,
		nowFn:            time.Now,
		byFlash:          make(map[string]*flashStill),
		byName:           make(map[string]wire.BARTID),
	}
}

// FlashAvatarStills makes the still pictures the server shows in place of a
// Flash avatar to the clients that can't play one (everyone but ICQ 6, see
// state.Session.SupportsFlashAvatars), so they show the owner's animated
// avatar as a picture instead of no picture at all.
//
// Only the avatars of the legacy web's own gallery have a still: a Flash
// avatar document whose address has the path /icq/avatars/<name>.swf. The
// still is <legacy web>/icq/avatars/<name>-still.jpg, stored in the BART store
// as a buddy icon under its MD5 hash so that any client can download it.
// Stills are made in the background, the first time one is asked for, and
// kept in memory; once one is ready, the buddies of the users who were sent
// their user info without it are told again.
//
// FlashAvatarStills implements state.FlashAvatarStillFinder and is safe for
// concurrent use.
type FlashAvatarStills struct {
	legacyWebURL     string
	httpClient       *http.Client
	bartItemManager  BARTItemManager
	buddyBroadcaster buddyBroadcaster
	sessionRetriever SessionRetriever
	logger           *slog.Logger
	nowFn            func() time.Time

	mutex sync.Mutex
	// byFlash holds the still of each Flash avatar item asked about, keyed
	// by the item's hash.
	byFlash map[string]*flashStill
	// byName holds the stills made so far, keyed by gallery avatar name.
	byName map[string]wire.BARTID
	// fetches tracks the stills being made, so tests can wait for them.
	fetches sync.WaitGroup
}

// flashStill is what FlashAvatarStills knows about the still of one Flash
// avatar item.
type flashStill struct {
	// still is the buddy icon standing in for the item, once ready.
	still wire.BARTID
	ready bool
	// fetching is set while the still is being made.
	fetching bool
	// retryAt is when a still that could not be made may be tried again; the
	// zero time never, for an avatar that has no still.
	retryAt time.Time
	failed  bool
	// owners are the users sent their user info without the still while it
	// wasn't ready, whose buddies are told again once it is.
	owners map[state.IdentScreenName]struct{}
}

// FlashAvatarStill returns the still picture standing in for owner's Flash
// avatar item flash and reports whether it is ready. A still that isn't is
// made in the background, and owner's buddies are sent owner's user info
// again once it is ready. It never blocks on the network.
func (f *FlashAvatarStills) FlashAvatarStill(owner state.IdentScreenName, flash wire.BARTID) (wire.BARTID, bool) {
	// no gallery, or a document the client has yet to upload
	if f.legacyWebURL == "" || flash.Flags&wire.BARTFlagsUnknown != 0 {
		return wire.BARTID{}, false
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	key := string(flash.Hash)
	entry, ok := f.byFlash[key]
	if !ok {
		entry = &flashStill{owners: make(map[state.IdentScreenName]struct{})}
		f.byFlash[key] = entry
	}
	if entry.ready {
		return entry.still, true
	}
	if entry.failed && (entry.retryAt.IsZero() || f.nowFn().Before(entry.retryAt)) {
		return wire.BARTID{}, false
	}
	entry.owners[owner] = struct{}{}
	if !entry.fetching {
		entry.fetching = true
		f.fetches.Add(1)
		go f.makeStill(bytes.Clone(flash.Hash))
	}
	return wire.BARTID{}, false
}

// makeStill makes the still of the Flash avatar item whose hash is flashHash
// and, once it is ready, tells the buddies of the users waiting for it.
func (f *FlashAvatarStills) makeStill(flashHash []byte) {
	defer f.fetches.Done()

	ctx, cancel := context.WithTimeout(context.Background(), flashStillFetchTimeout)
	defer cancel()

	still, err := f.fetchStill(ctx, flashHash)

	f.mutex.Lock()
	entry := f.byFlash[string(flashHash)]
	entry.fetching = false
	owners := entry.owners
	entry.owners = make(map[state.IdentScreenName]struct{})
	switch {
	case errors.Is(err, errNotGalleryAvatar):
		entry.failed, entry.retryAt = true, time.Time{}
	case err != nil:
		entry.failed, entry.retryAt = true, f.nowFn().Add(flashStillRetryAfter)
	default:
		entry.failed, entry.ready, entry.still = false, true, still
	}
	f.mutex.Unlock()

	switch {
	case errors.Is(err, errNotGalleryAvatar):
		f.logger.DebugContext(ctx, "Flash avatar has no still picture", "hash", fmt.Sprintf("%x", flashHash), "err", err.Error())
		return
	case err != nil:
		f.logger.WarnContext(ctx, "unable to make the still picture of a Flash avatar", "hash", fmt.Sprintf("%x", flashHash), "err", err.Error())
		return
	}

	// the announcements get their own time: the fetch may have used up ctx's
	for owner := range owners {
		f.announce(context.Background(), owner, flashHash)
	}
}

// fetchStill reads the Flash avatar document whose hash is flashHash, takes
// the still of the gallery avatar it names from the legacy web and stores it
// in the BART store. A document that names no gallery avatar returns
// errNotGalleryAvatar.
func (f *FlashAvatarStills) fetchStill(ctx context.Context, flashHash []byte) (wire.BARTID, error) {
	doc, err := f.bartItemManager.BARTItem(ctx, flashHash)
	if err != nil {
		return wire.BARTID{}, fmt.Errorf("BARTItem: %w", err)
	}
	if len(doc) == 0 {
		return wire.BARTID{}, errors.New("the Flash avatar document is not in the BART store")
	}
	name, ok := galleryAvatarName(doc)
	if !ok {
		return wire.BARTID{}, errNotGalleryAvatar
	}

	f.mutex.Lock()
	still, ok := f.byName[name]
	f.mutex.Unlock()
	if ok {
		return still, nil
	}

	stillURL := f.legacyWebURL + "/icq/avatars/" + name + "-still.jpg"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stillURL, nil)
	if err != nil {
		return wire.BARTID{}, err
	}
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return wire.BARTID{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return wire.BARTID{}, fmt.Errorf("GET %s: %s", stillURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFlashStillSize+1))
	switch {
	case err != nil:
		return wire.BARTID{}, fmt.Errorf("GET %s: %w", stillURL, err)
	case len(body) == 0:
		return wire.BARTID{}, fmt.Errorf("GET %s: empty picture", stillURL)
	case len(body) > maxFlashStillSize:
		return wire.BARTID{}, fmt.Errorf("GET %s: picture larger than %d bytes", stillURL, maxFlashStillSize)
	}

	hash := md5.Sum(body)
	if err := f.bartItemManager.InsertBARTItem(ctx, hash[:], body, wire.BARTTypesBuddyIcon); err != nil && !errors.Is(err, state.ErrBARTItemExists) {
		return wire.BARTID{}, fmt.Errorf("InsertBARTItem: %w", err)
	}

	still = wire.BARTID{
		Type: wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{
			Flags: wire.BARTFlagsCustom,
			Hash:  hash[:],
		},
	}
	f.mutex.Lock()
	f.byName[name] = still
	f.mutex.Unlock()

	return still, nil
}

// announce tells owner's buddies about owner's user info again, now that the
// still of the Flash avatar item whose hash is flashHash is ready, unless
// owner has gone offline or set another avatar since.
func (f *FlashAvatarStills) announce(ctx context.Context, owner state.IdentScreenName, flashHash []byte) {
	sess := f.sessionRetriever.RetrieveSession(owner)
	if sess == nil {
		return
	}
	if item, ok := sess.AvatarItem(wire.BARTTypesFlashAvatar); !ok || !bytes.Equal(item.Hash, flashHash) {
		return
	}
	if err := f.buddyBroadcaster.BroadcastBuddyArrived(ctx, owner, sess.TLVUserInfo()); err != nil {
		f.logger.WarnContext(ctx, "unable to announce the still picture of a Flash avatar", "owner", owner.String(), "err", err.Error())
	}
}

// galleryAvatarName returns the name of the legacy web gallery avatar the
// Flash avatar document doc points at, and reports whether it points at one:
// its address has the path /icq/avatars/<name>.swf.
func galleryAvatarName(doc []byte) (string, bool) {
	m := flashAvatarDocURL.FindSubmatch(doc)
	if m == nil {
		return "", false
	}
	u, err := url.Parse(string(m[1]))
	if err != nil {
		return "", false
	}
	name := galleryAvatarPath.FindStringSubmatch(u.Path)
	if name == nil {
		return "", false
	}
	return name[1], true
}
