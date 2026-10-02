package e2e

import (
	"context"
	"crypto/ed25519"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/mk6i/open-oscar-server/state"
)

// Store is the persistence of the key directory (state.SQLiteUserStore).
type Store interface {
	E2EAccount(ctx context.Context, screenName state.IdentScreenName) (*state.E2EAccount, error)
	E2EPublishAccountKey(ctx context.Context, screenName state.IdentScreenName, key []byte, now time.Time) error
	E2ERotateAccountKey(ctx context.Context, screenName state.IdentScreenName, oldKey, newKey, proof []byte, resigned []state.E2EDeviceSignature, now time.Time) error
	E2EResetAccountKey(ctx context.Context, screenName state.IdentScreenName, oldKey, newKey []byte, now time.Time) error
	E2EAccountKeyHistory(ctx context.Context, screenName state.IdentScreenName) ([]state.E2EAccountKeyChange, error)
	E2EDevices(ctx context.Context, screenName state.IdentScreenName) ([]state.E2EDevice, error)
	E2EDevice(ctx context.Context, screenName state.IdentScreenName, deviceID uint32) (*state.E2EDevice, error)
	E2EPutDevice(ctx context.Context, screenName state.IdentScreenName, accountKey []byte, dev state.E2EDevice, maxDevices int, now time.Time) (bool, error)
	E2ERevokeDevice(ctx context.Context, screenName state.IdentScreenName, deviceID uint32, now time.Time) error
	E2ESetFallbackKey(ctx context.Context, screenName state.IdentScreenName, deviceID uint32, key state.E2ESignedKey, now time.Time) error
	E2EAddOneTimeKeys(ctx context.Context, screenName state.IdentScreenName, deviceID uint32, keys []state.E2ESignedKey, maxPool int, now time.Time) (int, error)
	E2EKeyStatus(ctx context.Context, screenName state.IdentScreenName, deviceID uint32) (int, bool, error)
	E2EClaimKey(ctx context.Context, screenName state.IdentScreenName, deviceID uint32) (state.E2EClaim, error)
	E2ECreateLinkRequest(ctx context.Context, link state.E2ELinkRequest, maxPending int, now time.Time) error
	E2ELinkRequests(ctx context.Context, screenName state.IdentScreenName, now time.Time) ([]state.E2ELinkRequest, error)
	E2ELinkRequest(ctx context.Context, screenName state.IdentScreenName, id string, now time.Time) (*state.E2ELinkRequest, error)
	E2EReplyLinkRequest(ctx context.Context, screenName state.IdentScreenName, id string, reply []byte, now time.Time) error
	E2EDeleteLinkRequest(ctx context.Context, screenName state.IdentScreenName, id string) error
	E2EKTState(ctx context.Context) (int64, tlog.Hash, error)
	E2EKTEntries(ctx context.Context, start, count int64) ([][]byte, error)
	E2EKTSigningKey(ctx context.Context) (ed25519.PrivateKey, error)
	E2EKTRoot(ctx context.Context, size int64) (tlog.Hash, error)
	E2EKTSetCosignature(ctx context.Context, c state.E2EKTCosignature) error
	E2EKTCosignatures(ctx context.Context) ([]state.E2EKTCosignature, error)
}

// CookieBaker issues and checks the signed tokens (state.HMACCookieBaker).
type CookieBaker interface {
	Issue(data []byte, ttl time.Duration) ([]byte, error)
	Crack(data []byte) ([]byte, time.Time, error)
}

// SessionRetriever finds an account's session, also while it is still
// signing on (state.InMemorySessionManager).
type SessionRetriever interface {
	RetrieveSessionSigningOn(screenName state.IdentScreenName) *state.Session
}
