package state

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newE2ETestStore returns a store in its own database file with the users
// alice and bob, closed and removed when the test ends.
func newE2ETestStore(t *testing.T) *SQLiteUserStore {
	t.Helper()
	f, err := NewSQLiteUserStore(filepath.Join(t.TempDir(), "e2e_test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	for _, sn := range []string{"alice", "bob"} {
		require.NoError(t, f.InsertUser(context.Background(), User{
			IdentScreenName:   NewIdentScreenName(sn),
			DisplayScreenName: DisplayScreenName(sn),
		}))
	}
	return f
}

func e2eTestDevice(id uint32, seed byte) E2EDevice {
	return E2EDevice{
		DeviceID:         id,
		Curve25519Key:    bytes32(seed),
		Ed25519Key:       bytes32(seed + 1),
		AccountSignature: []byte{seed, seed},
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

var (
	e2eAlice = NewIdentScreenName("alice")
	e2eT0    = time.Unix(1_700_000_000, 0)
)

func TestSQLiteUserStore_E2EPublishAccountKey(t *testing.T) {
	cases := []struct {
		name    string
		first   []byte
		second  []byte
		wantErr error
		wantKey []byte
		wantLog int
	}{
		{name: "first key is stored", first: bytes32(1), wantKey: bytes32(1), wantLog: 1},
		{name: "same key again is a no-op", first: bytes32(1), second: bytes32(1), wantKey: bytes32(1), wantLog: 1},
		{name: "other key is refused", first: bytes32(1), second: bytes32(2), wantErr: ErrE2EAccountExists, wantKey: bytes32(1), wantLog: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := newE2ETestStore(t)
			require.NoError(t, f.E2EPublishAccountKey(ctx, e2eAlice, tc.first, e2eT0))
			if tc.second != nil {
				assert.ErrorIs(t, f.E2EPublishAccountKey(ctx, e2eAlice, tc.second, e2eT0.Add(time.Minute)), tc.wantErr)
			}
			acc, err := f.E2EAccount(ctx, e2eAlice)
			require.NoError(t, err)
			require.NotNil(t, acc)
			assert.Equal(t, tc.wantKey, acc.Key)
			assert.Equal(t, e2eT0, acc.CreatedAt)

			hist, err := f.E2EAccountKeyHistory(ctx, e2eAlice)
			require.NoError(t, err)
			assert.Len(t, hist, tc.wantLog)
			assert.Equal(t, E2EKeyPublished, hist[0].Kind)
			assert.Nil(t, hist[0].OldKey)
		})
	}

	t.Run("no key yet", func(t *testing.T) {
		f := newE2ETestStore(t)
		acc, err := f.E2EAccount(context.Background(), e2eAlice)
		assert.NoError(t, err)
		assert.Nil(t, acc)
	})
}

func TestSQLiteUserStore_E2ERotateAccountKey(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) *SQLiteUserStore {
		f := newE2ETestStore(t)
		require.NoError(t, f.E2EPublishAccountKey(ctx, e2eAlice, bytes32(1), e2eT0))
		for _, d := range []E2EDevice{e2eTestDevice(10, 10), e2eTestDevice(20, 20)} {
			_, err := f.E2EPutDevice(ctx, e2eAlice, bytes32(1), d, 10, e2eT0)
			require.NoError(t, err)
		}
		_, err := f.E2EAddOneTimeKeys(ctx, e2eAlice, 20, []E2ESignedKey{{KeyID: "a", PublicKey: bytes32(5), Signature: []byte{5}}}, 10, e2eT0)
		require.NoError(t, err)
		return f
	}

	cases := []struct {
		name        string
		oldKey      []byte
		resigned    []E2EDeviceSignature
		wantErr     error
		wantKey     []byte
		wantRevoked map[uint32]bool
	}{
		{
			name:        "listed device kept with new signature, the other revoked",
			oldKey:      bytes32(1),
			resigned:    []E2EDeviceSignature{{DeviceID: 10, AccountSignature: []byte{9, 9}}},
			wantKey:     bytes32(2),
			wantRevoked: map[uint32]bool{10: false, 20: true},
		},
		{
			name:        "stale old key is refused",
			oldKey:      bytes32(3),
			wantErr:     ErrE2EAccountKeyChanged,
			wantKey:     bytes32(1),
			wantRevoked: map[uint32]bool{10: false, 20: false},
		},
		{
			name:        "unknown device in the list rolls everything back",
			oldKey:      bytes32(1),
			resigned:    []E2EDeviceSignature{{DeviceID: 99, AccountSignature: []byte{9}}},
			wantErr:     ErrE2EDeviceNotFound,
			wantKey:     bytes32(1),
			wantRevoked: map[uint32]bool{10: false, 20: false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			err := f.E2ERotateAccountKey(ctx, e2eAlice, tc.oldKey, bytes32(2), make([]byte, 64), tc.resigned, e2eT0.Add(time.Hour))
			assert.ErrorIs(t, err, tc.wantErr)

			acc, err := f.E2EAccount(ctx, e2eAlice)
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, acc.Key)

			devices, err := f.E2EDevices(ctx, e2eAlice)
			require.NoError(t, err)
			for _, d := range devices {
				assert.Equal(t, tc.wantRevoked[d.DeviceID], d.Revoked(), "device %d", d.DeviceID)
			}
			if tc.wantErr == nil {
				assert.Equal(t, []byte{9, 9}, devices[0].AccountSignature)
				count, _, err := f.E2EKeyStatus(ctx, e2eAlice, 20)
				require.NoError(t, err)
				assert.Zero(t, count, "a revoked device's keys go")

				hist, err := f.E2EAccountKeyHistory(ctx, e2eAlice)
				require.NoError(t, err)
				require.Len(t, hist, 2)
				assert.Equal(t, E2EKeyRotated, hist[1].Kind)
				assert.Equal(t, bytes32(1), hist[1].OldKey)
				assert.Equal(t, bytes32(2), hist[1].NewKey)
			}
		})
	}
}

func TestSQLiteUserStore_E2EResetAccountKey(t *testing.T) {
	ctx := context.Background()
	f := newE2ETestStore(t)
	require.NoError(t, f.E2EPublishAccountKey(ctx, e2eAlice, bytes32(1), e2eT0))
	_, err := f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(10, 10), 10, e2eT0)
	require.NoError(t, err)

	assert.ErrorIs(t, f.E2EResetAccountKey(ctx, e2eAlice, bytes32(1), bytes32(2), e2eT0), ErrE2EActiveDevices)

	require.NoError(t, f.E2ERevokeDevice(ctx, e2eAlice, 10, E2ERecovery("test"), e2eT0))
	assert.ErrorIs(t, f.E2EResetAccountKey(ctx, e2eAlice, bytes32(7), bytes32(2), e2eT0), ErrE2EAccountKeyChanged)
	require.NoError(t, f.E2EResetAccountKey(ctx, e2eAlice, bytes32(1), bytes32(2), e2eT0))

	hist, err := f.E2EAccountKeyHistory(ctx, e2eAlice)
	require.NoError(t, err)
	require.Len(t, hist, 2)
	assert.Equal(t, E2EKeyReset, hist[1].Kind)
}

func TestSQLiteUserStore_E2EPutDevice(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		accountKey  []byte
		dev         E2EDevice
		maxDevices  int
		revokeFirst bool
		wantCreated bool
		wantErr     error
	}{
		{name: "new device", accountKey: bytes32(1), dev: e2eTestDevice(2, 2), maxDevices: 10, wantCreated: true},
		{name: "same keys refresh", accountKey: bytes32(1), dev: e2eTestDevice(1, 1), maxDevices: 10},
		{name: "same id other keys", accountKey: bytes32(1), dev: e2eTestDevice(1, 7), maxDevices: 10, wantErr: ErrE2EDeviceConflict},
		{name: "revoked id is not reused", accountKey: bytes32(1), dev: e2eTestDevice(1, 1), maxDevices: 10, revokeFirst: true, wantErr: ErrE2EDeviceRevoked},
		{name: "device cap", accountKey: bytes32(1), dev: e2eTestDevice(2, 2), maxDevices: 1, wantErr: ErrE2ETooManyDevices},
		{name: "revoked devices do not count to the cap", accountKey: bytes32(1), dev: e2eTestDevice(2, 2), maxDevices: 1, revokeFirst: true, wantCreated: true},
		{name: "signed by an old key", accountKey: bytes32(9), dev: e2eTestDevice(2, 2), maxDevices: 10, wantErr: ErrE2EAccountKeyChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newE2ETestStore(t)
			require.NoError(t, f.E2EPublishAccountKey(ctx, e2eAlice, bytes32(1), e2eT0))
			_, err := f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(1, 1), 10, e2eT0)
			require.NoError(t, err)
			if tc.revokeFirst {
				require.NoError(t, f.E2ERevokeDevice(ctx, e2eAlice, 1, E2ERecovery("test"), e2eT0))
			}

			later := e2eT0.Add(time.Minute)
			created, err := f.E2EPutDevice(ctx, e2eAlice, tc.accountKey, tc.dev, tc.maxDevices, later)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.wantCreated, created)
			if tc.wantErr == nil {
				got, err := f.E2EDevice(ctx, e2eAlice, tc.dev.DeviceID)
				require.NoError(t, err)
				assert.Equal(t, later, got.LastSeenAt)
				assert.Equal(t, tc.dev.Curve25519Key, got.Curve25519Key)
			}
		})
	}

	t.Run("no account key", func(t *testing.T) {
		f := newE2ETestStore(t)
		_, err := f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(1, 1), 10, e2eT0)
		assert.ErrorIs(t, err, ErrE2EAccountNotFound)
	})
}

func TestSQLiteUserStore_E2EOneTimeKeys(t *testing.T) {
	ctx := context.Background()
	f := newE2ETestStore(t)
	require.NoError(t, f.E2EPublishAccountKey(ctx, e2eAlice, bytes32(1), e2eT0))
	_, err := f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(1, 1), 10, e2eT0)
	require.NoError(t, err)

	key := func(id string) E2ESignedKey {
		return E2ESignedKey{KeyID: id, PublicKey: bytes32(id[0]), Signature: []byte(id)}
	}

	count, err := f.E2EAddOneTimeKeys(ctx, e2eAlice, 1, []E2ESignedKey{key("a"), key("b")}, 3, e2eT0)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	count, err = f.E2EAddOneTimeKeys(ctx, e2eAlice, 1, []E2ESignedKey{key("b")}, 3, e2eT0)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "a retried key is skipped")

	_, err = f.E2EAddOneTimeKeys(ctx, e2eAlice, 1, []E2ESignedKey{key("c"), key("d")}, 3, e2eT0)
	assert.ErrorIs(t, err, ErrE2EKeyPoolFull)
	count, _, err = f.E2EKeyStatus(ctx, e2eAlice, 1)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "an overfilling upload adds nothing")

	_, err = f.E2EAddOneTimeKeys(ctx, e2eAlice, 99, []E2ESignedKey{key("x")}, 3, e2eT0)
	assert.ErrorIs(t, err, ErrE2EDeviceNotFound)

	require.NoError(t, f.E2ESetFallbackKey(ctx, e2eAlice, 1, key("f"), e2eT0))

	// Two claims take the two one-time keys, the third falls back.
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		c, err := f.E2EClaimKey(ctx, e2eAlice, 1)
		require.NoError(t, err)
		require.NotNil(t, c.OneTimeKey)
		assert.Nil(t, c.FallbackKey)
		assert.False(t, seen[c.OneTimeKey.KeyID], "a key is handed out once")
		seen[c.OneTimeKey.KeyID] = true
		assert.Equal(t, uint32(1), c.Device.DeviceID)
	}
	c, err := f.E2EClaimKey(ctx, e2eAlice, 1)
	require.NoError(t, err)
	assert.Nil(t, c.OneTimeKey)
	require.NotNil(t, c.FallbackKey)
	assert.Equal(t, "f", c.FallbackKey.KeyID)

	_, err = f.E2EClaimKey(ctx, e2eAlice, 99)
	assert.ErrorIs(t, err, ErrE2EDeviceNotFound)

	require.NoError(t, f.E2ERevokeDevice(ctx, e2eAlice, 1, E2ERecovery("test"), e2eT0))
	_, err = f.E2EClaimKey(ctx, e2eAlice, 1)
	assert.ErrorIs(t, err, ErrE2EDeviceRevoked)
	assert.ErrorIs(t, f.E2ESetFallbackKey(ctx, e2eAlice, 1, key("g"), e2eT0), ErrE2EDeviceRevoked)
	_, hasFallback, err := f.E2EKeyStatus(ctx, e2eAlice, 1)
	require.NoError(t, err)
	assert.False(t, hasFallback)
	assert.NoError(t, f.E2ERevokeDevice(ctx, e2eAlice, 1, E2ERecovery("test"), e2eT0), "revoking twice is a no-op")
	assert.ErrorIs(t, f.E2ERevokeDevice(ctx, e2eAlice, 99, E2ERecovery("test"), e2eT0), ErrE2EDeviceNotFound)
}

func TestSQLiteUserStore_E2ELinkRequests(t *testing.T) {
	ctx := context.Background()
	f := newE2ETestStore(t)
	bob := NewIdentScreenName("bob")

	link := func(id string, created time.Time) E2ELinkRequest {
		return E2ELinkRequest{
			ID: id, ScreenName: e2eAlice, EphemeralKey: bytes32(3), RequestBlob: []byte("hello"),
			CreatedAt: created, ExpiresAt: created.Add(10 * time.Minute),
		}
	}

	require.NoError(t, f.E2ECreateLinkRequest(ctx, link("one", e2eT0), 2, e2eT0))
	require.NoError(t, f.E2ECreateLinkRequest(ctx, link("two", e2eT0), 2, e2eT0))
	assert.ErrorIs(t, f.E2ECreateLinkRequest(ctx, link("three", e2eT0), 2, e2eT0), ErrE2ETooManyLinks)

	// Once the first two expire they make room.
	later := e2eT0.Add(11 * time.Minute)
	require.NoError(t, f.E2ECreateLinkRequest(ctx, link("three", later), 2, later))
	links, err := f.E2ELinkRequests(ctx, e2eAlice, later)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, "three", links[0].ID)
	assert.Nil(t, links[0].ReplyBlob)

	got, err := f.E2ELinkRequest(ctx, bob, "three", later)
	require.NoError(t, err)
	assert.Nil(t, got, "another account does not see it")
	assert.ErrorIs(t, f.E2EReplyLinkRequest(ctx, bob, "three", []byte("x"), later), ErrE2ELinkNotFound)

	require.NoError(t, f.E2EReplyLinkRequest(ctx, e2eAlice, "three", []byte("answer"), later))
	assert.ErrorIs(t, f.E2EReplyLinkRequest(ctx, e2eAlice, "three", []byte("again"), later), ErrE2ELinkReplied)

	got, err = f.E2ELinkRequest(ctx, e2eAlice, "three", later)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []byte("answer"), got.ReplyBlob)
	assert.Equal(t, later, got.RepliedAt)
	assert.Equal(t, bytes32(3), got.EphemeralKey)

	got, err = f.E2ELinkRequest(ctx, e2eAlice, "three", later.Add(time.Hour))
	require.NoError(t, err)
	assert.Nil(t, got, "expired")

	require.NoError(t, f.E2EDeleteLinkRequest(ctx, e2eAlice, "three"))
	assert.ErrorIs(t, f.E2EDeleteLinkRequest(ctx, e2eAlice, "three"), ErrE2ELinkNotFound)
}
