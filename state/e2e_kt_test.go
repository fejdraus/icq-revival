package state

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/sumdb/tlog"
)

// ktFields splits a log leaf into its fields after the context.
func ktFields(t *testing.T, leaf []byte) [][]byte {
	t.Helper()
	require.True(t, len(leaf) >= len(E2EKTContext) && string(leaf[:len(E2EKTContext)]) == E2EKTContext)
	rest := leaf[len(E2EKTContext):]
	var out [][]byte
	for len(rest) > 0 {
		require.GreaterOrEqual(t, len(rest), 2)
		n := int(binary.BigEndian.Uint16(rest))
		require.GreaterOrEqual(t, len(rest), 2+n)
		out = append(out, rest[2:2+n])
		rest = rest[2+n:]
	}
	return out
}

// ktKinds returns "kind screenname" of every leaf in the log.
func ktKinds(t *testing.T, f *SQLiteUserStore) []string {
	t.Helper()
	leaves, err := f.E2EKTEntries(context.Background(), 0, E2EKTMaxEntries)
	require.NoError(t, err)
	var out []string
	for _, l := range leaves {
		fs := ktFields(t, l)
		require.GreaterOrEqual(t, len(fs), 3)
		out = append(out, string(fs[0])+" "+string(fs[1]))
	}
	return out
}

// rfc6962Root computes the Merkle tree hash of the leaves the slow way, as
// RFC 6962 section 2.1 defines it, independently of tlog.
func rfc6962Root(leaves [][]byte) tlog.Hash {
	if len(leaves) == 1 {
		return sha256.Sum256(append([]byte{0}, leaves[0]...))
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	l, r := rfc6962Root(leaves[:k]), rfc6962Root(leaves[k:])
	return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
}

func ktCheckRoot(t *testing.T, f *SQLiteUserStore) int64 {
	t.Helper()
	ctx := context.Background()
	size, root, err := f.E2EKTState(ctx)
	require.NoError(t, err)
	leaves, err := f.E2EKTEntries(ctx, 0, E2EKTMaxEntries)
	require.NoError(t, err)
	require.Len(t, leaves, int(size))
	if size > 0 {
		assert.Equal(t, rfc6962Root(leaves), root)
	}
	return size
}

func TestSQLiteUserStore_E2EKT_RecordsEveryChange(t *testing.T) {
	ctx := context.Background()
	f := newE2ETestStore(t)

	require.NoError(t, f.E2EPublishAccountKey(ctx, e2eAlice, bytes32(1), e2eT0))
	// Refused changes leave no trace.
	assert.ErrorIs(t, f.E2EPublishAccountKey(ctx, e2eAlice, bytes32(2), e2eT0), ErrE2EAccountExists)
	_, err := f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(1, 10), 10, e2eT0)
	require.NoError(t, err)
	_, err = f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(2, 20), 10, e2eT0)
	require.NoError(t, err)
	// The same device and signature again: nothing new.
	_, err = f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(1, 10), 10, e2eT0)
	require.NoError(t, err)
	_, err = f.E2EPutDevice(ctx, e2eAlice, bytes32(9), e2eTestDevice(3, 30), 10, e2eT0)
	assert.ErrorIs(t, err, ErrE2EAccountKeyChanged)

	require.NoError(t, f.E2ERotateAccountKey(ctx, e2eAlice, bytes32(1), bytes32(2), bytes32(8),
		[]E2EDeviceSignature{{DeviceID: 1, AccountSignature: []byte{7, 7}}}, e2eT0.Add(time.Hour)))
	require.NoError(t, f.E2ERevokeDevice(ctx, e2eAlice, 1, e2eT0.Add(2*time.Hour)))
	// Revoking a revoked device is a no-op.
	require.NoError(t, f.E2ERevokeDevice(ctx, e2eAlice, 1, e2eT0.Add(3*time.Hour)))
	require.NoError(t, f.E2EResetAccountKey(ctx, e2eAlice, bytes32(2), bytes32(3), e2eT0.Add(4*time.Hour)))

	assert.Equal(t, []string{
		"account alice", "device alice", "device alice",
		"account alice", "resign alice", "revoke alice",
		"revoke alice",
		"account alice",
	}, ktKinds(t, f))
	assert.EqualValues(t, 8, ktCheckRoot(t, f))

	leaves, err := f.E2EKTEntries(ctx, 0, E2EKTMaxEntries)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("rotate"), bytes32(2), bytes32(8)}, ktFields(t, leaves[3])[3:])
	assert.Equal(t, [][]byte{{0, 0, 0, 1}, {7, 7}}, ktFields(t, leaves[4])[3:])
	assert.Equal(t, [][]byte{{0, 0, 0, 2}}, ktFields(t, leaves[5])[3:])
	dev := e2eTestDevice(2, 20)
	assert.Equal(t, [][]byte{{0, 0, 0, 2}, dev.Curve25519Key, dev.Ed25519Key, dev.AccountSignature}, ktFields(t, leaves[2])[3:])

	// Reading a window.
	part, err := f.E2EKTEntries(ctx, 6, 5)
	require.NoError(t, err)
	assert.Equal(t, leaves[6:], part)
}

func TestSQLiteUserStore_E2EKT_Genesis(t *testing.T) {
	ctx := context.Background()
	f := newE2ETestStore(t)
	bob := NewIdentScreenName("bob")

	// A directory as it was before the log: written, then the log wiped.
	require.NoError(t, f.E2EPublishAccountKey(ctx, e2eAlice, bytes32(1), e2eT0))
	require.NoError(t, f.E2EPublishAccountKey(ctx, bob, bytes32(5), e2eT0))
	_, err := f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(1, 10), 10, e2eT0)
	require.NoError(t, err)
	_, err = f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(2, 20), 10, e2eT0)
	require.NoError(t, err)
	require.NoError(t, f.E2ERevokeDevice(ctx, e2eAlice, 2, e2eT0))
	for _, q := range []string{`DELETE FROM e2e_kt_leaf`, `DELETE FROM e2e_kt_hash`, `DELETE FROM e2e_kt_meta`} {
		_, err := f.db.ExecContext(ctx, q)
		require.NoError(t, err)
	}

	// The next change first replays the directory: both account keys and
	// alice's one active device, then the change.
	_, err = f.E2EPutDevice(ctx, bob, bytes32(5), e2eTestDevice(4, 40), 10, e2eT0)
	require.NoError(t, err)
	assert.Equal(t, []string{"account alice", "device alice", "account bob", "device bob"}, ktKinds(t, f))
	assert.EqualValues(t, 4, ktCheckRoot(t, f))

	// Once only.
	_, err = f.E2EPutDevice(ctx, bob, bytes32(5), e2eTestDevice(5, 50), 10, e2eT0)
	require.NoError(t, err)
	assert.Len(t, ktKinds(t, f), 5)
}

func TestSQLiteUserStore_E2EKT_EmptyLogAndKey(t *testing.T) {
	ctx := context.Background()
	f := newE2ETestStore(t)
	size, root, err := f.E2EKTState(ctx)
	require.NoError(t, err)
	assert.Zero(t, size)
	assert.Equal(t, tlog.Hash{}, root)

	k1, err := f.E2EKTSigningKey(ctx)
	require.NoError(t, err)
	k2, err := f.E2EKTSigningKey(ctx)
	require.NoError(t, err)
	assert.Equal(t, k1, k2)
}

func TestSQLiteUserStore_E2EKT_ManyLeaves(t *testing.T) {
	ctx := context.Background()
	f := newE2ETestStore(t)
	require.NoError(t, f.E2EPublishAccountKey(ctx, e2eAlice, bytes32(1), e2eT0))
	for i := uint32(1); i <= 40; i++ {
		_, err := f.E2EPutDevice(ctx, e2eAlice, bytes32(1), e2eTestDevice(i, byte(i*2)), 100, e2eT0)
		require.NoError(t, err)
		if i%3 == 0 {
			require.NoError(t, f.E2ERevokeDevice(ctx, e2eAlice, i, e2eT0))
		}
		ktCheckRoot(t, f)
	}
}
