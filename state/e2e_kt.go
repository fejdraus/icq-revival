package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// The key transparency log of the E2E key directory: an append-only RFC 6962
// Merkle tree with one leaf per change, written in the same transaction as
// the change. docs/e2e/KEY-TRANSPARENCY.md has the leaf format and how the
// clients check it.

// E2EKTContext opens every leaf, so a leaf can never be mistaken for one of
// the directory's signed messages.
const E2EKTContext = "OSCAR-E2E-KT-v1"

// Kinds of log leaf.
const (
	// E2EKTAccount sets the account key (change publish, rotate or reset).
	E2EKTAccount = "account"
	// E2EKTDevice adds a device.
	E2EKTDevice = "device"
	// E2EKTResign gives a device a new account signature.
	E2EKTResign = "resign"
	// E2EKTRevoke revokes a device.
	E2EKTRevoke = "revoke"
	// E2EKTDelete deletes the account, its key and devices with it.
	E2EKTDelete = "delete"
)

// E2EKTMaxEntries is the most leaves one read returns.
const E2EKTMaxEntries = 1000

const (
	e2eKTMetaGenesis = "genesis"
	e2eKTMetaSeed    = "signing-seed"
)

// E2EKTLeaf builds a log leaf: the context, the kind, the screen name, the
// time (Unix seconds, 8 bytes big endian) and the kind's own fields, each as a
// big-endian u16 length and the bytes.
func E2EKTLeaf(kind string, screenName IdentScreenName, at time.Time, fields ...[]byte) []byte {
	var b bytes.Buffer
	b.WriteString(E2EKTContext)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(at.Unix()))
	for _, f := range append([][]byte{[]byte(kind), []byte(screenName.String()), ts[:]}, fields...) {
		var n [2]byte
		binary.BigEndian.PutUint16(n[:], uint16(len(f)))
		b.Write(n[:])
		b.Write(f)
	}
	return b.Bytes()
}

func e2eKTDeviceID(id uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], id)
	return b[:]
}

// e2eKTAccountLeaf is the leaf of an account key change.
func e2eKTAccountLeaf(screenName IdentScreenName, change string, key []byte, at time.Time) []byte {
	return E2EKTLeaf(E2EKTAccount, screenName, at, []byte(change), key)
}

// e2eKTDeviceLeaf is the leaf of a device added.
func e2eKTDeviceLeaf(screenName IdentScreenName, d E2EDevice, at time.Time) []byte {
	return E2EKTLeaf(E2EKTDevice, screenName, at, e2eKTDeviceID(d.DeviceID), d.Curve25519Key, d.Ed25519Key, d.AccountSignature)
}

// e2eKTResignLeaf is the leaf of a device's new account signature.
func e2eKTResignLeaf(screenName IdentScreenName, deviceID uint32, sig []byte, at time.Time) []byte {
	return E2EKTLeaf(E2EKTResign, screenName, at, e2eKTDeviceID(deviceID), sig)
}

// e2eKTRevokeLeaf is the leaf of a device revoked.
func e2eKTRevokeLeaf(screenName IdentScreenName, deviceID uint32, at time.Time) []byte {
	return E2EKTLeaf(E2EKTRevoke, screenName, at, e2eKTDeviceID(deviceID))
}

// E2EKTDeleteAccount records, in the key log, that the account is deleted,
// if it has keys. Called inside the transaction that deletes the user.
func e2eKTDeleteAccount(ctx context.Context, q e2eQuerier, screenName IdentScreenName, now time.Time) error {
	acc, err := e2eAccount(ctx, q, screenName)
	if err != nil || acc == nil {
		return err
	}
	return e2eKTAppendLeaf(ctx, q, E2EKTLeaf(E2EKTDelete, screenName, now), now)
}

// E2EKTRoot returns the root hash of the log's first size leaves; size must
// not be more than the log has.
func (f SQLiteUserStore) E2EKTRoot(ctx context.Context, size int64) (tlog.Hash, error) {
	var root tlog.Hash
	err := f.e2eTx(ctx, func(tx *sql.Tx) error {
		n, err := e2eKTSize(ctx, tx)
		if err != nil {
			return err
		}
		if size < 1 || size > n {
			return fmt.Errorf("e2e log has %d leaves, not %d", n, size)
		}
		root, err = tlog.TreeHash(size, e2eKTHashReader(ctx, tx))
		return err
	})
	return root, err
}

// E2EKTCosignature is an auditor's latest signature over one of the log's
// checkpoints (c2sp.org/tlog-cosignature).
type E2EKTCosignature struct {
	Auditor string
	Size    int64
	Time    int64
	// Line is the signature line as the auditor sent it.
	Line string
}

// E2EKTSetCosignature keeps an auditor's cosignature, unless the one kept
// already is for a larger log or later.
func (f SQLiteUserStore) E2EKTSetCosignature(ctx context.Context, c E2EKTCosignature) error {
	_, err := f.db.ExecContext(ctx, `
		INSERT INTO e2e_kt_cosignature (auditor, size, time, line) VALUES (?, ?, ?, ?)
		ON CONFLICT (auditor) DO UPDATE SET size = excluded.size, time = excluded.time, line = excluded.line
		WHERE excluded.size > e2e_kt_cosignature.size
		   OR (excluded.size = e2e_kt_cosignature.size AND excluded.time > e2e_kt_cosignature.time)`,
		c.Auditor, c.Size, c.Time, c.Line)
	return err
}

// E2EKTCosignatures returns every auditor's latest cosignature.
func (f SQLiteUserStore) E2EKTCosignatures(ctx context.Context) ([]E2EKTCosignature, error) {
	rows, err := f.db.QueryContext(ctx, `SELECT auditor, size, time, line FROM e2e_kt_cosignature ORDER BY auditor`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []E2EKTCosignature
	for rows.Next() {
		var c E2EKTCosignature
		if err := rows.Scan(&c.Auditor, &c.Size, &c.Time, &c.Line); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// E2EKTState returns the log's size and root hash.
func (f SQLiteUserStore) E2EKTState(ctx context.Context) (int64, tlog.Hash, error) {
	var size int64
	var root tlog.Hash
	err := f.e2eTx(ctx, func(tx *sql.Tx) error {
		var err error
		if size, err = e2eKTSize(ctx, tx); err != nil || size == 0 {
			return err
		}
		root, err = tlog.TreeHash(size, e2eKTHashReader(ctx, tx))
		return err
	})
	return size, root, err
}

// E2EKTEntries returns up to count leaves from index start, fewer at the end
// of the log, and at most E2EKTMaxEntries.
func (f SQLiteUserStore) E2EKTEntries(ctx context.Context, start, count int64) ([][]byte, error) {
	if count > E2EKTMaxEntries {
		count = E2EKTMaxEntries
	}
	var leaves [][]byte
	err := f.e2eTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT leaf FROM e2e_kt_leaf WHERE idx >= ? ORDER BY idx LIMIT ?`, start, count)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var leaf []byte
			if err := rows.Scan(&leaf); err != nil {
				return err
			}
			leaves = append(leaves, leaf)
		}
		return rows.Err()
	})
	return leaves, err
}

// E2EKTSigningKey returns the log's Ed25519 key, made on the first call and
// kept in the database, so a backup of the database carries it.
func (f SQLiteUserStore) E2EKTSigningKey(ctx context.Context) (ed25519.PrivateKey, error) {
	var seed []byte
	err := f.e2eTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT value FROM e2e_kt_meta WHERE name = ?`, e2eKTMetaSeed).Scan(&seed)
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO e2e_kt_meta (name, value) VALUES (?, ?)`, e2eKTMetaSeed, seed)
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("e2e log signing key: %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// e2eKTAppendLeaf appends a leaf to the log. Called inside e2eTx, which has
// written the genesis already.
func e2eKTAppendLeaf(ctx context.Context, q e2eQuerier, leaf []byte, now time.Time) error {
	n, err := e2eKTSize(ctx, q)
	if err != nil {
		return err
	}
	hashes, err := tlog.StoredHashes(n, leaf, e2eKTHashReader(ctx, q))
	if err != nil {
		return err
	}
	if _, err := q.ExecContext(ctx,
		`INSERT INTO e2e_kt_leaf (idx, leaf, createdAt) VALUES (?, ?, ?)`, n, leaf, now.Unix()); err != nil {
		return err
	}
	base := tlog.StoredHashIndex(0, n)
	for i, h := range hashes {
		if _, err := q.ExecContext(ctx,
			`INSERT INTO e2e_kt_hash (idx, hash) VALUES (?, ?)`, base+int64(i), h[:]); err != nil {
			return err
		}
	}
	return nil
}

// e2eKTGenesis writes the directory as it was before the log into it, once,
// at the start of the first transaction after the log came in:
// one leaf per account key and one per active device. Revoked devices and
// earlier keys are not replayed; clients only ever saw them as gone.
func e2eKTGenesis(ctx context.Context, q e2eQuerier, now time.Time) error {
	var done []byte
	err := q.QueryRowContext(ctx, `SELECT value FROM e2e_kt_meta WHERE name = ?`, e2eKTMetaGenesis).Scan(&done)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Marked first, so the appends below do not come back here.
	if _, err := q.ExecContext(ctx,
		`INSERT INTO e2e_kt_meta (name, value) VALUES (?, ?)`, e2eKTMetaGenesis, []byte(now.UTC().Format(time.RFC3339))); err != nil {
		return err
	}
	if n, err := e2eKTSize(ctx, q); err != nil || n > 0 {
		return err
	}

	type account struct {
		sn  IdentScreenName
		key []byte
		at  time.Time
	}
	rows, err := q.QueryContext(ctx, `SELECT identScreenName, accountKey, updatedAt FROM e2e_account ORDER BY identScreenName`)
	if err != nil {
		return err
	}
	var accounts []account
	for rows.Next() {
		var sn string
		var a account
		var at int64
		if err := rows.Scan(&sn, &a.key, &at); err != nil {
			rows.Close()
			return err
		}
		a.sn, a.at = NewIdentScreenName(sn), time.Unix(at, 0)
		accounts = append(accounts, a)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, a := range accounts {
		if err := e2eKTAppendLeaf(ctx, q, e2eKTAccountLeaf(a.sn, E2EKeyPublished, a.key, a.at), now); err != nil {
			return err
		}
		devices, err := e2eDevices(ctx, q, a.sn)
		if err != nil {
			return err
		}
		for _, d := range devices {
			if d.Revoked() {
				continue
			}
			if err := e2eKTAppendLeaf(ctx, q, e2eKTDeviceLeaf(a.sn, d, d.CreatedAt), now); err != nil {
				return err
			}
		}
	}
	return nil
}

func e2eKTSize(ctx context.Context, q e2eQuerier) (int64, error) {
	var n int64
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM e2e_kt_leaf`).Scan(&n)
	return n, err
}

// e2eKTHashReader reads the tree's stored hashes.
func e2eKTHashReader(ctx context.Context, q e2eQuerier) tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			var b []byte
			if err := q.QueryRowContext(ctx, `SELECT hash FROM e2e_kt_hash WHERE idx = ?`, idx).Scan(&b); err != nil {
				return nil, fmt.Errorf("e2e log hash %d: %w", idx, err)
			}
			if len(b) != tlog.HashSize {
				return nil, fmt.Errorf("e2e log hash %d: %d bytes", idx, len(b))
			}
			copy(out[i][:], b)
		}
		return out, nil
	})
}
