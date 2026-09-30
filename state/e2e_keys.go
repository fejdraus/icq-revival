package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Errors reported by the end-to-end encryption key directory.
var (
	// ErrE2EAccountExists means the account already has a different account
	// key; replacing it takes a rotation or a reset.
	ErrE2EAccountExists = errors.New("e2e account key already published")
	// ErrE2EAccountNotFound means the account has not published an account key.
	ErrE2EAccountNotFound = errors.New("e2e account key not published")
	// ErrE2EAccountKeyChanged means the account key is no longer the one the
	// request was checked against: it changed in the meantime.
	ErrE2EAccountKeyChanged = errors.New("e2e account key changed")
	// ErrE2EActiveDevices means the account key cannot be reset while the
	// account still has devices that are not revoked.
	ErrE2EActiveDevices = errors.New("e2e account still has active devices")
	// ErrE2EDeviceConflict means the device id is taken by other keys.
	ErrE2EDeviceConflict = errors.New("e2e device id taken by other keys")
	// ErrE2EDeviceNotFound means the account has no such device.
	ErrE2EDeviceNotFound = errors.New("e2e device not found")
	// ErrE2EDeviceRevoked means the device was revoked; its id is not reused.
	ErrE2EDeviceRevoked = errors.New("e2e device revoked")
	// ErrE2ETooManyDevices means the account has as many active devices as
	// allowed.
	ErrE2ETooManyDevices = errors.New("too many e2e devices")
	// ErrE2EKeyPoolFull means the upload would take a device's one-time key
	// pool over its limit.
	ErrE2EKeyPoolFull = errors.New("e2e one-time key pool full")
	// ErrE2ELinkNotFound means the account has no such unexpired device-link
	// request.
	ErrE2ELinkNotFound = errors.New("e2e link request not found")
	// ErrE2ELinkReplied means the device-link request already has a reply.
	ErrE2ELinkReplied = errors.New("e2e link request already answered")
	// ErrE2ETooManyLinks means the account has as many pending device-link
	// requests as allowed.
	ErrE2ETooManyLinks = errors.New("too many pending e2e link requests")
)

// Kinds of account key change recorded in E2EAccountKeyChange.
const (
	// E2EKeyPublished is the account's first account key.
	E2EKeyPublished = "publish"
	// E2EKeyRotated is a new key vouched for by the previous one.
	E2EKeyRotated = "rotate"
	// E2EKeyReset is a new key without a proof from the previous one.
	E2EKeyReset = "reset"
)

// E2EAccount is an account's account public key (Ed25519), which signs the
// account's devices.
type E2EAccount struct {
	Key       []byte
	CreatedAt time.Time
	// UpdatedAt is when the current key was set.
	UpdatedAt time.Time
}

// E2EAccountKeyChange records one change of an account's key.
type E2EAccountKeyChange struct {
	ID   int64
	Kind string
	// OldKey is nil for the first key.
	OldKey    []byte
	NewKey    []byte
	ChangedAt time.Time
}

// E2EDevice is one of an account's devices: its Olm keys and the account
// key's signature over them.
type E2EDevice struct {
	DeviceID         uint32
	Curve25519Key    []byte
	Ed25519Key       []byte
	AccountSignature []byte
	CreatedAt        time.Time
	LastSeenAt       time.Time
	// RevokedAt is zero for an active device.
	RevokedAt time.Time
}

// Revoked reports whether the device was revoked.
func (d E2EDevice) Revoked() bool {
	return !d.RevokedAt.IsZero()
}

// E2EDeviceSignature is a new account signature for one of the account's
// devices, carried by an account key rotation.
type E2EDeviceSignature struct {
	DeviceID         uint32
	AccountSignature []byte
}

// E2ESignedKey is a device's fallback or one-time Curve25519 key and the
// device Ed25519 key's signature over it.
type E2ESignedKey struct {
	KeyID     string
	PublicKey []byte
	Signature []byte
	CreatedAt time.Time
}

// E2EClaim is what a sender gets to open a session with a device: the device,
// and one of its one-time keys or, when the pool is empty, its fallback key.
// Both keys are nil when the device has published neither.
type E2EClaim struct {
	Device      E2EDevice
	OneTimeKey  *E2ESignedKey
	FallbackKey *E2ESignedKey
}

// E2ELinkRequest is a device-link exchange: a new device's ephemeral key and
// optional request blob and, once one of the account's devices has approved
// it, the encrypted reply.
type E2ELinkRequest struct {
	ID           string
	ScreenName   IdentScreenName
	EphemeralKey []byte
	RequestBlob  []byte
	ReplyBlob    []byte
	CreatedAt    time.Time
	ExpiresAt    time.Time
	// RepliedAt is zero until the request is answered.
	RepliedAt time.Time
}

// E2EAccount returns the account's key, or nil if it has none.
func (f SQLiteUserStore) E2EAccount(ctx context.Context, screenName IdentScreenName) (*E2EAccount, error) {
	return e2eAccount(ctx, f.db, screenName)
}

// E2EPublishAccountKey stores the account's first account key. Publishing the
// key it already has is a no-op; a different one is ErrE2EAccountExists.
func (f SQLiteUserStore) E2EPublishAccountKey(ctx context.Context, screenName IdentScreenName, key []byte, now time.Time) error {
	return f.e2eTx(ctx, func(tx *sql.Tx) error {
		cur, err := e2eAccount(ctx, tx, screenName)
		if err != nil {
			return err
		}
		if cur != nil {
			if bytes.Equal(cur.Key, key) {
				return nil
			}
			return ErrE2EAccountExists
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO e2e_account (identScreenName, accountKey, createdAt, updatedAt) VALUES (?, ?, ?, ?)`,
			screenName.String(), key, now.Unix(), now.Unix()); err != nil {
			return err
		}
		return e2eRecordKeyChange(ctx, tx, screenName, E2EKeyPublished, nil, key, now)
	})
}

// E2ERotateAccountKey replaces the account key oldKey, whose proof the caller
// has checked, with newKey. The active devices in resigned stay, with the
// signatures by newKey they carry; every other active device is revoked,
// since only the old key vouches for it.
func (f SQLiteUserStore) E2ERotateAccountKey(ctx context.Context, screenName IdentScreenName, oldKey, newKey []byte, resigned []E2EDeviceSignature, now time.Time) error {
	return f.e2eTx(ctx, func(tx *sql.Tx) error {
		if err := e2eReplaceAccountKey(ctx, tx, screenName, oldKey, newKey, now); err != nil {
			return err
		}
		keep := make(map[uint32]bool, len(resigned))
		for _, d := range resigned {
			res, err := tx.ExecContext(ctx, `
				UPDATE e2e_device SET accountSignature = ?
				WHERE identScreenName = ? AND deviceID = ? AND revokedAt IS NULL`,
				d.AccountSignature, screenName.String(), d.DeviceID)
			if err := e2eOneRow(res, err, fmt.Errorf("device %d: %w", d.DeviceID, ErrE2EDeviceNotFound)); err != nil {
				return err
			}
			keep[d.DeviceID] = true
		}
		devices, err := e2eDevices(ctx, tx, screenName)
		if err != nil {
			return err
		}
		for _, d := range devices {
			if d.Revoked() || keep[d.DeviceID] {
				continue
			}
			if err := e2eRevokeDevice(ctx, tx, screenName, d.DeviceID, now); err != nil {
				return err
			}
		}
		return e2eRecordKeyChange(ctx, tx, screenName, E2EKeyRotated, oldKey, newKey, now)
	})
}

// E2EResetAccountKey replaces the account key oldKey with newKey without a
// proof from the old key. It is allowed only once every device of the account
// is revoked (ErrE2EActiveDevices otherwise), e.g. after all of them were
// lost; peers learn of it from the key history.
func (f SQLiteUserStore) E2EResetAccountKey(ctx context.Context, screenName IdentScreenName, oldKey, newKey []byte, now time.Time) error {
	return f.e2eTx(ctx, func(tx *sql.Tx) error {
		var active int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM e2e_device WHERE identScreenName = ? AND revokedAt IS NULL`,
			screenName.String()).Scan(&active); err != nil {
			return err
		}
		if active > 0 {
			return ErrE2EActiveDevices
		}
		if err := e2eReplaceAccountKey(ctx, tx, screenName, oldKey, newKey, now); err != nil {
			return err
		}
		return e2eRecordKeyChange(ctx, tx, screenName, E2EKeyReset, oldKey, newKey, now)
	})
}

// E2EAccountKeyHistory returns every account key change of the account,
// oldest first.
func (f SQLiteUserStore) E2EAccountKeyHistory(ctx context.Context, screenName IdentScreenName) ([]E2EAccountKeyChange, error) {
	rows, err := f.db.QueryContext(ctx, `
		SELECT id, kind, oldKey, newKey, changedAt
		FROM e2e_account_key_history WHERE identScreenName = ? ORDER BY id`, screenName.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var changes []E2EAccountKeyChange
	for rows.Next() {
		var c E2EAccountKeyChange
		var at int64
		if err := rows.Scan(&c.ID, &c.Kind, &c.OldKey, &c.NewKey, &at); err != nil {
			return nil, err
		}
		c.ChangedAt = time.Unix(at, 0)
		changes = append(changes, c)
	}
	return changes, rows.Err()
}

// E2EDevices returns the account's devices, revoked ones included, by device
// id.
func (f SQLiteUserStore) E2EDevices(ctx context.Context, screenName IdentScreenName) ([]E2EDevice, error) {
	return e2eDevices(ctx, f.db, screenName)
}

// E2EDevice returns one of the account's devices, or nil if there is no such
// device.
func (f SQLiteUserStore) E2EDevice(ctx context.Context, screenName IdentScreenName, deviceID uint32) (*E2EDevice, error) {
	return e2eDevice(ctx, f.db, screenName, deviceID)
}

// E2EPutDevice publishes a device signed by accountKey, which must still be
// the account's key. Publishing a device again with the same keys refreshes
// its signature and last-seen time; the same id with other keys is
// ErrE2EDeviceConflict, a revoked id is ErrE2EDeviceRevoked. An account holds
// at most maxDevices active devices. It reports whether the device is new.
func (f SQLiteUserStore) E2EPutDevice(ctx context.Context, screenName IdentScreenName, accountKey []byte, dev E2EDevice, maxDevices int, now time.Time) (bool, error) {
	var created bool
	err := f.e2eTx(ctx, func(tx *sql.Tx) error {
		if err := e2eCheckAccountKey(ctx, tx, screenName, accountKey); err != nil {
			return err
		}
		cur, err := e2eDevice(ctx, tx, screenName, dev.DeviceID)
		if err != nil {
			return err
		}
		if cur != nil {
			switch {
			case cur.Revoked():
				return ErrE2EDeviceRevoked
			case !bytes.Equal(cur.Curve25519Key, dev.Curve25519Key) || !bytes.Equal(cur.Ed25519Key, dev.Ed25519Key):
				return ErrE2EDeviceConflict
			}
			_, err := tx.ExecContext(ctx, `
				UPDATE e2e_device SET accountSignature = ?, lastSeenAt = ?
				WHERE identScreenName = ? AND deviceID = ?`,
				dev.AccountSignature, now.Unix(), screenName.String(), dev.DeviceID)
			return err
		}

		var active int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM e2e_device WHERE identScreenName = ? AND revokedAt IS NULL`,
			screenName.String()).Scan(&active); err != nil {
			return err
		}
		if active >= maxDevices {
			return ErrE2ETooManyDevices
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO e2e_device (identScreenName, deviceID, curve25519Key, ed25519Key, accountSignature, createdAt, lastSeenAt)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			screenName.String(), dev.DeviceID, dev.Curve25519Key, dev.Ed25519Key, dev.AccountSignature, now.Unix(), now.Unix()); err != nil {
			return err
		}
		created = true
		return nil
	})
	return created, err
}

// E2ERevokeDevice revokes a device and deletes its fallback and one-time keys.
// Revoking a revoked device is a no-op.
func (f SQLiteUserStore) E2ERevokeDevice(ctx context.Context, screenName IdentScreenName, deviceID uint32, now time.Time) error {
	return f.e2eTx(ctx, func(tx *sql.Tx) error {
		cur, err := e2eDevice(ctx, tx, screenName, deviceID)
		if err != nil {
			return err
		}
		if cur == nil {
			return ErrE2EDeviceNotFound
		}
		if cur.Revoked() {
			return nil
		}
		return e2eRevokeDevice(ctx, tx, screenName, deviceID, now)
	})
}

// E2ESetFallbackKey replaces the fallback key of an active device.
func (f SQLiteUserStore) E2ESetFallbackKey(ctx context.Context, screenName IdentScreenName, deviceID uint32, key E2ESignedKey, now time.Time) error {
	return f.e2eTx(ctx, func(tx *sql.Tx) error {
		if err := e2eTouchActiveDevice(ctx, tx, screenName, deviceID, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO e2e_fallback_key (identScreenName, deviceID, keyID, publicKey, signature, createdAt)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (identScreenName, deviceID) DO UPDATE SET
				keyID = excluded.keyID, publicKey = excluded.publicKey,
				signature = excluded.signature, createdAt = excluded.createdAt`,
			screenName.String(), deviceID, key.KeyID, key.PublicKey, key.Signature, now.Unix())
		return err
	})
}

// E2EAddOneTimeKeys adds keys to an active device's one-time key pool and
// returns how many keys the pool holds now. A key id already in the pool is
// skipped, so a retried upload is harmless. The pool holds at most maxPool
// keys; an upload that would overfill it adds nothing and is
// ErrE2EKeyPoolFull.
func (f SQLiteUserStore) E2EAddOneTimeKeys(ctx context.Context, screenName IdentScreenName, deviceID uint32, keys []E2ESignedKey, maxPool int, now time.Time) (int, error) {
	var count int
	err := f.e2eTx(ctx, func(tx *sql.Tx) error {
		if err := e2eTouchActiveDevice(ctx, tx, screenName, deviceID, now); err != nil {
			return err
		}
		for _, k := range keys {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO e2e_one_time_key (identScreenName, deviceID, keyID, publicKey, signature, createdAt)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (identScreenName, deviceID, keyID) DO NOTHING`,
				screenName.String(), deviceID, k.KeyID, k.PublicKey, k.Signature, now.Unix()); err != nil {
				return err
			}
		}
		var err error
		if count, err = e2eOneTimeKeyCount(ctx, tx, screenName, deviceID); err != nil {
			return err
		}
		if count > maxPool {
			return ErrE2EKeyPoolFull
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// E2EKeyStatus reports how many one-time keys the device has left and whether
// it has a fallback key.
func (f SQLiteUserStore) E2EKeyStatus(ctx context.Context, screenName IdentScreenName, deviceID uint32) (int, bool, error) {
	count, err := e2eOneTimeKeyCount(ctx, f.db, screenName, deviceID)
	if err != nil {
		return 0, false, err
	}
	fallback, err := e2eFallbackKey(ctx, f.db, screenName, deviceID)
	if err != nil {
		return 0, false, err
	}
	return count, fallback != nil, nil
}

// E2EClaimKey hands out an active device and one of its one-time keys, which
// is deleted from the pool in the same transaction so no other sender gets
// it. When the pool is empty the device comes with its fallback key instead.
func (f SQLiteUserStore) E2EClaimKey(ctx context.Context, screenName IdentScreenName, deviceID uint32) (E2EClaim, error) {
	var claim E2EClaim
	err := f.e2eTx(ctx, func(tx *sql.Tx) error {
		dev, err := e2eDevice(ctx, tx, screenName, deviceID)
		if err != nil {
			return err
		}
		if dev == nil {
			return ErrE2EDeviceNotFound
		}
		if dev.Revoked() {
			return ErrE2EDeviceRevoked
		}
		claim.Device = *dev

		var otk E2ESignedKey
		var at int64
		err = tx.QueryRowContext(ctx, `
			DELETE FROM e2e_one_time_key
			WHERE rowid = (SELECT rowid FROM e2e_one_time_key
			               WHERE identScreenName = ? AND deviceID = ?
			               ORDER BY createdAt, rowid LIMIT 1)
			RETURNING keyID, publicKey, signature, createdAt`,
			screenName.String(), deviceID).Scan(&otk.KeyID, &otk.PublicKey, &otk.Signature, &at)
		switch {
		case err == nil:
			otk.CreatedAt = time.Unix(at, 0)
			claim.OneTimeKey = &otk
			return nil
		case errors.Is(err, sql.ErrNoRows):
			claim.FallbackKey, err = e2eFallbackKey(ctx, tx, screenName, deviceID)
			return err
		default:
			return err
		}
	})
	if err != nil {
		return E2EClaim{}, err
	}
	return claim, nil
}

// E2ECreateLinkRequest stores a new device-link request. Expired requests of
// the account are dropped first; an account holds at most maxPending
// unexpired ones.
func (f SQLiteUserStore) E2ECreateLinkRequest(ctx context.Context, link E2ELinkRequest, maxPending int, now time.Time) error {
	return f.e2eTx(ctx, func(tx *sql.Tx) error {
		sn := link.ScreenName.String()
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM e2e_link_request WHERE identScreenName = ? AND expiresAt <= ?`, sn, now.Unix()); err != nil {
			return err
		}
		var pending int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM e2e_link_request WHERE identScreenName = ?`, sn).Scan(&pending); err != nil {
			return err
		}
		if pending >= maxPending {
			return ErrE2ETooManyLinks
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO e2e_link_request (id, identScreenName, ephemeralKey, requestBlob, createdAt, expiresAt)
			VALUES (?, ?, ?, ?, ?, ?)`,
			link.ID, sn, link.EphemeralKey, link.RequestBlob, link.CreatedAt.Unix(), link.ExpiresAt.Unix())
		return err
	})
}

// E2ELinkRequests returns the account's unexpired device-link requests,
// oldest first.
func (f SQLiteUserStore) E2ELinkRequests(ctx context.Context, screenName IdentScreenName, now time.Time) ([]E2ELinkRequest, error) {
	rows, err := f.db.QueryContext(ctx, `
		SELECT id, identScreenName, ephemeralKey, requestBlob, replyBlob, createdAt, expiresAt, repliedAt
		FROM e2e_link_request WHERE identScreenName = ? AND expiresAt > ?
		ORDER BY createdAt, id`, screenName.String(), now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []E2ELinkRequest
	for rows.Next() {
		l, err := scanE2ELink(rows)
		if err != nil {
			return nil, err
		}
		links = append(links, l)
	}
	return links, rows.Err()
}

// E2ELinkRequest returns one of the account's unexpired device-link requests,
// or nil if there is no such request.
func (f SQLiteUserStore) E2ELinkRequest(ctx context.Context, screenName IdentScreenName, id string, now time.Time) (*E2ELinkRequest, error) {
	row := f.db.QueryRowContext(ctx, `
		SELECT id, identScreenName, ephemeralKey, requestBlob, replyBlob, createdAt, expiresAt, repliedAt
		FROM e2e_link_request WHERE id = ? AND identScreenName = ? AND expiresAt > ?`,
		id, screenName.String(), now.Unix())
	l, err := scanE2ELink(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// E2EReplyLinkRequest stores the reply to one of the account's unexpired
// device-link requests. A request is answered once only.
func (f SQLiteUserStore) E2EReplyLinkRequest(ctx context.Context, screenName IdentScreenName, id string, reply []byte, now time.Time) error {
	return f.e2eTx(ctx, func(tx *sql.Tx) error {
		var replied bool
		err := tx.QueryRowContext(ctx, `
			SELECT replyBlob IS NOT NULL FROM e2e_link_request
			WHERE id = ? AND identScreenName = ? AND expiresAt > ?`,
			id, screenName.String(), now.Unix()).Scan(&replied)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrE2ELinkNotFound
		}
		if err != nil {
			return err
		}
		if replied {
			return ErrE2ELinkReplied
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE e2e_link_request SET replyBlob = ?, repliedAt = ? WHERE id = ?`,
			reply, now.Unix(), id)
		return err
	})
}

// E2EDeleteLinkRequest removes one of the account's device-link requests.
func (f SQLiteUserStore) E2EDeleteLinkRequest(ctx context.Context, screenName IdentScreenName, id string) error {
	res, err := f.db.ExecContext(ctx,
		`DELETE FROM e2e_link_request WHERE id = ? AND identScreenName = ?`, id, screenName.String())
	return e2eOneRow(res, err, ErrE2ELinkNotFound)
}

// e2eQuerier is what the helpers below need from either the database or a
// transaction.
type e2eQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// e2eRowScanner is a *sql.Row or *sql.Rows.
type e2eRowScanner interface {
	Scan(dest ...any) error
}

func (f SQLiteUserStore) e2eTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func e2eAccount(ctx context.Context, q e2eQuerier, screenName IdentScreenName) (*E2EAccount, error) {
	var a E2EAccount
	var created, updated int64
	err := q.QueryRowContext(ctx,
		`SELECT accountKey, createdAt, updatedAt FROM e2e_account WHERE identScreenName = ?`,
		screenName.String()).Scan(&a.Key, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt = time.Unix(created, 0)
	a.UpdatedAt = time.Unix(updated, 0)
	return &a, nil
}

// e2eCheckAccountKey reports whether key is still the account's key.
func e2eCheckAccountKey(ctx context.Context, q e2eQuerier, screenName IdentScreenName, key []byte) error {
	cur, err := e2eAccount(ctx, q, screenName)
	if err != nil {
		return err
	}
	if cur == nil {
		return ErrE2EAccountNotFound
	}
	if !bytes.Equal(cur.Key, key) {
		return ErrE2EAccountKeyChanged
	}
	return nil
}

func e2eReplaceAccountKey(ctx context.Context, q e2eQuerier, screenName IdentScreenName, oldKey, newKey []byte, now time.Time) error {
	if err := e2eCheckAccountKey(ctx, q, screenName, oldKey); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx,
		`UPDATE e2e_account SET accountKey = ?, updatedAt = ? WHERE identScreenName = ?`,
		newKey, now.Unix(), screenName.String())
	return err
}

func e2eRecordKeyChange(ctx context.Context, q e2eQuerier, screenName IdentScreenName, kind string, oldKey, newKey []byte, now time.Time) error {
	_, err := q.ExecContext(ctx, `
		INSERT INTO e2e_account_key_history (identScreenName, kind, oldKey, newKey, changedAt)
		VALUES (?, ?, ?, ?, ?)`,
		screenName.String(), kind, oldKey, newKey, now.Unix())
	return err
}

const e2eDeviceColumns = `deviceID, curve25519Key, ed25519Key, accountSignature, createdAt, lastSeenAt, revokedAt`

func e2eDevices(ctx context.Context, q e2eQuerier, screenName IdentScreenName) ([]E2EDevice, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+e2eDeviceColumns+` FROM e2e_device WHERE identScreenName = ? ORDER BY deviceID`,
		screenName.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []E2EDevice
	for rows.Next() {
		d, err := scanE2EDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func e2eDevice(ctx context.Context, q e2eQuerier, screenName IdentScreenName, deviceID uint32) (*E2EDevice, error) {
	row := q.QueryRowContext(ctx,
		`SELECT `+e2eDeviceColumns+` FROM e2e_device WHERE identScreenName = ? AND deviceID = ?`,
		screenName.String(), deviceID)
	d, err := scanE2EDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func scanE2EDevice(row e2eRowScanner) (E2EDevice, error) {
	var d E2EDevice
	var created, seen int64
	var revoked sql.NullInt64
	if err := row.Scan(&d.DeviceID, &d.Curve25519Key, &d.Ed25519Key, &d.AccountSignature, &created, &seen, &revoked); err != nil {
		return d, err
	}
	d.CreatedAt = time.Unix(created, 0)
	d.LastSeenAt = time.Unix(seen, 0)
	if revoked.Valid {
		d.RevokedAt = time.Unix(revoked.Int64, 0)
	}
	return d, nil
}

func e2eRevokeDevice(ctx context.Context, q e2eQuerier, screenName IdentScreenName, deviceID uint32, now time.Time) error {
	sn := screenName.String()
	if _, err := q.ExecContext(ctx,
		`UPDATE e2e_device SET revokedAt = ? WHERE identScreenName = ? AND deviceID = ?`,
		now.Unix(), sn, deviceID); err != nil {
		return err
	}
	if _, err := q.ExecContext(ctx,
		`DELETE FROM e2e_one_time_key WHERE identScreenName = ? AND deviceID = ?`, sn, deviceID); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx,
		`DELETE FROM e2e_fallback_key WHERE identScreenName = ? AND deviceID = ?`, sn, deviceID)
	return err
}

// e2eTouchActiveDevice records that an active device was just in use;
// ErrE2EDeviceNotFound or ErrE2EDeviceRevoked if it is not active.
func e2eTouchActiveDevice(ctx context.Context, q e2eQuerier, screenName IdentScreenName, deviceID uint32, now time.Time) error {
	dev, err := e2eDevice(ctx, q, screenName, deviceID)
	if err != nil {
		return err
	}
	if dev == nil {
		return ErrE2EDeviceNotFound
	}
	if dev.Revoked() {
		return ErrE2EDeviceRevoked
	}
	_, err = q.ExecContext(ctx,
		`UPDATE e2e_device SET lastSeenAt = ? WHERE identScreenName = ? AND deviceID = ?`,
		now.Unix(), screenName.String(), deviceID)
	return err
}

func e2eFallbackKey(ctx context.Context, q e2eQuerier, screenName IdentScreenName, deviceID uint32) (*E2ESignedKey, error) {
	var k E2ESignedKey
	var at int64
	err := q.QueryRowContext(ctx, `
		SELECT keyID, publicKey, signature, createdAt FROM e2e_fallback_key
		WHERE identScreenName = ? AND deviceID = ?`,
		screenName.String(), deviceID).Scan(&k.KeyID, &k.PublicKey, &k.Signature, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	k.CreatedAt = time.Unix(at, 0)
	return &k, nil
}

func e2eOneTimeKeyCount(ctx context.Context, q e2eQuerier, screenName IdentScreenName, deviceID uint32) (int, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM e2e_one_time_key WHERE identScreenName = ? AND deviceID = ?`,
		screenName.String(), deviceID).Scan(&n)
	return n, err
}

func scanE2ELink(row e2eRowScanner) (E2ELinkRequest, error) {
	var l E2ELinkRequest
	var sn string
	var created, expires int64
	var replied sql.NullInt64
	if err := row.Scan(&l.ID, &sn, &l.EphemeralKey, &l.RequestBlob, &l.ReplyBlob, &created, &expires, &replied); err != nil {
		return l, err
	}
	l.ScreenName = NewIdentScreenName(sn)
	l.CreatedAt = time.Unix(created, 0)
	l.ExpiresAt = time.Unix(expires, 0)
	if replied.Valid {
		l.RepliedAt = time.Unix(replied.Int64, 0)
	}
	return l, nil
}

// e2eOneRow turns a statement that touched no row into notFound.
func e2eOneRow(res sql.Result, err error, notFound error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound
	}
	return nil
}
