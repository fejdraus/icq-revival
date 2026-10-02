-- Key transparency log of the E2E key directory (docs/e2e/KEY-TRANSPARENCY.md).
--
-- An append-only RFC 6962 Merkle tree over every change in the directory:
-- account keys, devices added, re-signed and revoked. Rows are only ever
-- inserted. Nothing here references users or e2e_account: deleting an account
-- must not delete its history from the log.

-- The leaves, by index from 0, in commit order.
CREATE TABLE IF NOT EXISTS e2e_kt_leaf
(
    idx       INTEGER PRIMARY KEY,
    leaf      BLOB    NOT NULL,
    createdAt INTEGER NOT NULL
);

-- The tree's stored hashes, by the index golang.org/x/mod/sumdb/tlog gives
-- them (StoredHashIndex): every leaf hash and every complete subtree's hash.
CREATE TABLE IF NOT EXISTS e2e_kt_hash
(
    idx  INTEGER PRIMARY KEY,
    hash BLOB NOT NULL
);

-- The log's own settings: its Ed25519 signing key (seed) and whether the
-- directory as it was before the log has been written into it (genesis).
CREATE TABLE IF NOT EXISTS e2e_kt_meta
(
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
