-- Key directory for the end-to-end encryption add-on (ICQ 6.5 and 7.2).
--
-- Everything here is public material or opaque ciphertext. The server never
-- holds a private key or a plaintext message; it stores what the clients
-- publish and hands it out again. Authenticity comes from signatures the
-- clients check themselves (the server checks them too, so a buggy client
-- cannot store garbage): each device is signed by the account key, each
-- fallback and one-time key by its device's Ed25519 key. The signed byte
-- strings are specified in docs/e2e/KEY-DIRECTORY-API.md.
--
-- Keys, signatures and blobs are raw bytes. Times are Unix seconds.

-- One account key (Ed25519) per screen name, shared by all of the account's
-- devices.
CREATE TABLE IF NOT EXISTS e2e_account
(
    identScreenName VARCHAR(16) PRIMARY KEY,
    accountKey      BLOB    NOT NULL,
    createdAt       INTEGER NOT NULL,
    updatedAt       INTEGER NOT NULL,
    FOREIGN KEY (identScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Every account key an account has had, so a peer's client can warn that the
-- safety number changed. oldKey is NULL for the first key. kind is publish
-- (the first key), rotate (replaced with a proof from the old key) or reset
-- (replaced without one, allowed only once every device is revoked).
CREATE TABLE IF NOT EXISTS e2e_account_key_history
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    identScreenName VARCHAR(16) NOT NULL,
    kind            TEXT        NOT NULL CHECK (kind IN ('publish', 'rotate', 'reset')),
    oldKey          BLOB,
    newKey          BLOB        NOT NULL,
    changedAt       INTEGER     NOT NULL,
    FOREIGN KEY (identScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX IF NOT EXISTS e2e_account_key_history_by_sn ON e2e_account_key_history (identScreenName, id);

-- The account's devices. accountSignature is the account key's signature over
-- the device id and both device keys. A revoked device keeps its row, so its
-- id is never reused and peers can see that it went; its fallback and
-- one-time keys are deleted.
CREATE TABLE IF NOT EXISTS e2e_device
(
    identScreenName  VARCHAR(16) NOT NULL,
    deviceID         INTEGER     NOT NULL,
    curve25519Key    BLOB        NOT NULL,
    ed25519Key       BLOB        NOT NULL,
    accountSignature BLOB        NOT NULL,
    createdAt        INTEGER     NOT NULL,
    lastSeenAt       INTEGER     NOT NULL,
    revokedAt        INTEGER,
    PRIMARY KEY (identScreenName, deviceID),
    FOREIGN KEY (identScreenName) REFERENCES e2e_account (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);

-- A device's fallback key: the one handed out when its one-time keys have run
-- out. Replaced, never consumed.
CREATE TABLE IF NOT EXISTS e2e_fallback_key
(
    identScreenName VARCHAR(16) NOT NULL,
    deviceID        INTEGER     NOT NULL,
    keyID           TEXT        NOT NULL,
    publicKey       BLOB        NOT NULL,
    signature       BLOB        NOT NULL,
    createdAt       INTEGER     NOT NULL,
    PRIMARY KEY (identScreenName, deviceID),
    FOREIGN KEY (identScreenName, deviceID) REFERENCES e2e_device (identScreenName, deviceID) ON DELETE CASCADE ON UPDATE CASCADE
);

-- A device's pool of one-time keys. A claim deletes the key it hands out in
-- the same transaction, so each key goes to one sender only.
CREATE TABLE IF NOT EXISTS e2e_one_time_key
(
    identScreenName VARCHAR(16) NOT NULL,
    deviceID        INTEGER     NOT NULL,
    keyID           TEXT        NOT NULL,
    publicKey       BLOB        NOT NULL,
    signature       BLOB        NOT NULL,
    createdAt       INTEGER     NOT NULL,
    PRIMARY KEY (identScreenName, deviceID, keyID),
    FOREIGN KEY (identScreenName, deviceID) REFERENCES e2e_device (identScreenName, deviceID) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Device linking: a new device opens a request with its ephemeral key (and
-- optionally a blob for the existing devices), one of the account's existing
-- devices answers with a blob encrypted to that key. Both blobs are opaque to
-- the server. Rows live for minutes.
CREATE TABLE IF NOT EXISTS e2e_link_request
(
    id              TEXT PRIMARY KEY,
    identScreenName VARCHAR(16) NOT NULL,
    ephemeralKey    BLOB        NOT NULL,
    requestBlob     BLOB,
    replyBlob       BLOB,
    createdAt       INTEGER     NOT NULL,
    expiresAt       INTEGER     NOT NULL,
    repliedAt       INTEGER,
    FOREIGN KEY (identScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX IF NOT EXISTS e2e_link_request_by_sn ON e2e_link_request (identScreenName, expiresAt);
