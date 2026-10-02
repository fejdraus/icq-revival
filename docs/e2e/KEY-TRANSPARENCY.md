# Key transparency for the E2E key directory

Stage 1: an append-only, signed log of every change in the key directory,
which every client replays and checks, and in which each client watches its
own account. Stage 2, not here yet: independent witnesses that cosign the
log's checkpoints.

Why: the directory is untrusted (`KEY-DIRECTORY-API.md`, section 1). Clients
pin a contact's account key on first use and compare safety numbers by hand.
Without a log, the server - or whoever took it over - can add a device to an
account, or hand one client a different account key, and only a manual
safety-number check would ever show it. With the log:

| Attack | Without the log | With the log (stage 1) | With witnesses (stage 2) |
|---|---|---|---|
| a key that is not what the directory recorded | caught only by a safety-number check | refused: not in the log | same |
| a device quietly added to your account | invisible | your own client sees it and says so | same |
| history rewritten afterwards | possible | caught: the log no longer adds up | same |
| one log shown to you, another to your contact (split view) | invisible | **not caught** | caught |
| the operator adds a device openly | invisible | visible to everyone, not prevented | same |

Signal does the same with prefix trees, a verifiable random function and
third-party auditors (signal.org/blog/automatic-key-verification,
draft-ietf-keytrans-architecture). A private server has a few hundred
entries, not billions, so every client downloads the whole log once and then
only what was appended. That needs no inclusion proofs and no privacy layer:
everything in the log is already public through `GET /users/{uin}/devices`.

## The log

An RFC 6962 Merkle tree (SHA-256, leaf hash `H(0x00 || leaf)`, node hash
`H(0x01 || left || right)`), as `golang.org/x/mod/sumdb/tlog` builds it. One
leaf per change, in the order the changes were committed; a leaf is never
changed or removed. The server appends in the same database transaction as
the change itself, so the directory and the log cannot disagree.

### Leaf

Byte strings in the style of the signed messages (`KEY-DIRECTORY-API.md`,
section 5): the context, then fields, each a big-endian u16 length and the
bytes.

```
"OSCAR-E2E-KT-v1" || f(kind) || f(screen name) || f(time) || f(...)
```

`screen name` is the identity form the directory uses (`IdentScreenName`, the
UIN as digits). `time` is the commit time, Unix seconds as 8 bytes big
endian. The kinds and their fields:

| kind | fields after time | meaning |
|---|---|---|
| `account` | change (`publish`, `rotate` or `reset`), new account key (32) | the account key is now this |
| `device` | device id (4, BE), Curve25519 key (32), Ed25519 key (32), account signature (64) | a device was added |
| `resign` | device id (4, BE), account signature (64) | a device got a new account signature (rotation) |
| `revoke` | device id (4, BE) | a device was revoked |

Replaying the leaves in order gives, for each account, its account key and
its active devices with their keys - what `GET /users/{uin}/devices` must
return. A `publish` for an account that already has a key (the account was
deleted and its UIN reused) is a key change like a `reset`.

### Genesis

A directory that existed before the log gets one leaf per account key
(`account`, `publish`, the current key) and one per active device
(`device`), written once, on the first append or read, in one transaction.
Revoked devices and earlier keys are not replayed: they were never visible
to clients as anything but gone.

### Checkpoint

A signed note (`golang.org/x/mod/sumdb/note`), the format transparency logs
and witnesses share (c2sp.org/tlog-checkpoint):

```
<origin>
<tree size>
<root hash, base64>

— <origin> <base64(key hash || Ed25519 signature)>
```

`origin` is `E2E_KT_ORIGIN` (default `open-oscar-server/e2e-kt`); set it to
something unique per server, such as `icq.example.org/e2e-kt`, before
witnesses come in. The log's Ed25519 key is generated on the first use and
kept in the database, so a backup of the database carries it; losing it
makes every client see a log with a new key, which they refuse.

## Endpoints

Public, no token, like the other `GET /users/...` endpoints.

| Request | Answer |
|---|---|
| `GET /e2e/v1/log/checkpoint` | the signed checkpoint, `text/plain` |
| `GET /e2e/v1/log/key` | the log's verifier key, `text/plain` (`<origin>+<key hash>+<base64 key>`) |
| `GET /e2e/v1/log/entries?start=N&count=M` | `{"start": N, "entries": ["<base64 leaf>", ...]}`, at most 1000 per request; fewer at the end of the log |

## The client

`tools/icq-e2e/core/src/kt.rs` (the log) and `crypto.rs` (`Engine::sync_log`
and what uses it). The copy lives in the state file (`OwnKeys::log`): the
log's key, the size, the tree's right edge and every account replayed.

- **Log key.** Pinned on first sight, per state file - trust on first use,
  like a contact's account key. A checkpoint signed by another key, or naming
  another log, is not accepted.
- **Sync.** The checkpoint, then the entries from the size we had, in pages
  of 1000. Each leaf hash goes into the right edge (at most 64 hashes) and
  the leaf is replayed. The new copy is kept only when the edge's root is the
  checkpoint's root. A smaller size than before, a root that does not match,
  an entry that is no leaf, or a server that had a log and has none now all
  mean the log was rewritten. At most once a minute; at once when a contact's
  keys do not match our copy, since they may have changed a moment ago.
- **Contacts.** Checked before anything is pinned. An account key that is not
  the log's for the contact (or a contact the log does not have) holds the
  message - the note offers `/e2e plain` - and the key is not pinned. A
  device that is not in the log with the same keys and signature is left
  out, and the chat says so once. `/e2e status` looks a contact up the same
  way, so asking never pins a key either.
- **Incoming.** A new session from a contact (a pre-key message) is made only
  with an account key and device the log shows; otherwise the message is
  unreadable and nothing is pinned or spent. If our copy may just be behind,
  it is brought up to date and the message tried once more.
- **Own account.** After each sync, once our keys are in: an account key that
  is not ours is a warning (once per key); a device we have not been told
  about is reported once (`LogState::own_seen`, kept in the state file) - it
  may be another computer the user linked, or someone else's.
- **A log that cannot be trusted** (rewritten, other key): a warning once per
  sign-on, `/e2e status` says `NOT TRUSTED`, and until it is sorted out keys
  are trusted on first use as without a log. Holding every message instead
  would leave the user with no messenger whenever the operator restores an
  old backup. `/e2e resetlog` forgets the copy and its key, for when the
  operator explains.
- **Unreadable for now** (network): nothing is checked against the copy until
  it can be brought up to date again; no note.
- **No log on the server** (an older server: the endpoints answer 404): the
  client works as before and `/e2e status` says so.
- **Status.** `/e2e status` says whether the contact's key is the log's, and
  the log's size.

## Operation

- The log and its key are in the server's database (`e2e_kt_*` tables), so
  the database backup carries them. Restoring an older backup makes every
  client see a shorter log - a rewrite - and warn; each user then types
  `/e2e resetlog` once.
- `E2E_KT_ORIGIN` must not change once clients have pinned the key.
- Deleting an account deletes its directory rows, not its log entries: the
  log keeps showing its last keys, which no client uses since the directory
  has no devices for it. A new account on the same UIN starts with a
  `publish`, which replaces them.

## Not done here (stage 2)

Witnesses: other parties that check the log only grows and cosign its
checkpoints, so the server cannot show two users two different logs. The
checkpoint is already in the format they cosign (c2sp.org/tlog-witness).
