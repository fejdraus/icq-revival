# Key transparency for the E2E key directory

Stage 1: an append-only, signed log of every change in the key directory,
which every client replays and checks, and in which each client watches its
own account. Stage 2: an auditor, as Signal has, that follows the log on its
own, checks every entry against the directory's rules and cosigns the
checkpoints; clients take the log only when every auditor they trust agrees
with their own copy and at least one has cosigned lately. There may be
several, and the client patches pin their keys.

Why: the directory is untrusted (`KEY-DIRECTORY-API.md`, section 1). Clients
pin a contact's account key on first use and compare safety numbers by hand.
Without a log, the server - or whoever took it over - can add a device to an
account, or hand one client a different account key, and only a manual
safety-number check would ever show it. With the log:

| Attack | Without the log | With the log (stage 1) | With the auditor (stage 2) |
|---|---|---|---|
| a key that is not what the directory recorded | caught only by a safety-number check | refused: not in the log | same |
| a device quietly added to your account | invisible | your own client sees it and says so | same |
| history rewritten afterwards | possible | caught: the log no longer adds up | same |
| one log shown to you, another to your contact (split view) | invisible | **not caught** | caught, as long as the auditor is not the operator's |
| the operator adds a device openly | invisible | visible to everyone, not prevented | the auditor refuses a device the account key did not sign |
| a key swapped in as a "reset" while devices are active, or as a "new account" | invisible | visible, not refused | the auditor refuses it |

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
| `account` | change (`publish`, `rotate` or `reset`), new account key (32); for `rotate` also the proof (64): the old key's signature over the rotate message | the account key is now this |
| `device` | device id (4, BE), Curve25519 key (32), Ed25519 key (32), account signature (64) | a device was added |
| `resign` | device id (4, BE), account signature (64) | a device got a new account signature (rotation) |
| `revoke` | device id (4, BE) | a device was revoked |
| `delete` | - | the account was deleted, its key and devices with it (`DeleteUser`) |

Replaying the leaves in order gives, for each account, its account key and
its active devices with their keys - what `GET /users/{uin}/devices` must
return. A `publish` or a `reset` starts the account's devices afresh; a
`delete` removes the account. (Logs written before `delete` existed may hold
a `publish` over an account that was deleted unlogged; the auditor refuses
that from now on.)

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
| `GET /e2e/v1/log/auditors` | the auditors' verifier keys (`E2E_KT_AUDITORS`, comma-separated), one per line, in that order; a key that does not read is logged and left out |
| `GET /e2e/v1/log/cosigned` | `{"checkpoints": ["<note>", ...]}`: per configured auditor, the latest checkpoint it cosigned, signed by the log and by the auditor |
| `POST /e2e/v1/log/cosignature` | an auditor hands in `{"checkpoint": "<body>", "cosignature": "<line>"}`; kept only if it verifies under a configured auditor key, is within 10 minutes of the server's clock, and is over a checkpoint this log really had (204) |

## The auditor (stage 2)

As in Signal's key transparency, a party apart from the server checks the
log and vouches for it. `cmd/e2e-kt-auditor` (`server/e2e/audit.go`):

- Pins the log's key on first sight, then every minute fetches the
  checkpoint and the new entries, and checks that the log only grew (the
  entries add up to the signed root on top of what it had).
- Replays every entry against the directory's rules: a `publish` only for an
  account without a key; a `rotate` with the old key's proof; a `reset` only
  once every device is revoked; a `device` with an id the account never used,
  signed by the account key; a `resign` of an active device signed by the
  current key; a `revoke` of an active device; a `delete` of an account that
  has a key; nothing of a kind it does not know.
- If all is well, cosigns the checkpoint (c2sp.org/tlog-cosignature, Ed25519,
  with the time) and posts it to the server. If not, it records the violation,
  logs it loudly and never cosigns that log again: clients then warn within
  the hour.
- Needs only outbound HTTPS. Its key is a 32-byte seed file made on first
  run; `-print-key` prints the verifier key for the server's
  `E2E_KT_AUDITORS`.

Who runs it is the whole point: an auditor the server's operator runs alone
catches a server taken over by someone else, but not the operator. Signal's
are run by other organisations; ours should be run by someone else too, on a
machine the operator cannot touch.

```
e2e-kt-auditor -log https://icq.example.org:8102/e2e/v1/ \
  -name auditor.example.net/icq -key auditor.key -state auditor.json
```

### Several auditors

`E2E_KT_AUDITORS` takes any number of keys, comma-separated; the server
takes cosignatures from each and hands out the latest of every one. Each
auditor works alone - they do not know of one another - so adding one is:
install it (`deploy/e2e-kt-auditor/`: a hardened systemd unit and
`install.sh`, which makes the key and prints the verifier key), add its key
to `E2E_KT_AUDITORS`, restart the server, and apply the client patches again
so they pin it (below).

Auditors on different machines, networks and providers - a home machine
behind NAT will do, since an auditor needs only outbound HTTPS - keep the log
audited when one of them is down, and make a server taken over by someone
else face several independent checks instead of one machine to silence. They
are still the operator's if the operator runs them all (see Limits).

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
- **A log that cannot be trusted** (rewritten, other key, gone, a split
  view): a warning once per sign-on and `/e2e status` says `NOT TRUSTED`.
  Three states are told apart (`kt::Trust`, audit 2026-10, finding 4):
  *never had a log* (an older server) - trust on first use as before;
  *trusted*; and *broken after trust* - kept in the state file
  (`LogState::broken`) across sign-ons until `/e2e resetlog`. Broken after
  trust, the copy is frozen as it was last trusted: sessions already made go
  on, so the user keeps a messenger with the contacts they had, but a
  contact never checked, a changed account key, a device neither in the
  frozen copy nor already in a session, and a new Olm session from any of
  them are refused (held, or unreadable, with a note). It used to fall back
  to trust on first use, which handed a server that breaks its own log the
  very keys the log is there to check. `/e2e resetlog` forgets the copy and
  its key, for when the operator explains.
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

## Stage 2 in the client

- **Which auditors are trusted.** With an `auditors =` line in
  `icq-e2e.ini` (or `ICQE2E_AUDITORS`), exactly the keys it gives; what the
  server names on `GET /log/auditors` is not used for trust then, and no
  other auditor is ever pinned. The ICQ 6.5 and 7.2 patches write the line
  at Apply (below), as Signal's app carries its auditors' keys. Without the
  line - an older patch, or a server that could not be asked at Apply - the
  auditors are pinned on first sight from `GET /log/auditors`, like the
  log's key; a server that later names other auditors or none changes
  nothing, and `/e2e resetlog` forgets them with the rest. The line's keys
  replace whatever the state file had pinned, and stay pinned there even if
  the line goes away again.
- After every sync, every cosignature by a trusted auditor over a checkpoint
  signed by the log's key is looked at (`GET /log/cosigned`). The copy keeps
  every leaf hash, so a checkpoint of any earlier size is checked against the
  root our copy had at that size; an older copy without them reads its
  entries again once.
- A cosigned checkpoint that our copy does not have, by **any** trusted
  auditor - however many others agree with us - is a **split view**: the log
  is not trusted, as for a rewritten one (WARNING once per sign-on, keys
  trusted on first use).
- At least one trusted auditor must have cosigned within the hour
  (`kt::AUDIT_MAX_AGE`; an auditor cosigns every minute). If none has, it is
  a warning once per sign-on naming each auditor's last word, and
  `/e2e status` says `NOT AUDITED`; messages go on, checked against the log.
  A server could withhold newer cosignatures from one user, so an hour is
  the window in which a split view goes unnoticed.
- `/e2e status` ends the log's part with every trusted auditor: ", audited by
  A (1 min ago), B (2 min ago); C silent 3 h". The state file keeps each
  auditor's latest cosignature (`LogState::audits`); a file from before
  several auditors fills it on the next look.

### Pinned by the patch

The patches take only the domain from the user, so the keys come from the
server the patch is pointed at: `GET https://<domain>:8102/e2e/v1/log/auditors`
at Apply, over HTTPS checked against the certificate chain (Let's Encrypt) by
.NET. The message box lists the keys pinned. Applying again only ever adds
keys: a key the server no longer names stays pinned and the message box says
so (an auditor taken out of service then shows as silent, which costs nothing
while another vouches); deleting the line and applying starts over. If the
request fails, the line stays as it was - or, with none, is left out and the
add-on pins on first use - and the message box says so. Restore removes the
ini with everything else.

This is trust on first use moved from the add-on's first sign-on to Apply,
and made explicit: a server that is already lying at Apply time can name
auditors of its own. What it buys is that the set is fixed from then on,
readable in a file the user can compare with others, and grows only when the
user applies again.

## Limits

- Auditors run by the server's operator do not protect against the
  operator, however many there are and wherever they run: whoever holds
  their keys can cosign anything. Several on different machines and
  providers (home machines included) add location and provider diversity -
  the auditing survives one machine down, and an intruder on the server or
  on one auditor's machine is still caught by the others - but protection
  against the operator needs an auditor someone else runs.
- A split view younger than an hour, or a key used before the auditor's next
  look, is caught afterwards, not prevented - the same trade Signal makes.
- The patch pins the auditors the server names at Apply time; a server
  already compromised then could name its own. Clients without the patch's
  line still pin on first use, and take no auditor added later until they
  are patched again (or `/e2e resetlog`).
