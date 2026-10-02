# Stage 3 - Client: encryption for one device (DESIGN.md Phase 2)

Self-contained task for one session. Client add-on (`tools/icq-e2e`, Rust, i686),
the two patches' E2E row, and one nginx location. No change to the Go server:
the key directory is deployed as it is (`KEY-DIRECTORY-API.md`).

## Goal

Stage 2 (commit `90487b0`) proved that the add-on can rewrite message text in
place in both directions without the client noticing. This stage replaces the
ROT13 harness with real end-to-end encryption:

- one device per account (UIN), keys made and kept by the add-on;
- the account key announced on the BOS connection and the device published in
  the key directory, strictly by `KEY-DIRECTORY-API.md`;
- Olm sessions (vodozemac: X3DH-like handshake + Double Ratchet) built on the
  first message to a contact;
- the whole text fragment encrypted in an `IQE1` container, readable only by
  the contact's add-on; a contact without the add-on gets clear text.

Background: `DESIGN.md` sections 5-10, `CHECKLIST.md` sections 1-4, stage 2's
plan and owner test result.

## Decisions (owner, 2026-10-01 - do not reopen)

- **Where the directory is reached.** `https://<domain>:8102/e2e/v1/`. Port 8443
  carries the private-CA certificate made for AIM, which an ordinary
  certificate check refuses; 8102 has the Let's Encrypt one. nginx gets a
  `location /e2e/` on 8102 proxying to the WebAPI (8082)
  (`deploy/nginx/nginx.conf`); deploying it is a separate, explicit request of
  the owner. The add-on talks HTTPS through WinHTTP with the system's
  certificate check (TLS 1.2+; Rust already needs Windows 10). The patch knows
  only the domain (tools/README.md), so its E2E row writes the URL into
  `icq-e2e.ini` next to the DLL; `ICQE2E_DIRECTORY` overrides it for tests.
- **Frames may be added and removed** on the BOS connection, with the FLAP
  sequence numbers renumbered in that direction so both ends still see
  1, 2, 3...: control messages (empty, no content) go out as frames of their
  own, incoming control messages are taken out, and notes for the user are put
  in as messages from the contact. This departs from DESIGN.md section 6
  ("N frames in, N out"); the server does not check sequence numbers, and how
  ICQ 6.5 / 7.2 take it is part of the owner test.
- **Fallback keys are accepted** (CHECKLIST 1.3): when a contact's one-time
  keys are gone, the exchange uses the fallback key, as Olm is designed.
  Requiring a one-time key would let any signed-on account block new
  conversations by claiming the pool empty (100 claims, 5 a second).

## Decisions of this plan

- **Crypto**: vodozemac 0.11 (Apache-2.0), Olm `SessionConfig::version_1()`
  (the only one without its experimental feature). The account key is a
  vodozemac `Ed25519SecretKey`. The payload is encrypted with
  ChaCha20-Poly1305 (the same crate vodozemac uses) under a fresh random 32-byte
  key per message, nonce zero (the key is used once); the key is wrapped for
  the recipient's device with its Olm session (CHECKLIST 3.1). The container
  header is the AEAD's associated data.
- **Container** (`IQE1`, DESIGN.md section 7, adjusted to Olm):

  ```
  version u8 = 1 | scheme u8 = 1 (Olm) | flags u8 (bit 0: control message)
  sender_device u32 | n_wraps u8 | n x { device u32, olm_type u8, len u16, olm_message }
  ciphertext len u16 + ChaCha20-Poly1305(envelope)      (all big-endian)
  ```

  Olm carries its own ratchet header and MAC, so DESIGN's separate
  `ratchet_hdr`/`mac` fields are not needed. The version and scheme are read
  first: any other pair (scheme 2 is reserved for PQXDH, CHECKLIST 9.1) is
  never parsed with this layout, the frame is dropped and the user gets a note
  that a newer add-on is needed (9.8). The envelope inside:

  ```
  version u8 = 1 | kind u8 (0 control, 1 message)
  from len8 | to len8 | time u64 (Unix seconds)
  form u8 (1 = channel-1 fragment: charset u16, language u16; 2 = 8-bit text)
  text len u16 + bytes | padding len u16 + random bytes
  ```

  The text is the fragment exactly as the client produced it, HTML and
  `<FONT sml>` smileys included (3.2). Padding brings text + padding to at
  least 64 bytes and adds 0-200 random bytes more; any padding is accepted
  (3.3). `from`, `to` and `time` are checked on arrival (3.4-3.6).
- **On the wire** the container travels as ASCII text: a readable hint line,
  then `IQE1:` and the container in base64 (3.7):

  `[ICQ E2E] Encrypted message - install the ICQ E2E add-on to read it. IQE1:<base64>`

  ASCII survives every form the server may turn a message into (channel 1 in
  any charset, channel-2 type-2, offline, HTML wrapped or stripped), so the
  receiving add-on finds `IQE1:` in the decoded text whatever it came as. The
  channel-1 charset becomes ASCII (0x0000) on the way out and is restored from
  the envelope on the way in; a message that arrives in a different form than
  it left in (a bridged or offline message) gets its text converted.
- **Who gets encrypted text**: a contact with an active device in the directory
  whose chain checks (below). The capability `CapE2EEncrypt` only makes the
  add-on fetch the contact's devices early. A contact with no account in the
  directory gets clear text and one note per sign-on ("sent unencrypted"). A
  contact who announces the capability but cannot be encrypted for
  (directory unreachable, broken chain) does **not** get clear text: the frame
  is dropped and a note says the message was not sent. `ICQE2E_PEERS` still
  limits encryption to the listed contacts.
- **Trust (4.1, 4.3)**: a contact's account key is pinned on first use. Every
  device used must carry a valid account signature and every claimed key a
  valid device signature. A changed account key gives one note ("the key of
  <uin> has changed - check it with them") and is then pinned (a non-blocking
  warning, like Signal's); the management page (stage 5) adds verification.
  A key exchange whose sender cannot be checked against the directory (it is
  unreachable) is decrypted and marked `[ICQ E2E: sender not verified]`.
- **Own keys**: the account comes from the server's own user info, SNAC
  `0x0001/0x000F` on the BOS connection - not from the sign-on, which carries
  only a cookie because both clients sign in over the web API, and not from
  `-uin`, which a shortcut does not have. The MOTD (`0x0001/0x0013`) supplies
  the key-directory token (KEY-DIRECTORY-API.md 3.1: the token's payload names
  the screen name); it can arrive before the user info, in which case it is held
  and applied as soon as the account is known. Both are read where FLAP frames
  are reassembled, so a frame split across two reads, or several frames in one
  read, is still seen.
  At the `LocateSetInfo` that follows, it creates the account key and the device
  if there are none yet and appends TLV `0x0E2E` with the account key (3.3);
  after that a worker thread publishes: `PUT account`, `PUT device`, one-time
  keys, the fallback key. `403 not_announced` is retried every 2 s for 30 s.
  A directory holding another account key for the UIN is reset only when it
  has no active device (the server's rule); otherwise encryption stays off for
  this account and the log says why (revoke with the management API).
  `409 device_conflict` picks another id, `410 device_revoked` makes a new
  device.
- **One-time keys (1.2, 1.5)**: vodozemac publishes at most 50 at a time
  (`PUBLIC_MAX_ONE_TIME_KEYS`), so the pool is kept at 50 and refilled below
  25: at sign-on, after each incoming key exchange, and every 10 minutes.
  vodozemac deletes a used one-time key's private half itself.
- **Fallback key (1.4)**: replaced every 7 days; vodozemac keeps the previous
  one until `forget_fallback_key`, which runs 7 days after a replacement.
- **Sessions (2.1, 2.4-2.6)**: built only when a message is about to go out.
  An incoming key-exchange (pre-key) message is first matched against the
  sessions already held for that contact, then a new inbound session is made.
  Skipped message keys follow vodozemac's limits (40 kept per chain, a gap of
  at most 2000, 5 receiving chains). A message that cannot be read is replaced
  by a note; nothing starts a new session because of it. A message with no
  key for this device gets its own note.
- **Control messages (2.2, 2.3, 3.8, 8.3)**: a container with the control flag
  and an empty envelope, sent on its own frame without "store offline" (TLV
  `0x0006`) or an ack request, so the server never keeps it. Sent after an
  incoming key exchange (so the contact stops sending key exchanges) and after
  50 messages received without one sent (heartbeat). Incoming ones advance the
  ratchet and are removed from the stream; the server's error answer to one
  (e.g. contact went offline) is recognised by its request id and removed too.
- **Length (3.9)**: text of at most 7 000 bytes after encryption, well inside
  the server's 8 000; a longer message is not sent (frame dropped, note).
  Splitting stays for stage 5 (DESIGN.md section 11).
- **Storage**: `%APPDATA%\ICQ E2E\<uin>.state`, JSON (vodozemac pickles
  inside) protected with DPAPI for the Windows user, written through a
  temporary file after every change. `ICQE2E_HOME` moves the folder (tests).
- **Modes**: default is encryption; `ICQE2E_MODE=harness` keeps the stage-2
  transform for transport checks; `observe` stays the kill switch.
- **Token**: refreshed with `POST /token` an hour before it expires.

## Code layout (`tools/icq-e2e/core`)

- `container.rs` - container, envelope, padding, the armoured text form. Pure.
- `sign.rs` - the signed byte strings of KEY-DIRECTORY-API.md section 5, tested
  against the vectors of 5.1.
- `token.rs` - reading the token's screen name and expiry, base64url.
- `directory.rs` - the key-directory client over a `Transport` trait (JSON
  bodies, error codes); `winhttp.rs` is the Windows transport.
- `keys.rs` - own account, device and sessions, contacts' pins and device
  cache; encrypt/decrypt; the publishing steps. Tested against a fake
  directory in memory.
- `store.rs` - the state file; DPAPI on Windows.
- `crypto.rs` - what the stream asks of the encryption (`Crypto` trait): token,
  announcement, outbound, inbound, pending control messages and notes.
- `rewrite.rs` / `stream.rs` - message edits can now keep, replace or drop a
  frame; the stream renumbers FLAP sequences and takes injected frames;
  MOTD token capture, TLV `0x0E2E` in `LocateSetInfo`.
- `hook.rs` - the engine behind a lock, injected frames carried across the two
  directions of a socket, a worker thread for publishing and refills.
- `config.rs` - modes, `ICQE2E_DIRECTORY`/`icq-e2e.ini`, `ICQE2E_HOME`.

## Also in this stage

- Patches (`tools/patcher/Icq65`, `Icq72`): the `e2e-probe` row becomes
  "E2E encryption (stage 3 test build)" and writes `icq-e2e.ini` with the
  directory URL for the domain; "Restore original" removes it. DLL version
  0.3.0.
- `deploy/nginx/nginx.conf`: `location /e2e/` on 8102.
- `tools/icq-e2e/README.md` describes the stage and the owner test.

## Out of scope

Several devices per account, device linking, carbons (stage 4); the
management page, safety numbers, verification, splitting long messages
(stage 5); tZers (CHECKLIST 3.10, after stage 5); TLS for BOS (7.2).

## Done when

- `cargo test --release` passes in `tools/icq-e2e`: signed strings match
  KEY-DIRECTORY-API.md 5.1; container and envelope round-trip; two engines
  with a fake directory publish, exchange messages both ways (first
  pre-key, then normal), answer with a control message, survive a restart
  from the state file, refuse a wrong sender/recipient/time, show notes for an
  unreadable message and a message not for this device; the stream renumbers
  sequences around dropped and injected frames at every split point.
  `cargo run --release -p icqe2e_testhost` shows an encrypted exchange.
- The patches and DLLs build (`tools/common/Build-Patches.ps1`).
- **Owner test (not run by the agent)**, after the nginx change is deployed:
  two clients (6.5 and 7.2) with the add-on; the log shows the token, the
  account key announced and the device published; messages both ways with
  HTML, smileys and Cyrillic read normally; the other side in
  `ICQE2E_MODE=observe` shows the hint line and `IQE1:`; an offline message is
  readable after sign-on; typing, acks, status and mood behave as before; the
  clients accept the added and removed frames (control messages, notes); a
  contact without the add-on gets clear text and the sender a note.
- Committed in the repository's style once the owner has checked it.

## Against the checklist

Stage 3 covers CHECKLIST sections 1–3, and the parts of 5, 7 and 8 that are the
client's. Every row below is marked in `CHECKLIST.md` itself.

### 1. Keys

| # | What stage 3 does |
|---|---|
| 1.1 | The device publishes an identity key, its signed key and a pool of one-time keys, in the order the API expects (`crypto::Publisher`): account, device, pool, fallback. |
| 1.2 | The pool is topped up whenever the directory reports fewer than 25 keys, so a contact is never left without a key to claim. The count is measured against what the *directory* holds, not against what it was told, so a retry never spends a second pool. |
| 1.3 | Fallback keys are accepted, by the owner's decision recorded above. |
| 1.4 | The fallback key is replaced every 7 days; the old private half is not kept, because a message encrypted to it has already arrived or never will. |
| 1.5 | A one-time key is consumed by the session that used it: vodozemac drops the private half inside `create_inbound_session`, and the account is saved straight after. |
| 1.7 | No device labels. Nothing is signed that the directory does not need. |

### 2. Sessions

| # | What stage 3 does |
|---|---|
| 2.1 | A session is built on the first message to a contact, not when the device appears. |
| 2.2 | An incoming key exchange is answered with an empty control container, on a frame of its own, so the sender stops sending them. |
| 2.3 | A heartbeat control message goes out after 50 messages without one. |
| 2.4 | vodozemac's own limits are used and documented in `keys.rs`: 40 skipped keys per chain, a gap of 2000 messages, 5 receiving chains. |
| 2.5 | A decryption failure is a note, never a new session. The session is committed only after the payload is readable, so a tampered container costs no ratchet step. |
| 2.6 | A message addressed to another device is a note, not garbage. |

### 3. Message format

| # | What stage 3 does |
|---|---|
| 3.1 | The whole text fragment is encrypted under a fresh random key per message, wrapped for every device of the recipient. |
| 3.2 | The sender's own bytes go in, not a decoded and re-encoded copy: `icbm::Message` carries `raw` and `charset` alongside the decoded `text`, and the testhost proves HTML, smileys and Cyrillic come back byte for byte. |
| 3.3 | The capability is appended to the client's own `LocateSetInfo`, and the account key is announced in that same SNAC, so no frame is added for either. |
| 3.5 | A container that would exceed the limit is refused rather than cut, and the user is told. |
| 3.6 | Padding is random from 64 to 200 bytes, inside every container. |
| 3.7 | A contact known to have no add-on is remembered for the sign-on and not asked again; a directory that cannot be reached is not remembered, so an outage never blames a contact. |
| 3.8 | Control messages carry no content and are exempt from the trust rule. |
| 5.3 | An offline message is encrypted when it is stored and opened when it is replayed, so the server never holds readable text (DESIGN.md 5.3). |

### Elsewhere

| # | What stage 3 does |
|---|---|
| 5.3 | Key material goes up over HTTPS with the system's certificate check, and a connection is refused rather than downgraded. |
| 7.1 | The token no longer suffices to set a key: a first publish or a reset needs the key announced in TLV `0x0E2E` of `LocateSetInfo` on the token's own connection. |
| 8.3 | A control message goes out with neither the store-offline TLV `0x0006` nor an ack request `0x0003`, so it never reaches the offline store. |

### Not stage 3

Several devices per account, device linking and approving a new device (1.6,
4.4, 6.4), history messages, receipts, the management page, and groups.
Offline messages are in scope after all: the server stores whatever text it is
given, so the add-on encrypts them on the way out (`0x0015/0x0002`) and opens
them on delivery (`0x0015/0x0003`) exactly like a live message. A stage-3 build is for the owner's own two test accounts, one device
each; CHECKLIST says so on every one of those rows.

## Follow-up: user control and downgrade protection (CHECKLIST 10.1-10.8)

The owner's rules of 2026-10-01 replace the "who gets encrypted text" decision
above where they differ. `core/src/policy.rs` holds the rules and the words;
`crypto::Engine` applies them.

- **Per contact, in the state file**: the user's setting (automatic, `on`,
  `off`) and whether the contact was ever seen encrypting (signed devices in
  the directory, or an encrypted message exchanged). The capability is only a
  hint: it never sends a message in clear.
- **Outgoing**: `off` - clear. Otherwise a contact with a signed device is
  encrypted. Without one, a contact switched `on` by hand or seen encrypting
  before gets nothing: the frame is dropped and the chat says why; `/e2e plain`
  lets one message through (not for `on` by hand). A contact never seen
  encrypting gets clear text and the status note (trust on first use). An
  unreachable directory holds the message for a contact that is strict or
  announces the add-on, and sends clear text otherwise.
- **Incoming**: always decrypted; the text gets `🔒 ` in front (UCS-2; text in
  ASCII, valid UTF-8 or Latin-1 is turned into UCS-2 to carry it), or `[E2E] `
  for 8-bit text whose code page is unknown. It marks the contact as encrypting
  and switches the chat on with a note, unless the user switched it off by
  hand - then one hint per sign-on.
- **Commands** `/e2e on|off|auto|status|plain` are read out of the message text
  (HTML and `&nbsp;` stripped), carried out, answered with a note and dropped.
  With `ICQE2E_NO_INJECT` a dropped outbound frame goes out with its text
  replaced by a fixed "withheld" line instead, so nothing the user typed leaves.
- **Notes** carry the contact they are about and are put into that chat as a
  message from that contact. The hook puts them in straight after the client's
  `send` (and the worker every two seconds), not only after the server's next
  frame. Before, the note "Messages to <uin> are sent unencrypted" was taken out
  of the queue and written only to the log, and every other note waited for the
  next incoming frame and landed in the chat of whoever sent it.
- **Saving**: the engine marks every change (ratchet step, pin, setting), and
  the session writes the state file after the frame; before, only a publish
  marked it.
- **`/e2e auto`** forgets the manual on/off and keeps the seen-encrypting flag;
  `/e2e status` names the setting and that flag.
- **Key publication in the chat**: only a failure that leaves encryption not
  working (`Off`, or a `Retry` while our keys are not in the directory yet, or
  a token refresh that failed), once per sign-on per kind (refused /
  unreachable / off), with the publisher's one-line reason; after one, a single
  "Encryption is ready" once a publish succeeds. Notes go only to the
  connection that got the token or carried a message, never to a service
  connection.
