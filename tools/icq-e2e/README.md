# ICQ E2E add-on — stage 3 (end-to-end encryption)

A native add-on for the classic ICQ 6.5 and 7.2 clients that **encrypts instant
messages end to end** with Olm (the [vodozemac] Rust implementation, Apache-2.0).
A message leaves the sender's client as an opaque container, travels through the
ICQ server unreadable, and is opened on the recipient's device. The server never
holds anything it could read.

This is the third stage. Stage 1 proved the transport by rewriting message text
in place with a reversible transform; stage 3 replaces that with real crypto.
The plan is `docs/e2e/STAGE-3-CLIENT-CRYPTO.md`, the design is
`docs/e2e/DESIGN.md`, and the requirement list with its status is
`docs/e2e/CHECKLIST.md`. The key directory's API is
`docs/e2e/KEY-DIRECTORY-API.md`.

[vodozemac]: https://github.com/matrix-org/vodozemac

## What the user sees

- A message to someone with the add-on: normal text, HTML, `<FONT sml>` smileys,
  Cyrillic, Latin-1 accents — the sender's own bytes come back exactly as
  written, nothing added to them. Whether a chat is encrypted is said by the
  notes below and by `/e2e status`, not by a mark on each message (see "No lock
  in the window").
- A message to someone **without** it: the text goes out in clear, and the chat
  shows one note saying so, once per sign-on rather than once per message.
- The state of each chat as a note: when it is first used in a sign-on, and on
  every change ("Encryption is on in this chat", "off", "they do not have the
  add-on", "switched on: they sent an encrypted message").
- A container this device cannot open (a tampered one, or one for another
  device): a note, never garbage in the chat, and never a new key exchange
  because of it.
- A key publication that leaves encryption not working (keys refused, key
  directory unreachable, token refused): one note with the reason, once per
  sign-on for each kind; after it, one "Encryption is ready" once it works.
  Nothing when publishing simply works.
- A contact whose safety number changed (they reset their keys - or someone
  is in the middle): "Your safety number with <uin> has changed", once per
  change. Messages go on, encrypted to the new key - unless the contact was
  verified; then the verification is cleared and messages are held until the
  user confirms (see "Safety numbers"). Nothing is said the first time a
  contact is seen: like Signal, the first key is trusted on first use.
- Notes from the add-on itself are marked `[ICQ E2E]` and arrive as messages
  from the contact the chat is with.

## Two jobs, two rows

The patches offer the add-on as two rows, each with its own tick; either puts
the DLL in, and `icq-e2e.ini` says which of the two it does:

| Row (job key) | `icq-e2e.ini` |
|---------------|---------------|
| End-to-end encryption of messages (`e2e`) | `e2e = on` |
| Encrypted connection to the server (TLS) (`e2e-tls`) | `tls = on` |

With only the TLS row (`e2e = off`) the add-on is the plain client plus TLS:
no message is encrypted, no key is published, the key directory is never
called, the add-on is not announced to contacts (no capability, no account key
in `SetInfo`), and the message bytes both ways are the client's own - a
container from a contact with the add-on shows as the armoured text it is.
Only a `/e2e` command is still taken out of the chat and answered with
"End-to-end encryption is off on this install", so a command typed by mistake
never reaches the contact as text. With only the encryption row (`tls = off`)
the connection to the server is plain and the chat says so at every sign-on.

**Fail closed when the add-on is missing.** With the TLS row ticked (and
"automatic connection and voice calls use your server" too), the patch also
points the client's own sign-in at ports that do not work in plaintext, so a
client whose add-on is gone - the DLL deleted, renamed, or not loaded - cannot
sign in at all instead of signing in unencrypted:

| Client | Setting | TLS row off | TLS row on | Add-on maps it to |
|--------|---------|-------------|------------|-------------------|
| 6.5 | `MCore.dll`: the default of `ServerPort` (an immediate next to `login.icq.com`) | 5190 | 5194 | 5194, ALPN `oscar` |
| 7.2 | `AppConfig.xml`: `aimcc.connect.host.port` (getChallenge, clientLogin) | 8082 | 5195 | 5194, ALPN `http/1.1` |
| 7.2 | `AppConfig.xml`: `aimcc.connect.bossRedirect.port` (startOSCARSession) | 8082 | 5195 | 5194, ALPN `http/1.1` |
| 7.2 | `AppConfig.xml`: `aimcc.connect.skipSources` (new line) | absent | 4063266 (0x3E0022) | - |

On 7.2 the ports alone do not hold on a client that has signed in before: ACC
(`acccore.dll`) first tries the last connection that worked, which the client
keeps per Windows user in `%APPDATA%\ICQ\Application.qdb` (SQLite, `Records`,
section `ConnectionSettings`, `AccCachedSettings` =
`aimcc.connect.settings.OpenAuth1.0`/`OpenAuth2.0` with `domain:8082`), and
after the configured port it retries the same host on port 80.
`aimcc.connect.skipSources` (a bit per source, read while `autoConnect` is 1)
leaves out the cache (0x2) and the port-80 retries (0x20, 0x20000, 0x40000,
0x80000, 0x100000, 0x200000). The cache itself is not touched.

5194 speaks TLS 1.3 only: a plain FLAP client there hears no hello and is cut
off at its first bytes. The web sign-in cannot share it, because the add-on
picks the ALPN by the port before the client has said anything, so it gets
5195, where the server never listens: without the add-on the connect is
refused. The BOS host the server hands out after a sign-in over its TLS
listener is `domain:5194`, with SSL state 0 and no `tlsCertName` (the add-on
asks for no SSL, so the client keeps speaking plain FLAP and the add-on maps
5194 to TLS); the client's Settings > Connection then shows port 5194. The
add-on also maps 5190 and 8082 to TLS as before, which keeps installs patched
earlier working. Unticking the
row puts 5190/8082 back; Restore gives the original files byte for byte. The
domain, the pages (8101, 8102), the key directory and the STUN server are not
touched by this. A server typed by hand in the client's connection settings
stays the user's, and is not fail-closed. The way out is the row:
`tls = off` typed into the ini by hand (or `ICQE2E_TLS=off`) leaves the
sign-in on 5194/5195, so such a client does not sign in either; untick the
row and apply, and the message box says so.

The patch owns the `directory`, `server`, `e2e`, `tls`, `calls_encrypt` and
`auditors` lines of the ini and keeps every other line (`tls_pin`, comments,
anything added by hand). `auditors` it writes with the messages row: the
verifier keys the server names on `GET /e2e/v1/log/auditors` at Apply, read
over HTTPS (the certificate checked as for any web request), and listed in
the message box. Applying again only adds keys the server names now; a key it
no longer names stays pinned and the message box says so (delete the line and
apply to start over). If the server cannot be asked, the line stays as it
was, or is left out - the add-on then pins on first use - and the message box
says that too. An ini
from before the two rows has no `e2e` line, which reads as on: such an install
shows both rows applied. `-Skip`/`-Include e2e-probe`, the key of the single
row of earlier builds, still means both.

## Commands (CHECKLIST section 10)

Typed in the chat window and sent as a message; the add-on takes it out of the
stream, so the contact never gets it, and answers with a note in that chat.

| Command | What it does |
|---|---|
| `/e2e on` | Encryption on for this contact, by hand: nothing ever goes to them in clear. Without their keys the message is held and the chat says why. |
| `/e2e off` | Encryption off for this contact: messages go in clear. An encrypted message from them is still read, and gives one hint. |
| `/e2e auto` | Back to the default: the manual on/off is forgotten; whether the contact was seen encrypting is kept, so downgrade protection stays. |
| `/e2e status` | The setting (auto/on/off), whether the contact was seen encrypting, their signed devices in the key directory, and what the next message will do. |
| `/e2e plain` | The next message goes in clear, once - for a contact that encrypted before and now shows no keys. Refused when encryption is on by hand. |
| `/e2e safety` | The safety number with this contact - 60 digits in twelve groups of five, as Signal shows it - whether the contact is verified, and how to compare. |
| `/e2e verify` | Marks the contact verified, for the number `/e2e safety` showed last in this sign-on (the key behind it, not the contact). Refused if the number was not shown, or changed since. |
| `/e2e unverify` | Takes the verification back. |
| `/e2e accept` | After a verified contact's safety number changed: send on, encrypted to the new key, without verifying it. The contact is unverified from then on. |
| `/e2e resetlog` | Forgets this add-on's copy of the server's key log and its key, and reads it anew. Only when the server's operator says the log was restored from a backup or started afresh. |

The setting is kept per contact in the state file, with whether the contact was
ever seen encrypting. Without a setting a contact is encrypted whenever the key
directory has a signed device of theirs; the OSCAR capability is only a hint.
Once a contact has encrypted, the add-on never falls back to clear text by
itself: if the server later shows no keys for them, the message is held and the
chat says so (downgrade protection).

## Safety numbers (CHECKLIST 4.2, 4.3, 10.10)

Signal's safety number, computed exactly as libsignal does it
(`NumericFingerprintGenerator`, fingerprint version 0, 5200 rounds of SHA-512;
`safety.rs`, tested against Signal's own test vector). The inputs are each
side's **account key** - the one key per UIN that signs every device - and the
UIN. So there is one number per pair of accounts, and a new device of the
contact does not change it; only a new account key does, which is a key reset.

- `/e2e safety` in a chat shows the number. The contact types `/e2e safety` in
  their chat with you and sees the same 60 digits. Compare them in person or by
  phone - not through the chat, which the server carries.
- `/e2e verify` once they match. It is kept in the state file, bound to that
  key; `/e2e status` says "verified: yes".
- When the contact's key changes, the chat says "Your safety number with <uin>
  has changed", once. For an unverified contact that is all: messages go on,
  encrypted to the new key.
- For a **verified** contact the verification is cleared and every message is
  held ("was NOT sent") until the user either verifies the new number
  (`/e2e safety`, compare, `/e2e verify`) or types `/e2e accept` to send on
  without verifying. The hold survives a restart. `/e2e plain` stays what it
  always is - one message in clear - and is not the way past this hold.

## Automatic key checking: the key log (CHECKLIST 4.5)

Comparing safety numbers by hand is the strongest check, and few people do it.
So the server also keeps a key log - every account key and device the key
directory ever handed out, in a signed Merkle tree that can only grow - and
the add-on checks against it on its own, as Signal does
(docs/e2e/KEY-TRANSPARENCY.md):

- A contact's account key must be the one the log shows for them, or the
  message is held ("was NOT sent ... the server's key log") and the key is not
  pinned. A device of theirs the log does not show gets nothing, and the chat
  says so once.
- Your own account: a device you did not add, or an account key that is not
  this add-on's, is reported in the chat once ("A device was added to your
  account"). That is what catches a server that quietly adds a device to read
  your messages.
- A log that changes its past - shorter than before, another history, another
  key - gets a WARNING once per sign-on, and keys fall back to trust on first
  use until it is sorted out. After the operator restores an old backup every
  user sees this once and types `/e2e resetlog`.
- `/e2e status` ends its key part with what the log says ("key log: 100002's
  keys are in it, checked (N entries)").
- A server without a log (an older one) works as before.

And as in Signal, auditors - programs run apart from the server
(`cmd/e2e-kt-auditor`, installed with `deploy/e2e-kt-auditor/`) - follow the
log, check every entry against the directory's rules and cosign it every
minute. A server may have several. The add-on takes the log only when every
auditor it trusts agrees with its own copy and at least one has cosigned
lately:

- A cosigned log that differs from the one this add-on was shown - by any of
  the auditors, however many others agree - is a WARNING: the server is
  showing different users different logs.
- No cosignature by any of them for over an hour is a warning, once per
  sign-on; messages go on. `/e2e status` lists each auditor: "audited by A
  (1 min ago), B (2 min ago); C silent 3 h".
- Which auditors are trusted: the `auditors =` line of `icq-e2e.ini`, which
  the patch fills in at Apply with what the server names then (over HTTPS);
  exactly those, whatever the server names later. Without the line (an older
  patch, or the server could not be asked at Apply), the ones the server
  names are pinned on first use, as before; the line, once there, replaces
  them in the state file for good.

## No lock in the window (CHECKLIST 10.4, 10.9)

Two ways of showing encryption in the window were tried and dropped:

- **A lock button in the message window** (ICQ 6.5 and 7.2, put in by the
  patches). The window's markup does not expose which contact a chat is with,
  so the button could show no state; and having its script send `/e2e status`
  through the window's Send was unreliable - it sent the user's draft, live,
  instead of the command. The patches no longer put it in, and an Apply takes
  out what an earlier build put there (the markup edits, `e2eLock.js` and the
  pictures).
- **A mark before each decrypted message** (`🔒 `, or `[E2E] ` for 8-bit
  text). ICQ 6.5 and 7.2 draw that character as `??`. The add-on no longer adds
  anything: the reader sees the message exactly as the sender wrote it.

What says whether a chat is encrypted is the add-on's notes in the chat (when
the chat is first used in a sign-on and on every change) and `/e2e status`. An
earlier build kept a file per contact for the button under
`%APPDATA%\ICQ E2E\state\`, and the button's script logged to
`%APPDATA%\ICQ E2E\lockbutton.log`; the add-on removes both at sign-on.

## Layout

| Crate | Output | Role |
|-------|--------|------|
| `core` | `icqe2e_core` (lib) | The engine: FLAP stream rewriting, the Olm keys and container, the key directory client, the state file, and the Winsock IAT hook. Everything but `hook`/`log`/`store`/`winhttp` is plain Rust and unit-tested. |
| `loader-tbdiag` | `tbdiag.dll` | ICQ 7.2 loader. ICQ.exe loads `tbdiag.dll` from its own folder at startup; this replacement pins itself, starts the add-on, and answers the `FC*` telemetry probe harmlessly. |
| `loader-msimg32` | `msimg32.dll` | ICQ 6.5 loader. A proxy for `msimg32.dll` (a non-KnownDLL that `MUtils.dll` imports at process init); it forwards the real exports to `system32\msimg32.dll` and starts the add-on. |
| `testhost` | `icqe2e_testhost.exe` | Plays two clients in-process with the add-on on encrypt: a message goes out as a container and comes back exactly as typed. Then the same path through the real Winsock hooks over TLS 1.3 (`over_tls.rs`): sign-in, BOS, E2E, slow delivery, resets and every fail-closed case, including a client set to the TLS-only ports (5194, 5195) with and without the add-on. `--go` runs a sign-in against a local Open OSCAR Server's TLS listener. |

`core/src`, roughly in the order a message travels:

| File | Role |
|---|---|
| `stream.rs` | One direction of a socket as a stream of FLAP frames. Adds, removes and renumbers frames when the crypto path needs it. |
| `session.rs` | One signed-on session: owns the engine, its state file, the publish and refill steps. |
| `crypto.rs` | The `Crypto` trait the stream drives, and `Engine`/`Publisher` over the directory. |
| `keys.rs` | The Olm account and sessions, one-time and fallback keys, the state that survives a restart. |
| `container.rs` | The container: envelope, AEAD, padding, and the ASCII armor that carries it in the message text. |
| `directory.rs` | The key directory API, over WinHTTP or in memory for tests. |
| `store.rs` | The state file, protected with DPAPI. |
| `policy.rs` | The user's control (CHECKLIST 10): the `/e2e` commands, the per-contact setting, downgrade protection, the words of the notes. |
| `safety.rs` | Signal's safety number (numeric fingerprint, version 0) over the account keys and UINs. |
| `rewrite.rs` | Which SNACs are messages, and what happens to each one. |
| `icbm.rs`, `snac.rs`, `text.rs`, `caps.rs` | Decoding, and the add-on's capability and account-key announcement. |
| `hook.rs`, `log.rs` | Winsock, and the log. |
| `calls.rs`, `hook_calls.rs` | Call observation (`calls_log=on`, stage C0 of `docs/e2e/CALLS-RESEARCH.md`): the media sockets of `sipXtapi.dll` / `sipXmediaLib.dll`, each datagram classified (STUN, TURN, RTP, RTCP, other) without content, and the SIP of a call (ICBM channel 6) reduced to its media fields. With `calls_encrypt=on` the same hooks encrypt the media of a call both add-ons agreed on. |
| `callneg.rs` | Call encryption, key agreement (`calls_encrypt=on`, stages C1/C3): offer / answer / confirm as hidden control messages in the E2E session, keyed by the Call-ID; the state of each call; which datagrams belong to an agreed call; the notes. |
| `callmedia.rs` | Call encryption, media (stage C2): HKDF keys per direction, AES-128-GCM over RTP (RFC 7714, explicit rollover counter) and RTCP (SRTCP index), the replay window, and the TURN / ChannelData framing around them. |
| `route.rs` | Which connections go to our server (`server=` in `icq-e2e.ini`), and the TLS port and ALPN they go to instead (docs/e2e/STAGE-TLS.md). |
| `tls.rs`, `hook_tls.rs` | TLS 1.3 as byte buffers (rustls), and TLS at the bottom of the hooked sockets: the pump thread, `recv`/`send`/`FIONREAD`/`closesocket`/`getpeername`, fail closed with a message box; `tls=off` is the opt-out. |

## How a message travels

1. The loader's `DllMain(DLL_PROCESS_ATTACH)` pins the module and calls
   `icqe2e_core::install`, which reads the settings and installs the hooks in
   the networking module (`coolcore59.dll` on 7.2, `coolcore49.dll` on 6.5):
   at once if it is already loaded, else from a loader notification
   (`LdrRegisterDllNotification`) the moment it is mapped, before any of its
   code runs. A polling thread stays as the fallback, and a second thread runs
   the publish and refill steps that come due.
2. The hooks replace that module's Winsock imports: `send`, `recv`, `connect`,
   `closesocket`, `WSAAsyncSelect` and `ioctlsocket`. The imports are by
   ordinal, and an ordinal is turned into a name from the export table of the
   DLL it comes from (`wsock32` and `ws2_32` number 10-12 differently). Every
   `connect` is logged with its target, and the first bytes of each direction
   are classified (FLAP, HTTP, TLS, other) without being changed.
3. The server's MOTD carries a key-directory token in TLV `0x0E2E`. The add-on
   reads it and **never changes that SNAC**: the client's own copy goes out byte
   for byte.
4. The client claims its capability in `LocateSetInfo` (`0x0002/0x0004`). The
   add-on appends the account key to that same SNAC, so the server can tie a
   first publish to this connection. No frame is added and the client sends
   nothing extra.
5. Publishing then runs in the order the API expects: account, device, a pool of
   one-time keys topped up below 25, and a fallback key replaced on its own
   schedule.
6. Outbound, the message's own bytes — not a decoded and re-encoded copy — are
   sealed into a container with the recipient's Olm session, armored as ASCII,
   and put back into the message fragment, which now declares ASCII. The real
   charset rides in the envelope.
   An offline message (`0x0015/0x0002` out, `0x0015/0x0003` in) is treated the
   same way: the server stores whatever text it is given, so the stored text is
   a container and it is opened when it is replayed.
7. Inbound, the armor is found wherever the container was carried, opened, and
   the sender's bytes put back with the charset the envelope carried. A control
   message — an empty container that only advances the ratchet — is removed from
   the stream, along with the server's ack for it.
8. Frames may be added (a note, a control message) and removed (a container this
   device cannot read), so the add-on keeps its own FLAP sequence numbering per
   direction. `ICQE2E_NO_INJECT=1` turns that off, and nothing is added or
   removed at all.
9. A panic inside the add-on falls back to the original Winsock call.

## Settings

Environment variables, read when ICQ starts:

| Variable | Effect |
|----------|--------|
| `ICQE2E_MODE` | `encrypt` (the default), `harness` (stage 2's reversible transform), or `observe` (bytes untouched, log only, never TLS). Debugging only. |
| `ICQE2E_E2E` | Overrides `e2e =` of the ini: `off` is the TLS-only add-on above (log: `mode=plain`). Absent, empty or anything but `off`/`0`/`false`/`no`: on. |
| `ICQE2E_DIRECTORY` | The key directory's base URL. Without one there is nothing to publish to and encryption stays off, said out loud in the log. |
| `ICQE2E_HOME` | Where the state files go. Default: `%APPDATA%\ICQ E2E\`. |
| `ICQE2E_INI` | A different `icq-e2e.ini` to read. Only an override: the add-on finds `icq-e2e.ini` next to the client executable on its own, because the patch writes it there and never tells the add-on where it went. |
| `ICQE2E_PEERS` | `uin1,uin2`: encrypt outbound messages only to these contacts. Unset: to everybody. |
| `ICQE2E_NO_INJECT` | `1`: never add or remove a frame. |
| `ICQE2E_CALLS_LOG` | Overrides `calls_log =` of the ini (see "Call observation" below). `on`/`1`/`true`/`yes` is on; anything else, or nothing, is off. |
| `ICQE2E_CALLS_ENCRYPT` | Overrides `calls_encrypt =` of the ini (see "Call encryption" below). `on`/`1`/`true`/`yes` is on; anything else, or nothing, is **off** (the default). |
| `ICQE2E_AUDITORS` | Overrides `auditors =` of the ini: the key log's auditors to trust, their verifier keys comma-separated as `e2e-kt-auditor -print-key` prints them. Given, exactly these are trusted; absent or empty, the server's are pinned on first use. A key that does not read is left out and named in the start-up line. |
| `ICQE2E_LOG` | File to append the log to (local-time stamps). Lines also go to `OutputDebugString`. Unset: `%LOCALAPPDATA%\icqe2e\icqe2e.log`. |

At start-up the log says where it looked for the ini and whether it was there:

```
Looking for icq-e2e.ini in C:\Program Files (x86)\ICQ7.2: found
```

Then a line per inbound OService SNAC, and one that names the account, so it is
visible which account the add-on thinks it is and whether the server's MOTD
carried a token:

```
IN MOTD: key directory token read (63 byte(s) in 0x000B, 0x0E2E)
IN OService SNAC 0x0001/0x0014 (24 bytes)
IN own user info: account is 100001
[ICQ E2E] signed on as 100001
[ICQ E2E] device keys ready for 100001 (encrypt mode)
[ICQ E2E] Key directory token accepted.
[ICQ E2E] Keys published: 50 one-time key(s) in the directory.
```

That line appears **once**. The add-on checks the directory every two seconds
and tops the one-time pool up only when it has fallen below 25; a check that
finds nothing to send says nothing, so a quiet client and a broken one do not
look alike in the log.

```
OUT capabilities: E2E add-on announced (+16 bytes)
```

Every mode but observe sends the capability. It is how one client learns the
other has the add-on, and without it a contact reads as a plain ICQ client.

The account comes from the server's own user info (`0x0001/0x000F`) on the BOS
connection, not from the command line: both clients sign in over the web API,
so the BOS sign-on carries only a cookie, and ICQ 6.5 sends its UIN on the
authorization connection instead. The MOTD with the token can arrive before
that user info, so a token that has nowhere to go yet is held and applied as
soon as the account is known:

```
[ICQ E2E] MOTD token (63 bytes) held until the account is known
[ICQ E2E] applying the MOTD token that arrived first
```

This is read where frames are reassembled, not off the raw socket bytes: one
`recv` can return the tail of the previous frame, or three frames at once, and
the account must be found in all of those cases.

A service connection's MOTD has no token and says so - `token not present`. That
is the normal case, and it is why the log names the tags a MOTD carried: a BOS
MOTD that should have had one and did not is visible at once.

Nothing is published until the account key has gone out in the client's own
`LocateSetInfo`, because the directory accepts a first publish only for a key
announced on the BOS connection the token belongs to. The MOTD arrives before
that frame, so publishing on the token alone would spend a request the
directory refuses.

The keys, the token and what has been published belong to the account, not to a
connection. An ICQ client has several connections, and only the BOS one carries
the token; with the state on each connection, a service connection's tokenless
MOTD would put the account back to "encryption off" while its keys sat
published in the directory.

Then one line per message:

```
A  OUT peer=100002 ch1/html text="<font sml="default">Привет</font>" encrypted 538 bytes
B  IN  peer=100001 ch1/html text="<font sml="default">Привет</font>" decrypted 80 bytes
```

## Call observation (`calls_log`)

Stage C0 of `docs/e2e/CALLS-RESEARCH.md`: a spike that only looks at voice
and video calls, so the encryption of calls can be designed on what the client
really sends. Off by default; turned on by a line typed by hand into
`icq-e2e.ini` next to `ICQ.exe` (the patch keeps lines it does not own):

```
calls_log = on
```

or `ICQE2E_CALLS_LOG=on`. The start-up line then ends in `calls_log=on (call
media observed)`.

What it does, and nothing more - **no byte of a call is changed, held or
dropped**:

- When `sipXtapi.dll` (6.5, 7.2) or `sipXmediaLib.dll` (7.2) is loaded - at the
  start of a call - its Winsock imports `sendto`, `recvfrom`, `send`, `recv`,
  `WSASendTo`, `WSARecvFrom`, `bind` and `closesocket` are hooked the way the
  networking module's are (by name, ordinals resolved per DLL). Each hook calls
  the original first and returns its answer and last error unchanged.
- Each datagram that went through is classified: STUN (RFC 3489/5389), the
  TURN of ICQ 6.5 (Allocate, Send, Data Indication, Set Active Destination...),
  with the class of what a Send or Data Indication carries, ChannelData, RTP
  (payload type, SSRC, sequence number, payload size), RTCP (packet types) or
  other. The first 8 packets of each flow (socket, remote address, direction)
  get a line each, a new stream (another class, payload type or SSRC) one line,
  and then every 5 seconds a summary per flow: packets, packets/s, kbit/s and
  the largest size per class. A closed socket gives its totals.
- The SIP of a call (ICBM channel 6, TLV 0x0005, on the BOS connection) gives
  one line per message: method or status, CSeq, an 8-digit hash of the
  Call-ID, the user parts of From and To, and per SDP media line the media,
  port, profile (`RTP/AVP` or `RTP/SAVP`), payload types with their `rtpmap`
  names, the `c=` address class, the number of `a=crypto` lines, the ICE
  candidates by type, and the names of the other attributes.
- Never logged: a payload byte, a key, a request URI, a Call-ID, an IP
  address. An address shows as `server`, `private`, `loopback` or `public`
  with its port (`server` is the address `server=` resolves to, where the TURN
  relay is).

```
calls_log=on: call media and signalling are observed (classes, sizes, ports; never content)
call hooks installed in sipXtapi.dll at 0x10000000 (on load): patched [sendto#20, recvfrom#17, ...]; observation only, nothing is changed
call SIP OUT peer=100002 INVITE cseq=1 INVITE call=5d41402a from=100001 to=100002 1834 B sdp: audio port=16384 RTP/AVP pt=[103,0,8] rtpmap=[103=ISAC/16000,...] c=private crypto=0 candidates=3 (host 1, relay 1, srflx 1) attrs=[sendrecv]
call media: sipXtapi.dll bind sock=1234 -> L:16384 (udp)
call media: sipXtapi.dll sock=1234 L:16384 OUT -> server:3478 #1 28 B: TURN/aol Allocate Request (0x0003)
call media: sipXtapi.dll sock=1234 L:16384 OUT -> server:3478 #5 116 B: TURN/aol Send Request (0x0004) carrying 72 B: RTP v2 pt=103 m=0 seq=812 ssrc=0x1a2b3c4d payload=60 B
call media: sipXtapi.dll sock=1234 L:16384 OUT -> server:3478 5.0s: turn-send/rtp 167 pkt (33.4/s, 32.1 kbit/s) max 168 B
```

`docs/e2e/CALLS-RESEARCH.md` section 8 says how the owner runs the test and
what each line answers.

## Call encryption (`calls_encrypt`)

Stages C1-C3 of `docs/e2e/CALLS-RESEARCH.md` (section 9 there has the
details and the live test). **Off by default**, until the C0 data is in;
turned on by a line in `icq-e2e.ini` next to `ICQ.exe`, on **both** clients:

```
calls_encrypt = on
```

The ICQ 6.5 and 7.2 patches write that line themselves: the row "End-to-end
encryption of calls" (job `e2e-calls`, off until ticked) sets it `on`, and
unticking it and applying again sets it `off`. It is written `on` only when
"End-to-end encryption of messages" is ticked too, since calls are keyed in
that session; on its own the row reports that it was left out. Other lines
added by hand (`calls_log`, `tls_pin`, ...) are kept. Without the patch, set
the line by hand or use `ICQE2E_CALLS_ENCRYPT=on`. It needs encrypt mode (not `e2e=off`) and
frames allowed (not `ICQE2E_NO_INJECT`); otherwise the start-up line says
`calls_encrypt=on but inactive`. In effect, the start-up line ends in
`calls_encrypt=on (call media encrypted when both add-ons agree; any other
call untouched)`. It can be combined with `calls_log = on`.

The rule the owner set: **a call is never blocked, and a call that is not
encrypted is exactly what it was without the add-on** - no byte of it
changed. Encryption happens only when both add-ons agreed on keys for that
Call-ID; anything else passes untouched.

- **Key agreement** (`callneg.rs`): when the client sends an INVITE (ICBM
  channel 6) to a contact with E2E keys, the add-on first puts a hidden
  control message in the E2E session: `{call, device, device key, ephemeral
  X25519 key, SDP hash, suites}`. The callee's add-on, when its client sends
  the 200 OK, first answers the same way; the caller confirms with a tag
  only the same keys produce. Each control message goes on the wire before
  the SIP message it belongs to, so the decision needs no timer: no offer at
  the callee's answer, or no answer at the caller's 200 OK, means plain. An
  add-on without call support (older, or `calls_encrypt` off) takes the
  offer as an ordinary control message: nothing shown, nothing answered, and
  the call is plain.
- **Keys**: HKDF-SHA256 over the X25519 secret; salt: the Call-ID's SHA-256,
  both UINs, both device ids and Curve25519 device keys; info: both
  ephemeral keys and a label. Separate keys for caller-to-callee and
  callee-to-caller, and for RTP and RTCP. Dropped 10 s after BYE.
- **Media** (`callmedia.rs`): AES-128-GCM per RFC 7714 - the RTP header in
  the clear as associated data, the payload encrypted, the 16-byte tag, then
  the 4-byte rollover counter (explicit, so loss and reordering never confuse
  the index); RTCP with the first 8 bytes clear and an SRTCP index. 20 bytes
  more per packet. A 128-packet replay window per SSRC and direction. Inside
  TURN Send / Data Indication (the attribute and message lengths fixed),
  RFC 5766 ChannelData, or bare (direct path, or relayed after Set Active
  Destination). STUN and TURN control are never touched.
- **Fail closed, only for an agreed call**: a packet that does not
  authenticate, a replay, or plain RTP in an encrypted call is dropped; a
  packet that cannot be encrypted is dropped, never sent plain; a panic in a
  hook drops the packet of an agreed call and passes anything else.
- The callee holds the call as *answered* until the caller proves it has the
  keys (its confirmation, or its first packet that decrypts); without either
  in 8 s it goes plain too, so the two sides never disagree.
- **Notes** in the chat with the contact: `This call with 100002 is
  end-to-end encrypted ...`, or `This call with 100002 is not end-to-end
  encrypted: <reason>.`; for a contact under `/e2e on` or verified, it adds
  that calls are never blocked and to hang up if the call must stay private.
- **Packet size**: an encrypted datagram over 1472 bytes of UDP payload is
  logged (`... is over 1472 B of UDP payload; sent unfragmented by us`); the
  add-on does not fragment.

In the log, per call (`call=` is the same 8-hex label as the C0 lines):

```
calls_encrypt=on: a call is encrypted end to end when both add-ons agree on its keys through the E2E session; any other call is left exactly as it is
call 5d41402a with 100002 (we call): INVITE out, key offer sent first (local media ports {16384, 16385})
call 5d41402a with 100002 (we call): key answer in; media keys agreed (AES-128-GCM), confirmation queued
call 5d41402a with 100002 (we call): 200 OK in, the call is end-to-end encrypted
call 5d41402a with 100002 (we call): first media packet encrypted (local port 16384, 72 B -> 92 B)
call 5d41402a with 100002 (we call): first media packet decrypted (local port 16384)
call 5d41402a with 100002 (we call): BYE; keys kept 10 s for packets on the way
call 5d41402a with 100002 (we call): forgotten (ended); media: out: 1500 RTP + 30 RTCP encrypted (...); in: ...; dropped: 0 plain, 0 failed authentication, 0 replayed, 0 other
```

## Build

```
cargo build --release
```

Built for `i686-pc-windows-msvc` with a static CRT (see `.cargo/config.toml`),
the same way `tools/icq65/flashplayer` builds its DLL.
`tools/common/Build-Patches.ps1` builds these and copies them next to the patch
exes as `Icqe2eProbe.dll` (7.2) and `Icqe2eProbe-msimg32.dll` (6.5) — gitignored,
and deliberately kept out of the public download zips (owner-only test build).

## Test

```
cargo test --release            # unit, integration and loopback-socket tests (run under WOW64)
cargo run --release -p icqe2e_testhost
```

The test host plays two clients against an in-memory key directory and checks
that the plaintext is nowhere on the wire and that every message comes back
byte for byte.

## How it is checked (owner)

> Run this yourself — do not start the clients from here.

1. Apply the patch with both E2E rows (job keys `e2e` and `e2e-tls`, off by
   default) on both clients, or:

   ```
   ICQ-7.2-Patch.exe -Apply -Root <copy> -Server icq.example.org -Include e2e,e2e-tls
   ICQ-6.5-Patch.exe -Apply -Root <copy> -Server icq.example.org -Include e2e,e2e-tls
   ```

2. Sign both on **without** `-uin` — the account has to come from the server's
   own user info, which is the path that was broken. Each log should show:

   ```
   IN MOTD: key directory token read (63 byte(s) in 0x000B, 0x0E2E)
   IN own user info: account is 100001
   [ICQ E2E] signed on as 100001
   [ICQ E2E] device keys ready for 100001 (encrypt mode)
   [ICQ E2E] Key directory token accepted.
   [ICQ E2E] Keys published: 50 one-time key(s) in the directory.
   ```

   If the token line comes first, `MOTD token (N bytes) held until the account
   is known` and then `applying the MOTD token that arrived first` follow it:
   also correct.

3. Give **both** clients the same `ICQE2E_LOG`, or set it for none of them —
   a client with it and a client without it write two different files and the
   second one looks like it never ran. With nothing set the add-on writes
   `%LOCALAPPDATA%\icqe2e\icqe2e.log`: it always leaves a trail, because a
   silent log and an add-on that never loaded are indistinguishable from the
   outside, and that ambiguity is what made 100002 hard to diagnose.

4. Send a message each way. Both chats show the text normally. The log shows
   `encrypted N bytes` on the way out and `decrypted N bytes` on the way in,
   and the state file `%APPDATA%\ICQ E2E\<uin>.state` exists.

5. Capture the traffic between the client and the server: the message TLV holds
   `IQE1:` and base64, not the text.

6. Send from a client **without** the add-on. The message arrives in clear and
   the chat shows one `[ICQ E2E]` note that messages to that contact go
   unencrypted — once, not per message.

7. Restart one client and send again: the message still opens, which is what the
   state file is for.

8. The commands, in a chat between the two clients: `/e2e status`, `/e2e off`
   (the next message goes in clear, and the far side gets it as a plain message),
   `/e2e on`, and in the chat with a contact without the add-on `/e2e on`
   (the next message is held, not sent). None of the commands reaches the
   contact.

9. Safety numbers, in a chat between the two clients (100001 and 100002 here):
   - `/e2e safety` on both: the same 60 digits, "is not verified". Nothing
     about safety numbers was said before this - not at the first message.
   - `/e2e verify` on 100001: "100002 is marked verified"; `/e2e status` says
     "verified: yes", also after a restart of 100001.
   - Simulate a key change of 100002: close 100002's client; move
     `%APPDATA%\ICQ E2E\100002.state` aside (keep it - it is the device's
     identity); revoke 100002's device in the management API on the server
     (`GET /user/100002/e2e/devices` for the id, then
     `DELETE /user/100002/e2e/devices/<id>` - without that the directory
     refuses the new key with `active_devices`); start 100002 again. It makes
     and publishes a new account key.
   - 100002 writes to 100001: 100001 reads it and gets "Your safety number with
     100002 has changed ... You had verified 100002, so that verification is
     cleared". 100001's reply is NOT sent, with a note naming `/e2e safety`,
     `/e2e verify` and `/e2e accept`; it stays held after a restart.
   - On 100001: `/e2e safety` (new digits, the same as on 100002), then
     `/e2e verify` - the next message goes out encrypted. Or, instead,
     `/e2e accept` - it goes out encrypted and 100002 is unverified.
   - Unverified case: repeat the reset without verifying first - the change
     note appears once, "still encrypted", and nothing is held.

10. "Restore original" (or `-Restore`) removes the add-on and the `icq-e2e.ini`,
   and puts the client back. The state file is left alone on purpose — it is the
   device's identity, and deleting it would make every contact see a new device.

11. Fail closed (TLS row on). With ICQ closed, rename the add-on in the ICQ
   folder (6.5: `msimg32.dll`, 7.2: `tbdiag.dll`, e.g. to `*.off`) and start
   the client: it must **not** sign in (6.5: cannot connect to `domain:5194`;
   7.2: the connection to `domain:5195` is refused), and a capture shows no
   FLAP or HTTP in plaintext to the server - at most a refused SYN to 5195 and
   a TCP connection to 5194 that brings no FLAP hello and is closed by the
   server at the client's first bytes (no UIN, no password digest in
   plaintext: the BUCP challenge request needs the server's hello first). Close ICQ, rename the DLL back, start again: it signs in, over TLS.
   Then untick the TLS row and apply: `AppConfig.xml` has 8082 again (6.5:
   `MCore.dll` is 5190 again) and the client signs in in plaintext with the
   "not encrypted" note.