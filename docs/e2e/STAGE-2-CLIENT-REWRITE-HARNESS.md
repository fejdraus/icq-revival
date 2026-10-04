# Stage 2 - Client: pass-through rewrite harness (DESIGN.md Phase 1)

> **Historical completed stage plan.** This records the plan and decisions
> of a development stage that is finished. It is kept for history and
> rationale and is **not a specification of the current add-on**; later
> stages and the audits changed several of its rules, and its "decisions
> already made" are not current requirements. For current behaviour and
> security rules use `tools/icq-e2e/README.md`, `docs/e2e/CHECKLIST.md`,
> `docs/e2e/AUDIT-2026-10.md` and the source and tests.

Self-contained task for one session. Client add-on only (`tools/icq-e2e`, Rust,
i686), plus the wording of the two patches' opt-in row. No server change, no
crypto.

## Goal

Phase 0 (commit `b778d29`) proved the load hook, the networking-module
resolution, FLAP reassembly and message-text extraction on ICQ 6.5 and 7.2 - but
it only *watched*: the hooks called the original `send`/`recv` first and looked at
the bytes afterwards. Phase 1 (DESIGN.md section 11) makes the add-on **rewrite the
message text in place**, in both directions, with a trivial reversible transform,
to prove that everything Phase 2 needs from the transport works before any crypto
is added:

- a FLAP frame whose payload grows is re-emitted with the right length and the
  client's own sequence number (N frames in, N frames out - DESIGN.md section 6);
- every nested length (TLV, fragment, little-endian ICQ fields) is fixed up;
- the client neither notices nor stalls: typing, acks, HTML, smileys, offline
  messages, file transfer and sign-in all behave as before.

Background: `docs/e2e/DESIGN.md` sections 4-6 and 10.

## Decisions (do not reopen)

- **The transform.** Outbound message text `T` becomes `M + rot13(T)` where `M` is
  the ASCII marker `[e2e-harness] ` and ROT13 touches only ASCII letters **outside
  HTML markup** (inside `<...>` tags and `&...;` entities nothing changes). The
  marker goes at the first text position - after the leading tags - so an HTML
  message stays well-formed. Inbound, text carrying the marker at that position
  has it removed and ROT13 applied again (ROT13 is its own inverse and does not
  move tags, so the position is found the same way on both sides). Text without
  the marker is passed through untouched.

  Why this one: it changes the length (the point of the exercise), it changes the
  content (a peer *without* the add-on visibly sees `[e2e-harness] Uryyb`, which
  proves the bytes on the wire were really rewritten), and it keeps smileys and
  formatting intact even for that peer. It works on **code units**, not decoded
  text: bytes for ASCII/UTF-8/Latin-1/code-page text, big-endian `u16` for UCS-2.
  ROT13 on ASCII letters is an involution on either, so the round trip is exact
  whatever the charset and no decoding can lose anything.
- **What is rewritten** (and only this):
  - outbound `ICBM 0x0004/0x0006` channel 1: fragment `ID==1` text of TLV 0x0002;
  - outbound `ICBM 0x0004/0x0006` channel 2 with capability
    `09461349-4C7F-11D1-8222-444553540000` (ICQ server relay): the text of a
    plain type-2 message (`msgType 0x01`) inside rendezvous TLV 0x2711;
  - inbound `ICBM 0x0004/0x0007`, the same two forms (undo);
  - inbound `ICQ 0x0015/0x0003` (DB reply) carrying `0x0041` offline message,
    `msgType 0x01` (undo). Phase 0 matched subgroup `0x0002` (the *request*), so
    offline replies were never logged; fixed here.

  And one non-message rewrite: the add-on's capability `CapE2EEncrypt`
  (`0946E2E1-4C7F-11D1-8222-444553540000`, DESIGN.md section 7) is appended in
  place to the capability list (TLV 0x0005) of every outbound
  `LocateSetInfo` (`0x0002/0x0004`) that carries one - again on each resend, as
  a mood change resends the list. Contacts announcing it are read from inbound
  "buddy arrived" (`0x0003/0x000B`, user info TLV 0x000D) and logged when that
  changes. Outbound rewriting is not made to depend on it in this phase, so a
  contact without the add-on still visibly receives the rewritten form; stage 3
  sends clear text to such contacts (CHECKLIST 3.7).

  Everything else - typing (`0x0004/0x0014`), acks, presence, feedbag, avatars,
  rendezvous proposals for files/voice, tZers and other plugin messages, login -
  goes through byte for byte.
- **Modes.** `ICQE2E_MODE=observe` gives exactly the Phase 0 behaviour (original
  call first, bytes untouched, log only) as a kill switch; anything else - and the
  default - is the rewrite harness. `ICQE2E_PEERS=uin1,uin2` limits outbound
  rewriting to those contacts, so a test client does not scramble messages to
  everybody else; inbound undo always applies (it only acts on the marker).
- **Stream detection.** A socket is treated as FLAP only if its first frame in that
  direction is a channel-1 frame starting with FLAP version `00 00 00 01`, and every
  later header has marker `0x2A` and channel 1-5. Anything else (direct
  connections, file transfer, proxies) is switched to raw pass-through at once,
  with any bytes held so far released unchanged; from then on the original
  `send`/`recv` are called directly.
- **Size guard.** If a rewrite would push a frame past the `u16` FLAP limit or the
  message text past 7 000 bytes, the frame is sent unchanged and the log says so
  (Phase 2 chunking - DESIGN.md section 10 - is out of scope).

## Hook mechanics

The Winsock imports of both networking modules, read from the pristine files
(`coolcore59.dll` 3525, `coolcore49.dll`), by `wsock32` ordinal: 1, 2, 3, 4, 5, 6,
8, 9, 11, 12, 13, 15, 16, 17, 19, 20, 21, 23, 101, 103, 108, 111, 115, 116, 52, 57
- plus 10 (`ioctlsocket`), 51, 55, 56 in 6.5 only. No `select` (18), no
`WSARecv`/`WSASend`. So the client is non-blocking `WSAAsyncSelect` Winsock 1.1,
and the hooks are:

| Ordinal | Function | Phase 1 role |
|---------|----------|--------------|
| 19 | `send` | feed the client's bytes to the outbound rewriter, send what it emits, report the client's whole length as sent |
| 16 | `recv` | read from the socket into the inbound rewriter, hand the client what it emits |
| 4 | `connect` | peer address for the log (unchanged) |
| 3 | `closesocket` | drop the socket's state (unchanged) |
| 101 | `WSAAsyncSelect` | remember the window, message and events of the socket |
| 10 | `ioctlsocket` | `FIONREAD` counts bytes the add-on holds for the client; `FIONBIO` recorded (6.5 only) |

The rules that keep the client from noticing:

- **`send`**: the client's bytes are accepted whole (return value = its length);
  complete frames are emitted rewritten, a partial frame is held until the rest
  arrives in a later `send`. Emitted bytes are pushed out with the original
  `send`; on `WSAEWOULDBLOCK` the hook waits for the socket to become writable
  (`select`, bounded) and continues, so bytes are never reordered or dropped. A
  hard error is returned to the client with its error code, as the original would.
- **`recv`**: bytes the add-on already holds for the client are served first; only
  when there are none does it read from the socket. A partial frame is held and
  the client gets `WSAEWOULDBLOCK` - on a non-blocking socket that is the normal
  "nothing yet" answer, and Winsock posts the next `FD_READ` when more arrives.
  When the client's buffer is smaller than what is held, the rest stays held and
  the hook **posts a synthetic `FD_READ`** to the window registered through
  `WSAAsyncSelect`, because Winsock will not post one for data it no longer has.
  End of stream is passed on after held bytes are delivered. `MSG_PEEK` is served
  from the held bytes without consuming; `MSG_OOB` goes straight to the original.
- `WSAGetLastError` is preserved across everything the hook does after the
  original call returned (it is the thread's `GetLastError`, which a log write can
  change).
- Separate locks per socket and direction, so a `recv` waiting on one thread never
  blocks a `send` on another.
- Every hook body runs under `catch_unwind`; a panic in the add-on falls back to
  the original call where it still can.

## Code layout (`tools/icq-e2e/core`)

- `harness.rs` - the transform over code units (`u8`/`u16`): marker position,
  markup-aware ROT13, `apply`/`undo`. Pure, unit-tested.
- `rewrite.rs` - SNAC-level rewriting: parse a message SNAC, rebuild it with new
  text and every length fixed up, or report "not a message"; produces the log
  record. Pure, unit-tested against hand-built frames.
- `stream.rs` - per-direction stream rewriter: FLAP detection/validation,
  reassembly, emitting frames (rewritten or verbatim), raw pass-through, flush at
  end of stream. Replaces Phase 0's `flap::Reassembler`. Pure, unit-tested,
  including arbitrary split points.
- `engine.rs` - keeps the Phase 0 API (`on_send`/`on_recv` returning log lines)
  on top of `stream.rs` in observe mode, so the test host and the existing tests
  still run.
- `caps.rs` - `CapE2EEncrypt`: appended to `LocateSetInfo`, read from "buddy
  arrived". Pure, unit-tested.
- `config.rs` - `ICQE2E_MODE`, `ICQE2E_PEERS`.
- `hook.rs` - the Winsock hooks above; `icbm.rs`/`snac.rs`/`text.rs` stay the
  decoders for the log.

## Also in this stage

- Patch rows (`tools/patcher/Icq65`, `Icq72`) and the after-apply notes say
  "Phase 1 test harness" and name the two variables; the job key `e2e-probe`, the
  shipped file names and the version-resource identity stay, so an installed
  Phase 0 DLL is recognised and replaced. `FileDescription`/version of both DLLs
  bumped to 0.2.0.
- `tools/icq-e2e/README.md` describes Phase 1 and the owner test below.
- `Build-Patches.ps1` comment updated; the DLLs are rebuilt next to the patches.

## Out of scope

Crypto, the `IQE1` container, the key-directory client,
chunking, the management page - Phase 2 and later.

## Done when

- `cargo test --release` passes in `tools/icq-e2e`: the transform round-trips for
  every charset, a rewritten frame decodes back to the original through the
  inbound path, lengths and sequence numbers are right, frames split at every byte
  boundary give the same output, non-FLAP streams pass unchanged, the offline
  reply is found. `cargo run --release -p icqe2e_testhost` shows a
  message going out rewritten and coming back restored.
- The patches and DLLs build (`tools/common/Build-Patches.ps1`).
- **Owner test (not run by the agent)**: apply the patch with `e2e-probe` to two
  clients (6.5 and 7.2), set `ICQE2E_LOG`, and check with both add-ons in place:
  messages both ways read normally, with HTML, smileys and Cyrillic; typing
  notifications and delivery acks still work; offline messages arrive readable;
  the log shows `wire="[e2e-harness] ..."` for each message, `OUT capabilities:
  E2E add-on announced` at sign-on, and `contact <uin> announces the E2E add-on`
  for the other test client; sign-in, status and mood changes, and the contact
  list behave as before with the extra capability. With the add-on on one
  side only, the other side sees `[e2e-harness] ` and ROT13 text - proof that the
  wire really changed. `ICQE2E_MODE=observe` brings back Phase 0 behaviour.
- Committed in the repository's style (English message, no AI attribution lines)
  once the owner has checked it in the clients.

## Owner test result (2026-10-01)

ICQ 6.5 and ICQ 7.2 on two machines, both with the add-on: passed.

- Hooks installed in `coolcore49.dll` (6 hooks) and `coolcore59.dll` (5; 7.2
  does not import `ioctlsocket`). Both announced `CapE2EEncrypt` and saw it on the
  other side; sign-in, status and mood unaffected.
- Messages both ways with HTML, bold, Cyrillic and smileys: `rewritten +28 bytes`
  on the sender, `restored -28 bytes` on the receiver, shown exactly as sent.
  Typing notifications and delivery acks work.
- With the receiver in `ICQE2E_MODE=observe`, ICQ 6.5 showed
  `[e2e-harness] Uryyb, мир` - the text really crossed the server rewritten, and
  the server and the client took the rewritten HTML.
- An offline message was stored rewritten and restored when 6.5 signed on. 6.5
  fetches offline messages over ICBM, so it arrived as `ch1/html`, not through
  the ICQ `0x0041` reply.
- Seen on the wire only: ROT13 also changes letters in a smiley's text between
  `<FONT sml>` tags (`O:-)` to `B:-)`); restored exactly, but a client without
  the add-on shows the changed text.
- Not tried in the clients: 6.5 to 6.5 over channel 2 (type-2); covered by tests.

## Against the checklist (`docs/e2e/CHECKLIST.md`)

This stage carries no crypto, so most rows belong to stage 3 and later. What it
touches:

- **3.2 (encrypt the whole content)** - the transport part is done: the whole text
  fragment, HTML and `<FONT sml>` included, is replaced and restored exactly, in
  every charset. The harness transform itself leaves markup readable on purpose
  (so a peer without the add-on still renders it); stage 3 must encrypt the
  fragment as a whole and must not reuse that shortcut.
- **3.7 (mark the scheme, readable hint)** - the stage-2 part: the
  `[e2e-harness] ` marker is the readable line a client without the add-on shows,
  the add-on acts only on marked text, and `CapE2EEncrypt` is announced in the
  client's capability list and read from contacts'. Still for stage 3: the real
  container's hint line and choosing clear text for contacts without the
  capability. Whether the stock clients and the server accept the extra
  capability is checked in the owner test (DESIGN.md section 12, risk 2).
- **2.5, 2.6 (no garbage, no automatic re-key)** - groundwork: unmarked or
  unparsable text passes untouched, and nothing the add-on does starts a new
  exchange.
- **7.1** - closed on the server: the token still travels in clear on the BOS
  connection this add-on sits on, but setting an account key now also needs the
  key announced on that connection (TLV `0x0E2E` in `LocateSetInfo`,
  KEY-DIRECTORY-API.md 3.3). The add-on appends it in stage 3, next to its
  capability.

## Found on the way

- Phase 0 looked for offline messages in ICQ subgroup `0x0002` (the client's
  request); the server answers in `0x0003`, so they were never logged. Fixed, with
  a test built on the server's own layout (`foodgroup/icq.go` `OfflineMsgReq`).
- Phase 0 read channel-2 text only in the tZer plugin layout; plain type-2
  messages are now read by their real layout, the plugin form stays as a fallback.
- The server announced `MaxIncomingICBMLen` 8000 but did not enforce it; it
  does now (CHECKLIST.md 3.9). The 7 000-byte guard keeps a rewritten message
  below that.
