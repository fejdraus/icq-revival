# ICQ E2E add-on — Phase 1 (pass-through rewrite harness)

An in-process native add-on for the classic ICQ 6.5 and 7.2 clients. This phase
**rewrites the text of every instant message in place** with a trivial,
reversible transform - a marker and ROT13 going out, undone coming in - to prove
that the transport works before any crypto is added: frames grow and shrink,
every length is fixed up, the client's frame count and sequence numbers stay as
they were, and the client notices nothing. **There is no encryption yet.** The
plan of this stage is `docs/e2e/STAGE-2-CLIENT-REWRITE-HARNESS.md`; the overall
design is `docs/e2e/DESIGN.md`.

Phase 0 (observation only) is still there: `ICQE2E_MODE=observe`.

## Layout

| Crate | Output | Role |
|-------|--------|------|
| `core` | `icqe2e_core` (lib) | The engine: stream rewriting over FLAP, SNAC/ICBM/ICQ-offline rewriting, the harness transform, the Winsock IAT hook and the logger. Everything but `hook`/`log` is plain Rust and unit-tested. |
| `loader-tbdiag` | `tbdiag.dll` | ICQ 7.2 loader. ICQ.exe loads `tbdiag.dll` from its own folder at startup; this replacement pins itself, starts the add-on, and answers the `FC*` telemetry probe harmlessly. |
| `loader-msimg32` | `msimg32.dll` | ICQ 6.5 loader. A proxy for `msimg32.dll` (a non-KnownDLL that `MUtils.dll` imports at process init); it forwards the real exports to `system32\msimg32.dll` and starts the add-on. |
| `testhost` | `icqe2e_testhost.exe` | Plays two clients with the add-on in-process: a message goes out rewritten and comes back as typed. |

`core/src`: `stream.rs` (per-direction FLAP stream rewriter), `rewrite.rs`
(message SNACs rebuilt with new text), `harness.rs` (the transform), `caps.rs`
(the add-on's capability), `config.rs`
(the environment variables), `engine.rs` (both directions of many sockets behind
a simple API), `icbm.rs`/`snac.rs`/`text.rs` (decoding for the log), `hook.rs`
(Winsock), `log.rs`.

## What is rewritten

- Outbound ICBM `0x0004/0x0006` and inbound `0x0004/0x0007`: channel 1 (fragment
  1 of TLV 0x0002, in its own charset - ASCII/UTF-8, UCS-2 BE or Latin-1) and
  channel 2 type-2 plain text under the ICQ server-relay capability (TLV 0x2711).
- Inbound ICQ `0x0015/0x0003` offline messages (`0x0041`).

- The capability `CapE2EEncrypt` (`0946E2E1-4C7F-11D1-8222-444553540000`) is
  appended to the client's capability list in `LocateSetInfo` (`0x0002/0x0004`);
  contacts announcing it are read from "buddy arrived" (`0x0003/0x000B`) and
  logged (`contact 100002 announces the E2E add-on`).

Outbound text `T` becomes `[e2e-harness] ` + ROT13(`T`); ROT13 changes only ASCII
letters outside HTML tags and entities, and the marker goes after any leading
tags, so HTML and `<FONT sml>` smileys stay intact. Inbound text carrying the
marker is restored; text without it (a contact without the add-on) is left
alone. Everything else - typing, acks, presence, file transfer, tZers, login -
passes byte for byte, and so does any connection that does not open like OSCAR.

## How it works

1. The loader's `DllMain(DLL_PROCESS_ATTACH)` pins the module and calls
   `icqe2e_core::install`, which reads the settings and starts a worker thread.
2. The thread waits for the networking module (`coolcore59.dll` on 7.2,
   `coolcore49.dll` on 6.5) to load, then IAT-patches that module's `wsock32`
   imports: `send`, `recv`, `connect`, `closesocket`, `WSAAsyncSelect`, and
   `ioctlsocket` (6.5 only).
3. `send` takes the client's bytes whole, rewrites complete frames (holding a
   partial one until the rest comes) and pushes the result out, waiting for room
   on `WSAEWOULDBLOCK`; the client is told all its bytes went.
4. `recv` reads the socket, rewrites, and hands the client what is ready. With
   only part of a frame so far it answers `WSAEWOULDBLOCK`; with more ready than
   the client's buffer holds, it keeps the rest and posts a synthetic `FD_READ`
   to the window given to `WSAAsyncSelect`. `ioctlsocket(FIONREAD)` counts the
   bytes held.
5. A panic inside the add-on falls back to the original Winsock call.

## Settings (environment, read when ICQ starts)

| Variable | Effect |
|----------|--------|
| `ICQE2E_LOG` | File to append the log to (local-time stamps). Lines also go to `OutputDebugString`. Unset: no file. |
| `ICQE2E_PEERS` | `uin1,uin2`: rewrite outbound messages only to these contacts. Unset: to everybody. |
| `ICQE2E_MODE` | `observe`: Phase 0 - bytes untouched, log only. Anything else: the harness. |

A log line per message, for example:

```
OUT peer=100002 ch1/html text="<b>Hello</b>" rewritten +14 bytes wire="<b>[e2e-harness] Uryyb</b>" via=203.0.113.5:5190
IN  peer=100002 ch1/html text="<b>Hi</b>" restored -14 bytes wire="<b>[e2e-harness] Uv</b>" via=203.0.113.5:5190
```

## Build

```
cargo build --release
```

Built for `i686-pc-windows-msvc` with a static CRT (see `.cargo/config.toml`),
the same way `tools/icq65/flashplayer` builds its DLL. `tools/common/Build-Patches.ps1`
builds these and copies them next to the patch exes as `Icqe2eProbe.dll`
(7.2) and `Icqe2eProbe-msimg32.dll` (6.5) — gitignored, and deliberately kept
out of the public download zips (owner-only test build).

## Test

```
cargo test --release            # unit, integration and loopback-socket tests (run under WOW64)
cargo run --release -p icqe2e_testhost
```

## Enabling in the client (owner test)

Use the patch's opt-in row **"E2E encryption test harness (Phase 1 ...)"** (job
key `e2e-probe`, off by default), or a scripted run:

```
ICQ-7.2-Patch.exe -Apply -Root <copy> -Server icq.example.org -Include e2e-probe
ICQ-6.5-Patch.exe -Apply -Root <copy> -Server icq.example.org -Include e2e-probe
```

With the add-on on both sides, messages read normally (HTML, smileys, Cyrillic,
offline messages), typing notifications and acks work, and the log shows the
`wire=` form. With it on one side only, the other side sees `[e2e-harness] ` and
ROT13 text - the proof that the wire really changed. Use `ICQE2E_PEERS` to keep
other contacts out of the test. "Restore original" (or `-Restore`) removes the
add-on and puts the client back.
