# ICQ E2E add-on — Phase 0 (observation only)

An in-process native add-on for the classic ICQ 6.5 and 7.2 clients. This first
phase is **observation only**: it watches the client's own OSCAR (BOS) traffic,
decodes instant-message text, and writes it to a log. **Every byte reaches the
client and the server unchanged — there is no encryption and no rewriting in
this phase.** It exists to prove the load hook, the networking-module
resolution, FLAP reassembly and ICBM/offline text extraction on both clients,
before any crypto is added in later phases (see the E2E design document).

## Layout

| Crate | Output | Role |
|-------|--------|------|
| `core` | `icqe2e_core` (lib) | The engine: FLAP reassembly, SNAC/ICBM/ICQ-offline parsing, charset decode, the Winsock IAT hook and the logger. Pure-Rust parsing is unit-tested; only `hook`/`log` touch Windows. |
| `loader-tbdiag` | `tbdiag.dll` | ICQ 7.2 loader. ICQ.exe loads `tbdiag.dll` from its own folder at startup; this replacement pins itself, starts the observer, and answers the `FC*` telemetry probe harmlessly. |
| `loader-msimg32` | `msimg32.dll` | ICQ 6.5 loader. A proxy for `msimg32.dll` (a non-KnownDLL that `MUtils.dll` imports at process init); it forwards the real exports to `system32\msimg32.dll` and starts the observer. |
| `testhost` | `icqe2e_testhost.exe` | Drives the engine in-process with synthetic frames and prints the decoded lines. |

## How it works

1. The loader's `DllMain(DLL_PROCESS_ATTACH)` pins the module and calls
   `icqe2e_core::install`, which starts a worker thread.
2. The thread waits for the networking module (`coolcore59.dll` on 7.2,
   `coolcore49.dll` on 6.5) to load, then IAT-patches that module's import
   thunks for `wsock32.dll!send/recv/connect/closesocket`.
3. Each hook calls the original first, returns its result verbatim, and then —
   inside `catch_unwind`, so a parsing bug can never reach the host — feeds the
   observed bytes to the engine.
4. The engine reassembles FLAP frames per socket, parses ICBM
   `ChannelMsgToHost`/`ChannelMsgToClient` (channel 1 text/HTML and channel 2
   type-2 text) and ICQ offline replies, and logs one line per message:
   direction, peer, channel/form, decoded text.

## Logging

Set the `ICQE2E_LOG` environment variable to a file path before starting the
client; each decoded message is appended there with a local-time stamp. Lines
also go to `OutputDebugString` (visible in DebugView). With no `ICQE2E_LOG`, no
file is opened.

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
cargo test --release            # unit + integration tests (run under WOW64)
cargo run --release -p icqe2e_testhost
```

## Enabling in the client (owner test)

Use the patch's opt-in row **"E2E encryption observer (Phase 0, log-only)"**
(job key `e2e-probe`, off by default), or a scripted run:

```
ICQ-7.2-Patch.exe -Apply -Root <copy> -Server icq.example.org -Include e2e-probe
ICQ-6.5-Patch.exe -Apply -Root <copy> -Server icq.example.org -Include e2e-probe
```

"Restore original" (or `-Restore`) removes the observer and puts the client
back. Set `ICQE2E_LOG` before starting the client to capture the log.
