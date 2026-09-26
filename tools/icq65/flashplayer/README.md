# FlashPlayerControl.dll for ICQ 6.5 (Ruffle)

ICQ 6.5 (build 2024) shows tZers, the short animations with sound over the
message window, through `FlashPlayerControl.dll`. The original is Softanics
Flash Player Control, a wrapper around the Adobe Flash ActiveX control, which no
longer exists. This folder builds a drop-in replacement that plays the same SWF
movies with [Ruffle](https://github.com/ruffle-rs/ruffle), the open-source Flash
emulator. The client needs no changes beyond this DLL and a per-user type
library registration.

This is a prototype. It plays tZers; it does not cover everything the original
DLL exported.

## What the client expects

These facts come from a static analysis of `MCore.dll`, `MUIMessage.dll` and
`MUIUtils.dll`, which delay-load the DLL by bare name.

- **Exports**, all `__stdcall` and undecorated. Between them, the three modules
  import exactly these ten: `FPCIsFlashInstalled`, `RegisterFlashWindowClass`,
  `UnregisterFlashWindowClass`, `FPC_LoadMovieW`, `FPC_Play`, `FPC_Stop`
  (stop and rewind), `FPC_StopPlay` (pause), `FPC_IsPlaying`,
  `FPC_UpdateWindow` and `FPCSetEventListener`. The DLL also exports
  `DllRegisterServer` and `DllUnregisterServer`.
- **Window class** `FlashPlayerControl` (`CS_GLOBALCLASS | CS_DBLCLKS`). The
  client creates it as a layered popup (exstyle `0x08080080`, style
  `0x90000000`), subclasses it, sizes it, then calls `FPC_UpdateWindow`. Frames
  go to the window through `UpdateLayeredWindow` with per-pixel premultiplied
  alpha. The movie's background colour is not drawn (Flash `wmode=transparent`).
  The movie is scaled to the client area (`showAll`).
- **Window messages**:
  - `0x1401` queries an interface through `{IID; void* pv; HRESULT hr}`.
  - `0x1404` returns a new 32bpp top-down DIB of the current frame; the caller
    frees it.
  - `0x1405` is a no-op.
- **COM object**. `IShockwaveFlash` is a dual interface with the full vtable in
  Flash's method order. The client calls `get_TotalFrames` (+0x20) and
  `GotoFrame` (+0x88); a unit test checks every slot against the type library.
  The object also implements `IConnectionPointContainer` and a connection point
  for `_IShockwaveFlashEvents`. The DLL fires `OnReadyStateChange` (-609) with 3
  and then 4 after a load. It fires `FSCommand` (0x96) for every `fscommand`
  from the movie.
- **Type library**. The client's ATL `IDispEventImpl` sinks call
  `LoadRegTypeLib({D27CDB6B-AE6D-11CF-96B8-444553540000}, 1, 0)`. The DLL
  carries a compatible library as resource `TYPELIB #1`, built from
  `typelib/flash.idl`. `DllRegisterServer` registers it for the current user
  (`RegisterTypeLibForUser`, HKCU only), and `DllUnregisterServer` removes it.

`FPC_IsPlaying` returns `VARIANT_TRUE` from `FPC_Play` (also while the movie
still loads) until the movie has finished, and `VARIANT_FALSE` from then on.
A movie counts as finished when it sends `fscommand("animEnd")`, or when its
root timeline has stood on the last frame for 250 ms. The DLL stops a tZer
there instead of looping it. A root timeline stopped mid-movie does not count:
some tZers stop it while a nested clip plays, and the clip moves it on.
`FPC_Stop`, `FPC_StopPlay` and `GotoFrame` make it `VARIANT_FALSE` at once, and
so does a movie that fails to load.

## Threads

The client uses the DLL from more than one thread. tZers play on the UI thread.
Flash avatars (BART type 8) are rendered by MCore's FlashSnapshotImgService
job on a worker thread. That job creates an ownerless, offscreen window, runs
its own `GetMessage` loop, takes one `0x1404` snapshot and destroys the window;
then the thread may exit. Its COM apartment is unknown. So:

- **Each window belongs to the thread that created it.** Its player, timer and
  events all run on that thread. An export called for the window from another
  thread returns `RPC_E_WRONG_THREAD` at once. The DLL never sends messages
  across threads and holds no lock while it waits for anything.
- **One GPU device for the whole process.** It is opened on a thread of its own,
  `FlashPlayerControl gpu`, which never exits, and it is never destroyed.
  Earlier builds kept one device per thread in a thread-local. When an avatar
  job's thread exited, the DLL's TLS callback destroyed that device under the
  loader lock. The Vulkan driver's `vkDestroyInstance` then waited for its own
  thread, which needed the loader lock to exit. That deadlock froze the whole
  client.
- **One sound output for the whole process.** The `FlashPlayerControl audio`
  thread owns the cpal stream and never exits. Each player gets its own mixer,
  and the stream sums them. So no COM initialisation and no audio teardown
  happen on the client's threads. A window created with no owner or parent
  (the snapshot service) plays without sound.
- **Loads run in the background.** A load thread fetches the movie and waits
  for the GPU device and the sound output. The window's thread then only
  builds the player (about 30-40 ms for a tZer), so the UI thread never waits
  for the device to open.
- **Nothing heavy runs at thread exit.** If a thread exits with windows it has
  not destroyed, their players are leaked rather than torn down under the
  loader lock.

## How it works

- `src/lib.rs` holds the exports and the window class.
- `src/instance.rs` has the per-window state and the window procedure. It
  drives the player with a 10 ms timer on the window's thread and presents
  frames with `UpdateLayeredWindow`.
- `src/movie.rs` wraps the Ruffle player. It renders offscreen with
  `ruffle_render_wgpu` into a texture, reads the pixels back, and converts them
  from premultiplied RGBA to BGRA.
- `src/gpu.rs` opens the shared device on its own thread. It tries, in order:
  1. Vulkan.
  2. WARP: DX12 on Windows' software rasterizer, the only renderer a virtual
     machine without a GPU has.
  3. OpenGL, only when DXGI lists a hardware GPU. Without one, OpenGL would be
     Windows' GDI OpenGL 1.1, which cannot run Ruffle.

  A device counts only when Ruffle's shaders build on it, including the
  multisampled ones, and when two 256x256 test frames read back right.
  Otherwise the next option is tried.
- `src/audio.rs` sends sound to the default output device through cpal
  (WASAPI) from its own thread, mixing all players.
- `src/com.rs` implements `IShockwaveFlash` and the connection point by hand.
- `src/typelib.rs` loads the embedded type library and handles its
  registration.
- `src/fetch.rs` reads local paths, `file:` URLs and `http(s)` URLs (WinINet)
  on a background thread.

Ruffle is pinned to tag `nightly-2026-09-26`, commit
`5455c72da5472a24cc293a7b13643709e9469587`.

`vendor/wgpu-hal` is wgpu-hal 30.0.1 with one fix (see `[patch.crates-io]` in
`Cargo.toml`). Its DX12 backend aligned pipeline-state-stream subobjects to 8
bytes. D3D12 aligns them to pointer size, which is 4 on 32-bit, so every DX12
pipeline in this x86 DLL failed with `E_INVALIDARG`, WARP included. Drop the
patch once wgpu fixes `RenderPipelineStateStream::add_object`.

## When something fails

No failure may crash the client:

- **Panics are caught.** Every export, COM method, the window procedure and
  every thread of the DLL catch panics, so an unwinding panic never reaches
  the client, where it would abort the process. Panics are logged with their
  source location. The release profile keeps `panic = "unwind"`.
- **wgpu errors are logged, not raised.** wgpu's own error handler (which
  panics) is replaced by one that logs.
- **A failing movie stops.** A movie whose playing or drawing panics stops its
  timer, leaks its player, and counts as ended (`FPC_IsPlaying` false). The
  window stays valid.
- **`0x1404` always returns a bitmap.** When nothing can be drawn it is a
  fully transparent one of the window's size.
- **No renderer at all:**
  - Loads end without events, and `FPC_IsPlaying` turns false.
  - `FPCIsFlashInstalled` returns FALSE, so the client shows static pictures
    and hides tZers.
  - `FPCIsFlashInstalled` runs on the UI thread and waits at most 250 ms for
    the probe. An undecided probe counts as TRUE: saying TRUE and failing
    later is harmless (see the points above), but a wrong FALSE would hide
    tZers and Flash avatars on a working machine.

## Build

You need Rust (rustup) and Visual Studio or the Build Tools with the C++
workload and a Windows SDK. `rust-toolchain.toml` selects stable Rust and the
`i686-pc-windows-msvc` target. `.cargo/config.toml` makes it the default
target and links the C runtime statically. ICQ is 32-bit, so the DLL must be
too.

```
cd tools\icq65\flashplayer
cargo build --release
```

The output is `target\i686-pc-windows-msvc\release\FlashPlayerControl.dll`
(about 15 MB). The first build compiles Ruffle and takes a few minutes.

`typelib\flash.tlb` is checked in. After you edit `typelib\flash.idl`,
rebuild it with MIDL:

```
typelib\build-tlb.cmd
```

## Test without ICQ

Run the unit test first. It checks that every vtable slot takes as many stack
bytes as the type library says, and that +0x20 and +0x88 are `TotalFrames` and
`GotoFrame`:

```
cargo test --release --lib
```

`examples/host/` is a 32-bit program that drives the DLL the way the client
does. It loads the DLL with `LoadLibrary`, creates the layered popup over an
owner window and subclasses it. It gets `IShockwaveFlash` through `0x1401` and
advises a logging event sink. Then it loads a movie, plays it and polls
`FPC_IsPlaying` every 100 ms. It also takes a screenshot and `0x1404`
snapshots, and exercises `GotoFrame`, `Stop` and `StopPlay`:

```
cargo build --release --example host
set H=target\i686-pc-windows-msvc\release
%H%\examples\host.exe %H%\FlashPlayerControl.dll play C:\path\kisses.swf C:\out
%H%\examples\host.exe %H%\FlashPlayerControl.dll two C:\path\kisses.swf http://127.0.0.1:8765/kisses.swf C:\out
%H%\examples\host.exe %H%\FlashPlayerControl.dll reg
%H%\examples\host.exe %H%\FlashPlayerControl.dll check
%H%\examples\host.exe %H%\FlashPlayerControl.dll unreg
```

`reg` writes the type library registration to HKCU and `unreg` removes it.
`unreg` removes any registration of this LIBID for the user, including the
patch's registration of the installed client. Re-register the client afterwards.

`avatars` reproduces the client's avatar snapshot jobs. Each job runs on a
worker thread in the given COM apartment (`mta`, `none`, `sta`, or `mixed` to
alternate), with its own `GetMessage` loop. It creates an ownerless 87x109
window offscreen, advises a sink that posts `0x7BA`/`0x7BB` on ready states 3
and 4, and loads the SWF over http. It then calls `GotoFrame(total/2)`, saves
the `0x1404` bitmap as PNG and tears everything down. `spawn` starts a thread
per job, which then exits; `pool` reuses the same threads. Meanwhile the UI
thread replays a tZer. The host also checks that exports called from the wrong
thread fail, and reports the longest message the UI thread handled:

```
%H%\examples\host.exe %H%\FlashPlayerControl.dll avatars http://127.0.0.1:8766 C:\out mixed 3 2 spawn C:\path\kisses.swf pirate.swf robot.swf ...
```

(Serve the avatar SWFs, for example `deploy/oscar-legacy-web/avatars`, with
`python -m http.server 8766`.)

If a run hangs, `host.exe dumpstacks <pid> <symbol path>` attaches from outside
and prints every thread's stack and the owner of the loader lock. Build with
`cargo build --profile diag` to get a PDB for the DLL.

## Try it in ICQ 6.5

The ICQ 6.5 patch does all of this when "tZers without Flash" is ticked
(`tools\patcher\Icq65\Icq65Client.cs`): it takes this DLL from next to
`ICQ-6.5-Patch.exe`, where `tools\common\Build-Patches.ps1` puts it as
`FlashPlayerControl-Ruffle.dll` (a name of its own, so a patch dropped into the
ICQ folder cannot mistake the client's original for it), copies it into the
client as `FlashPlayerControl.dll`, tells it from the original by the ProductName and
InternalName of its version resource (`typelib\resource.rc`), and runs the
same `regsvr32` lines. By hand:

Use a copy of the ICQ 6.5 folder, not the installed one.

1. Copy `FlashPlayerControl.dll` over the file of the same name in the copied
   folder. Keep the original somewhere else.
2. Register the type library for your user. This writes to HKCU only and
   needs no administrator rights:

   ```
   %SystemRoot%\SysWOW64\regsvr32.exe /s "C:\path\to\ICQ copy\FlashPlayerControl.dll"
   ```

   The registration stores the DLL's full path. If you move the folder,
   register again.
3. Start `ICQ.exe` from the copy and send or receive a tZer.

To undo the registration:

```
%SystemRoot%\SysWOW64\regsvr32.exe /s /u "C:\path\to\ICQ copy\FlashPlayerControl.dll"
```

If nothing shows up, set `FLASHPLAYERCONTROL_LOG=C:\temp\fpc.log` before you
start ICQ. The DLL then writes the loads, the chosen GPU, fscommands and errors
to that file. It always writes the same lines to the debugger
(`OutputDebugString`), so DebugView also shows them.

## Settings (environment variables)

| Variable | Effect |
|----------|--------|
| `FLASHPLAYERCONTROL_LOG` | Appends log lines to this file |
| `FLASHPLAYERCONTROL_BACKEND` | Devices to try, in order: `vulkan`, `warp`, `gl`, `dx12` (hardware DX12), `fail` (behave as if the adapter request failed), or `none` (no renderer). Default `vulkan,warp,gl`, with `gl` only when there is a hardware GPU |
| `FLASHPLAYERCONTROL_TEST_PANIC` | Test only: render number *n* and every later render panic, to exercise the failure handling |
| `WGPU_DX12_COMPILER` | Passed to wgpu (`fxc`, `dynamicdxc`) |

## Known gaps

- **Windows 10 or newer only.** Rust's `i686-pc-windows-msvc` target and wgpu
  need it, so Windows XP and 7 are not supported.
- **Hardware DX12 is not used.** With the patched wgpu-hal it builds its
  pipelines on the test machine (AMD, 32-bit), but its test frames read back
  empty, and a forced run failed to map the readback buffer. So it is not in
  the default order. When forced, the probe rejects it, and WARP after it
  then took 12.7 s instead of 1.1 s.
- **WARP is slow.** Opening it takes about 1.1 s on its own thread. Rendering
  in software can hold up the window's thread: up to 2.9 s once, while three
  avatar snapshots ran next to a tZer.
- **Slow first load.** The first movie per process waits 0.2 to 1.6 s while the
  GPU device starts. The wait happens on the load thread, not the UI thread.
  Later movies reuse the device.
- **Only the ten exports.** `FPC_SetVariable*`, `FPC_GetVariable*`,
  `FPCLoadMovieFromMemory` and the other exports of the original are missing.
  The client imports none of them.
- **Snapshot windows play no sound.** A window created with no owner or parent
  plays without sound. That matches the client's avatar snapshot service; a
  sound in any other ownerless use would be lost.
- **Many IShockwaveFlash methods return `E_NOTIMPL`**, including
  `SetVariable`, `TGotoLabel` and `CallFunction`. The type library still
  describes them all.
- **The `Loop` property is stored but ignored.** Movies always stop on their
  last frame.
- **`GotoFrame` steps one frame at a time.** Ruffle has no public goto, so the
  DLL steps through the frames between. Frame scripts on those frames run too,
  which a real goto would skip.
- **No mouse or keyboard input reaches the movie.** Clicks go to the client's
  subclass as before. As with the original's layered window, clicks on fully
  transparent pixels fall through to the window below.
- **Only the `animEnd` fscommand is special.** Every fscommand fires
  `FSCommand`, but only `animEnd` counts as the end of the movie.
- **`FPCSetEventListener` stores the listener but sends it nothing.**
- **1 MB stack.** Ruffle runs on ICQ's UI thread, whose stack is 1 MB (from
  `ICQ.exe`). Movies with deep ActionScript recursion could overflow it.
