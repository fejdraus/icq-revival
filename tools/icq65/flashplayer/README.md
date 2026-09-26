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

## How it works

- `src/lib.rs` holds the exports and the window class.
- `src/instance.rs` has the per-window state and the window procedure. It
  drives the player with a 10 ms timer on the window's thread and presents
  frames with `UpdateLayeredWindow`.
- `src/movie.rs` wraps the Ruffle player. It renders offscreen with
  `ruffle_render_wgpu` into a texture, reads the pixels back, and converts them
  from premultiplied RGBA to BGRA. It tries the graphics APIs in the order
  Vulkan, DX12, GL. An API only counts once Ruffle's shaders build on it; on
  failure the next one is tried.
- `src/audio.rs` sends sound to the default output device through cpal
  (WASAPI), like Ruffle's desktop player does.
- `src/com.rs` implements `IShockwaveFlash` and the connection point by hand.
- `src/typelib.rs` loads the embedded type library and handles its
  registration.
- `src/fetch.rs` reads local paths, `file:` URLs and `http(s)` URLs (WinINet)
  on a background thread.

Ruffle is pinned to tag `nightly-2026-09-26`, commit
`5455c72da5472a24cc293a7b13643709e9469587`.

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

`examples/host.rs` is a 32-bit program that drives the DLL the way the client
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

`reg` writes the type library registration to HKCU; run `unreg` afterwards.

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
| `FLASHPLAYERCONTROL_BACKEND` | Order of graphics APIs, for example `gl` or `dx12,vulkan` (default `vulkan,dx12,gl`) |
| `WGPU_DX12_COMPILER` | Passed to wgpu (`fxc`, `dynamicdxc`) |

## Known gaps

- **Windows 10 or newer only.** Rust's `i686-pc-windows-msvc` target and wgpu
  need it, so Windows XP and 7 are not supported.
- **DX12 does not work in the 32-bit build** on the test machine. Pipeline
  creation fails with `E_INVALIDARG` from the FXC shader path. The DLL falls
  back to Vulkan or OpenGL on its own, but a machine with neither cannot play
  tZers.
- **Slow first load.** The first movie per process waits 0.3 to 1.6 s while the
  GPU device starts. Later movies reuse the device.
- **Only the ten exports.** `FPC_SetVariable*`, `FPC_GetVariable*`,
  `FPCLoadMovieFromMemory` and the other exports of the original are missing.
  Features that use them, such as Flash avatars, do not work.
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
