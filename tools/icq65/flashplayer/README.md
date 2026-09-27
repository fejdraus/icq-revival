# FlashPlayerControl.dll for ICQ 6.5 (Ruffle)

ICQ 6.5 (build 2024) shows tZers, the short animations with sound over the
message window, through `FlashPlayerControl.dll`. The original is Softanics
Flash Player Control, a wrapper around the Adobe Flash ActiveX control, which no
longer exists. This folder builds a drop-in replacement that plays the same SWF
movies with [Ruffle](https://github.com/ruffle-rs/ruffle), the open-source Flash
emulator. The same DLL is also the ShockwaveFlash ActiveX control that ICQ's
Boxely UI embeds for animated (Flash) avatars. The client needs no changes
beyond this DLL and its per-user registration.

This is a prototype. It plays tZers and Flash avatars; it does not cover
everything the original DLL or Adobe's control offered.

## What the client expects

These facts come from a static analysis of `MCore.dll`, `MUIMessage.dll` and
`MUIUtils.dll`, which delay-load the DLL by bare name.

- **Exports**, all `__stdcall` and undecorated. Between them, the three modules
  import exactly these ten: `FPCIsFlashInstalled`, `RegisterFlashWindowClass`,
  `UnregisterFlashWindowClass`, `FPC_LoadMovieW`, `FPC_Play`, `FPC_Stop`
  (stop and rewind), `FPC_StopPlay` (pause), `FPC_IsPlaying`,
  `FPC_UpdateWindow` and `FPCSetEventListener`. The DLL also exports
  `DllRegisterServer`, `DllUnregisterServer`, `DllGetClassObject` and
  `DllCanUnloadNow`.
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

### Flash avatars: the ShockwaveFlash ActiveX control

Animated avatars (BART type 8) are shown by the "devil" gadget of the Boxely
UI (`boxelyRenderer.dll`, `MUIUtils` `MCFlashPlayerImpl`, `MUICoreLib`
`MCDevilImpl`). It does not use FlashPlayerControl's window; it hosts Flash
directly:

- **Creation.** `CLSIDFromString("{D27CDB6E-AE6D-11cf-96B8-444553540000}")`
  or the ProgID `ShockwaveFlash.ShockwaveFlash`, then
  `CoGetClassObject`/`CoCreateInstance`. The DLL provides the class factory
  (`IClassFactory2`, licence always verified) and registers the class for the
  user.
- **Activation order.**
  1. `IOleObject::GetMiscStatus`. The DLL reports Flash's `0x20191`, which
     includes `OLEMISC_SETCLIENTSITEFIRST`.
  2. `IPersistPropertyBag::Load` with the `<param>`s: `Movie`, `WMode`
     (`transparent` for the ICQ box), `Scale` (`NoBorder`), `Play`, `Quality`.
  3. `SetClientSite`.
  4. `IViewObjectEx`, `IOleObject::Advise`, `IViewObject::SetAdvise`.
  5. `SetHostNames`, then `SetExtent` (HIMETRIC).
  6. `DoVerb(OLEIVERB_INPLACEACTIVATE)`: windowless when the site allows it
     (`OnInPlaceActivateEx(ACTIVATE_WINDOWLESS)`).
  7. `IObjectWithSite::SetSite`, then
     `IOleInPlaceObjectWindowless::SetObjectRects`.
- **Painting.** `IViewObject::Draw` puts the frame into the host's DC,
  premultiplied, with `AlphaBlend`: transparent where the movie draws nothing
  with WMode transparent, opaque otherwise.
  - **The destination rectangle** is `lprcBounds` when the host passes one
    (boxely's memory-DC path). Otherwise it is the `SetObjectRects`
    rectangle (the windowless path, `lprcBounds` NULL).
  - **Every Draw renders at its destination's size in device pixels**
    (`LPtoDP`, so a DC that scales is handled), and AlphaBlend copies 1:1.
    A frame is never stretched. A few sizes of the current frame are cached
    as GDI bitmaps.
  - **`Scale` and `ScaleMode`** (from the property bag, `put_Scale` or
    `put_ScaleMode`) decide the fit: NoBorder fills and crops, ShowAll
    letterboxes, ExactFit stretches, NoScale keeps the movie's pixels.
  - **`SetExtent`** takes HIMETRIC and converts with the screen DPI.
  - `QueryHitPoint` hits where the frame has pixels.
- **Telling the host to repaint.** On each new frame, after activation and
  after a size change, the DLL calls:
  - `IOleInPlaceSiteWindowless::InvalidateRect`, with its rectangle once
    `SetObjectRects` has given one, else NULL;
  - `IAdviseSink::OnViewChange` on the `SetAdvise` sink (`ADVF_PRIMEFIRST`
    sends one at once, `ADVF_ONLYONCE` drops the sink after one).

  Until the host has drawn the newest frame, a timer asks again every
  100 ms, with a NULL rectangle, for up to 10 s without a Draw.

  boxelyRenderer's site (ATL's `CAxHostWindow` with Boxely additions):
  - Its `InvalidateRect` is `USER32!InvalidateRect(m_hWnd, rect, erase)` on
    its "ActiveX frame" window. Boxely shows or hides that window
    (`SW_SHOWNA`/`SW_HIDE`), and a hidden window gets no `WM_PAINT`.
  - Its `OnViewChange` does nothing.
  - So a repaint request can be lost; the avatar then stayed empty until
    something else repainted. That is why the DLL keeps asking. When the
    site's window (`IOleWindow::GetWindow`) is hidden, it also invalidates
    the nearest visible ancestor over its rectangle.
- **Driving it** (through `IShockwaveFlash` or `IDispatch`):
  - `Movie` (put through `Invoke`), `Play` (+0x70), `Stop` (+0x74), `put_Movie`
    (+0x58), `TGotoLabel` (+0xF0), `SetVariable` (+0x104).
  - The devil calls `SetVariable("face.emotion", "stam")`, then
    `SetVariable("face.emotion", e)` for smile, sad, laugh, mad, cry and love,
    or offline, busy and stam for a status. In the avatar SWFs `face` has
    `addProperty("emotion", ...)`, and its setter does
    `gotoAndPlay(label)`.
  - **The face goes back after a smiley** (`src/face.rs`). Each emotion's
    animation plays once and stands on its last frame; neither the movie nor
    ICQ 6.5 goes back to the status face. `MCDevilImpl` has no timer (only
    `MCAdImpl` and `MCSelectUsersDlg` in `MUICoreLib` use one), and it sets the
    status face only when the status changes (`ChangeDevilStatus`: offline,
    busy for statuses 2 to 5, else stam). So a smiley's face stayed until the
    next status change, with Adobe's control as well. ICQ's own devil testing
    page (`devils.zip` of the devil kit) went back to stam 9 seconds after a
    smiley. The DLL now does that: 9 seconds after a smiley face it sets the
    last status face again. A new smiley starts the wait again, a status face
    ends it. The leading "stam" of ICQ's pair is not taken for a status: a face
    that follows a "stam" within 250 ms restores the status from before it.
    `FLASHPLAYERCONTROL_FACE_RETURN` sets the wait; a host that times the faces
    itself turns it off with the export `FPCSetFaceReturn(0)` (milliseconds,
    for the whole process), as the Miranda plugin does.
  - Also implemented: `GetVariable`, `TGotoFrame`, `TPlay`, `TStopPlay`, and
    `WMode`/`Scale` get/put. The other property setters are accepted and
    ignored.

The control is the same engine as a tZer window. Each control creates a
hidden message-only window of class `FlashPlayerControl` on its thread, with
the same player, timer, loading and `IShockwaveFlash`. The window's
`IShockwaveFlash` object delegates its `IUnknown` to the control (COM
aggregation), so every interface has one identity. Unlike tZers, avatars loop
(Flash's default), and they keep their sound.

**SetVariable and friends in Ruffle.** At the pinned commit `ruffle_core` has
no public SetVariable (its `avm1` module is private). The DLL does not patch
Ruffle. It builds a few bytes of AVM1 code, for example `Push path; Push value;
SetVariable`, into a stand-in `SwfMovie`, and queues them on the root clip with
the public `UpdateContext::action_queue` (`ActionType::Normal`) inside
`Player::update`. That runs them exactly like a frame script, so paths and
`addProperty` setters behave as in Flash:
- **GetVariable** ends with `getURL("FSCommand:<private name>", value)`; the
  DLL's fscommand provider catches the value.
- **TGotoLabel, TGotoFrame, TPlay and TStopPlay** use `SetTarget2` plus the
  matching action.
- **ActionScript 3 movies** are not supported: these calls return `E_FAIL`.

### tZer windows: end of movie

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
- `src/control.rs` is the ShockwaveFlash ActiveX control and its class
  factory.
- `src/registry.rs` registers the control class and ProgIDs for the user.
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

Miranda NG plays ICQ 6 Flash avatars with this DLL too
(`tools\miranda-icq\IcqRevivalFlash`, which loads it from Miranda's `Libs`
folder without registration). For `miranda64.exe` build the same source for
64 bits; `.cargo/config.toml` links the C runtime statically there as well:

```
cargo build --release --lib --target x86_64-pc-windows-msvc
```

The output is `target\x86_64-pc-windows-msvc\release\FlashPlayerControl.dll`.
The `vendor/wgpu-hal` fix aligns pipeline subobjects to pointer size, which is
8 bytes there, as upstream did, so it is right for both. Registration is per
bitness: `DllRegisterServer` of the 64-bit DLL, run by the 64-bit `regsvr32`,
writes the 64-bit view of the HKCU classes. ICQ 6.5 needs only the 32-bit
one, Miranda neither.

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
%H%\examples\host.exe %H%\FlashPlayerControl.dll avatars http://127.0.0.1:8766 C:\out mixed 3 2 spawn C:\path\kisses.swf pirate.swf smile.swf ...
```

(Serve the avatar SWFs, for example `deploy/oscar-legacy-web/avatars`, with
`python -m http.server 8766`.)

`ax` tests the ShockwaveFlash control:
- **It creates the control through COM without the registry.** It registers
  the DLL's class factory for the process (`CoRegisterClassObject`), then
  calls `CoCreateInstance` by CLSID.
- **It hosts every named avatar at once in a windowless container** that
  follows the Boxely activation order above. Its site implements
  `IOleClientSite`, `IOleInPlaceSiteWindowless` and `IAdviseSink`, and its
  property bag holds WMode transparent and Scale NoBorder.
- **It drives the controls like the devil gadget:** it sets `Movie` through
  `IDispatch`, calls `Play`, and sends each emotion through
  `SetVariable("face.emotion", ...)`.
- **It captures every avatar through `IViewObject::Draw`** into
  `sheet-avatars-x-emotions.png` (a row per avatar, a column per emotion) and
  screenshots the windowless painting.
- **It measures the load:** frames per second, and how busy the UI thread is.
- **It also tries `TGotoLabel`, `GetVariable`, `Stop` and `Play`,** then puts
  three controls into Windows' own ATL host (`atl.dll`, `AtlAxAttachControl`).

`axfirst` reproduces the two field bugs in a container that paints like
boxelyRenderer. It paints an element only while it is "ready", and it
repaints only when the control asks.
- **First paint:**
  - Movies play, then stand still while the host paints no element; the
    elements become ready without a repaint of the container's own.
  - A modal dialog runs while the faces change.
  - The site's window is a hidden child, like Boxely's hidden ActiveX frame.

  Each time, every avatar's current frame must be on screen. The check
  compares the screenshot with the control's own Draw, composited on the
  background.
- **Size:**
  - `Draw` with rectangles unlike `SetObjectRects`, in both of boxely's
    paths.
  - A DC mapped from logical 49x49 to 38x49 device pixels.
  - Sizes that change, and Scale NoBorder, ShowAll and ExactFit.

  The smiley's round face must stay round, except with ExactFit.
- **Before and after:** the build before this change fails all three first
  paint cases and squeezes in the scaled DC; this one passes.

```
%H%\examples\host.exe %H%\FlashPlayerControl.dll axfirst W:\...\deploy\oscar-legacy-web\avatars C:\out pirate.swf smile.swf ...
```

The host is DPI aware, so its screenshots line up with window coordinates on
a scaled display.

`face` hosts one avatar, sends the faces as ICQ 6.5 does ("stam", then the
face) and checks with `GetVariable` that a smiley's face goes back to the
status face after the wait, that a second smiley restarts it, that a status
face ends it, and that `FPCSetFaceReturn(0)` turns it off. Set
`FLASHPLAYERCONTROL_FACE_RETURN=2` first; it expects a 2-second wait:

```
%H%\examples\host.exe %H%\FlashPlayerControl.dll face W:\...\deploy\oscar-legacy-web\avatars pirate.swf
```

`axreg` runs `DllRegisterServer` and `DllUnregisterServer` under a test root
(`FLASHPLAYERCONTROL_TEST_REGROOT`), checks every key, and shows that the
user's real registration did not change:

```
%H%\examples\host.exe %H%\FlashPlayerControl.dll ax W:\...\deploy\oscar-legacy-web\avatars C:\out pirate.swf smile.swf ...
%H%\examples\host.exe %H%\FlashPlayerControl.dll axreg
```

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
3. Start `ICQ.exe` from the copy and send or receive a tZer. With a Flash
   avatar set (on the server, BART type 8), the avatar in the contact list and
   the message window plays and changes with emotions.

`regsvr32` registers two things for the user:
- the type library;
- the ShockwaveFlash control class (under `HKCU\Software\Classes`, which a
  32-bit `regsvr32` puts in the 32-bit view: `CLSID\{D27CDB6E-...}` with
  `InprocServer32` = this DLL and `ThreadingModel` = Apartment, plus the
  ProgIDs `ShockwaveFlash.ShockwaveFlash`, `.9` and `.10`).

`/u` removes the class only when it is registered to this DLL, and the
ProgIDs only when they point at it.

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
| `FLASHPLAYERCONTROL_FACE_RETURN` | Seconds a Flash avatar shows a smiley's face before it goes back to its status face (fractions allowed). Default 9; `0` turns it off. A host's `FPCSetFaceReturn` wins |
| `FLASHPLAYERCONTROL_BACKEND` | Devices to try, in order: `vulkan`, `warp`, `gl`, `dx12` (hardware DX12), `fail` (behave as if the adapter request failed), or `none` (no renderer). Default `vulkan,warp,gl`, with `gl` only when there is a hardware GPU |
| `FLASHPLAYERCONTROL_TEST_REGROOT` | Test only: register the control class under this HKCU key instead of `Software\Classes`, and leave the type library alone |
| `FLASHPLAYERCONTROL_TEST_PANIC` | Test only: render number *n* and every later render panic, to exercise the failure handling |
| `WGPU_DX12_COMPILER` | Passed to wgpu (`fxc`, `dynamicdxc`) |

## Known gaps

- **The field cause of the empty first paint is inferred, not seen.** It
  comes from boxelyRenderer's code; the DLL now covers all channels and
  keeps asking.
- **The log tells what really happens in ICQ.** With
  `FLASHPLAYERCONTROL_LOG` set, it records per control (`control #N`):
  - every host call: interfaces asked for and missed, property bag values,
    `SetExtent` (HIMETRIC, pixels, DPI), `SetObjectRects`, `DoVerb`,
    `GetWindowContext`;
  - the site window with its visibility and parents;
  - each `Draw` with its rectangle, device size, mapping mode and frame;
  - each repaint request and retry with its result.

  Per-frame lines are rate-limited: the first 40 per control, then every
  240th.

- **No input reaches a Flash avatar.** `OnWindowMessage` returns S_FALSE, so
  clicks go to the host.
- **Windowed hosts get no window.** A host that cannot activate the control
  windowless gets no window of its own; it hears about new frames only
  through `IAdviseSink::OnViewChange` and must call `Draw` itself.
- **Missing interfaces:** `IQuickActivate`, `IPersistStreamInit::Load`/`Save`
  and property-bag `Save` are not implemented.
- **Many avatars cost CPU.** Each one renders every frame it changes and
  reads it back from the GPU. With 31 avatars (87x109) animating at 24 fps,
  the UI thread was busy 63% on the test machine (about 0.7 ms per frame).
  On WARP it managed 10.6 fps per avatar at 98%.
- **`GetVariable` of an undefined variable** returns an empty string, not
  NULL.

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
  The client imports none of them. `FPCSetFaceReturn` is ours, not the
  original's.
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
