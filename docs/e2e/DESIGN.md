# End-to-end encryption add-on for ICQ 6.5 and ICQ 7.2

Status: design only. No code in the repo, no commits. Read-only research against
copies of the clients (never the live install). All findings below are backed by
import tables, string tables and disassembly of the pristine copies in the
scratchpad (`icq65-pristine`, `icq72copy` build 3143).

---

## 1. Goal and shape

A single small native DLL (`crate-type = cdylib`, `i686-pc-windows-msvc`, the same
target the Ruffle `FlashPlayerControl.dll` already builds for) that the patch drops
into the client folder. The client loads it at start. It intercepts the client's
own OSCAR (BOS) traffic **in-process**, and transparently encrypts/decrypts IM text
end-to-end with a Signal-like scheme, so the server (and anyone on the wire) sees
only ciphertext. A tiny management page is served on `127.0.0.1` and opened inside
an ICQ window through our existing Xtraz list; status is surfaced as in-chat system
notes.

The DLL does **not** replace the client's networking. It sits on top of the
client's existing Winsock calls and rewrites the payloads of message SNACs in
both directions. Everything else (login, presence, typing, acks, file transfer,
voice) is passed through untouched.

Key design principle: **fail readable, not silent.** A message the DLL cannot
encrypt for a recipient is either sent in clear (user-visible downgrade note) or
refused with a system note; a ciphertext a peer cannot decrypt is shown as a
"[encrypted message you cannot read]" note, never as garbage.

---

## 2. How the clients are built (relevant facts)

Both clients are the same Boxely engine in different layouts. Both are **32-bit**
(`x86`, `Machine == 0x14C`). Networking and messaging happen in a **single
process, `ICQ.exe`** — there is no separate network process:

- **6.5**: `aolload.exe` is not even present in the folder; the only helper DLLs
  are the M* core set. Networking lives in `coolcore49.dll`.
- **7.2**: `aolload.exe` is present but only launches the AOL diagnostics chain
  (`aoltest.dll`, `portaol.dll`, `aoldiag.dll`…). It does **not** carry OSCAR
  traffic. Networking lives in `coolcore59.dll` (and `acccore.dll` for the web
  login). All of it is inside `ICQ.exe`.

So a single in-process DLL is sufficient; no cross-process plumbing is needed.

---

## 3. Q1 — DLL load hook

### 3.1 KnownDLLs baseline

`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` on this machine:
kernel32, advapi32, clbcatq, combase, comdlg32, coml2, difxapi, gdi32, **gdiplus**,
imagehlp, imm32, msctf, msvcrt, normaliz, nsi, ole32, oleaut32, psapi, rpcrt4,
sechost, setupapi, shcore, shell32, shlwapi, user32, wldap32, **ws2_32**,
xtajitf/xtajitse. KnownDLLs are always resolved from `system32` and can never be
proxied from the app directory. This rules out `ws2_32.dll`, `gdiplus.dll`,
`shell32.dll`, `shlwapi.dll`, `imm32.dll`, `rpcrt4.dll`, `comdlg32.dll`, etc.

Candidates that are **NOT** KnownDLLs and are resolved from the application
directory first for implicitly-linked imports: `version.dll`, `winmm.dll`,
`dbghelp.dll`, `msimg32.dll`, `wininet.dll`, `urlmon.dll`, `riched20.dll`,
`comctl32.dll`, `wsock32.dll`, `iphlpapi.dll`, `crypt32.dll`, `dnsapi.dll`,
`sensapi.dll`, `rasapi32.dll`, `msi.dll`, `mfc42.dll`, `msvfw32.dll`.

### 3.2 Who imports what (evidence)

From the import tables (`[I]` = static import, `[D]` = delay import, `<LOCAL>` =
ICQ-owned DLL already in the folder):

- **`msimg32.dll`** — 6.5: **static** import of `MUtils.dll` (`msimg32.dll[I]`);
  7.2: **delay** import of `MUtils.dll` (`msimg32.dll[D]`). `MUtils.dll` is loaded
  at process start in both (it is statically imported by `ICQ.exe` itself).
- **`version.dll`** — 6.5: static in `MCrashReport.dll` and `dBenderC14.dll`, delay
  in `MUtils.dll`; 7.2: delay in `MUtils.dll`, static in `aoldiag.dll`.
- **`dbghelp.dll`** — 6.5: static in `MCrashReport.dll` only. Not present as an
  import at all in 7.2's folder DLLs I checked.
- **`wininet.dll`** — static in many core DLLs (6.5 `MCore`, `MUICore`, `MReport`;
  7.2 `MUIMessage`, `MReport`) — but it is a large, load-bearing surface to proxy.
- **`tbdiag.dll`** (7.2 only) — see below, a purpose-built load slot.

### 3.3 The `tbdiag.dll` slot (ICQ 7.2) — recommended for 7.2

Disassembly of `ICQ.exe` (7.2) at `0x40a9f0` shows the startup path explicitly
loads `tbdiag.dll` from the application directory very early:

```
0x40a9f9 push 0x412cf0            ; "tbdiag.dll"
0x40a9fe call GetModuleHandleA     ; already loaded?
...                                ; else build "<exe dir>\tbdiag.dll"
0x40aa80 push 0x412d08            ; "tbdiag.dll"
0x40aa9d call LoadLibraryExA       ; LOAD_WITH_ALTERED_SEARCH_PATH (flag 8)
...                                ; fallback: HKLM\...\AOL Diagnostics\InstallDir\tbdiag.dll
0x40ac19 ... store handle in g_tbdiag (0x413564)
0x40ac32 call 0x40ac90             ; resolve FCCreateKey/FCSetKeyOptions/... via GetProcAddress
```

This is reached from the very first init call (`0x409ab0`, called from
`0x409a80` in the startup chain). The exports the client resolves are the AOL
"feature counter" telemetry set: `FCCreateKey`, `FCSetKeyOptions`,
`FCCreatePersistentKey`, `FCCreateCounter`, `FCAddIntToKey`, `FCAddStringToKey`,
`FCAddDataToKey`, `FCFlushNonSharedPersistentKeys`, etc. The client tolerates a
missing handle and missing procs (it null-checks the handle before resolving).

**The patch already owns this slot**: `tools/patcher/Icq72/Icq72Client.cs` renames
the stock `tbdiag.dll` out of the way because it crashes ICQ 7. That leaves the
slot free for our DLL. We ship a DLL named `tbdiag.dll` that:
- exports the `FC*` names as no-ops returning success (so the telemetry probe is
  harmless), and
- in `DllMain(DLL_PROCESS_ATTACH)` spins up the E2E engine on a worker thread.

This is the **cleanest 7.2 hook**: an intended, app-dir `LoadLibraryEx`, executed
before any network activity, in the process that does the networking, and already
managed by our patch.

Note: 6.5's `ICQ.exe` references `tbdiag.dll` too (at `0x40f074`) but via
`GetModuleHandleW` + `GetProcAddress` — it only *uses* tbdiag if something else
already loaded it; it never `LoadLibrary`s it itself. So the tbdiag slot is
**7.2-only**.

### 3.4 `msimg32.dll` proxy (ICQ 6.5) — recommended for 6.5

6.5 has no free intended slot, so use a classic proxy DLL. `msimg32.dll` is the
best candidate: it is statically imported by `MUtils.dll`, which is statically
imported by `ICQ.exe`, so it loads at process init, before any BOS connection. Its
export surface is tiny and pure (`AlphaBlend`, `TransparentBlt`, `GradientFill`,
`vSetDdrawflag`, and a handful of `Dll*`), all trivially forwarded to the real
`C:\Windows\System32\msimg32.dll` via `#pragma`-style export forwarders (or a
`.def` with `EXPORTS AlphaBlend=REAL.AlphaBlend`). In `DllMain` we start the
engine, then hand GDI calls straight through.

`version.dll` is a viable alternative for 6.5 (also non-KnownDLL, imported by
`MCrashReport`/`dBenderC14` statically and `MUtils` by delay); its export set
(`GetFileVersionInfoW`, `VerQueryValueW`, `GetFileVersionInfoSizeW`, …) is equally
easy to forward. `dbghelp.dll` works too but only loads through the crash reporter,
whose init timing is less certain — not preferred.

### 3.5 Recommendation

| Client | Hook DLL | Mechanism | Why |
|--------|----------|-----------|-----|
| ICQ 7.2 | `tbdiag.dll` | app-dir `LoadLibraryEx` from `ICQ.exe` startup (0x40aa9d); patch already frees the slot | intended, earliest, patch-managed, no forwarding needed |
| ICQ 6.5 | `msimg32.dll` proxy | static import chain `ICQ.exe → MUtils.dll → msimg32.dll` | non-KnownDLL, loads at init, tiny forward surface |

A single universal DLL is possible (`msimg32.dll` in both folders) if we accept
that on 7.2 `msimg32` is *delay*-loaded — it comes in on the first `AlphaBlend`
during early UI paint, still comfortably before any message traffic. But since the
two patches already diverge and `tbdiag` is strictly cleaner on 7.2, **ship two
tiny loader stubs that both dlopen a shared `icqe2e_core.dll`** holding all the
real logic. The loader stub is per-client; the engine is one codebase.

In every case, the actual message interception is done by hooking the networking
module's Winsock calls (next section), independent of which stub loaded us.

---

## 4. Q2 — Networking and interception surface

### 4.1 Winsock APIs used

Both networking cores import the classic **BSD/`wsock32.dll`** Winsock 1.1 surface,
not the overlapped/IOCP `WSASend`/`WSARecv` surface:

- `coolcore49.dll` (6.5) imports from `wsock32.dll`: `connect`, `send`, `recv`,
  `sendto`, `recvfrom`, `socket`, `bind`, `setsockopt`, `ioctlsocket`,
  `WSAAsyncSelect`, `WSAStartup`, `closesocket`, `gethostbyname`,
  `WSAAsyncGetHostByName`, `WSACancelAsyncRequest`, `inet_addr`, … (30 imports).
- `coolcore59.dll` (7.2) imports the same set from `wsock32.dll` (26 imports),
  including `connect`, `send`, `recv`, `WSAAsyncSelect`.

So the model is **blocking `send`/`recv` driven by `WSAAsyncSelect`** (message-pump
notifications), classic Winsock 1.1. No `WSASend`/`WSARecv`, no overlapped I/O, no
IOCP anywhere in the OSCAR path. This makes interception simple: we only need to
intercept `send` and `recv` (and `connect` to identify the BOS socket).

`sipXtapi.dll`/`sipXmediaLib.dll` use `ws2_32.dll` for RTP (voice/video) — out of
scope.

### 4.2 Which module, and how to hook

The calls live in `coolcore49.dll` / `coolcore59.dll`. The cleanest interception
is **IAT hooking of that module's import thunks for `wsock32.dll!send` and
`wsock32.dll!recv`** (their thunk addresses are in the import table, e.g. 6.5
`send@0x40194130`, `recv@0x40194170`; 7.2 `send@0x401b4198`, `recv@0x401b41d8`,
as RVAs into the loaded module). We resolve the module base at runtime
(`GetModuleHandle("coolcore49"/"coolcore59")`), walk its import table, and swap the
two thunks. A module-scoped IAT hook is far safer than an inline/global hook: it
touches only the OSCAR core, leaves RTP and HTTP alone, and survives ASLR.

Because the hook is byte-stream level, the engine must **reassemble FLAP frames**
itself (section 6). We track the BOS socket by watching `connect` to the BOS
host/port (the patch points BOS at our server's 5190; plain, no TLS).

### 4.3 TLS on the BOS connection

None. The patch puts BOS on plain `5190` for both clients; 6.5 is plain by design.
`crypt32.dll` appears in `coolcore59.dll` (only `CertCreateCertificateContext`,
`CertGetCertificateChain`, `CertFreeCertificateChain/Context`) — that is for
validating the HTTPS **web-login** certificate, not the BOS stream. So the BOS byte
stream we intercept is cleartext OSCAR; we can parse and rewrite it directly.

### 4.4 7.2 web login (informational only)

ICQ 7.2 signs in over HTTP to the web API (`:8082` in our patch, no TLS in its ACC
config). The HTTP client for it is **WinINet** (`coolcore59.dll` imports
`InternetOpenA`, `InternetOpenUrlW`, `InternetReadFile`; `acccore.dll` imports the
`*UrlCacheEntry*` helpers). This login exchange carries **no messages**, only auth
and the BOS redirect/cookie, so the DLL does not touch it — but it is worth noting
that the BOS auth token the client receives here is exactly what we can reuse
server-side to authenticate the DLL's key-directory channel (section 8).

---

## 5. Q3 — Where the IM text sits, and what to rewrite

The DLL must recognise and rewrite message payloads inside
`ICBM` (food group `0x0004`) SNACs, in both directions:

- Outbound: `ICBMChannelMsgToHost` (`0x0004/0x0006`,
  `SNAC_0x04_0x06_ICBMChannelMsgToHost`).
- Inbound: `ICBMChannelMsgToClient` (`0x0004/0x0007`,
  `SNAC_0x04_0x07_ICBMChannelMsgToClient`).

### 5.1 Channel 1 (plain IM / HTML) — 6.5↔6.5, 7.2↔7.2, 6.5↔7.2

Channel-1 text rides in TLV `ICBMTLVAOLIMData` (0x0002) as a fragment list
(`ICBMCh1Fragment{ID,Version,Payload}`). Fragment `ID==1` is the message
(`ICBMCh1Message{Charset uint16, Language uint16, Text []byte}`). `Charset`:
`0x0000` ASCII, `0x0002` UCS-2 BE, `0x0003` Latin-1. Fragment `ID==5` carries the
capabilities/features prefix (`{1,1,2}` = "supports text").

ICQ 6/7 send and read **HTML** without announcing XHTML; smileys ride inside the
HTML as `<FONT sml="...">` naming the smiley set (see `foodgroup/icbm.go`
`readsHTML`, and the server's `stripHTML` for clients that don't read HTML). The
DLL must therefore treat the fragment `ID==1` payload text (after charset decode)
as the plaintext to protect, and on decrypt re-emit it in the **same charset and
with the same HTML/`<FONT sml>` wrapper conventions** the sending client used, so
smileys and formatting survive. Concretely the DLL:
- Outbound: decode `ICBMCh1Message.Text` per `Charset` → UTF-8 plaintext →
  encrypt → wrap as the E2E ciphertext container (section 7) → re-encode as the
  message text (we keep charset UCS-2 BE so arbitrary ciphertext transport is
  clean) and rebuild the fragment list.
- Inbound: detect our container in fragment `ID==1`, decrypt → restore the
  original charset/HTML text the sender produced → rebuild the fragment list so the
  client renders it exactly as a normal IM.

### 5.2 Channel 2 type-2 messages (ICQ server relay) — mainly 6.5

6.5 (and Miranda) announce `CapICQCh2Extended`
(`09461349-4C7F-11D1-8222-444553540000`) and can send **channel-2 extended
messages** via rendezvous TLV `0x2711` (`ICBMRdvTLVTagsSvcData`,
`ICBMCh2Fragment{Type,Cookie,Capability,TLVRestBlock}`). These are UTF-8 text plus
a capability GUID; `CapUTF8Messages` is `0946134E-...`. 7.2 announces
`CapICQTZers` but **not** `CapICQCh2Extended`, so it does not send type-2 relay
messages (see `foodgroup/icbm_tzer.go` comment). The DLL must rewrite the text body
inside the `0x2711` payload for 6.5↔6.5 the same way as channel 1. For the mixed
case the server already normalises between the two forms; the DLL should protect
the **plaintext** and let the server's existing translation carry the container.

### 5.3 Offline messages

Offline delivery for ICQ is retrieved through the `ICQ` food group (`0x0015`):
`OfflineMsgReq` → `ICQ_0x0041_DBQueryOfflineMsgReply` (per-message) →
`ICQ_0x0042_DBQueryOfflineMsgReplyLast` (see `foodgroup/icq.go`). Because our wire
format carries **per-device wrapped keys inside the message body** (section 7), an
offline message is just a stored ciphertext; when it is replayed to the client the
DLL decrypts it on arrival exactly like a live one. The DLL must therefore also
watch the offline-reply SNACs and run inbound decryption on their message bodies,
not only on `ICBMChannelMsgToClient`.

### 5.4 Pass-through (must NOT be touched)

Typing notifications and message acks must pass unchanged: `ICBMClientEvent`
(typing, `0x0004/0x0014`), `ICBMHostAck`/`ClientErr` acks, mini-typing. Presence
(`Buddy`/`OService`), `Feedbag`, `Locate`, `BART` (avatars), rendezvous for file
transfer and RTC, and all login SNACs are passed through verbatim. Only the text
body of channel-1 fragment `ID==1`, the channel-2 `0x2711` body, and offline
message bodies are rewritten.

### 5.5 Cross-generation matrix

| Path | Container | DLL action |
|------|-----------|-----------|
| 6.5↔6.5 | ch1 HTML, or ch2 type-2 (0x2711) | encrypt/decrypt text, keep charset+HTML+`<FONT sml>` |
| 7.2↔7.2 | ch1 HTML | encrypt/decrypt text, keep HTML |
| 6.5↔7.2 | ch1 HTML (server already bridges ch2→ch1) | encrypt/decrypt text; rely on server's existing form translation for the envelope, protect plaintext only |

---

## 6. Interception layer: FLAP reassembly and sequencing

The hooked `recv`/`send` see a raw byte stream, not framed SNACs. The engine keeps
a per-socket ring buffer and reassembles **FLAP frames**
(`FLAPFrame{StartMarker=0x2A, FrameType, Sequence uint16, PayloadLength uint16}`,
`wire/frames.go`). FLAP `FrameType==2` (data) carries a SNAC; we parse the SNAC
header (`foodGroup, subGroup, flags, requestID`) and only act on the ICBM/ICQ-offline
subset above. Everything else is forwarded byte-for-byte.

Because encryption changes payload length, a rewritten FLAP frame has a new
`PayloadLength`; we re-emit the frame with the corrected length and the **client's
own `Sequence` value preserved** (we rewrite in place in the same frame, so the
client's monotonic sequence counter is never disturbed). This is the crucial reason
to rewrite existing message frames rather than inject new ones: **we never change
the number of frames on the BOS connection, so no FLAP renumbering is needed** for
the message path.

Partial frames across `recv` boundaries are held until complete. The engine is
strictly a stream transformer: N frames in, N frames out, only payloads changed.

---

## 7. On-the-wire message format (E2E container)

Versioned, self-describing, and marked so non-supporting clients degrade
readably.

```
E2E container (little-endian inside, carried as the ICBM message text):
  magic      : 4 bytes  "IQE1"           (also lets a peer DLL detect us)
  version    : u8       = 1
  scheme     : u8       (1 = X3DH+DoubleRatchet, 2 = PQXDH+DoubleRatchet)
  flags      : u8
  sender_dev : u32      sender device id
  n_wraps    : u8       number of per-recipient-device wrapped message keys
  wraps[]    : { dev_id:u32, len:u16, wrapped_key:bytes }   // for offline fan-out
  ratchet_hdr: len-prefixed  Double Ratchet header (DH ratchet pubkey, N, PN)
  ciphertext : len-prefixed  AEAD(plaintext = original charset+HTML text)
  mac        : 16 bytes
```

- The container is carried in the **ICBM channel-1 fragment `ID==1`** text, charset
  marked UCS-2 BE so arbitrary bytes transit cleanly; a base64/ASCII-armored
  variant is used where a transport insists on text (channel-2 0x2711).
- **Capability marking**: the DLL adds a private capability GUID to the client's
  advertised caps so peers know we speak E2E. Proposed
  `CapE2EEncrypt = 0946E2E1-4C7F-11D1-8222-444553540000` (slots into the existing
  `09460000/09460001`-style ICQ short-cap family; final value TBD). The DLL injects
  it into the client's `Locate`/`OService` capability list on login (this is one of
  the few places we do modify an outbound SNAC; it changes payload length only, in
  place — no reframing).
- **Readable downgrade**: if a recipient does not advertise `CapE2EEncrypt`, the
  outbound message is sent in clear with a one-time in-chat system note
  ("this contact is not using encryption"). If we receive an `IQE1` container we
  cannot decrypt (no session, wrong device), we render
  `[encrypted message — cannot be read on this device]` instead of raw bytes. A
  peer **without** the DLL simply sees the UCS-2 armored blob; to keep that
  readable we prepend a short human line ("🔒 encrypted — get the ICQ E2E add-on")
  before the container so a non-supporting client shows a hint, and the supporting
  DLL strips that prefix before decoding.

Crypto scheme (Signal-like, per the owner's spec):
- one **identity key** per UIN, shared by the account's devices;
- per-device **signed prekeys**, signed by the identity key (so the server cannot
  inject a device);
- **one-time prekeys**;
- **X3DH** (or **PQXDH** when both sides advertise scheme 2) to establish, then
  **Double Ratchet** per pair-of-devices;
- messages carry **per-device wrapped message keys** (the `wraps[]` array) so
  offline delivery to every one of the recipient's devices works;
- **one safety number per pair of UINs** (derived from both identity keys), shown
  on the management page.

---

## 8. Q5 — Server side: key directory and DLL channel

### 8.1 Key directory service

The directory is what makes X3DH work without trusting the server for authenticity:
the server stores and serves bundles but cannot forge them because prekeys are
signed by the identity key, which never leaves the devices.

Operations needed:
- **publish**: identity key (once per UIN), device entry, signed prekey, batch of
  one-time prekeys;
- **fetch bundle** for a target UIN: identity key + one device's signed prekey +
  one one-time prekey (consumed);
- **device list** for a UIN (so a sender can fan out `wraps[]`);
- **device-link relay**: approve-on-existing-device flow (below);
- **notifications**: device-list-changed and prekey-low events pushed to online
  clients.

Two ways to host it on the server:

**Option A — new OSCAR food group.** OSCAR food group numbers in use:
`0x0000–0x0018`, `0x0022`, `0x0025`, `0x044A`, `0x050C` (`wire/snacs.go`). A new
food group, e.g. **`0x0033` "KeyDir"**, with subgroups for publish/fetch/list/
link/notify, would ride the existing BOS connection and reuse login/session. But
injecting these SNACs from the DLL into the client's BOS stream means **adding
frames**, which forces FLAP-sequence renumbering in both directions (rewrite every
subsequent client→server `Sequence`, and hide the server's replies to our injected
requests from the client). That is fragile and error-prone — exactly what section 6
avoids for the message path.

**Option B (recommended) — separate authenticated side channel.** The DLL opens its
**own** connection to a dedicated key-directory endpoint, so the client's BOS
stream is never reframed. Two sub-choices for the endpoint and auth:

1. *Own OSCAR-style TCP connection using the BOS cookie.* The server already mints a
   `ServerCookie` and cracks it (`foodgroup/auth.go` `CrackCookie`,
   `RegisterBOSSession`). We add a second listener that accepts the same cookie the
   client used, so the DLL — which can read the cookie out of the intercepted login
   SNAC — reconnects on its own socket, authenticated as the same UIN. This keeps
   one auth model but needs the DLL to extract the cookie.
2. *(preferred)* **HTTPS key-directory endpoint authenticated by a server-issued
   token.** On successful BOS login the server pushes a short-lived, session-bound
   **E2E token** to the client — either as a TLV inside `OServiceHostOnline`/
   `OServiceClientOnline`, or as a single new `KeyDir` SNAC sent once. The DLL reads
   that token from the intercepted inbound stream (read-only; no reframing) and uses
   it as a bearer token against an HTTPS endpoint on our server (a new handler
   alongside `server/http` / `server/webapi`). This is the **safest**: the message
   path stays a pure N-in/N-out transformer, the side channel is ordinary
   request/response, the token is bound to the UIN+session server-side, and we reuse
   the web stack the project already runs. The only outbound modification on BOS is
   the one in-place capability injection (section 7).

**Recommendation: Option B.2** — a new HTTPS key-directory service, token issued
over the BOS login and captured read-only by the DLL. Server persists bundles in a
new set of tables under `state/` (mirroring `SQLiteUserStore`), with migrations in
`state/migrations/`. The server never sees plaintext and cannot forge bundles
(identity-signed prekeys), so its role is an untrusted-but-available directory and
relay — exactly the Signal trust model.

### 8.2 Device linking

New device flow, no server trust:
1. New device generates its identity-scoped device key and a signed prekey (signed
   by the **account identity key**, which it does not yet have).
2. To get the identity private key onto the new device, the user **approves on an
   existing device**: the existing device shows a short authentication string
   (derived from both devices' ephemeral keys), the user confirms it matches on the
   new device, then the existing device encrypts the identity private key to the new
   device's ephemeral key and sends it **through the key-directory relay** (server
   only relays ciphertext).
3. New device publishes its signed prekey + one-time prekeys; server pushes a
   device-list-changed notification so peers refresh and start fanning out `wraps[]`
   to the new device.

The relay and notifications are the `link`/`notify` operations of the key-directory
service (8.1).

---

## 9. Q4 — Crypto library and licence

- Repo licence is **MIT** (`LICENSE`, "Copyright (c) 2024 mk6i").
- **libsignal** (`signalapp/libsignal`, crate `libsignal-protocol`): licence
  **AGPL-3.0-only**, `rust-version = 1.93.1` (verified from its `Cargo.toml`). It is
  pure-Rust and would build for `i686-pc-windows-msvc` (the same target the Ruffle
  DLL already ships; toolchain is `stable` with `i686-pc-windows-msvc` +
  `crt-static`, per `tools/icq65/flashplayer/rust-toolchain.toml` and
  `.cargo/config`). **But AGPL-3.0 is copyleft and incompatible with keeping the DLL
  under the repo's MIT terms**: linking `libsignal-protocol` makes the whole DLL a
  derivative work that must be AGPL, with AGPL's source-offer obligations. For a
  client-side add-on shipped to users this is workable only if we license *this DLL*
  separately as AGPL and keep it in its own crate/repo — it cannot be MIT. It also
  pulls a large dependency tree.
- **libsignal-protocol-c** (GPLv3, used by Miranda's OMEMO): same copyleft problem,
  and C not Rust.
- **vodozemac** (`matrix-org/vodozemac`): licence **Apache-2.0** (MIT-compatible),
  implements **Olm** (X3DH-like handshake + Double Ratchet) and **Megolm**,
  `rust-version = 1.96`, pure Rust (curve25519-dalek/ed25519-dalek/x25519-dalek,
  hkdf, hmac, aes, chacha20poly1305) — all build for i686. Apache-2.0 sits cleanly
  next to MIT.

**Recommendation.** Do **not** take libsignal into an MIT DLL. Two acceptable
paths:
1. **vodozemac (Apache-2.0)** for the core ratchet if Olm's X3DH+Double-Ratchet is
   acceptable. It gives us Double Ratchet, X25519/Ed25519, safety-number-able
   identity keys out of the box; the multi-device prekey directory, signed prekeys,
   one-time prekeys and per-device wrapping we build on top (Olm sessions are
   1-to-1-per-device, which matches our `wraps[]` fan-out). **No PQXDH** — scheme 2
   (PQXDH) would be a later addition.
2. **Assemble X3DH/PQXDH + Double Ratchet from RustCrypto primitives** (all
   MIT/Apache: `x25519-dalek`, `ed25519-dalek`, `hkdf`, `hmac`, `sha2`,
   `chacha20poly1305`, plus `ml-kem`/`pqcrypto` for PQXDH). More work, full control,
   licence-clean, and the only route that gives PQXDH as specified. Given the owner
   asked specifically for X3DH/**PQXDH**, this is the better long-term choice;
   vodozemac is a faster path to a first working ratchet.

All options build for `i686-pc-windows-msvc` on the existing stable toolchain with
`+crt-static` (the ICQ folder has no modern VC++ runtime — matching how the Ruffle
DLL links). MSRV of libsignal (1.93) / vodozemac (1.96) is satisfied by current
stable.

---

## 10. Failure modes

- **Peer without the DLL**: recipient lacks `CapE2EEncrypt` → send in clear with a
  one-time system note, or (user setting) refuse to send. Inbound `IQE1` on a
  client whose DLL is absent → shows the armored blob prefixed with a human hint.
- **No session / no prekeys for a device**: fetch bundle; if the directory has no
  one-time prekey, fall back to the signed prekey (standard X3DH behaviour) and
  raise a "prekeys low" note so the device replenishes.
- **Decrypt failure (wrong device, out-of-order beyond ratchet window, corrupt)**:
  render `[encrypted message — cannot be read on this device]`; never surface raw
  bytes; log to the local diagnostics page.
- **Length growth vs client limits**: ciphertext + `wraps[]` can exceed
  `MaxIncomingICBMLen` from `ICBMParameterReply`. The DLL must chunk oversize
  containers across multiple ICBM frames (still N-in/N-out per chunk) or negotiate a
  larger limit; design the container with an optional continuation flag.
- **Hook not installed / networking module not yet loaded**: engine retries module
  resolution; until hooked, traffic flows unmodified (no E2E, clear fallback).
- **Key-directory unreachable**: no new sessions can be established; existing
  ratchet sessions keep working offline; UI shows directory status.
- **Charset/HTML round-trip**: if the sender used UCS-2 or `<FONT sml>` smileys, the
  decrypting DLL must restore the exact original text so rendering matches; store
  the original charset id in the plaintext envelope.
- **Server-side clear fallback interop**: the server's existing `stripHTML`/tZer
  translation still runs on the (now ciphertext) body for mixed clients — verify it
  treats our UCS-2 container as opaque text and does not corrupt it; if it does,
  prefer the ASCII-armored container form on paths that cross the server translator.

---

## 11. Phased plan

**Phase 0 — spike (owner-testable): log-only.**
A DLL that installs via the chosen hook (7.2 `tbdiag.dll`, 6.5 `msimg32.dll`
proxy), resolves `coolcore5x`/`coolcore4x`, IAT-hooks `send`/`recv`, reassembles
FLAP, parses ICBM SNACs, and **writes the decoded inbound and outbound IM text to a
local log file** (and/or the 127.0.0.1 page). No crypto, no rewriting — proves the
hook, the module resolution, the FLAP reassembly and the ICBM text extraction on
both clients. This is the first thing the owner runs.

**Phase 1 — pass-through rewrite harness.**
Same, but actually rewrite the ICBM text in place (e.g. a trivial reversible
transform) to prove N-in/N-out framing and length fix-up don't disturb the client
(typing, acks, HTML, smileys all still work). Plan and decisions:
`docs/e2e/STAGE-2-CLIENT-REWRITE-HARNESS.md`.

**Phase 2 — crypto core, single device per UIN.**
X3DH + Double Ratchet (vodozemac or RustCrypto), `IQE1` container, `CapE2EEncrypt`
advertisement, clear-fallback and readable-downgrade notes. Key directory as the
HTTPS side channel (Option B.2) with server-issued token; one device per account.

**Phase 3 — multi-device.**
Signed prekeys, one-time prekeys, per-device `wraps[]` fan-out, offline delivery,
device-list notifications, device-linking (approve-on-existing-device) flow.

**Phase 4 — management UI + polish.**
127.0.0.1 page (identity, per-contact safety numbers, device list, link approvals,
directory status) opened through the Xtraz list the same way our server serves
`/icq/details`-style pages; in-chat system notes; PQXDH (scheme 2) if pursuing the
RustCrypto route; chunking for oversize messages.

---

## 12. Open risks

1. **Licence**: libsignal is AGPL — cannot go into an MIT DLL. Decision needed:
   vodozemac (Apache, no PQXDH) vs. hand-rolled X3DH/PQXDH from RustCrypto (clean,
   more work). This gates Phase 2.
2. **Capability GUID injection** modifies an outbound login SNAC in place; must
   confirm the server and both clients accept the extra cap without side effects
   (it changes only the caps TLV length).
3. **Message length limits**: chunking design must be validated against real
   `MaxIncomingICBMLen`; `wraps[]` fan-out grows with device count.
4. **Server translator interop**: the existing `stripHTML`/tZer translation on the
   BOS path must treat the ciphertext container as opaque; verify per path, may
   force ASCII-armored form for cross-generation.
5. **Hook robustness across builds**: 7.2 auto-updates 3143→3525; the `tbdiag`
   slot and `coolcore59` import layout must be re-checked on 3525 (addresses here
   are from the 3143 copy; the live 3525 install is read-only and must only be
   copied from, never run).
6. **Device-linking UX security**: the approve-on-existing-device authentication
   string and the identity-key transfer are the crypto-critical path; get this
   reviewed carefully.
7. **AV/UAC**: an unsigned proxy/hook DLL in a program folder may trip antivirus;
   the patch runs elevated to place it, but runtime AV heuristics on IAT hooking are
   a risk worth testing early.
