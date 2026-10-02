# Encrypted voice and video calls - research

Status: research (2026-10-02); stage C0, the observation spike, is built
(section 8) and its live test is the owner's next step. Sections 1-6 are
static analysis of the import, export and string tables of the shipped DLLs
and of their configuration; native code paths were not reversed. Nothing here
was seen on a live call yet - sections 7 and 8 say what a live test must
confirm.

Files examined: ICQ 7.2 as installed (read only), ICQ 6.5 from the pristine
copy in the scratchpad. Offsets below are file offsets of strings, IAT
offsets are RVAs.

## 1. The media stack of ICQ 6.5 and 7.2

Both clients carry AOL's AV stack: **sipXtapi** (SIP user agent, SDP, STUN,
ICE, the draft TURN) with the **GIPS VoiceEngine / VideoEngine** inside it.
There is no other voice module (no `MCAvMsgAgent`-style DLL, no WebRTC, no
RingRTC).

| | ICQ 6.5 | ICQ 7.2 |
|---|---|---|
| SIP + SDP + NAT | `sipXtapi.dll` (2.9 MB, 314 exports) | `sipXtapi.dll` (1.9 MB, 214 exports) |
| Voice/video engine | inside `sipXtapi.dll` (exports `GipsVoiceEngineLib`, `GipsVideoEngine`, `GIPS_media_process`) | `sipXmediaLib.dll` (2.5 MB), loaded by `sipXtapi.dll` by name (string `sipXmediaLib.dll` at 0x174294) |
| Video render | `pb_videoconf.dll` (`PB_CreateVideoRender`, imports `MSVFW32`, no sockets) | same |
| Who drives it | `coolcore49.dll` loads `sipxtapi.dll` at run time (string 0xa857c) and resolves ~90 `sipx*` functions by name | `coolcore59.dll` (string 0x99b50); the ACC layer `acccore.dll` exposes it as `AccAvManager` / `AccAvSession` (`AccAvSessionType_Talk`, `_Rtp`, `_RtpConference`; `AccAvStreamType_Audio/VideoSend/Receive`) |
| Loaded | at run time - nothing imports `sipXtapi.dll` statically | same |

Codecs (string `IPCMWB ISAC ISACLC EG711U EG711A PCMU PCMA iLBC GSM
telephone-event G723` and `VP71-VGA ... H263-CIF ...` in 7.2
`sipXmediaLib.dll` at 0x1c2210 / 0x1c21a8): audio iSAC, iLBC, G.711, GSM,
G.723; video On2 VP7 and H.263.

### 1.1 How a call is set up

- **SIP**, tunnelled through OSCAR. `coolcore` resolves
  `sipxConfigExternalTransportAdd` and
  `sipxConfigExternalTransportHandleMessage` (both clients): sipX hands each
  SIP message to coolcore, which sends it as an **ICBM on channel 6**, raw SIP
  in TLV `0x0005` (`wire.ICBMChannelSIP`, `foodgroup/icbm.go`, which logs the
  first line and the SDP of each one). Messages are several KB, hence the
  8000-byte ICBM limit. A call report goes to the server as SNAC `0x13/0x37`.
- **Not ICBM channel 2 rendezvous.** The channel-2 voice path
  (`CapVoiceChat` `09461341-...`, `AccAvSessionType_Talk`, the `Talk_*`
  strings in `coolcore49.dll` at 0x9f39c) is the older AIM Talk; ICQ 6 calls
  use the RTC/SIP path.
- **Capabilities** (all present in `coolcore49/59`, `MCore`, `acccore`;
  short caps `0946xxxx-4C7F-11D1-8222-444553540000`):
  `CapRTCAudio` 0x0104, `CapRTCVideo` 0x0101, `CapHasMicrophone` 0x0103,
  `CapHasCamera` 0x0102 (`wire/snacs.go`). The same GUIDs in big-endian form
  sit in the media engine (`sipXtapi.dll` 6.5 at 0x233ef8, `sipXmediaLib.dll`
  7.2 at 0x1c4a04): it puts them in its own SIP/SDP.
- **NAT**: coolcore turns on `sipxConfigEnableStun`, `sipxConfigEnableTurn`,
  `sipxConfigEnableIce` (7.2 also `sipxConfigEnableArs`). The host is
  `StunHost`/`StunPort` in 6.5 `MCore.dll` (default `turn.oscar.aol.com`,
  patched to our domain) and `aimcc.connect.stun.address`/`.port` (3478) in
  7.2 `AppConfig.xml`. Our server answers STUN and the TURN of
  draft-rosenberg-midcom-turn-08 that sipX speaks (`server/stun`, UDP 3478,
  relay ports 49160-49199): Allocate, Send, Data Indication, Set Active
  Destination; after Set Active Destination media goes **without TURN
  framing** (`relay.go` `fromClient`). ICE candidates: `Adding local
  candidate type=%s IP=%s port=%d` (7.2 `sipXtapi.dll` 0x188f9c).
- **Transport**: UDP. RTP/RTCP on even/odd local ports from 16384 (seen
  earlier: sipX bound UDP 5061 and 16384/16385 during a test call,
  `scratchpad/stun/udp-watch.log`). SDP profiles known to sipX: `RTP/AVP`,
  `RTP/SAVP`, `TCP/RTP/AVP`, `ARS/RTP/AVP`; `sipxConfigEnableRtpOverTcp` is
  exported but coolcore does not resolve it, so TCP media is not used.
- **7.2**: the whole stack is there and `aimcc.av.*` settings exist
  (permissions 0, the same as the stock file), but the project only claims
  calls for 6.5. Whether 7.2's UI offers a call is not verified.

### 1.2 Is the media already encrypted?

**No, in practice - but the engine can do SRTP.**

- Built in: libSRTP (`libSRTP: Copyright (c) 2001-2003 Cisco Systems` -
  6.5 `sipXtapi.dll` 0x23a2d0, 7.2 `sipXmediaLib.dll` 0x1d2a88), the GIPS
  calls `GIPSVE_InitEncryption`, `GIPSVE_EnableSRTPSend(channel, cipherType,
  cipherKeyLength, authType, authKeyLength, authTagLength, level, key)`,
  `GIPSVE_EnableSRTPReceive`, `GIPSVideo_EnableSRTPSend/Receive` (6.5),
  `rtpsender::encryptandsend`. sipX's SDP knows `RTP/SAVP`, `crypto:1 `,
  `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32`, `F8_128_HMAC_SHA1_80`,
  `UNENCRYPTED_SRTP`, `UNAUTHENTICATED_SRTP` (6.5 0x22e110-0x22e314,
  7.2 0x17e818-0x17ea44) - SDES-style keys in the SDP, in clear.
- sipX's security switch is `SIPX_SECURITY_ATTRIBUTES` with S/MIME of the
  SDP through NSS: `sipxConfigSetSecurityParameters`,
  `sipxConfigLoadSecurityRuntime`, strings `nss3.dll`, `smime3.dll`,
  `ssl3.dll`, `nspr4.dll`, `CAUSE_SMIME_FAILURE`. **No NSS DLL is shipped,
  and coolcore resolves none of the security functions** (its list of ~90
  `sipx*` names has no `Security`, `Srtp` or `Crypt`). So the client never
  configures SRTP; media is plain RTP. A live capture must confirm
  (`RTP/AVP` in the logged SDP, decodable RTP in Wireshark).
- No `crypt32`/`bcrypt` imports in any media DLL, no DTLS strings
  (`ATTR_STUN_FINGERPRINT` is the STUN CRC attribute, not a DTLS
  fingerprint).

## 2. Socket APIs on the media path (hook targets)

All imports are **by ordinal**, like coolcore's; `hook.rs` already turns an
ordinal into a name from the exporting DLL. No module is dynamic-base, but
the RVAs are what the hook uses anyway. The stack is Winsock 1.1 style:
blocking `select` + `recvfrom`/`sendto` on worker threads; no `WSASendTo`,
`WSARecvFrom`, overlapped I/O or `WSAAsyncSelect`.

| Module | DLL | Media-relevant imports (IAT RVA) |
|---|---|---|
| 6.5 `sipXtapi.dll` | `wsock32.dll` | `sendto` 0x22238c, `recvfrom` 0x222348, `select` 0x222354, `socket` 0x222384, `bind` 0x222394, `connect`, `send`, `recv`; `ws2_32.dll` only `inet_addr` |
| 7.2 `sipXtapi.dll` | `ws2_32.dll` | `sendto` 0x1c4758, `recvfrom` 0x1c47a0, `select` 0x1c4798, `socket`, `bind`, `connect`, `send`, `recv`, `getsockopt`... |
| 7.2 `sipXmediaLib.dll` | `wsock32.dll` (+ `ws2_32` for `setsockopt`, `ntohs`...) | `sendto` 0x1c1374, `recvfrom` 0x1c134c, `select` 0x1c1354, `socket`, `bind`, `connect`, `send`, `recv` |
| `coolcore49/59.dll` | `wsock32.dll` | `sendto`, `recvfrom` too (already hooked for `send`/`recv`/`connect`); its UDP use is not the call media |

In sipX the GIPS engine sends through a callback socket into sipX's own
`OsNatDatagramSocket` (strings `callbacksocket::enableSRTP`), so on 7.2 RTP
most likely leaves through `sipXtapi.dll`'s `sendto`; `sipXmediaLib.dll`'s
own imports must be hooked as well until the spike shows which one carries it.

The add-on can do this with what it has: the `LdrRegisterDllNotification`
watcher in `hook.rs` (today it waits for `coolcore*`) can also patch
`sipXtapi.dll` and `sipXmediaLib.dll` the moment they load (only when a call
starts), swapping `sendto`, `recvfrom` and, for bookkeeping, `socket`,
`bind`, `closesocket`. One packet = one datagram, so there is no stream
reassembly as for FLAP.

## 3. Where the signalling travels, and carrying a key

- The SIP of a call (INVITE with SDP, `200 OK` with SDP, ACK, BYE, INFO)
  is ICBM channel 6 on the **BOS connection**, through coolcore's `send` /
  `recv` - which the add-on already hooks and parses into FLAP/SNAC. Today
  it passes channel 6 through untouched (DESIGN.md 5.4).
- So the add-on sees, per call: the SIP `Call-ID`, both SDPs (local and
  remote RTP/RTCP ports, ICE candidates, relay addresses, payload types,
  `RTP/AVP`), and who the peer is - enough to bind a key to a call and to
  find the call's sockets.
- **Yes, a per-call key can travel inside the existing Olm session.** The
  add-on already sends hidden control containers (`container.rs`,
  `FLAG_CONTROL`, kind 0) to a contact, encrypted per device, never shown.
  A call control message `{call_id, role, ephemeral X25519 public key, suite,
  sdp_hash}` sent when the add-on sees the outgoing INVITE, answered when it
  sees the `200 OK`, reaches the other add-on through the Olm session that
  safety numbers already authenticate. Both use the same BOS connection and
  the server relays in order, so the key usually arrives before the first
  media packet; media is held or dropped until it does.
- Encrypting the whole SIP message in Olm (the Matrix way: the signalling
  itself is E2E) is possible but not first: a SIP message is several KB,
  and armoured Olm adds ~40%, so it can pass the 8000-byte ICBM limit; it
  would also hide the SDP from the server's call log. The server learns the
  addresses from TURN anyway. A later option.

## 4. How Signal and Matrix do it

- **Signal (RingRTC, WebRTC)**: offer/answer/ICE/hangup go as Signal
  Protocol messages. Each side puts an ephemeral X25519 key in its offer or
  answer; SRTP keys are derived from that DH with HKDF, bound to the
  identities - Signal removed DTLS-SRTP from 1:1 calls in favour of this.
  Media relays (TURN) are Signal's; "always relay calls" hides the IP. Group
  calls add frame encryption over an SFU.
- **Matrix (legacy 1:1 VoIP)**: `m.call.invite/answer/candidates/hangup`
  events carry the SDP; in an encrypted room they are encrypted, so the
  DTLS fingerprints in the SDP are authenticated by the E2E layer, and
  DTLS-SRTP gives the media keys. **Element Call / MatrixRTC**: per-sender
  media keys sent with Olm to-device messages, frame encryption over a
  LiveKit SFU.
- **What we mirror**: Signal's model - ephemeral DH in E2E-encrypted
  signalling, HKDF to SRTP-style keys, no DTLS (sipX has none) - and the
  Element Call idea of keys delivered over Olm and applied per packet by a
  layer below the codec.

## 5. Design options, ranked

### (a) Per-packet encryption in the add-on - recommended

Hook `sendto`/`recvfrom` of the sipX modules; transform RTP and RTCP, leave
everything else alone.

- **Keys**: per call, each side an ephemeral X25519 key in the Olm control
  message (section 3). `HKDF-SHA256(DH, salt = Call-ID || both UINs ||
  both device keys, info = "icq-e2e call v1")` -> separate keys for each
  direction, and for RTP and RTCP. Forward secrecy per call, independent of
  the Olm ratchet; keys are wiped at BYE or timeout. `ring` (already a
  dependency) has X25519, HKDF and AES-GCM; `chacha20poly1305` is there too.
- **RTP**: header (12 bytes + CSRC + extension) stays clear as associated
  data, so the relay and NATs see a normal RTP packet; payload encrypted
  with AES-128-GCM (RFC 7714 layout) or ChaCha20-Poly1305, 16-byte tag
  appended. Nonce from SSRC + packet index (ROC*65536 + seq); either
  RFC 3711 ROC estimation or an explicit 4-byte index (+4 bytes, no
  estimation errors - simpler to get right).
- **RTCP**: first 8 bytes clear, rest encrypted, SRTCP index with E bit and
  tag appended (RFC 3711/7714).
- **Replay**: a 128-packet window per SSRC and direction; old or repeated
  index dropped.
- **Classifying a datagram**: first two bits `10` = RTP/RTCP (RTCP by PT
  200-204); `00` = STUN/TURN - passed clear (connectivity checks, Allocate,
  refresh). TURN **Send** (0x0004) and **Data Indication** (0x0115) carry
  media in a `DATA` (0x0013) attribute: transform the inner value and fix the
  attribute and message lengths (attributes are unpadded in this dialect).
  After Set Active Destination media is raw and handled as plain RTP. Both
  the direct and the relayed path are covered; the server relays bytes as
  they are and needs no change.
- **Matching packets to a call**: local port from `bind`/`getsockname`
  against the `m=` ports of the local SDP, remote address against the peer's
  candidates and relay addresses; with one call at a time the local port is
  enough.
- **Interop and fail-closed**:
  - Encrypt only after both sides agreed in the control exchange for this
    `Call-ID`. A contact without the add-on (no capability, no answer in a
    few seconds) never gets encrypted media - it would only hear noise.
  - Policy (new ini line, e.g. `calls = encrypted | allow-plain`): if the
    chat is under `/e2e on` or the contact is verified -> **refuse**: drop
    all media and say in the chat "Call not encrypted: <uin> has no add-on;
    call blocked" (the user hangs up; BYE is not forged). Otherwise allow
    plain with a note "This call is not encrypted".
  - Once agreed: a packet that fails authentication is dropped, never
    passed on; a plain RTP packet on an encrypted call is dropped
    (downgrade); a panic in the hook drops the packet (never falls back to
    the original call with clear media - unlike the IM hooks, where the
    fallback is safe).
  - Note in the chat "This call is end-to-end encrypted" and the safety
    number state of the contact, as for messages.
  - A dropped incoming datagram: `recvfrom` returns the next one if
    `FIONREAD` shows more, else a zero-length datagram; how sipX takes that
    must be checked in the spike.
- **Risks**:
  - Size: +16 to +20 bytes per packet. Audio (iSAC/iLBC, 30-60 ms frames,
    ~60-200 bytes) is no issue, ~+5 kbit/s. Video: VP7/H.263 packets may be
    near 1400 bytes; with TURN framing (+~36) and the tag they can pass 1500
    and fragment. The spike must log the largest RTP payload; if needed the
    max packet size is lowered (`sipxConfigSetVideoParameters` /
    `SetVideoBitrate` exist) or fragmentation is accepted on direct paths.
  - Jitter/CPU: AEAD per packet is microseconds; no buffering is added, no
    effect on the jitter buffer. Loss and reordering are fine (each packet
    stands alone).
  - VQmon/RTCP-XR and the call report read RTCP: with RTCP encrypted
    end to end only the peers read it; the SNAC 0x13/0x37 report is
    client-side and unaffected.
  - Only one SSRC per media line expected; conferences (sipX supports them)
    are out of scope for v1.
  - A cross-version call (6.5 <-> 7.2) needs both add-ons on the same
    rules; 7.2 calls are not yet known to work at all.

### (b) Use the client's own SRTP

- **b1. Key the GIPS engine directly**: get the engine with
  `sipxCallGetVoiceEnginePtr` / `sipxConfigGetVideoEnginePtr` (exported)
  and call `GIPSVE_EnableSRTPSend/Receive` (AES_CM_128, HMAC-SHA1-80) with
  keys from the same Olm exchange. Codec-aware and no packet parsing, but it
  needs native reversing: those are C++ virtuals (vtable offsets differ
  between 6.5's in-`sipXtapi` engine and 7.2's `sipXmediaLib`), channel ids
  must be learned, and 2003-era libSRTP is old code. Also no replay window
  we control, and it does not cover RTCP or video unless the video calls
  exist and work alike.
- **b2. SDP rewrite to `RTP/SAVP` + `a=crypto`** (SDES) in the add-on, with
  the SIP itself carried inside Olm: the sipX code is there, but the client
  never sets `SIPX_SECURITY_ATTRIBUTES`, and without them sipX probably
  rejects or ignores an SAVP offer. Unknown without a live test or native
  reading; fragile.
- Both share (a)'s interop problem (a peer without the add-on cannot
  decrypt), so neither saves the policy work. **(b) is a fallback**, worth a
  look only if (a) hits packet-size or performance limits.

### (c) Not viable

DTLS-SRTP with fingerprints (Matrix, WebRTC): sipX has no DTLS; adding it in
the hook is a full DTLS stack per call for no gain over (a), whose keys are
already authenticated by Olm.

## 6. Stages and effort (rough)

| Stage | What | Effort |
|---|---|---|
| C0 spike | Hook `sendto`/`recvfrom`/`bind` in `sipXtapi.dll` (+ `sipXmediaLib.dll`) via the DLL notification; log per datagram only class (STUN/TURN/RTP/RTCP/other), size, PT, SSRC, never content; parse channel 6 SIP for `Call-ID`, SDP ports, `RTP/AVP`. Answers: which module sends RTP, max packet size, TURN framing in use, that media is plain. | 1-2 days + live test |
| C1 key exchange | Call control message over Olm (ephemeral X25519, `Call-ID`, SDP hash), timeouts, capability bit for "calls v1" | 2-3 days |
| C2 media transform | AEAD for RTP/RTCP, replay window, TURN Send/Data Indication, unit tests in `testhost` with captured packet shapes | 3-4 days |
| C3 policy | ini line, refuse/allow rules, chat notes, fail-closed, patch row per "one row per job" if the owner wants one | 1-2 days |
| C4 live | direct, forced TURN, video, loss, no-add-on peer, long call | 2-3 days |
| C5 7.2 | only if 7.2 calls work at all | open |

## 7. What a live test needs

For the stages that change the media (C2 on). The C0 observation test, which
changes nothing, is in section 8.1 and can run against the production server.

- Two Windows machines or VMs, each with ICQ 6.5 + the add-on, two accounts
  on a **local** Open OSCAR Server (`STUN_LISTENER`, `TURN_ENABLED`, not the
  production machine). VMs need a virtual audio device (and a virtual
  camera for video).
- A call each way; capture on both with Wireshark (UDP 3478, 49160-49199,
  16384+; "Decode As RTP"); server log for the channel 6 SIP lines.
- Before the add-on: confirm SDP says `RTP/AVP`, no `a=crypto`, and the RTP
  player plays the voice (proves media is plain today).
- With it: same call, RTP player gives noise, add-on log shows encrypt and
  decrypt counts and zero auth failures; voice is clear to both users.
- Forced relay: block direct UDP between the two machines (firewall) so the
  call goes through TURN; check both the Send/Data Indication and the raw
  (active destination) path.
- Loss/reorder: a tool like clumsy on one side; check replay and no
  audible damage beyond the loss itself.
- One side without the add-on: under `/e2e on` the call is blocked with the
  note; otherwise plain with the note.
- Long call or a unit test past 65536 packets (index rollover).

## 8. C0 status

**Built, not yet run on a live call.** The add-on (`tools/icq-e2e`) has an
observation mode for calls, `calls_log = on`, off by default. It changes no
byte of a call: every hook calls the original Winsock function first, with the
client's own arguments, and returns its result and last error as they are;
only afterwards are the bytes looked at. The server is not touched.

What it does (`core/src/calls.rs`, `core/src/hook_calls.rs`; README "Call
observation"):

- The `LdrRegisterDllNotification` watcher in `hook.rs` now also patches
  `sipXtapi.dll` and `sipXmediaLib.dll` the moment either is mapped (a module
  unloaded after a call and loaded for the next is patched again; one whose
  imports are not bound yet is patched from a thread once the load is done).
  Hooked by name, ordinals resolved per DLL as for coolcore: `sendto`,
  `recvfrom`, `send`/`recv` (classified only on a UDP socket), `WSASendTo`/
  `WSARecvFrom` (where present - section 2 found none), `bind`,
  `closesocket`. Each module keeps its own originals.
- Per datagram: STUN (RFC 3489 / 5389, by message type), the TURN of ICQ 6.5
  (Allocate, Send, Data Indication, Set Active Destination, Close Binding;
  for Send and Data Indication also the class of the datagram in `DATA`),
  RFC 5766 ChannelData, RTP (PT, SSRC, seq, marker, payload size), RTCP
  (packet types of the compound packet), other. Per flow (socket, remote,
  direction): the first 8 packets one line each, a new stream (class, PT or
  SSRC) once, a summary every 5 s (packets, packets/s, kbit/s, max size per
  class), totals at `closesocket`.
- Per SIP message (ICBM channel 6, TLV `0x0005`, read where the BOS stream is
  reassembled; the frame passes unchanged): method or status, CSeq, an 8-hex
  hash of the Call-ID, From/To user parts, and per `m=` line: media, port,
  profile, payload types, `rtpmap` names, the class of `c=`, the number of
  `a=crypto` lines, ICE candidates by type, the other attribute names.
- Addresses are logged only as `server`, `private`, `loopback` or `public`
  plus port, so the log can be shared; no payload, key, URI or Call-ID.
- Tests: the classifiers on STUN/TURN/ChannelData/RTP/RTCP samples, the
  tracker, SIP/SDP extraction from a channel-6 ICBM in both directions
  (including that no address, key or Call-ID reaches the line), the frame
  passing a `StreamRewriter` byte for byte, and the hooks over real loopback
  UDP sockets (datagram unchanged, Winsock's error and last error unchanged).

### 8.1 Live test (owner)

> Run it yourself; nothing here starts a client.

**Where.** The production server is the simplest safe choice for C0: it
already answers STUN and TURN (UDP 3478, relay ports 49160-49199,
`TURN_ENABLED`), the add-on changes nothing on the wire, and nothing is
deployed or changed on the server. Use two test accounts (e.g. 100001 and
100002), not real users'. The server logs each SIP message's first line and
SDP as it always does (`call signalling` in its log): that is the server-side
cross-check. A local server is needed only from stage C2 on, where the media
is changed. A TURN allocation is given only to a client signed in to the
server from the same public address it asks from.

**Machines.** Two ICQ 6.5 installs on two machines with different local
addresses: two VMs, or one VM and a 6.5 copy on this PC (this PC's installed
client is 7.2). Each needs a working audio device (in a VM a virtual sound
card, or the host's passed through), and for the video call a camera (a
virtual one, e.g. OBS Virtual Camera, will do).

**Set-up, on each machine:**

1. Apply the 6.5 patch (rebuilt for this change by
   `tools\common\Build-Patches.ps1`, so `Icqe2eProbe-msimg32.dll` next to it
   is the new add-on) with the encryption rows to the client copy - either
   row puts the add-on in:
   `ICQ-6.5-Patch.exe -Apply -Root <ICQ 6.5 folder> -Server <domain> -Include e2e,e2e-tls`.
2. With ICQ closed, add one line to `icq-e2e.ini` next to `ICQ.exe` (the patch
   keeps it on a later Apply):

   ```
   calls_log = on
   ```

3. Point the log at a known file: `mkdir C:\IcqLogs` and
   `setx ICQE2E_LOG C:\IcqLogs\icqe2e.log` (then sign out of Windows and in
   again, so ICQ inherits it). Without it the log is
   `%LOCALAPPDATA%\icqe2e\icqe2e.log`.
4. Optional packet capture, in an **elevated** prompt, started before the
   call:

   ```
   pktmon filter remove
   pktmon filter add C0udp -t UDP
   pktmon start --capture --pkt-size 0 --file-name C:\IcqLogs\call.etl
   ```

   and after the call:

   ```
   pktmon stop
   pktmon etl2pcap C:\IcqLogs\call.etl --out C:\IcqLogs\call.pcapng
   ```

   The capture holds the call's audio and video: keep it private.

**The calls:**

1. Start both clients and sign in; each log has
   `calls_log=on: call media and signalling are observed ...`.
2. From A, a **voice** call to B; B answers; talk for about 30 s; hang up.
3. From B, a **video** call to A; A answers; about 30 s; hang up.
4. Optional, the relayed path: on one machine block the direct path,
   `New-NetFirewallRule -DisplayName C0-block -Direction Outbound -Protocol UDP -RemoteAddress <other machine's IP> -Action Block`
   (and the same with `-Direction Inbound`), call again, then
   `Remove-NetFirewallRule -DisplayName C0-block`.
5. Close both clients, so the sockets close and the totals are written.

**What to collect:** the log from **both** machines
(`C:\IcqLogs\icqe2e.log`), with the time of each call; optionally both
`call.pcapng`. The log holds no address beyond the classes above and can be
sent as it is.

### 8.2 What each line tells

| Line | Answers |
|---|---|
| `call hooks installed in sipXtapi.dll ... patched [sendto#20, recvfrom#17, ...]` | The module was loaded at call start, and which imports it really has (the names after `patched`). On 7.2 a second line for `sipXmediaLib.dll`. `could not patch` and a reason means nothing of that module is seen. |
| `call SIP OUT/IN peer=... INVITE`, `180 Ringing`, `200 OK`, `ACK`, `BYE` | The signalling goes over ICBM channel 6 as section 1.1 says, in this order; `call=` ties the messages of one call together. |
| `... sdp: audio port=16384 RTP/AVP pt=[...] rtpmap=[...]` | The offered and answered codecs (`103=ISAC/16000` and so on) and ports. `RTP/AVP` with `crypto=0`: **no SRTP** is negotiated; `RTP/SAVP` or `crypto>0` would contradict section 1.2. |
| `candidates=N (host a, relay b, srflx c)`, `c=server` | Whether ICE is used and whether a relayed (TURN) address is offered. |
| `call media: <module> bind sock=N -> L:P (udp)` | The local ports (SIP 5061, RTP/RTCP from 16384) and which module opens them. |
| `STUN/3489 Binding Request` to `server:3478` | The STUN query for the public address; to `public:`/`private:` ports: ICE connectivity checks. |
| `TURN/aol Allocate Request` / `Allocate Response` | A relay was asked for, and given. |
| `TURN/aol Send Request carrying N B: RTP ...` (OUT), `Data Indication carrying N B: RTP ...` (IN) | Media **through TURN, with framing** (the Send/Data Indication case of section 5a). |
| `TURN/aol Set Active Destination ...`, then plain `RTP ...` to `server:3478` | Media through TURN **without framing**, after Set Active Destination. |
| `RTP ...` to or from `public:P` / `private:P` | The **direct path**, no relay. |
| `RTP v2 pt=.. seq=.. ssrc=.. payload=N B` | Plain RTP v2 with a readable header; the PT matches an `rtpmap` of the SDP (the codec); one SSRC per media line expected. The `<module>` of the RTP lines answers which module sends RTP (on 7.2 `sipXtapi.dll` or `sipXmediaLib.dll`). |
| `5.0s: rtp 167 pkt (33.4/s, 32.1 kbit/s) max 168 B` | Packet rate and the **largest packet** per class: the budget for the +16 to +20 bytes of C2 (video near 1400 B would need its packet size lowered). `turn-send/rtp` maxima include the TURN framing. |
| `closed; total: ...` | Totals per flow at the end of the call. |

The capture, if taken, cross-checks it: in Wireshark, Decode As RTP on the
ports from the log (or turn on the `rtp_udp` heuristic); Telephony > RTP >
RTP Streams lists the streams, and a G.711 (PCMU/PCMA) stream plays back.
iSAC and iLBC do not play in Wireshark; there, an unencrypted header with the
SDP's PT and clean sequence numbers is what "plain RTP" means.

C0 is done when the two logs answer: which module carries RTP; direct or TURN
(and which TURN framing); codecs and payload types; packet sizes (audio and
video maxima); and that the SDP says `RTP/AVP` with no `a=crypto`.
