# Encrypted voice and video calls - research

Status: research only (2026-10-02). No code was changed for it. Static
analysis of the import, export and string tables of the shipped DLLs and of
their configuration; native code paths were not reversed. Nothing here was
seen on a live call yet - section 7 says what a live test must confirm.

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
