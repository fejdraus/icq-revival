# Encrypted voice and video calls - research

Status: research (2026-10-02). Stage C0, the observation spike, is built
(section 8). Stages C1-C3 - key agreement, media encryption, policy and
notes - are built behind `calls_encrypt = on`, **off by default** (section
9). Neither has run on a live call yet: the owner's live test (sections 8.1
and 9.4) is the next step. Sections 1-6 are static analysis of the import,
export and string tables of the shipped DLLs and of their configuration;
native code paths were not reversed.

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
    **Superseded** by the owner's rule (section 9): a call is never blocked;
    a call that is not encrypted is exactly what it was without the add-on,
    and the note says so, in stronger words for such a contact.
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

C1-C3 are built (section 9); C4 is the live test of section 9.4.
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

## 9. C1-C3 status

**Built, off by default, not yet run on a live call.** `calls_encrypt = on`
in `icq-e2e.ini` (or `ICQE2E_CALLS_ENCRYPT=on`) turns it on; it needs
encrypt mode and frames allowed (not `e2e=off`, not `ICQE2E_NO_INJECT`). Off,
the add-on behaves exactly as with C0 alone: nothing is offered, an incoming
offer is an ordinary control message, no datagram is ever changed. The
server is not changed. Code: `tools/icq-e2e/core/src/callneg.rs` (C1, C3),
`callmedia.rs` (C2), `hook_calls.rs` (the hooks), `stream.rs` and
`crypto.rs` (the control messages); README "Call encryption".

The owner's rule, which overrides section 5a: **backward compatibility of
calls**. A call where either side has no add-on, an older one, or
`calls_encrypt` off works exactly as today - plain, every byte untouched.
Encryption only after both add-ons agreed for that Call-ID; anything not
agreed passes untouched. A call is never blocked.

### 9.1 Key agreement (C1)

Hidden control messages in the existing Olm session (`container.rs` kind 0,
`FLAG_CONTROL`), payload `IQC1 | type | call (first 16 bytes of the Call-ID's
SHA-256) | ...`:

| Message | Sent | Fields |
|---|---|---|
| Offer | by the caller, just **before** its INVITE goes out | device id, device Curve25519 key, ephemeral X25519 key, SDP hash, suites |
| Answer | by the callee, just **before** its 200 OK goes out | device id, device key, ephemeral key, SDP hash, the suite |
| Decline | instead of an answer, when the callee's add-on refuses (`/e2e off` for the caller, no common suite) | reason |
| Confirm | by the caller, before the next SIP message (the ACK) | HMAC tag under a key both sides derived |

- Because each control message goes on the same connection just before
  the SIP message it belongs to, and the server relays both in order, the
  decision needs no timer: the callee knows at the INVITE whether there was
  an offer, the caller at the 200 OK whether there was an answer.
- An offer is made only to a contact with signed devices in the key
  directory, under the message rules (not `/e2e off`, our keys published,
  not a changed safety number of a verified contact). An add-on without call
  support (C0 or older, or `calls_encrypt` off) decrypts the offer as an
  ordinary control message: nothing is shown, the ratchet moves, it answers
  with an empty control message at its next message, and the call is plain.
  A contact with published keys who now runs a client without the add-on
  sees the offer as the usual "Encrypted message - install the add-on" line,
  as for any control message.
- Keys: HKDF-SHA256 over the X25519 secret of the two ephemeral keys; salt =
  a label, SHA-256(Call-ID), then caller and callee each as UIN, device id
  and Curve25519 device key; info = a label, both ephemeral keys and the
  purpose. Separate key + salt for caller-to-callee and callee-to-caller, each
  for RTP and RTCP, and a confirmation key. The Olm session authenticates the
  ephemeral keys, so the call keys are as trusted as the chat (the safety
  number). Forward secrecy per call; dropped 10 s after BYE, CANCEL or a
  final error, or when a set-up is given up.
- The SDP hashes are compared, not bound into the keys: a 200 OK whose SDP
  is not the one the callee's add-on saw is logged as a warning and the call
  stays encrypted (the keys do not depend on the addresses).
- The callee encrypts from its 200 OK on, but holds the call as *answered*
  until the caller proves it has the keys: the Confirm, or simply its first
  packet that decrypts. With neither in 8 s (the answer was lost, so the
  caller went plain) the callee goes plain too, with a note - never a call
  where one side encrypts and the other does not.

### 9.2 Media (C2)

As section 5a recommends, in the add-on's `sendto`/`recvfrom` (and
`send`/`recv` on connected UDP sockets) of the call modules:

- RTP: AES-128-GCM in RFC 7714's layout (header clear as associated data,
  payload encrypted, 16-byte tag), with the rollover counter sent explicitly
  in 4 bytes after the tag (authenticated). The sender never repeats an
  index: a sequence number that goes back takes the next rollover counter.
  RTCP: first 8 bytes clear, the rest encrypted, tag, `E | 31-bit index`.
  Overhead 20 bytes per packet.
- Replay: 128 packets per SSRC and direction, for RTP and RTCP.
- Framing: bare (direct path, and the relayed path after Set Active
  Destination), inside the DATA of a TURN Send / Data Indication (ICQ 6.5's
  unpadded dialect and RFC 5766's padded one, lengths fixed), or ChannelData.
  STUN and TURN control are never touched.
- Which datagrams: only while a call has keys, only on a datagram socket of
  that call - a local port of our SDP (`m=` port and the next, `a=rtcp`, host
  candidates, `rport`), or any port while it is the only call with keys (one
  call at a time; until C0 shows how sipX binds behind ICE).
- Fail closed, for an agreed call only: no authentication, a replay, plain
  RTP in an encrypted call: dropped. A packet that cannot be encrypted (an
  integrity attribute after DATA, too many SSRCs): dropped, never sent plain.
  A panic in a hook: dropped if the socket belongs to an agreed call, passed
  untouched otherwise. `WSASendTo` (imported by no module) with an agreed
  call's media: dropped.
- A dropped incoming datagram: the next one is read if one is waiting or
  comes within 20 ms, else the client gets a zero-length datagram. How sipX
  takes that is for the live test to show (the RTP code is expected to
  discard it as too short).
- MTU: an encrypted datagram over 1472 bytes of UDP payload is logged once
  per call and counted; the add-on does not fragment. C0 data will tell
  whether video gets there.
- Media before the answer (none is expected) and media of a call that is
  not agreed pass untouched.

### 9.3 Policy and notes (C3)

Never blocked. One note per call, in the chat with the contact:

- `[ICQ E2E] This call with 100002 is end-to-end encrypted: the voice and
  video are encrypted with keys agreed through your encrypted chat.` plus
  "100002 is verified." or the hint to compare the safety number.
- `[ICQ E2E] This call with 100002 is not end-to-end encrypted: <reason>.`
  Reasons: the contact did not offer to encrypt it / did not answer the key
  exchange (no add-on there, an older one, or call encryption off); declined
  (encryption off for this chat on their side); has no encryption keys; the
  key directory could not be reached; our keys not published yet; `/e2e off`
  here; a changed safety number not verified again; never confirmed the call
  keys; the key exchange could not be sent.
- For a contact under `/e2e on` or verified, the plain note adds: "Encryption
  is on for 100002 in this chat, but calls are never blocked: the server and
  the network can listen to this one. Hang up if it must stay private."
- With `calls_encrypt` off there are no call notes at all.

Tests (`cargo test --release`): the KDF (every input bound, directions
apart), RTP/RTCP round trips with CSRC/extension/padding, tampering, the
replay window with reordering and loss, rollover past 65536 packets and a
sender that restarts its sequence numbers, plain RTP dropped, TURN Send /
Data Indication / RFC 5766 Send Indication / ChannelData rewrapping, STUN
and TURN control untouched, the MTU count; the payloads; the state machine
(both on -> encrypted; callee without / off / old -> plain; caller without /
off -> plain; decline; mismatched Call-ID, peer or device; implicit
confirmation; confirmation timeout; wrong tag; BYE grace; set-up expiry);
the same through two engines and their Olm sessions; the stream putting the
control message before the SIP frame only when on; and two endpoints over
real loopback UDP sockets through the hooks (encrypted on the wire, decrypted
through the other hook, plain dropped, `WSAEMSGSIZE`, STUN and an unagreed
call byte for byte).

### 9.4 Live test (owner)

> Run it yourself; nothing here starts a client.

The ICQ 6.5 VM and ICQ 7.2 on this PC, two test accounts (e.g. 100001 and
100002). The server is not changed and relays the media as bytes, so the
same server as for C0 serves. Whether 7.2 places calls at all is itself
open (section 1.1); if it does not, use two 6.5 installs.

Set-up on both: apply the patches rebuilt by
`tools\common\Build-Patches.ps1` with the encryption rows
(`-Include e2e,e2e-tls`), set `ICQE2E_LOG` as in section 8.1, and edit
`icq-e2e.ini` next to `ICQ.exe` with ICQ closed (the patch keeps the lines).
Make sure a message between the two accounts is encrypted first (the chat
says so): an offer needs the E2E session.

1. **C0, `calls_encrypt` off** (only `calls_log = on` on both): the calls of
   section 8.1. Every call line of section 8.2, and no line starting with
   `call ... with` (the C1 lines), no call note in the chats. This is also
   the C0 data: which module sends RTP on 7.2, the packet sizes, direct or
   TURN.
2. **Both on** (`calls_log = on` and `calls_encrypt = on` on both): a voice
   call each way, a video call, and if possible a forced relay (section 8.1
   step 4). Expected:
   - start-up: `calls_encrypt=on: a call is encrypted end to end when both
     add-ons agree ...`, and `call hooks installed in ...: media of a call
     both add-ons agreed on is encrypted, all else untouched` when the call
     starts;
   - caller: `INVITE out, key offer sent first`, `key answer in; media keys
     agreed`, `200 OK in, the call is end-to-end encrypted`; callee: `INVITE
     in, with a key offer`, `answered; key answer sent first`, then `the
     caller confirmed the keys` (or `the caller's media decrypts`);
   - both: `first media packet encrypted (local port P, N B -> N+20 B)`,
     `first media packet decrypted`; the C0 flow lines show RTP 20 bytes
     larger than in run 1; at the end `forgotten (ended); media: ...` with
     **0 failed authentication** and voice and video clear on both sides;
   - both chats: "This call with ... is end-to-end encrypted";
   - optional capture: RTP headers readable, payload noise (a G.711 stream
     no longer plays);
   - any `over 1472 B of UDP payload` line (video) is worth sending.
3. **One side off** (`calls_encrypt = off` on the 6.5 VM, on here), a call
   each way: the call works as in run 1, the on side says in the chat "This
   call with ... is not end-to-end encrypted: ... did not answer the key
   exchange" (it calls) or "... did not offer to encrypt it" (it is called),
   its log shows the same with `not encrypted`, and no `first media packet`
   line: the media sizes match run 1. On the off side: nothing new at all.

What to collect: both logs with the time of each call, and anything the
calls did differently from run 1 (silence, noise, a dropped call).
