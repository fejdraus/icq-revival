# Encrypted file transfer - implementation research and design record

Status (2026-10-04): **implemented and security-reviewed; a live transfer
between ICQ 6.5 and ICQ 7.2 is not yet documented as completed.** Stages F0
and F2-F4 are built behind `files_encrypt = on`, off by default (section 9),
and are covered by the audits in `AUDIT-2026-10.md`. F1 and F5 remain
unimplemented, as described below. The original research (2026-10-03) is
kept as the rationale. F1 (the rendezvous proxy on the
server) and F5 (the file name) are not built. The research itself: static
analysis of the import, export and string tables of the shipped DLLs and of
their configuration, plus the Go server and the add-on source; native code
paths were not reversed, and no client was started. Modelled on
`CALLS-RESEARCH.md`.

Files examined: ICQ 7.2 as installed (read only), ICQ 6.5 from the pristine
copy in the scratchpad. Offsets are file offsets of strings. The server's
domain is written `icq.example.org`.

## 1. How ICQ 6.5 and 7.2 send a file

**OFT2 (OSCAR File Transfer) over a peer TCP connection, negotiated by an ICBM
channel-2 rendezvous with `CapFileTransfer` `09461343-4C7F-11D1-8222-444553540000`.**
No other path was found.

| | ICQ 6.5 | ICQ 7.2 |
|---|---|---|
| Protocol engine | `coolcore49.dll`: the OFT2 magic as an immediate (`32 54 46 4F`, `'OFT2'` compared as a dword, 0x732c2), the OFT id string `Cool FileXfer` (0x9ee4c), `ResumeFailure`, `PeerUnreachable`, `Proxy*` errors, `Rendezvous` | `coolcore59.dll`: the same (`OFT2` at 0x797f5, `Cool FileXfer` 0x97df4) |
| Agent / session layer | `MCore.dll`: `MCFileXfer`, `MCFileXferAgentProps`, `MCFileXferChannel(Props)`, `MCFileXferSession`, collision actions (save as, skip, replace, ...), the capability `{09461343-...}` (0xe7ac0 in 7.2) | `MCore.dll` (same objects) on top of ACC: `acccore.dll` `IAccFileXferManager`, `IAccFileXferSession`, `AccSecondarySessionServiceId_FileXfer`, `AccFileXferSessionProp_*` (TotalNumFiles, IsDirectory, Speed, ...) |
| UI | `MUIMessage.dll` `FileXfer.*` strings, `MUICore.dll` `OnCmdUserFileTransfer`, prefs `SaveFileTransfers`, `FileXfer.XferDisabled` | same, plus `FileXfer.VirusWarning`, `ChangeFileExtensionWarning`, prefs panel `oprefspanelfiletransfer.box` |
| Proxy (ARS) host | `MCore.dll` wide string `ars.oscar.aol.com` (0x1b6f50) in the `MCFileXferChannelProps` block; port 5190 (the "other 5190" of `MCore.dll` that the 6.5 patch deliberately leaves, `Icq65Client.cs`) | `acccore.dll` prefs `aimcc.connect.ars.address` (default `ars.icq.com`, 0x81d58) and `aimcc.connect.ars.port`, which `AppConfig.xml` sets to **443**; also `aimcc.connect.rendezvousMode`, `aimcc.fileXfer.permissions.buddies/nonBuddies` |

Other paths checked and not found:

- **No HTTP upload / "send via server" / offline files.** 7.2's upload strings
  are the Lifestream photo upload (`LS.PhotoUploadApiBase`, `PictureUpload`,
  `UploadStatusPhotos`) and avatars; `OnEmbedUpload*` / `OnEmbedDownload*` are
  ACC listener names for images embedded in Direct IM. There is no
  `files.icq.com`-style URL and no offline-file flag.
- **AIM "Get File" / file sharing** (`AccFileSharingSession`, `RequestXfer`,
  `aimcc.fileSharing.*`, cap `09461348`) exists in 7.2's `acccore.dll`, but
  `MCore` only names `MIDFileXferAgent` / `SendFiles`; ICQ's UI is not seen to
  offer it. Out of scope.
- **Direct IM** (`ODC2<BINARY>` in both coolcores, cap `09461345`) is another
  peer connection of the same kind; the design below would cover it later.
- **The client's own secure rendezvous** (`ICBMRdvTLVTagsRequestSecure`
  0x0011, `aimcc.fileSharing.secure`): 6.5's `coolcore49.dll` names `nss3.dll`,
  `ssl3.dll`, `smime3.dll`, `nspr4.dll` and `SSL_*` functions, but **no NSS
  DLL is shipped** with either client and 7.2's coolcore names none. Not usable
  (and it would be certificate-based, not end to end).

### 1.1 Socket APIs - the hooks already in place

The whole file transfer runs in coolcore, through the **same import table the
add-on already patches** (`hook.rs`):

| Module | `wsock32.dll` imports (by ordinal) |
|---|---|
| 6.5 `coolcore49.dll` | `send recv connect closesocket WSAAsyncSelect ioctlsocket` (hooked) + `listen accept bind getsockname socket sendto recvfrom` (not hooked) |
| 7.2 `coolcore59.dll` | the same set |

No other module of either client imports Winsock except the call stack
(`sipXtapi`, `sipXmediaLib`) and 7.2's `tbdiag.dll` (crash reporting).
`MCore.dll`, `acccore.dll` and the UI DLLs have no socket imports (MCore and
the UI only WinINet, for updates and pictures).

So today:

- Every byte of an OFT connection already passes `hook_send` / `hook_recv`:
  the outgoing connection through `hook_connect` too, an accepted one shows up
  as "data without a connect the hooks saw" (`hook.rs`).
- `stream.rs` sees that the first frame is not FLAP and turns the stream
  **raw**: the bytes pass untouched (the deliberate "peer connections are left
  alone"). `route.rs` maps only `connect`s to the server's own addresses and
  ports, so peer connections never get TLS.
- To tie an accepted socket to a transfer the add-on needs `accept` hooked (or
  calls `getsockname` itself on the first data: the local port is the one the
  proposal advertised). `listen`/`bind` hooks are optional, for logging.

## 2. Rendezvous paths and where they go today

OFT has three ways to connect, all signalled on channel 2 with the same 8-byte
cookie and increasing `ICBMRdvTLVTagsSeqNum` (0x000A):

1. **Direct (stage 1).** The sender listens on a TCP port and proposes
   `RdvIP` (0x0002), `RequesterIP` (0x0003), `Port` (0x0005), with the XOR
   checks 0x0016/0x0017. The receiver connects. The port is the client's own
   choice (not visible statically; the spike logs it).
2. **Reverse (stage 2).** If that fails, the receiver listens and sends a
   counter-proposal (seq 2); the sender connects to it.
3. **Proxy (stage 3, ARS).** If both fail (or if a client asks for it with
   `UseARS` 0x0010), one side connects to its configured rendezvous proxy,
   sends `INIT_SEND` (screen name, cookie, capability; ARS frames are
   `u16 length | 0x044A | u16 command | ...`), gets an `ACK` with the proxy's
   IP and a port token, and proposes those; the other side connects to **that
   IP**, sends `INIT_RECV` (port token, cookie), both get `READY`, and from
   then on the proxy splices the two TCP streams and OFT2 runs through it.

**The Go server implements no rendezvous proxy.** `wire.ARS = 0x044A` is a
food-group constant only; there is no listener, no `INIT_SEND` handling, no
proxy anywhere in `server/`, `foodgroup/`, `state/`. What the server does on
a proposal (`foodgroup/icbm.go`, `addExternalIP`): it puts the sender's public
address into `RequesterIP` (keeping the LAN address when both clients share a
public address) and appends `VerifiedIP` (0x0004). `docs/RENDEZVOUS.md` tells
AIM users to forward a TCP port for direct transfers.

Where the proxy fallback goes today:

| Client | Proxy host | Result |
|---|---|---|
| 6.5 | `ars.oscar.aol.com:5190` (hard-coded, not patched) | the name does not exist any more (NXDOMAIN, checked 2026-10-03): the fallback fails; only a DNS query leaks |
| 7.2 | `aimcc.connect.ars.address` default `ars.icq.com`, port 443 from `AppConfig.xml` | **`ars.icq.com` resolves** (a CNAME to the current ICQ operator's `www.icq.com`, checked 2026-10-03). A 7.2 that falls back to the proxy would open a TCP connection to a **third party** and send it an `INIT_SEND` in clear: the UIN, the transfer cookie, the fact of a transfer, the user's IP. The transfer itself fails (that host speaks HTTPS). Static evidence only - whether 7.2's file path reads this pref is for the spike to confirm |

So: same LAN or a forwarded port works directly; behind two NATs the transfer
fails after the 7.2 leak described above. **Independent of E2E, the 7.2 patch
should write `aimcc.connect.ars.address` (to our domain, or to a dead name
until the server has a proxy)**, and 6.5's `ars.oscar.aol.com` slot should be
pointed at our domain the way `turn.oscar.aol.com` is (one domain, per "client
patches take only a domain").

## 3. What the signalling exposes

With the TLS row, the rendezvous ICBMs travel inside TLS to the server, so the
network sees nothing of them. **The server sees all of it**, and the data
connection itself is plain TCP between the peers (or through a proxy):

| Where | What is visible |
|---|---|
| Proposal TLVs (to the server) | cookie, capability, seq, sender's LAN IP (0x0002/0x0003), port, XOR checks, `UseARS`/proxy IP when stage 3; server adds the public IP (0x0004) and replaces 0x0003 |
| Proposal service data `0x2711` (to the server) | multiple-files flag, file count, **total size**, **file name** (or folder name) null-terminated; `0x2712` its charset; optional invitation text `0x000C` |
| Server log | `foodgroup/icbm.go` logs every proposal at Info: all TLVs (256 bytes each) and `service_data` (1024 bytes) in hex - **file names, sizes and both IPs end up in the server log**. Worth trimming regardless of E2E. |
| The peer | your public IP (and LAN IP when on the same public address) - inherent to a direct connection; only a proxy hides it |
| The network between peers / the proxy operator | today **everything**: OFT2 headers (file name, size, dates, checksum, `Cool FileXfer`) and the file bytes in clear |

## 4. How others do it

- **Signal**: attachments are encrypted on the device with a random
  AES-256-CBC + HMAC-SHA256 key, uploaded to a CDN, and the key + digest go in
  the E2E message. The server never sees the name or contents.
- **Matrix**: same model (`EncryptedFile`: AES-256-CTR key, IV and SHA-256 in
  the encrypted event); the media repo holds ciphertext only.
- **Peer-to-peer tools** (Magic Wormhole, Wire's old P2P, WebRTC data
  channels): a key agreed over an authenticated channel, then an AEAD record
  stream over the direct or relayed connection.

We have no upload store and the clients only speak OFT peer to peer, so the
mirror is the third one, keyed the way the calls are: an ephemeral key per
transfer agreed inside the Olm session, then an AEAD record stream at the
bottom of the peer socket.

## 5. Design options, ranked

### (a) AEAD record stream under the peer socket, keyed through Olm - recommended

The add-on runs a record layer at the bottom of the OFT socket, exactly where
`hook_tls.rs` runs TLS for server connections (pump thread, held plaintext,
`FIONREAD`, synthetic `FD_READ`, non-blocking connect). The client sees plain
OFT2 above it; the wire carries only records. OFT headers, file names inside
them, resume requests, multiple files and folders are all just bytes inside
the stream - nothing OFT-specific has to be rewritten.

**Key agreement** (hidden control messages, `container.rs` kind 0,
`FLAG_CONTROL`, like the calls' `IQC1`; say `IQF1 | type | transfer`):

| Message | Sent | Fields |
|---|---|---|
| Offer | by the file sender, just **before** its first proposal ICBM (seq 1) | cookie, device id + Curve25519 key, ephemeral X25519 key, a random 32-byte transfer secret, suites, optionally the real file name (5.c) |
| Answer | by the receiver, just **before** its accept (or counter-proposal) ICBM | cookie, device id + key, ephemeral key, suite |
| Decline | instead of an answer | reason |

- `transfer` = the cookie (it is what both the ICBMs and the OFT/ARS frames
  carry). An offer is made only under the message rules (contact has signed
  devices, not `/e2e off`, keys published, safety number not changed).
- Keys: `HKDF-SHA256(IKM = X25519(eS, eR) || transfer secret, salt = label ||
  cookie || sender UIN/device/key || receiver UIN/device/key, info = label ||
  eS || eR || purpose)` -> one key per direction and a confirmation key.
  Mixing the Olm-delivered secret into the IKM means an ephemeral key that
  arrives in-band (see below) is still authenticated: nobody without the
  offer can derive the keys. Forward secrecy per transfer; keys wiped when the
  socket closes or the cookie is cancelled.
- **In-band hello.** The ICBM order gives the sender the answer before the
  receiver connects in most cases, but the sender is the side that speaks
  first on a direct connection (the OFT2 prompt `0x0101`), and coolcore's
  networking is one window-message loop, so the add-on cannot block a `send`
  waiting for a BOS frame. So each add-on that agreed writes a hello as the
  first bytes of the connection - `"IQFT" | version | cookie-hash | its
  ephemeral key | MAC under the confirmation key` - and reads the peer's hello
  before any OFT byte goes to the client. The accepting side waits a bounded
  time (about 2 s, `select` with `MSG_PEEK`) for the hello before the client's
  first `send` leaves only when an offer for that port is pending and no answer
  arrived yet; otherwise it already knows.
- **Records**: STREAM construction (as in age / Tink): ChaCha20-Poly1305
  (already a dependency) or AES-256-GCM, plaintext chunks of at most 16 KiB,
  `u32 length | ciphertext | tag`, nonce = 11-byte counter per direction ||
  1-byte last-chunk flag. Reordering, replay, truncation in the middle and
  splicing of two transfers are caught by the AEAD + counter + per-transfer
  key. On the client's `closesocket`/`shutdown` the add-on writes an empty
  final record first; EOF without it is logged as truncated (the client sees
  the stream end as it would anyway). Overhead about 20 bytes per 16 KiB.
- **Whole-file integrity** follows from the stream: every byte the client
  reads is authenticated and in order, OFT's own done (`0x0204`) and checksums
  included. An optional SHA-256 per file in the add-on (needs OFT parsing) is
  not required.
- **Which sockets**: outgoing - `connect` to the `RdvIP:Port` of an agreed
  proposal (or to the proxy, below); accepted - local port equals the port the
  agreed proposal advertised. Anything else stays raw, as today.
- **Through the proxy**: the ARS frames (`INIT_SEND`, `ACK`, `INIT_RECV`,
  `READY`) stay as they are; the add-on parses them, matches the cookie, and
  starts the hello and records after `READY`. Any proxy, ours or another,
  sees only ciphertext.
- **Backward compatibility** (the owner's rule, as for calls): a peer with no
  add-on, an older add-on (it decrypts the offer as an ordinary control message
  and sends no answer), file encryption off, or no hello in time -> the
  transfer is exactly what it is today, every byte untouched, never blocked.
  One chat note per transfer: `[ICQ E2E] The file "<name>" to/from 100002 was
  not end-to-end encrypted: <reason>.` (stronger wording for a contact under
  `/e2e on` or verified), or `... was end-to-end encrypted.` plus the safety
  number state. Once a transfer is agreed it fails closed: a hello missing or
  wrong, plain `OFT2` bytes, a record that does not authenticate -> the add-on
  closes the socket (the client reports a failed transfer and may retry), never
  passes plaintext.

### (b) OFT-aware: encrypt only the file bytes, keep OFT2 headers clear

Length-preserving encryption (AES-CTR) of the data phase, headers left so a
middlebox could read them. Worse on every count: names, sizes and dates stay
visible; no integrity without changing lengths; resume offsets and the OFT
checksum of a partial file have to be recomputed against ciphertext. Only
useful if some component had to read OFT, and none does.

### (c) Real TLS 1.3 (rustls) on the peer socket with pinned keys

Reuse `hook_tls.rs` as it is: each side a fresh key pair, the two public keys
(or certificate fingerprints) exchanged in the Olm offer/answer, rustls with a
custom verifier on both sides (client auth) - Matrix's "fingerprint in the
E2E signalling" model. Gains a well-reviewed record layer and `close_notify`;
costs a certificate generator in the release build (`rcgen` is a dev
dependency today, or raw public keys if the rustls version in use supports
RFC 7250 - to check), a server-role TLS engine the add-on does not have yet,
and the role question on proxied connections. A fair alternative to (a)'s
own record layer; (a) is smaller.

### (d) Not viable

The clients' own secure rendezvous (no NSS shipped, certificate trust, not
E2E); an HTTP upload path (the clients have none).

### 5.c Hiding the file name from the server (optional)

The name sits in the proposal's `0x2711` service data. The sender's add-on can
put the real name in the Olm offer and replace it in the ICBM with a
placeholder of the same extension class (for example `file.bin` or
`3 files`), and the receiver's add-on restores it before the client parses the
proposal (it already rewrites ICBMs in place). Size and count stay (the client
shows them before accepting; the server could also round them, but the OFT
header inside the encrypted stream carries the true size anyway). Feasible,
but only for a peer whose add-on is known to support it - otherwise a
receiver without the add-on sees the placeholder. So it needs a capability
("files v1") learned before the proposal: a bit in the device record of the key
directory, or the answer to an earlier transfer. Stage F5, after the stream
works.

### 5.d The proxy path through our server

Yes, worth doing, and partly independent of E2E:

- **Server**: a rendezvous proxy (ARS protocol, `0x044A` frames) in Go:
  `INIT_SEND` from a signed-in screen name whose session comes from the same
  address (as the TURN rule), `ACK` with the server's address and a port
  token, `INIT_RECV` matched by token + cookie, `READY`, then splice with a
  byte cap and a timeout. About 2-3 days with tests. Ports: 6.5 uses 5190 for
  ARS, which is the FLAP port - either sniff the first bytes on the OSCAR
  listener (FLAP starts `0x2A`, ARS has `0x044A` at offset 2) or patch 6.5's
  ARS port immediate to a port of its own; 7.2's `aimcc.connect.ars.port` is
  a plain pref and should be set to the same port, so mixed 6.5/7.2 transfers
  meet (the peer connects to the proxy IP from the proposal, on its *own*
  configured port).
- **Patch**: write our domain for the ARS host in both clients (this also
  removes 7.2's third-party leak, section 2).
- **Add-on**: map the ARS port on the server's address to the TLS port, with
  an ALPN of its own (`route.rs`, as 8082 -> `http/1.1`). Then a proxied
  transfer is TLS to the server on the add-on's side even when the peer has no
  add-on, and the ARS frames (UIN, cookie) never travel in clear from that
  side. With (a) on top, the proxy sees only ciphertext.
- **Privacy option**: an ini line `files_relay = always` makes the add-on add
  `UseARS` to its proposals (and answer counter-proposals the same way), so
  the peer never learns the user's IP - Signal's "always relay calls".

## 6. Risks and differences

- **Race at connection start**: whether coolcore sends the OFT prompt before or
  after the accept ICBM arrives, and how it takes a delayed first byte, is not
  known statically; the bounded hello wait is the guess. The spike measures it.
- **Resume**: OFT resume (`0x0205` resume request with received bytes and
  checksum, `0x0106`, `0x0207`) runs inside the stream, unchanged. A resumed
  transfer is a new connection, normally with the same cookie and a new seq:
  the keys are per cookie, so a second connection derives new per-connection
  keys (add a connection counter to the HKDF info) - never reuse nonces across
  connections.
- **Partial transfers / cancel**: a cancel ICBM (`0x0001`, reason `0x000B`)
  forgets the keys; the add-on's note says "cancelled" rather than encrypted.
- **Multiple files and folders**: one connection, one OFT header per file
  (names with path separators): all inside the stream, nothing special.
  Folder names in the proposal are covered by 5.c only.
- **Counter-proposals / stage changes**: each new proposal for the same cookie
  must keep the agreement (offer/answer once per cookie; new proposals are
  matched by cookie).
- **6.5 <-> 7.2**: same OFT engine (both coolcore, `Cool FileXfer`), so the
  stream is the same; the differences are the proxy configuration (host and
  port) and ACC's permission prefs on 7.2. Both add-ons must speak the same
  `IQF1` version.
- **Throughput**: AEAD per 16 KiB chunk is negligible next to TCP; buffering
  is one record per direction.
- **Large files and `FIONREAD`**: the held-plaintext machinery of `hook_tls.rs`
  already handles this for long-lived streams.
- **Fail-closed vs never-blocked**: never blocked applies to transfers that
  were not agreed; an agreed transfer that then sees plaintext is an attack or
  a bug and is closed, as for calls. (Changed by the second audit of 2026-10,
  finding 4: never blocked holds only for a contact that is not strict; see
  section 9.)

## 7. Stages and effort (rough)

| Stage | What | Effort |
|---|---|---|
| F0 spike | `files_log = on`, off by default, changes no byte: log each file proposal (cookie hash, seq, which TLVs, `UseARS`, port, address classes, file count and size - no name), hook `accept`/`listen`/`bind` for logging, classify each raw peer socket (OFT2 header types `0101/0202/0204/0205/0106/0207`, ARS commands), which stage carried the data, who spoke first and the delay between the accept ICBM and the first OFT bytes | 1-2 days + live test |
| F1 server ARS + patch | Go rendezvous proxy, ARS host in both patches, 7.2 ARS port, add-on route of the ARS port to TLS. Fixes the 7.2 leak and NAT-to-NAT transfers for everybody | 3-4 days |
| F2 key agreement | `IQF1` offer/answer/decline, transfer secret, KDF, in-band hello, timers, capability bit | 2-3 days |
| F3 record stream | STREAM records under the socket (reusing the `hook_tls.rs` plumbing), socket matching (connect target, accepted local port, ARS cookie), fail-closed, tests in `testhost` over loopback incl. resume and two files | 3-4 days |
| F4 policy and notes | ini line (`files_encrypt`), chat notes, `files_relay = always` | 1 day |
| F5 file name | placeholder in `0x2711`, name in the offer, restore on receipt | 1-2 days |
| F6 live | the test below, both directions, both client versions | 2 days |

Independently of these, trim the server's `rendezvous proposal` log line
(no service data, address classes only).

## 8. Live test (owner)

Section 9.5 has the run for what is built now (F0, F2-F4); this is the
original plan, with the proxy runs that need F1.

> Run it yourself; nothing here starts a client.

Two clients (the 6.5 VM and 7.2 on this PC), two test accounts, a local
server or the production one for F0 (it changes nothing). Before any test that
can fall back to the proxy on 7.2, either have the patch from F1 or block
`ars.icq.com` (hosts file `0.0.0.0 ars.icq.com`), so nothing reaches the
third-party host.

1. **F0, observation**: `files_log = on` (and `ICQE2E_LOG` as in
   CALLS-RESEARCH 8.1) on both. Send a ~5 MB file each way, then two files at
   once, then a folder; cancel one in the middle and resend it (resume).
   Capture TCP with `pktmon` (`pktmon filter add F0tcp -t TCP`, then
   `etl2pcap`) and the server log. Expected: proposals with
   `CapFileTransfer`, the direct port, OFT2 frames in the log and readable
   OFT2 headers and file bytes in Wireshark (follow TCP stream) - proof the
   files go in clear today. Then force failure of the direct path (firewall
   rule blocking inbound TCP on the receiver and sender) to see the reverse and
   proxy stages: with the F1 patch the proxy is our server; without it 6.5
   fails on DNS.
2. **Both on** (`files_encrypt = on`): the same transfers. Expected in the
   logs: `file offer sent`, `answer in`, `hello ok`, `first record`,
   `final record`, 0 authentication failures; the received files byte-equal
   (compare SHA-256 of sent and received files with `Get-FileHash`); in
   Wireshark, after the `IQFT` hello only noise, no `OFT2`, no file name; both
   chats say "end-to-end encrypted".
3. **One side off / no add-on**: the transfer works exactly as in run 1, the
   on side's chat says "not end-to-end encrypted: ...", the off side shows
   nothing new.
4. **Through the proxy** (after F1): block the direct path as in run 1; the
   server log shows the ARS splice; the capture between client and server
   shows TLS only; with both on, the proxy log shows only byte counts.

## 9. F0, F2-F4 status

**Built, off by default, not yet run on a live transfer.** The server is not
changed. Code: `tools/icq-e2e/core/src/files.rs` (F0: parsing and the watch),
`filesneg.rs` (F2, F4: key agreement, sockets, notes), `filestream.rs` (F3:
hellos and records), `hook_files.rs` (F3: the socket layer), `stream.rs` and
`crypto.rs` (the control messages); README "File transfer observation" and
"File encryption"; the patch row "End-to-end encryption of file transfers"
(`e2e-files`, writes `files_encrypt`, needs the messages row).

The owner's rule, as for calls: **backward compatibility of transfers**. A
transfer where the peer has no add-on, an older one, or `files_encrypt` off
works exactly as today - every byte untouched - and is never blocked; the
data connection is encrypted only after both add-ons agreed for that
cookie; connections that are not file transfers (direct IM, voice) are
never touched. Once agreed, a transfer fails closed.

Changed by the second audit of 2026-10, finding 4: the rule above holds for
a contact that is not strict. For a contact under `/e2e on` or verified, and
with `files_encrypt = required` for every contact, "encryption is on" means
the same for files as for messages and calls: a transfer that does not agree
on keys (no offer or answer, a decline, no key hello within 4 s) is not sent
- the sender's connection is shut and its held bytes dropped, a receiver
refuses the transfer's sockets - and the chat says so. A connection whose
first bytes are no key hello only closes itself and decides nothing about the
transfer (nothing on it was authenticated), so an outsider that reaches the
sender's listening port first cannot turn the transfer plain.

Differences from section 5a, decided while building:

- **The hello carries the answer.** The receiver connects (direct stage)
  before it sends its accept ICBM, so the Olm answer often reaches the sender
  after the data connection started. The receiver's add-on derives the keys
  at the proposal (it has the offer) and writes its hello the moment the
  connection is up; the hello carries its ephemeral key and device, and a MAC
  under a key that needs the offer's transfer secret, so the sender can
  derive from the hello alone and the Olm answer only confirms (a mismatch is
  logged). Who speaks first is fixed: the receiver (the answerer) always;
  the sender only once it knows the receiver agreed (the answer came, or the
  hello did). So an add-on never writes a hello to a peer that cannot read it.
- **The sender's wait** is 4 s from the connection (`HELLO_WAIT_MS`), with
  its client's first bytes held, not a blocking `select`: the pump thread
  reads the hello and runs the timer, the client's `send` returns at once.
  A decline through the chat ends the wait at once; an answer through the
  chat makes the sender speak first and wait without a limit (agreed: fail
  closed, never plain). A transfer that went plain by the wait stays plain
  for its later connections.
- **Per-connection keys** come from both hellos (connection number and a
  random 16-byte nonce each side), not from a counter in the transfer keys.
- **Records**: ChaCha20-Poly1305 through `ring` (`u32 length | ciphertext |
  tag`, nonce = 11-byte record counter || last flag). The last flag is set
  on the empty final record only; the receiver knows it by its length.
- **A rendezvous that is not a message.** The message path took every
  channel-2 ICBM for a message, a file proposal included (its file name as
  the text): with keys for the contact it was encrypted and thrown away, and
  with the message held (`/e2e on`, keys not reachable) the proposal was
  dropped - a blocked transfer. `icbm.rs` now takes a channel-2 ICBM of the
  AOL rendezvous family other than the ICQ server relay (`0946134x`) for no
  message at all.

### 9.1 What is logged (F0)

`files_log = on` (or `ICQE2E_FILES_LOG=on`), any mode, no byte changed. Per
rendezvous ICBM: direction, propose/accept/cancel, `transfer=` (the first 4
bytes of the cookie's SHA-256), seq and stage, port, address classes, proxy
flag, file count and total size, TLV tags. Per peer connection that starts
with OFT2 or ARS (or carries an encrypted transfer): `connect` or `accept`
(now hooked), each ARS frame and OFT2 header (type, length, file n of m,
size, resume offset), and at `closesocket` the totals per direction, files
done, duration, way and stage. No file name, no address, no content in these
lines (the add-on's general `connect` lines still name addresses, as before).

### 9.2 Key agreement (F2)

Hidden control messages in the Olm session (`container.rs` kind 0), payload
`IQF1 | type | cookie (8) | ...`:

| Message | Sent | Fields |
|---|---|---|
| Offer | by the sender, just **before** its first proposal ICBM | device id, device Curve25519 key, ephemeral X25519 key, transfer secret (32 random bytes), suites |
| Answer | by the receiver, queued at the proposal, put **before** its next ICBM to the sender (accept, counter-proposal, cancel) | device id, device key, ephemeral key, suite |
| Decline | instead of an answer (`/e2e off` for the sender, no keys, no common suite) | reason |

- An offer is made only under the message rules (contact has keys in the
  directory, not `/e2e off`, our keys published, not a changed safety number
  of a verified contact); otherwise the transfer is plain at once and the
  chat says why.
- Keys: `HKDF-SHA256(IKM = X25519(eS, eR) || transfer secret, salt = label ||
  cookie || sender UIN/device/key || receiver UIN/device/key, info = label ||
  eS || eR)` gives the transfer's root and the hello's MAC key; each
  connection: `HKDF(root, info = direction || both hellos' nonces and
  connection numbers)` one key per direction. Wiped with the transfer (30 s
  after a cancel, 2 h idle).
- The role is fixed by who made the first proposal: a counter-proposal of
  the receiver (reverse stage) or a proxy proposal is never an offer.

### 9.3 Data connection (F3)

- Which sockets: `connect` to an address and port of the peer's proposal
  (`0x0002`/`0x0003`/`0x0004`, `0x0005`); an accepted socket on the port of
  our proposal; first outbound bytes an ARS `INIT_SEND`/`INIT_RECV` (or an
  OFT2 header) naming the cookie; a receiver's socket whose first inbound
  bytes are the sender's hello (it has sent nothing yet). Any other socket,
  and every socket of a transfer not agreed, takes the old path.
- Hello: `"IQFT" | 1 | role | SHA-256(label || cookie)[..8] | ephemeral key
  | device id | device key | connection number | nonce (16) | MAC (16)`, 118
  bytes; checked for role, cookie, the agreed ephemeral key and device, MAC.
- Proxy: the ARS frames pass untouched both ways; the hello phase starts at
  `READY`.
- Fail closed (agreed connection): a wrong hello, plain bytes, a record that
  does not authenticate, data after the final record, a record cut by the
  end of the stream, a late hello after the sender went plain, a panic in
  these hooks - the socket is shut both ways and `send`/`recv` answer
  `WSAECONNRESET`; one note per transfer. The end of the stream without the
  final record is logged as truncated (OFT2 itself tells the client whether
  the file was complete).

### 9.4 Policy and notes (F4)

`files_encrypt = on` in `icq-e2e.ini` (or `ICQE2E_FILES_ENCRYPT=on`), only in
encrypt mode with frames allowed; **default off** until the live test below.
The patch row "End-to-end encryption of file transfers" writes it (only with
the messages row). Never blocked. One note per transfer in the chat with the
contact: `This file transfer with 100002 is end-to-end encrypted ...` /
`... is not end-to-end encrypted: <reason>.` (stronger words for a contact
under `/e2e on` or verified) / `The encrypted file transfer with 100002 was
stopped: <reason>.` With `files_encrypt` off there are no file notes.

Tests (`cargo test --release`): records (chunking, last flag, truncation,
reordering, tampering, another key, impossible lengths); the hello and the
KDFs (every input bound, directions apart, a new connection new keys); the
pipe (both orders of answer and hello, the wait, a decline, an answer
during the wait, every fail-closed case, the proxy's frames); the table
(both on, a peer that never answers, no offer, a decline, mismatched
cookie/peer/device, reverse stage and resume, a cancel, one note); two
engines over their Olm sessions; the stream putting the offer before the
proposal only when on; and two endpoints through the hooks over real
loopback sockets with a recording relay in between: direct, reverse, proxy
with simulated ARS frames, a receiver found by the sender's hello, a peer
that does not take part (byte for byte on the wire after the wait), plain
bytes on an agreed connection (closed, nothing handed over), `FIONREAD` and
`MSG_PEEK`.

### 9.5 Live test (owner)

> Run it yourself; nothing here starts a client.

The ICQ 6.5 VM and ICQ 7.2 on this PC, two test accounts (e.g. 100001 and
100002), the same server as for messages. Direct transfers need the two to
reach each other (same LAN, or a forwarded port as `docs/RENDEZVOUS.md`
says): the proxy stage has no proxy until F1, and the patch points both
clients' proxy at a closed address.

Set-up on both: apply the patches rebuilt by `tools\common\Build-Patches.ps1`
with the encryption rows (`-Include e2e,e2e-tls`, and `e2e-files` for run 2),
set `ICQE2E_LOG` to a file, and edit `icq-e2e.ini` next to `ICQ.exe` with ICQ
closed (the patch keeps the lines). Make sure a message between the two
accounts is encrypted first (the chat says so): an offer needs the E2E
session. Have three test files ready: one of ~5 MB, a second one, and a
folder with two files; note `Get-FileHash -Algorithm SHA256 <file>` of each
on the sending side.

1. **F0 only** (`files_log = on`, `files_encrypt = off` on both): send the
   5 MB file each way, then two files at once, then the folder; cancel one
   in the middle and send it again (resume). Expected: `file rendezvous OUT
   ... propose ... seq=1` on the sender, `IN ... propose` on the receiver,
   `accept: socket ...` on whichever side listened, `file transfer ...: socket
   ...: first bytes OUT OFT2`, the OFT2 lines, and a `closed (...)` line with
   the totals; no `key offer` line and no file note in the chats. This is the
   F0 data: which side listens, whether the OFT2 header carries the cookie
   (the `transfer=` of the rendezvous and of the socket lines match), whether
   the receiver connects to the proposal's address, the resume frames.
   Compare SHA-256 of sent and received files: equal.
2. **Both on** (`files_log = on` and `files_encrypt = on` on both, or the
   patch row): the same transfers. Expected:
   - start-up: `files_encrypt=on: a file transfer is encrypted end to end
     when both add-ons agree ...`;
   - sender: `proposal out (direct stage), key offer sent first`, `socket ...
     carries it, we send`, `key hello received and checked`, `key hello
     sent`, `the data connection is end-to-end encrypted`, `key answer in`;
     receiver: `proposal in (direct stage) with a key offer; keys agreed`,
     `socket ... carries it, they send`, `key hello sent`, `key hello
     received and checked`, `... end-to-end encrypted`;
   - at close: `closed (..., encrypted): ... records N out / M in`, no
     `fail closed` line, no `was stopped` note;
   - both chats: "This file transfer with ... is end-to-end encrypted";
   - SHA-256 of every received file equal to the sent one (also after the
     resume, which is a second connection: `connection 2` in the hello
     lines);
   - optional capture (`pktmon` as in section 8): after the `IQFT` hello only
     noise, no `OFT2`, no file name on the peer connection.
3. **One side off** (`files_encrypt = off` on the 6.5 VM, on here), a
   transfer each way: it works as in run 1, and the files' SHA-256 match.
   Sending from here: the log shows `key offer sent first`, then after 4 s
   `the data connection goes unencrypted, untouched: the other side sent no
   key hello within 4 s`, and this chat says "This file transfer with ... is
   not end-to-end encrypted: ..."; the transfer starts about 4 s later than
   in run 1 (the held prompt) and otherwise behaves the same. Receiving here:
   "... is not end-to-end encrypted: ... did not offer to encrypt it". On the
   off side: nothing new at all.

What to collect: both logs with the time of each transfer, the SHA-256 lists,
and anything the transfers did differently from run 1 (a stall at the start,
a failed transfer, a retry).
