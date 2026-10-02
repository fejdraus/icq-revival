# Stage TLS - TLS 1.3 for the client's server connections, then SCRAM sign-in

CHECKLIST section 7, rows 7.2-7.4 (and the ground for 7.5). Written as a plan;
T0-T4 are implemented, and section 5 gives the status of each stage. Host names below use the placeholder `icq.example.org`; the
production machine is never named.

Goal: the E2E add-on (`tools/icq-e2e`), already sitting on the client's Winsock
calls, wraps every connection the client makes **to our server** in TLS 1.3, so
sign-in, the contact list, presence, profiles, chat rooms, avatars and the key
directory token all travel encrypted and authenticated. Later, and separately,
the add-on signs in with SCRAM-SHA-256 instead of the MD5 digest.

---

## 1. What ICQ 6.5 and 7.2 actually connect to

Both clients do all OSCAR **and** their sign-in HTTP in one module, the AOL
networking core, through classic `wsock32` calls that the add-on already
IAT-hooks (`send`, `recv`, `connect`, `closesocket`, `WSAAsyncSelect`,
`ioctlsocket`). Evidence for 7.2 (read from the installed files, nothing
changed): `coolcore59.dll` imports 26 `wsock32` functions by ordinal (including
`listen`/`accept` for peer connections) and only five WinINet functions, all
GET-only (`InternetOpenA`, `InternetOpenUrlW`, `InternetReadFile`,
`InternetQueryOptionW`, `InternetGetConnectedState`). But `clientLogin` is a POST,
and the module carries its own HTTP client: its strings include
`auth/getChallenge`, `auth/clientLogin`, `aim/startOSCARSession`, `Content-Type`
and `CONNECT %s:%d HTTP/1.0` (its HTTP proxy support). So the web login runs over
coolcore's own sockets, and the add-on's hooks already see it in plaintext.
`acccore.dll` holds the client's own TLS (NSS, `acccore\nss`,
`aimcc.connect.secure`), which the patch leaves off.

| Connection | 6.5 | 7.2 | Carries | Transport today | Through the hooked sockets? |
|---|---|---|---|---|---|
| Sign-in | FLAP/BUCP to `domain:5190` (MCore.dll's `login.icq.com` repointed by the patch): `BUCPChallengeRequest` with the UIN, then `BUCPLoginRequest` with the MD5 digest | HTTP to `domain:8082` (ACC prefs `aimcc.connect.host.*`): `POST /auth/getChallenge`, `POST /auth/clientLogin` (digest=1, plus DH), with `aimcc.connect.secure=0` | Screen name, a password-equivalent digest (`StrongMD5Pass`; the salt is fixed, so the digest is the same on every sign-in), the auth cookie | Plain | Yes (coolcore49 / coolcore59) |
| BOS redirect | In the BUCP login reply (`ReconnectHere`) | `GET /aim/startOSCARSession` on `domain:8082` (`aimcc.connect.bossRedirect.*`), `useTLS` not set | BOS host:port and cookie | Plain | Yes |
| BOS | `domain:5190` (the plain advertised host) | same | Everything: contact list (feedbag), presence, profiles, ICBM (E2E containers), offline messages, the MOTD with the key directory token, `LocateSetInfo` with the account key | Plain | Yes |
| Service redirects | `OServiceServiceRequest` -> `ReconnectHere` = the same advertised plain host (`foodgroup/oservice.go`): BART (avatars), ChatNav, Chat, ODir, MDir, Admin, Alert | same | Avatars, chat room text, directory searches, password/e-mail changes (Admin) | Plain, same host:port as BOS | Yes |
| Key directory | WinHTTP from the add-on to `https://domain:8102/e2e/v1/` | same | Key bundles, the token | TLS 1.2 (nginx, Let's Encrypt), system certificate check | No - the add-on's own WinHTTP; already encrypted |
| Pages, Xtraz | WinINet/IE (MCore, MUICore, MISB): `https://domain:8102` for everything the patch writes (windows, the browser, and what the client fetches itself: Xtraz lists, country lookup, e-mail activation, tZers); `http://domain:8101` only for the buddy picture the picture page hands the client, whose picture loader takes http:// alone | WinINet (MUIMessage, MReport), same split | Public pages; the picture upload and e-mail activation are personal | 8101 plain, 8102 TLS 1.2 | No |
| Peer: direct IM, file transfer | coolcore `listen`/`accept`/`connect` to the other client's address (the server only relays the rendezvous; no proxy server exists in this project) | same | File contents, direct IM | Plain, peer to peer | Hooked, but not server-bound: **left alone** |
| Voice/video | sipXtapi over `ws2_32` (RTP), STUN/TURN UDP 3478 | STUN address from ACC prefs | Media; STUN only learns the public address | Plain UDP | No (out of scope) |
| Kerberos | not used (AIM 6.2-7.5 only: 1088, 1443) | not used | - | - | - |

So **every server connection that carries account data goes through the hooked
sockets**: the 6.5 BUCP sign-in, the 7.2 HTTP sign-in, BOS and all service
redirects. All of them go to two destinations: `domain:5190` (FLAP) and
`domain:8082` (HTTP). What stays outside: the key directory (already HTTPS, own
WinHTTP), the 8101/8102 pages (WinINet), peer connections and media.

### 1.1 Found on the way: the `ioctlsocket` hook uses the wrong ordinal

`hook.rs` hooks `ioctlsocket` as `wsock32` ordinal **10**. In
`C:\Windows\SysWOW64\wsock32.dll`, 10 is `inet_addr`, 11 is `inet_ntoa` and
**12 is `ioctlsocket`**. `coolcore59.dll` (7.2) imports 12, not 10, which is why
STAGE-2 found "7.2 does not import `ioctlsocket`". On 6.5, if `coolcore49.dll`
imports ordinal 10 (DESIGN 4.1 lists `inet_addr`), the add-on has put a
three-argument stdcall hook over the one-argument `inet_addr` (it does: 6.5
imports 10, 11 and 12). Every call to it
would then unbalance the stack. That 6.5 works suggests coolcore49 never calls
`inet_addr` on the paths used, but it has to be fixed before this stage, because
TLS makes `FIONREAD` matter (the socket holds ciphertext, not what the client
will get). Fix: ordinal 12 for both clients. The test `ordinal_imports_are_patched`
also calls ordinal 11 `inet_addr`; it is `inet_ntoa`.

---

## 2. What the server offers today, and what is missing

From `deploy/nginx/nginx.conf`, `deploy/VM-SPEC.md` and `config/config.go`:

| Port | What | TLS | Certificate | Backend |
|---|---|---|---|---|
| 5193 | OSCAR over TLS for modern clients (Miranda) | SSLv3-TLS 1.2, `ALL:!aNULL` | Let's Encrypt (`ts-cert.pem`) | 5191 (SSL group, PROXY v1) |
| 3143 | OSCAR over TLS for AIM 6.2-7.x, and the advertised SSL BOS host | same | Private RSA CA (`server.pem`), which AIM's NSS store trusts | 5191 |
| 1443 | Kerberos for AIM | same | private CA | 1088 |
| 8443 | WebAPI over TLS | same | private CA | 8082 |
| 8102 | Pages and the key directory `/e2e/` | TLS 1.2 only | Let's Encrypt | 8101 / 8082 |
| 5190, 8082, 8101, 9898 | OSCAR, WebAPI, pages, TOC | none | - | - |

What is missing:

1. **No TLS 1.3 anywhere.** The nginx container is built against OpenSSL 1.0.2u
   on purpose (SSLv2-format hellos from AIM). That library cannot do TLS 1.3 at
   all, and it must not be replaced (VM-SPEC 4). TLS 1.3 needs a second
   terminator.
2. **No channel binding to the server.** nginx terminates TLS, so the Go server
   cannot read the TLS exporter (RFC 9266 `tls-exporter`) that SCRAM-PLUS binds
   to, and does not know which TLS version a connection used.
3. **The SSL listener group has one advertised host.** 3143 and 5193 both
   forward to 5191, and everything arriving on 5191 is redirected to the one SSL
   host, `domain:3143` (the private CA, TLS 1.2 at most). So a Miranda that
   signs in on 5193 with a Let's Encrypt check is sent to the private-CA port
   for BOS. Not part of this stage, but the new endpoint fixes it for Miranda
   too (section 7).
4. WebAPI over TLS exists only with the private CA (8443). The key directory
   is on 8102 with TLS 1.2.

### 2.1 Proposed server endpoint: Go-native TLS 1.3, one new port

The Go server terminates TLS itself on one new port (suggested **5194**; check
it is free and get the owner's firewall approval, see `deploy/OPERATIONS.md`):

- `crypto/tls`, `MinVersion = MaxVersion = TLS 1.3`, the Let's Encrypt
  certificate that certbot already renews (the same files nginx uses for
  5193/8102), reloaded when the files change (`GetCertificate` with a cached,
  mtime-checked pair).
- **ALPN picks the protocol** on the one port: `oscar` -> the OSCAR connection
  handler, `http/1.1` -> the WebAPI `http.Handler` (sign-in, `startOSCARSession`
  and, optionally later, the key directory `/e2e/`). No ALPN -> OSCAR, so a
  native TLS client like Miranda works without ALPN.
- The connection's `Endpoint` gets a transport marker (`TLS13`). The session
  remembers it, and the SCRAM path, the 7.5 policy and the logs can ask for it.
  The `tls.ConnectionState` (for `ExportKeyingMaterial`) is kept with the
  connection for SCRAM-PLUS.
- Handshake with a deadline (10 s) before the handler runs, so a slow or silent
  client does not hold a goroutine forever.
- New config fields in the `Config` struct, then `make config` (never edit
  `settings.env` by hand): `OSCAR_LISTENERS_TLS` (bind address),
  `OSCAR_ADVERTISED_LISTENERS_TLS` (the host a natively TLS-capable client is
  sent to), `TLS_CERT_FILE`, `TLS_KEY_FILE`.
- nginx is untouched: every old port stays (owner's rule: keep all protocol
  ports).

Why not a second nginx with modern OpenSSL: it would work for transport, but it
gives the server neither the exporter for channel binding nor the TLS version.
A second container with its own certificate wiring is also more to operate
than a listener in the binary that already holds the sessions.

### 2.2 Redirects and TLS: the add-on maps, the client is told the TLS port

The client must never negotiate TLS itself: it speaks plain FLAP and plain
HTTP, and the add-on wraps them. A stock client never reaches the TLS listener
(it cannot speak TLS), so whatever the TLS listener hands out is read only by a
client that has TLS from somewhere: the add-on, or a native TLS client.

- **For the add-on's clients, the add-on maps destinations itself.** A
  `connect` from coolcore to the server's address on port 5190, 8082, 5194 or
  5195 is sent to 5194 and wrapped in TLS (5190 and 5194 with ALPN `oscar`,
  8082 and 5195 with `http/1.1`; 5194 and 5195 are the sign-in ports the patch
  writes with the TLS row ticked, see 3.5.1). No capability flag and no
  server-side knowledge of the add-on is needed, and a server that has not
  been upgraded is detected at once (the TLS port does not answer, and the
  add-on fails closed, see 3.5).
- **Every redirect over the TLS listener names the TLS host** (changed
  2026-10-02, owner's wish): the BUCP/FLAP login reply (`ReconnectHere`),
  every `OServiceServiceRequest` (BART, ChatNav, Chat, ODir, MDir, Admin,
  Alert) and `startOSCARSession` when the HTTP request itself came over the
  TLS listener (ALPN `http/1.1`, `r.TLS` set) all give
  `OSCAR_ADVERTISED_LISTENERS_TLS` (`domain:5194`). So ICQ 6.5/7.2 show
  "Active settings: Port: 5194" in Settings > Connection (the port of the last
  good BOS connection as the client saw it), which tells the user the
  connection is encrypted; before, they showed 5190 and the add-on mapped it
  silently. The add-on needs no change: `route.rs` already maps
  `domain:5194` to TLS with ALPN `oscar` (`FLAP_PORTS`), so the redirect
  lands on the mapping as 5190 did.
- **The SSL state tells the client whether to negotiate TLS itself, not which
  host it is.** Only a client that asked for SSL (TLV `0x8C` at login or in
  `ServiceRequest`, `useTLS=1` on `startOSCARSession`) gets state `Resume`
  (2) or the `tlsCertName`; that is a native TLS client (Miranda sends `0x8C`
  when its SSL is on and calls `Netlib_StartSsl` on a state other than 0).
  The add-on asks for nothing, so 6.5/7.2 get state `NotUsed` (0) and no
  `tlsCertName`, keep speaking plain FLAP/HTTP into the add-on, and never
  start their own NSS TLS. `Endpoint.LoginRedirect` and `ServiceRedirect`
  return `(host, clientSSL)` for this.
- **The plain and nginx SSL listeners answer exactly as before**: the plain
  host to a client that did not ask, the SSL host (3143) on the SSL
  terminator endpoint and to a client that asked elsewhere. Covered by the
  unchanged cases and by `TestAuthService_BUCPLogin_RedirectByListener`,
  `TestOServiceService_ServiceRequest_RedirectByListener`,
  `TestEndpoint_Redirects`, `TestAimHandler_StartOSCARSession`.
- Caveat: a native TLS client that reaches 5194 but does not send `0x8C`
  would be sent to 5194 with state 0 and speak plain FLAP there, which the
  TLS listener refuses. No known client does that (Miranda sends `0x8C`
  whenever its SSL is on); before this change it would have been sent to
  5190 in the clear.

The add-on knows the server's name from `icq-e2e.ini`. Today the patch writes
only `directory=https://<domain>:8102/e2e/v1/`. The domain can be taken from
that URL, but a `server=<domain>` line is cleaner, and the patch writes it. The
add-on resolves it (`getaddrinfo`, cached, refreshed when a `connect` misses) to
know which `connect` targets are the server, and uses it as SNI and as the name
the certificate must carry. `connect` only ever sees an IP address, so this is
the only reliable source of the name.

---

## 3. TLS inside the hooks

### 3.1 Library: rustls with ring - verified to build

A probe crate in the scratchpad (`rustls 0.23.45`, `default-features = false`,
features `ring`, `std`, `tls12`; `ring 0.17.14`; `webpki-roots 1.0.9`; then
also `rustls-platform-verifier 0.6.2`) builds for `i686-pc-windows-msvc` with the
repo's stable toolchain (rustc 1.96.1) in under 20 s. ring needs only `cc` and
MSVC, both already there; no NASM, no CMake. The release cdylib with a
TLS 1.3-only `ClientConfig`, a handshake start and `export_keying_material` was
about 1 MB. aws-lc-rs is not needed: it wants CMake and NASM, and i686 is not
among its well-trodden targets. Pure Rust plus ring keeps the add-on one
self-contained DLL.

Configuration: TLS 1.3 only (our own server, no need for 1.2), ALPN set by the
original port (`oscar` for 5190, `http/1.1` for 8082), SNI = `server=`, no
session resumption at first (simpler; 0-RTT never).

### 3.2 Layering

```
client (coolcore)  --send-->  [FLAP rewriter / E2E]  -->  [TLS: rustls writer]  --> orig send (ciphertext)
client (coolcore)  <--recv--  [FLAP rewriter / E2E]  <--  [TLS: rustls reader]  <-- orig recv (ciphertext)
```

TLS is the lowest layer, and the existing `StreamRewriter`s work on plaintext
exactly as now. The HTTP sockets (8082) have no FLAP to rewrite. The rewriter
must pass them through untouched (verify; a later SCRAM stage rewrites
`clientLogin` there, see 4.3).

A new pure-Rust module `tls.rs`, `TlsPipe`, holds a `rustls::ClientConnection`
and plain byte buffers, with no Winsock in it:

- `feed_ciphertext(&[u8])` -> `read_tls` + `process_new_packets`, plaintext
  moved to an internal buffer; returns errors as values.
- `take_plaintext(&mut [u8]) -> usize`, `plaintext_len()`.
- `write_plaintext(&[u8])` -> `writer().write_all` (before the handshake ends,
  rustls buffers it and sends it after `Finished`; the buffer limit is raised
  for this).
- `take_ciphertext() -> Vec<u8>` (`write_tls` into a Vec).
- `close()` -> `send_close_notify`.
- `state()`: Handshaking / Ready / Closed(clean | truncated) / Failed(reason).
- `exporter()` for SCRAM-PLUS later.

Everything that is hard (partial records, several records in one read, a read
that ends inside a handshake message, early writes, truncation) is tested on
this type alone (section 5, stage T2).

### 3.3 The socket life cycle with `WSAAsyncSelect`

The clients use non-blocking sockets with `WSAAsyncSelect` notifications to a
window. The add-on never subclasses that window. It only posts synthetic
`FD_READ` to it, as it already does (`post_fd_read`).

1. **`connect`**: if the target is the server's address and port 5190/8082/5194,
   the hook copies the `sockaddr_in`, puts in port 5194, calls the original,
   and marks the socket `Tls(TlsPipe::new(alpn))`. Other targets (peers, STUN)
   are untouched. `getpeername` (imported by coolcore59) should report the
   original port. Hook it too, or check that the client never compares it.
2. **ClientHello before the client's first byte.** On OSCAR the server speaks
   first (the FLAP hello), so waiting for the client's first `send` would
   deadlock. A **TLS pump thread** (one for all sockets) gets each new TLS
   socket and waits for it with `select()` (writable = connected, except =
   failed; `select` is allowed on a socket in async-select mode). It then sends
   the ClientHello with the original `send`. The client gets its own `FD_CONNECT`
   from Winsock as usual.
3. **Handshake reads.** The server's flight raises `FD_READ` for the client.
   The client's `recv` lands in the hook, which reads the socket, feeds the
   pipe, sends whatever the pipe produced (the client `Finished`), and answers
   `WSAEWOULDBLOCK` while there is no plaintext. That is the normal "nothing
   yet", and Winsock re-arms `FD_READ` because `recv` was called. The pump also
   reads during the handshake (`select` readable), so the handshake does not
   depend on the client calling `recv` at all. When the pump finishes the
   handshake and plaintext is already waiting (the server's FLAP hello), it
   posts a synthetic `FD_READ`.
4. **Client `send` at any time** (the 7.2 HTTP request right after
   `FD_CONNECT`): plaintext goes through the rewriter and into the pipe, the
   hook returns the full length, and ciphertext is flushed with the existing
   `flush`/`wait_writable` logic (bounded wait, never reordering).
5. **`recv` after the handshake**: serve plaintext already held first; else
   read the socket, feed, take plaintext, run the inbound rewriter, and answer.
   A partial record answers `WSAEWOULDBLOCK`. When more plaintext is left than
   the client's buffer holds, post a synthetic `FD_READ` (exists today).
   `MSG_PEEK` is served from the plaintext buffer. `MSG_OOB` is refused on TLS
   sockets.
6. **`ioctlsocket(FIONREAD)`** on a TLS socket reports only plaintext held for
   the client, never the socket's own count (ciphertext). This needs the ordinal
   fix from 1.1.
7. **End of stream**: a `close_notify` from the server makes `recv` return 0
   once the plaintext is drained. A TCP close without `close_notify`, or any TLS
   error, is reported as `WSAECONNRESET`, so a truncated stream is never
   mistaken for a clean end.
8. **`closesocket`**: one best-effort `close_notify` (non-blocking, ignored on
   `WSAEWOULDBLOCK`), then the state is dropped and the original is called.

Locking: one `Mutex<TlsPipe>` per socket, taken only around pipe operations and
never across a wait. The two rewriter halves keep their own locks, as now. The
order is fixed (rewriter, then pipe) so the pump and the client's thread cannot
deadlock.

**Install race.** Today the hooks go in from a polling thread once coolcore
appears. A connect made before that (auto sign-in at start-up) would go out in
plaintext. With TLS that is a hole, not a log gap. Patch synchronously instead:
`LdrRegisterDllNotification` from the loader's `DllMain`, plus an immediate
patch if coolcore is already loaded. Any socket seen in `send`/`recv` that the
add-on never saw `connect` for, while its peer is the server, is reset
(fail closed) and logged.

### 3.4 Certificate validation

- **Default: the Windows trust store**, through `rustls-platform-verifier`
  (`CertGetCertificateChain`, builds for i686, see 3.1). This is the same trust
  decision WinHTTP already makes for the key directory, so a machine that trusts
  one trusts the other, and enterprise or user roots work as on any program. The
  name checked is `server=` from the ini, never something the server or the
  stream supplies.
- **Optional pin** (`tls_pin=sha256/<base64 SPKI>[,...]`, at least two:
  current and backup). It is useful only if certbot keeps the key across
  renewals (`--reuse-key`). Otherwise every renewal breaks the pin. Not the
  default. Recommended later, for owners who control renewal.
- No bundled `webpki-roots` by default: it ages inside the binary. It is kept as
  the fallback only if the platform verifier cannot load (it builds too).
- The private AIM CA is not involved. rustls handles the ECDSA Let's Encrypt
  certificate that the 2011 NSS could not.

### 3.5 Fail closed, visibly; a deliberate opt-out

- With `server=` known and TLS not turned off, a server-bound connection that
  cannot complete TLS (port closed, certificate invalid, wrong name, TLS 1.2
  offered, handshake timeout) is **never** retried in plaintext. The socket is
  reset, so the client shows its own "cannot connect" and retries on its own
  schedule.
- Visible: before sign-in there is no chat to put a note in, so the add-on
  shows one `MessageBoxW` (from a worker thread, never the client's UI thread),
  once per run per reason: "ICQ E2E: the connection to icq.example.org could not
  be secured (certificate is not valid for this name). The client was not
  allowed to connect without encryption. To allow it anyway, untick
  "Encrypted connection to the server (TLS)" in the patch and apply it
  (tls=off)." The reason also goes to the log. (Before 3.5.1 the way out named
  was `tls=off` in the ini; with the sign-in moved to the TLS ports that line
  alone no longer lets the client sign in, the patch's row does.)
- **Opt-out per install**: `tls=off` in `icq-e2e.ini` (or `ICQE2E_TLS=off`).
  Then the add-on does no mapping, and at every sign-on says once in the first
  chat, and in the log: "[ICQ E2E] The connection to the server is not
  encrypted (tls=off)" (CHECKLIST 10 visibility). Whether the patch gets a tick
  for it, or it stays an ini line for experts, is the owner's call. By the
  "one row per job" rule it would at most be an option of the add-on's row,
  not a new row.
- `server=` absent (an old ini): TLS stays off, said once in the log, not a
  failure. The patch always writes it from this stage on.

### 3.5.1 Fail closed when the add-on is missing (the owner's call, 2026-10-02)

Everything above holds while the add-on runs. If it does not - the DLL
deleted, renamed or not loaded - a client patched for plain ports would sign in
to `domain:5190` / `domain:8082` in plaintext without a word. So with the TLS
row ticked (and the sign-in row, which puts the domain in), the patch points
the client's own sign-in at ports that do not work in plaintext:

| Client | Setting | Row off | Row on | Without the add-on |
|--------|---------|---------|--------|--------------------|
| 6.5 | `MCore.dll`, the default of `ServerPort` (`mov dword [esp+44h], 5190` in the function that registers `ServerHostName`/`login.icq.com`; file offset 0x464E) | 5190 | 5194 | TLS 1.3 only: no FLAP hello, the first plain bytes end the handshake |
| 7.2 | `AppConfig.xml`, `aimcc.connect.host.port` (getChallenge, clientLogin) | 8082 | 5195 | nothing listens: refused |
| 7.2 | `AppConfig.xml`, `aimcc.connect.bossRedirect.port` (startOSCARSession) | 8082 | 5195 | nothing listens: refused |
| 7.2 | `AppConfig.xml`, `aimcc.connect.skipSources` (added) | absent | 4063266 | the cached last good connection and the port-80 retries are not tried |

On 7.2 the ports alone do not hold on a client that has signed in before: ACC
(`acccore.dll`) first tries the last connection that worked, which the client
keeps per Windows user in `%APPDATA%\ICQ\Application.qdb` (SQLite, `Records`,
section `ConnectionSettings`, `AccCachedSettings` =
`aimcc.connect.settings.OpenAuth1.0`/`OpenAuth2.0` with `domain:8082`), and
after the configured port it retries the same host on port 80.
`aimcc.connect.skipSources` (a bit per source, read while `autoConnect` is 1)
leaves out the cache (0x2) and the port-80 retries (0x20, 0x20000, 0x40000,
0x80000, 0x100000, 0x200000). The cache itself is not touched.

- The web sign-in cannot share 5194 with OSCAR: the add-on chooses the ALPN by
  the port at `connect`, before the client has sent a byte. 5195 is free in
  `deploy/docker-compose.yaml`, the nginx configuration and the server's
  configuration, and the server must never listen on it; `route.rs` maps it to
  5194 with ALPN `http/1.1` (`TLS_ONLY_HTTP_PORT`).
- The BOS host handed out after sign-in needs nothing: the sign-in came over
  the TLS listener, so `LoginRedirect` (BUCP `ReconnectHere`),
  `ServiceRedirect` and `startOSCARSession` give `domain:5194` with SSL state
  0 and no `tlsCertName` (2.2), which the add-on maps to TLS. A client
  without the add-on never gets that far. An install whose sign-in still goes
  to 5190 or 8082 reaches the TLS listener through the add-on's mapping too,
  so it is also told 5194.
- The other 5190 in 6.5's `MCore.dll` is the port of `ars.oscar.aol.com` and
  stays. The pages (8101, 8102), the key directory (8102), STUN (3478) are not
  touched.
- Unticking the TLS row puts 5190 / 8082 back (each file is rebuilt from its
  original); Restore gives byte-identical originals; an Apply that changes
  nothing reports nothing. An install with `tls = off` keeps the plain ports.
  The opt-out is therefore the row: `tls = off` typed into the ini by hand (or
  `ICQE2E_TLS=off`) on an install with the row applied leaves the sign-in on
  5194/5195, where the plain client gets nowhere - closed as well, not open.
  An install whose TLS row was applied before this change has the plain ports
  and shows the row as "partly" until the next Apply.
- Not covered: a server typed by hand in the client's connection settings (6.5
  manual connection, 7.2 connection preferences) stays the user's and keeps its
  port.
- Checked: `route.rs` unit tests (5194, 5195 mapped with their ALPN, peers on
  them left alone, unresolved name refused); the test host scenario "fail
  closed: the client set to the TLS ports signs in only through the add-on"
  (BUCP straight to the TLS port, getChallenge and startOSCARSession on the
  TLS-only HTTP port, then BOS on the plain host; past the hooks the HTTP port
  refuses and the TLS port gives a plain FLAP client nothing and ends the
  handshake); both patches on copies (tick, re-Apply 0 changes, untick, sign-in
  skipped, domain change, Restore byte-identical). The owner's live check: T5.

### 3.6 What TLS also fixes

- 7.1's remaining gap (an active attacker on the path could rewrite the BOS
  connection and the MOTD token) closes for clients with the add-on: the
  connection is authenticated to the server's certificate.
- The 7.2 web-login digest and the 6.5 BUCP digest, both password-equivalent,
  no longer cross the wire in clear (7.3 in transit; storage is section 4).

---

## 4. SCRAM-SHA-256 later (a separate stage)

### 4.1 What the add-on can know

The add-on never sees the password. 6.5 sends `BUCPLoginRequest` with
`StrongMD5Pass = MD5(authKey || MD5(password) || "AOL Instant Messenger (SM)")`.
7.2 sends the same value as the `clientLogin` digest (`getChallenge` answers
with the account's `authKey` as the challenge word, `server/webapi/auth_challenge.go`).
`authKey` is fixed per account, so this value, call it **P'**, is constant: it
is what the client computes from the password, and it is what the server stores
today (`state.User.StrongMD5Pass`, compared in `ValidateHash`).

**SCRAM therefore runs over P' as its password.** The add-on lets the client
compute P' as usual, takes it out of the stream, and proves knowledge of it with
SCRAM-SHA-256-PLUS. The add-on is the TLS client, so it reads the exporter.
P' never leaves the machine.

### 4.2 Server

- Storage: a migration with `scram_verifier(screen_name, salt, iterations,
  stored_key, server_key)` over P' (RFC 5802/7677, at least 4096 iterations).
- Creating verifiers needs no user action: at registration and at a password
  change P' is computed from the plaintext. At any successful **stock**
  sign-in, P' itself arrives (BUCP digest, `clientLogin` digest), or the
  plaintext does (2003b's roasted password, a plaintext `clientLogin`), so the
  verifier is created the first time each account signs in after the upgrade.
- Verifying old methods against verifiers: a received P' (or P' computed from a
  roasted or plain password) can be checked against the verifier
  (`H(HMAC(Hi(P', salt, i), "Client Key")) == StoredKey`). That lets an account
  drop `StrongMD5Pass` and `WeakMD5Pass` from storage (7.4) without locking out
  stock 6.5/7.2/2003b. What still needs `WeakMD5Pass` is weak-MD5 BUCP (AIM
  3.5-4.7), so the drop is per account and opt-in. `authKey` must never change
  while verifiers exist.
- New auth path, only on the TLS-native endpoint (the server knows from the
  `Endpoint` transport), with `tls-exporter` channel binding (RFC 9266) from the
  `tls.ConnectionState` kept per connection:
  - FLAP: two new SNACs in food group `0x17` (unused subgroups, chosen against
    `wire/snacs.go`), client-first/server-first and client-final/server-final.
    The final one is answered with the ordinary login reply (`0x17/0x03` with
    cookie and `ReconnectHere`).
  - WebAPI: `POST /auth/scramStart` and `POST /auth/scramFinish`. The finish
    answers in exactly the `clientLogin` response shape (XML namespaces, token,
    `sessionSecret`, DH reply).
- Downgrade (7.5): once an account has signed in with SCRAM, a per-account,
  opt-in flag makes the server refuse MD5/roasted methods for it.
  `tls-exporter` binding stops a TLS-terminating MITM from relaying.

### 4.3 Add-on

- 6.5: on the auth connection, pass `BUCPChallengeRequest` through, take the
  client's `BUCPLoginRequest` out of the stream, pull P' from it, run the two
  SCRAM SNACs (the FLAP injection and removal machinery already exists), and
  hand the client the server's normal `0x17/0x03`.
- 7.2: the HTTP connection is the add-on's own TLS stream, so it can rewrite the
  request stream. It holds the client's `POST /auth/clientLogin`, sends
  `scramStart`, swallows that reply, sends `scramFinish` with the proof and the
  client's own form fields (DH, devId, tokenType), and the one response the
  client sees is the `clientLogin`-shaped reply. HTTP/1.1 keep-alive is needed
  upstream (coolcore speaks HTTP/1.0 to the add-on; the add-on owns the upstream
  bytes). The `getChallenge` call stays as the client makes it (it needs
  `authKey` to compute P').
- The server's final SCRAM message is checked. A server that cannot prove it
  knows the verifier is refused, and the client gets a sign-in failure.

This stage changes the auth code and stored credentials, so it is kept apart
from the TLS stage and starts only after TLS has run in production.

---

## 5. Stages

Effort is in working days for one developer, without the owner's live time.

### T0 - Fix-ups and observation (0.5-1 d)

**Status: implemented, waiting for the owner's live check (2026-10-02).**
`hook.rs` turns each imported ordinal into a name from the export table of the
DLL it comes from (`wsock32` or `ws2_32`, with a built-in Winsock 1.1 table as
the fallback) and matches slots by name, so `ioctlsocket` is hooked as
`wsock32` 12 on both clients and `inet_addr` (10) is left alone. 7.2 now gets
the `ioctlsocket` hook too (it imports 12). The hooks go in from
`LdrRegisterDllNotification` the moment coolcore is mapped (a test confirms the
imports are already bound at that point), or at once if it is already loaded;
the polling thread stays as the fallback. Every `connect` is logged
(`connect: socket N -> ip:port`), the first bytes of each direction per socket
are classified (`FLAP`, `HTTP POST /path` without the query, `CONNECT`, TLS,
other), and a socket with data but no `connect` seen is logged. Unit tests:
real `wsock32`/`ws2_32` ordinals, both numberings, unbound slots, the loader
notification, the classifier.

- Ordinal fix (1.1) with a test that uses the real `wsock32` ordinals.
  Synchronous IAT patching via `LdrRegisterDllNotification` (3.3).
- Observe mode logs, per `connect`: target, port, socket, and a classification
  of the first bytes (FLAP `0x2A`, HTTP verb, `CONNECT`, other). No bytes are
  changed.
- **Accept**: unit tests green. The owner signs in with 6.5 and 7.2 and opens a
  chat room, an avatar, a directory search, a file transfer. The log shows only
  `domain:5190` and `domain:8082` as server targets, peers on other ports, and
  no plaintext before the hooks were installed. This confirms table 1, or
  corrects it before anything is built on it.

### T1 - Server: TLS 1.3 listener (2 d)

**Status: code done, not deployed (2026-10-02).** The owner's part below is open.

- `server/tlsfront`: `CertReloader` (stats both files on every handshake,
  reloads on a change, keeps the old pair while a new one does not load, so
  certbot's two `cp` in a row are safe), `NewServerConfig` (TLS 1.3 only, ALPN
  `oscar`, plus `http/1.1` only with `ENABLE_WEBAPI=1`), `Handshake` (10 s
  deadline), `ChannelBinding` (RFC 9266 `tls-exporter`, 32 bytes) and
  `ConnListener` (hands http/1.1 connections to the WebAPI).
- `config`: the four settings, `ListenerGroup.TLSEndpoint()`,
  `Endpoint.Transport` (`TransportTLS13`), `Endpoint.LoginRedirect` and
  `ServiceRedirect`. `make config` puts them into the SSL dev profile
  (`certs/server.pem`); the basic profile has no TLS listener.
- `server/oscar`: the TLS endpoint handshakes in the connection's goroutine,
  then OSCAR (`oscar` or no ALPN) or the WebAPI (`http/1.1`). The handler's
  context carries the `tls.ConnectionState` (`tlsfront.ConnectionStateFromContext`);
  over HTTP it is `r.TLS`. The session does not store the transport yet; S1/S3
  add that where they need it.
- Redirects: `foodgroup/auth.go` (TLV `0x8C` at sign-in, `LoginTLVTagsUseSSL`),
  `foodgroup/oservice.go` (`ServiceRequest` now takes the `config.Endpoint`),
  `webapi/aim_handler.go` (a request over the TLS port gives the TLS host).
  Since 2026-10-02 every redirect over the TLS listener names the TLS host,
  with SSL state `Resume` or `tlsCertName` only for a client that asked for
  SSL (2.2). The existing plain and nginx SSL endpoints answer as before.
- Deploy files: `deploy/docker-compose.yaml` (env, `./certs:/certs:ro`, the
  certbot hook gives the key to group 1000), `deploy/VM-SPEC.md`,
  `deploy/docker/README.md` (one-time `chgrp 1000`/`chmod 640` of
  `certs/ts-key.pem` on an existing installation).
- Tests: `server/tlsfront/tlsfront_test.go`, `server/oscar/tls_test.go` (real
  loopback handshakes: ALPN `oscar`/none get the FLAP hello, `http/1.1` gets
  `GET /` from the real WebAPI, TLS 1.2 and unknown ALPN refused, exporter
  equal on both ends, a replaced certificate served without a restart, a silent
  client dropped after the deadline), `config/tls_test.go`, new cases in
  `foodgroup/auth_test.go`, `foodgroup/oservice_test.go`,
  `server/webapi/aim_handler_test.go`.

- `OSCAR_LISTENERS_TLS`, `OSCAR_ADVERTISED_LISTENERS_TLS`, `TLS_CERT_FILE`,
  `TLS_KEY_FILE`; Go-native TLS 1.3, ALPN dispatch (OSCAR / WebAPI),
  certificate reload, handshake deadline, `Endpoint` transport marker; redirects
  over the TLS listener advertise the TLS host, and tell only a client that
  asked for SSL to negotiate it (2.2). Run
  `make config`.
- **Accept** (Go, table-driven, testify): a TLS 1.2 client is refused. ALPN
  `oscar` gets the FLAP hello, `http/1.1` gets `GET /` from WebAPI, no ALPN gets
  OSCAR. Over the TLS listener a sign-in without `0x8C` is told the TLS host
  and SSL state 0, one with `0x8C` the TLS host and state 2; the same for
  every service redirect and `startOSCARSession`; the plain and SSL listeners
  as before. A replaced certificate file is
  served without a restart. `go test -race ./...`, `gofmt -s -l .`,
  `go vet ./...` clean.
- **Owner**: deploy, open the one new port in the firewall (approval per
  `deploy/OPERATIONS.md`), `openssl s_client -tls1_3 -alpn oscar -connect
  icq.example.org:5194` shows the Let's Encrypt chain and a FLAP hello. All
  old ports unchanged.

### T2 - `TlsPipe` (2 d)

**Status: done (2026-10-02).** `core/src/tls.rs`: `TlsClient` (built once from
`TlsSettings`: server name, `Trust::System` via `rustls-platform-verifier` or
`Trust::Roots`, optional SPKI pins) and `TlsPipe` (`feed_ciphertext`,
`end_of_input`, `take_plaintext`/`peek_plaintext`/`plaintext_len`,
`write_plaintext`, `take_ciphertext`, `close`, `state`, `alpn`, `exporter`).
rustls 0.23 with ring, TLS 1.3 only, no resumption, no early data. Failures are
final and carry a reason (`TlsFailure::reason`). 20 unit tests against an
in-process rustls server with rcgen certificates cover the accept list below,
plus the pin, the system store rejecting an unknown CA, `MSG_PEEK` and garbage
input. Not wired into the hooks yet (T3). Size: the loaders do not reference
it yet and grew only ~30 KB (1.29 MB); a probe cdylib that links `TlsPipe` with
the platform verifier grows by ~830 KB (1.29 -> 2.14 MB).

- `core/src/tls.rs` as in 3.2, with an in-process rustls **server** in tests
  (self-signed CA given to the client config).
- **Accept**: handshake and echo with ciphertext fed 1 byte at a time, in random
  splits, and coalesced. Plaintext written before the handshake arrives after
  it, in order. `close_notify` gives a clean end, a cut gives `truncated`.
  Wrong name, expired certificate, unknown CA and a TLS 1.2-only server all
  fail with the reason. The exporter is 32 bytes and the same on both ends.
  i686 build of the loaders still links; DLL size growth is noted (~1 MB
  expected).

### T3 - Into the hooks (3-4 d)

**Status: done in code and tests, waiting for the server (T1 deployed, port
5194 open) and the owner's live check (2026-10-02).**

- `core/src/route.rs` (plain Rust): the destination map. `server=` is resolved
  with `getaddrinfo` (IPv4, cached 5 min; a miss on a server port resolves
  again, at most once a second). The server on 5190/5194 goes to 5194 with ALPN
  `oscar`, on 8082 to 5194 with `http/1.1`. The server on any other port is
  refused, and so is a server port while the name does not resolve. Peers
  are left alone. It also reads proxy requests (`CONNECT`, SOCKS4/4a,
  SOCKS5) out of the first bytes.
- `core/src/hook_tls.rs` (a submodule of `hook`): `TlsConn` per mapped socket
  (`TlsPipe` and the ciphertext queue). The pump thread sends the ClientHello
  once `select` says connected, drives the handshake, posts `FD_READ` when
  plaintext is waiting, and times the handshake out after 20 s. `recv` gives
  plaintext only (`MSG_PEEK` from the plaintext, `MSG_OOB` refused),
  `FIONREAD` counts plaintext only after reading the socket, `send` goes into
  the pipe at any time (before the handshake, rustls holds it), and
  `closesocket` sends one `close_notify`. The new `getpeername` hook reports
  the original port. A cut without `close_notify`, or any TLS error, is
  `WSAECONNRESET`, and the server must agree to the ALPN. Locks: queue before
  pipe; only the client's own `send` waits while holding the queue.
- Re-arming `FD_READ`: every `recv` of the client on a TLS socket calls the
  original `recv` at least once, even when it is answered from bytes the
  add-on already holds. Winsock re-arms `FD_READ` only on a `recv` call. The
  add-on reads ahead (pump, `FIONREAD`, its own read loop), so answering
  without that call left the next bytes unannounced. This was the testhost's
  intermittent "B's reply never arrives" (about 1 run in 2 with slow
  delivery). Plaintext left after a short read is announced with an
  `FD_READ` of its own.
- Fail closed: no TLS client (settings, trust store), refused or reset TLS
  port, certificate, TLS 1.2, handshake timeout, wrong ALPN, other port,
  unresolved name, a proxy asked for the server, or data on a server socket
  whose `connect` the hooks never saw. The socket is refused or reset and the
  reason is logged. A message box from a worker thread, once per run and
  reason, for what the user can act on (not for offline or a cut mid-session):
  "ICQ E2E: the connection to icq.example.org could not be secured (...). The
  client was not allowed to connect without encryption. To allow it anyway,
  set tls=off in icq-e2e.ini." (Since 3.5.1 the way out named is the patch's
  TLS row.)
- Settings (`config.rs`, `TlsPolicy`): `server=`, `tls=on|off`, `tls_pin=`
  from `icq-e2e.ini`, with `ICQE2E_SERVER`/`ICQE2E_TLS`/`ICQE2E_TLS_PIN` as
  overrides. No `server=`: off, one log line. A value that cannot be read
  (`tls=maybe`, a bad pin, `server=` with a port or a scheme) fails closed.
  `tls=off`: nothing is mapped, and the BOS connection's chat gets
  "[ICQ E2E] The connection to the server (...) is not encrypted (tls=off ...)"
  at every sign-on. Observe mode never maps (bytes unchanged).
- `testhost` (`over_tls.rs`): the hooks driven like coolcore drives them (a
  real non-blocking socket, `WSAAsyncSelect` to a message-only window, one
  `recv` per `FD_READ` into a small buffer), against an in-process rustls
  server on loopback. The route maps two plain ports nobody listens on to it.
  16 scenarios: 6.5 BUCP sign-in (the server speaks first; FIONREAD, MSG_PEEK,
  getpeername), 7.2 `clientLogin` (written before the socket is even
  connected) and `startOSCARSession` over `http/1.1`, BOS with token, account
  key and E2E both ways to an in-memory second device (containers only inside
  TLS, the text never on the wire), slow and coalesced records, a cut
  mid-frame (`WSAECONNRESET`), reconnect, wrong certificate (no plaintext on
  the wire, not even the early HTTP request; one box), TLS 1.2 server, closed
  TLS port, another port of the server, a proxy, a socket opened past the
  hooks, 200 small frames each way, a long HTTP answer through a 64-byte
  buffer, 40 connections with the hello right after the handshake, the
  `FD_READ` re-arm regression, and `tls=off` (bytes unchanged both ways, the
  note in the chat). `cargo test --release` runs them. 45 runs in a row are
  green. Without the re-arm fix the regression scenario fails every time.
- Against the Go server (`icqe2e_testhost --make-cert <dir>`, then the server
  with `OSCAR_LISTENERS_TLS`, `ENABLE_WEBAPI=1`, `DISABLE_AUTH=true`, the
  plain host advertised as `127.0.0.1:5190`, then `icqe2e_testhost --go
  <tls-port> <dir>\ca.pem localhost`): FLAP hello over `oscar`, BUCP sign-in,
  the redirect to the plain host lands on TLS again, BOS `HostOnline`, and
  the WebAPI answers over `http/1.1`. All green on 2026-10-02. Since the TLS
  listener hands out the TLS host (2.2), the server for this run needs
  `OSCAR_ADVERTISED_LISTENERS_TLS=LOCAL://127.0.0.1:<tls-port>` (the scenario
  parses the redirect host as an IP address); the redirect then names the TLS
  port, which the scenario's route maps like 5190. Not re-run after that
  change.
- Size: the loaders are 2.31 MB (1.29 MB before; rustls, ring and the
  platform verifier).
- Open: a pin (`tls_pin`) is parsed and enforced, but the patch does not write
  one (3.4). Proxies fail closed rather than tunnel. `select` on a socket
  closed under the pump only costs a round. A blocking (non-async) client
  socket would see `WSAEWOULDBLOCK` (the clients are async; 2003b/QIP glue in
  section 7 must check this).

- Destination mapping, pump thread, `send`/`recv`/`FIONREAD`/`MSG_PEEK`/
  `closesocket`/`getpeername` on TLS sockets, fail closed with the message box,
  `server=`/`tls=`/`tls_pin=` settings, the sign-on note for `tls=off`.
- `testhost`: real loopback sockets, `WSAAsyncSelect` to a hidden window with a
  message loop, an in-process rustls server speaking a scripted FLAP hello, and
  the existing two-client E2E scenario run over TLS.
- **Accept**: testhost passes with TLS (messages encrypted end to end inside
  TLS, frames added/removed, sequence numbers right). A server that sends first
  works without the client sending anything. A server-side close mid-frame
  gives the client `WSAECONNRESET`. A wrong certificate gives no plaintext byte
  on the wire (asserted on the server side) and one message box. `tls=off`
  gives today's behaviour byte for byte.

### T4 - Patch (0.5 d)

**Status: done (2026-10-02).** Both patches write `directory = ...`,
`server = <domain>` and `tls = on`; the TLS port is the add-on's constant.
A `tls = off` the user put into the patch's own ini is kept by every later
Apply, with the same or another domain. Either value counts as "patched".
The finish message says what TLS does and how to turn it off. On copies
(`-Root <copy> -Server icq.example.org -Include e2e-probe`,
`__COMPAT_LAYER=RunAsInvoker`), for 6.5 and 7.2: an old ini without
`server=` becomes the new one, a second Apply changes nothing, `tls = off`
survives re-Apply and a domain change, and Restore leaves no ini. No tick of
its own (one row per job). Whether `tls=off` gets one is the owner's call.

**Two rows (2026-10-02, the owner's call).** The single E2E row is now two:
"End-to-end encryption of messages" (`e2e`, writes `e2e = on|off`) and
"Encrypted connection to the server (TLS)" (`e2e-tls`, writes `tls = on|off`).
Either puts the DLL in; it stays while one of them is ticked. TLS no longer
needs E2E: with `e2e = off` (or `ICQE2E_E2E=off`) the add-on runs in
`mode=plain` - TLS as above, and otherwise the plain client's bytes: no
encryption, no key publishing, no key-directory call, no capability or key
announced; a `/e2e` command is still swallowed and answered "end-to-end
encryption is off on this install". Observe mode stays log-only without TLS.
The patch sets only its own four lines (`directory`, `server`, `e2e`, `tls`)
and keeps the rest of the ini (`tls_pin`, comments); a `tls = off` set by
hand is now simply the TLS row unticked. An ini of the single row (no `e2e=`)
shows both rows applied, and `e2e-probe` on the command line means both.
Checked by the test host (`e2e=off: TLS only ...`: sign-in and messages both
ways unchanged over TLS, SetInfo unchanged, `/e2e` answered and not sent, no
key-directory request) and on copies of 6.5 and 7.2: each row alone, both,
re-Apply with 0 changes, row 1 unticked with row 2 kept (DLL stays, `e2e =
off`), hand-set lines kept, Restore byte-identical.

- `Icq65Client.cs`/`Icq72Client.cs`: `icq-e2e.ini` gets `server=<domain>` and
  `tls=on`. Only the domain is asked for, as always; the port is the add-on's
  constant.
- **Accept**: Apply/Restore round trip leaves the ini right. An old ini without
  `server=` keeps working in plaintext with a log line.

### T5 - Owner's live checks (owner time ~1 d; fixes 1-2 d)

With 6.5 and 7.2 on two machines against the production machine:

- Sign-in (6.5 BUCP, 7.2 web login), contact list, presence and mood, profile
  view and edit, offline messages, E2E messages both ways, chat room, avatar
  upload and download (BART), directory search (ODir/MDir), password change
  (Admin).
- A capture on the client machine (Wireshark): only TLS 1.3 to port 5194, no
  segment to 5190/8082 from ICQ.exe. The server log shows the sessions on the
  TLS endpoint.
- Network drop and resume, laptop sleep, a server restart: the client
  reconnects, still over TLS.
- Fail-closed checks: point `server=` at a name the certificate does not carry,
  then close the port. In both cases no sign-in, one message, nothing in
  plaintext. Then `tls=off`: sign-in works and the note says so.
- Add-on missing (3.5.1): with ICQ closed, rename the add-on (6.5
  `msimg32.dll`, 7.2 `tbdiag.dll`) and start the client: no sign-in, and the
  capture shows no FLAP or HTTP in plaintext (a refused SYN to 5195, a 5194
  connection closed by the server). Rename it back: sign-in works over TLS.
- File transfer between the two clients still works (peers untouched).
- After the next certbot renewal: clients keep connecting, the server picks up
  the new certificate without a restart.

### S1-S3 - SCRAM (later, separate; 6-8 d)

- S1 server (3-4 d): verifier migration and lazy creation, verification of old
  methods against verifiers, the FLAP and WebAPI SCRAM paths with
  `tls-exporter`, unit tests with RFC 7677 test vectors plus our P' derivation.
- S2 add-on (3 d): 6.5 BUCP and 7.2 `clientLogin` takeover, server-final check.
  Testhost scenarios for both.
- S3 policy (1 d): per-account "strong only" (7.5), per-server "refuse XOR
  roasted without TLS" (CHECKLIST 7 plan step 4), optional drop of MD5 columns
  per account (7.4).
- **Accept**: a captured sign-in (inside TLS, by test hook) contains no P'. A
  replay on another connection fails (binding). The stock 6.5/7.2 without the
  add-on still sign in, unless the account is "strong only".

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| Hooks installed after the first connect: one connection in plaintext | Synchronous patching on DLL load (T0). Unknown server-bound sockets are reset. |
| Client configured with an HTTP or SOCKS proxy (coolcore has `CONNECT %s:%d`) | The `connect` target is the proxy, not the server. v1: detect `CONNECT <server>` / SOCKS to the server in the first bytes and fail closed with a message ("proxies are not supported with TLS yet"). Later: TLS inside the tunnel. |
| `getpeername`, logs or the client comparing the port | Hook `getpeername` to report the original port. |
| DNS answers change, or several A/AAAA records | Resolve `server=` in the add-on, cache, re-resolve on a miss. IPv4 only, as the clients are. |
| Pump thread and client thread racing on one socket | One pipe lock, fixed lock order, no lock across waits. Testhost stress test with many small frames. |
| Server certificate renewal | Reload from files in the Go server. No pin by default. |
| Larger DLL, slower start | ~1 MB, measured in T2. The handshake is about 1 RTT per connection. |
| A regression that blocks sign-in for everybody with the add-on | `tls=off` per install. A server that does not offer 5194 makes the add-on fail closed, so deploy the server (T1) before the add-on (T3/T4). |
| Kerberos, TOC, the 8101 pages, peers, voice | Outside the add-on's server connections. Listed in table 1. The 8101 fetches could later be moved to HTTPS by rewriting URLs in a WinINet IAT hook. Not in this stage. |

---

## 7. The same layer for other clients

The parts are kept so they can be reused: `TlsPipe` (no Winsock), the
destination map and fail-closed policy, and the hook glue.

- **ICQ 2003b and QIP 2005**: a separate proxy DLL with the same core crate
  (CHECKLIST 7, plan step 2). Both speak plain FLAP to `domain:5190`, so the same
  mapping to 5194 and the same `TlsPipe` apply. The hook glue differs per client
  (which module imports `wsock32`/`ws2_32`, blocking or async sockets), and the
  load slot per client is to be found (for 2003b a non-KnownDLL import of its own
  folder, as DESIGN 3.1 lists; for QIP, research). 2003b sends a XOR-roasted
  password: inside TLS it is protected in transit, and the SCRAM layer can turn
  it into P' itself (it can un-roast it), so 2003b with the DLL gets SCRAM too.
  That is what makes the server's "refuse XOR without the layer" setting usable.
- **Miranda NG** (`tools/miranda-icq/IcqOscarJ`): it already speaks TLS through
  Netlib (`Netlib_StartSsl`, TLV `0x8C`/`0x8E` in `fam_17signon.cpp`,
  `fam_01service.cpp`, `chan_04close.cpp`), with a modern library. It only needs
  the new port and the server's "advertise the TLS host to a client that asked"
  (2.2). That also ends today's hop from 5193 (Let's Encrypt) to 3143 (private
  CA). SCRAM is built into the plugin's sign-in code (C++, or the Rust core as a
  static library through a C ABI), using Netlib's exporter if it exposes one,
  else `tls-server-end-point`.
- **The key directory** can later move from 8102 (nginx, TLS 1.2) to the same
  TLS 1.3 port with ALPN `http/1.1`, because WebAPI already serves `/e2e/`.
