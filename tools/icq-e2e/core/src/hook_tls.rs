//! TLS 1.3 at the bottom of the hooked sockets (STAGE-TLS 3.3, 3.5).
//!
//! A `connect` from the networking module to the server on one of its plain
//! ports ([`crate::route`]) is sent to the TLS port instead, and the socket
//! gets a [`TlsConn`]: a [`TlsPipe`] and the ciphertext waiting to be sent. The
//! FLAP rewriter above it works on plaintext exactly as before:
//!
//! ```text
//! client --send--> [rewriter / E2E] --> [TlsPipe] --> original send (ciphertext)
//! client <--recv-- [rewriter / E2E] <-- [TlsPipe] <-- original recv (ciphertext)
//! ```
//!
//! The life of such a socket:
//!
//! 1. The client's `connect` goes to the TLS port. The client gets its own
//!    `FD_CONNECT` from Winsock as usual.
//! 2. The pump thread (one for all sockets) waits with `select` until the
//!    socket is connected and sends the ClientHello at once: on OSCAR the
//!    server speaks first, so waiting for the client's first byte would never
//!    end. It also reads the server's flight, so the handshake never depends
//!    on the client calling `recv`, and posts `FD_READ` when the handshake ends
//!    with plaintext already waiting.
//! 3. The client's `send` goes into the pipe at any time; before the end of
//!    the handshake rustls keeps it and sends it after `Finished`. The hook
//!    reports the full length.
//! 4. The client's `recv` gets plaintext only. Ciphertext without a whole
//!    record yet answers `WSAEWOULDBLOCK`, `MSG_PEEK` is served from the
//!    plaintext, `FIONREAD` counts plaintext only.
//! 5. `close_notify` from the server ends the stream cleanly (`recv` returns 0
//!    once the plaintext is drained). A TCP close without it, or any TLS
//!    error, is `WSAECONNRESET`: a cut stream is never taken for a clean end.
//! 6. `closesocket` sends one best-effort `close_notify`.
//!
//! Fail closed: a server connection that cannot be secured is never retried in
//! plaintext. The socket is reset, the client shows its own "cannot connect",
//! and the user is told once per run and reason in a message box (from a
//! worker thread), with the reason in the log too. `tls=off` in `icq-e2e.ini`
//! is the deliberate way out, and is said in the chat at every sign-on.
//!
//! Locks: the ciphertext queue (`wire`) is taken before the pipe, never the
//! other way round, and the pipe lock is never held across a wait. Only the
//! client's own `send` waits for room while holding `wire`; the pump and the
//! `recv` path only try it, and leave what they could not send to the pump.

use super::*;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU8;
use std::sync::{Condvar, LazyLock, RwLock};
use std::time::{Duration, Instant};

use crate::route::{Mapping, ProxyHello, Route, Target};
use crate::tls::{CloseKind, TlsClient, TlsFailure, TlsPipe, TlsSettings, TlsState, Trust};

pub(super) const WSAECONNRESET: u32 = 10054;
pub(super) const WSAECONNREFUSED: u32 = 10061;
pub(super) const WSAEOPNOTSUPP: u32 = 10045;
const SD_SEND: i32 = 1;
const SOL_SOCKET: i32 = 0xFFFF;
const SO_ERROR: i32 = 0x1007;

/// How long the server has to answer the ClientHello.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

// --- the setup --------------------------------------------------------------

/// What the add-on does about TLS: decided once from the settings, replaced by
/// the tests.
pub enum Setup {
    /// Nothing mapped: observe mode, or an ini without `server=`.
    Inactive,
    /// `tls=off`: nothing goes over TLS, and every sign-on is told so in the
    /// chat. The guard ports of the server go to its plain ports through
    /// `guard` (fourth review, finding G): the patch points the sign-in at
    /// them whenever a protecting row is ticked, so that a client without a
    /// working add-on cannot sign in.
    OptedOut {
        server: String,
        guard: Option<Route>,
    },
    /// Connections to the server are wrapped in TLS.
    Active(Active),
}

/// The server's route and the TLS client for it.
pub struct Active {
    pub route: Route,
    /// The TLS client, or why there is none (the trust store could not be
    /// opened, the settings could not be read): then every connection to the
    /// server is refused with that reason.
    pub client: Result<TlsClient, TlsFailure>,
}

static SETUP: RwLock<Option<Arc<Setup>>> = RwLock::new(None);

#[cfg(test)]
thread_local! {
    /// A setup for this thread only (the fault matrix).
    pub(super) static TEST_SETUP: std::cell::RefCell<Option<Arc<Setup>>> =
        const { std::cell::RefCell::new(None) };
}

/// The setup, built from the policy the first time it is asked for once the
/// policy is read. Asked before that (nothing should: the gate holds every
/// hooked call until then), it is inactive and not kept, so the real one is
/// still built from the real policy.
pub(super) fn setup() -> Arc<Setup> {
    #[cfg(test)]
    if let Some(s) = TEST_SETUP.with(|t| t.borrow().clone()) {
        return s;
    }
    if let Some(s) = SETUP.read().unwrap_or_else(|e| e.into_inner()).clone() {
        return s;
    }
    if !policy_is_set() {
        return Arc::new(Setup::Inactive);
    }
    let mut w = SETUP.write().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = w.clone() {
        return s;
    }
    let s = Arc::new(from_policy(policy()));
    *w = Some(s.clone());
    s
}

/// Replaces the setup (the tests).
pub(super) fn replace_setup(s: Setup) {
    *SETUP.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(s));
}

fn from_policy(p: &Policy) -> Setup {
    use crate::config::TlsPolicy;
    if p.mode == Mode::Observe {
        log::line("TLS: off in observe mode (bytes are never changed)");
        return Setup::Inactive;
    }
    match &p.tls {
        TlsPolicy::NoServer => {
            log::line(
                "TLS: off: icq-e2e.ini names no server= (written before TLS); \
                 the connections to the server go in plaintext",
            );
            Setup::Inactive
        }
        TlsPolicy::Off { server } => {
            log::line(&format!(
                "TLS: off by tls=off; the connections to {server} are not encrypted; its guard ports {:?} go to its plain ports",
                crate::route::GUARD_PORTS
            ));
            Setup::OptedOut {
                server: server.clone(),
                guard: Some(Route::system(server)),
            }
        }
        TlsPolicy::On { server, pins } => {
            let client = TlsClient::new(&TlsSettings {
                server_name: server.clone(),
                trust: Trust::System,
                pins: pins.clone(),
            });
            match &client {
                Ok(_) => log::line(&format!(
                    "TLS: on: connections to {server} on ports {:?} go to {}:{} over TLS 1.3",
                    [&crate::route::FLAP_PORTS[..], &crate::route::HTTP_PORTS[..]].concat(),
                    server,
                    crate::route::TLS_PORT
                )),
                Err(f) => log::line(&format!(
                    "TLS: cannot be set up ({}); connections to {server} will be refused",
                    f.reason()
                )),
            }
            Setup::Active(Active {
                route: Route::system(server),
                client,
            })
        }
        TlsPolicy::Invalid { server, why } => {
            log::line(&format!(
                "TLS: the settings cannot be read ({why}); connections to {server} will be refused"
            ));
            Setup::Active(Active {
                route: Route::system(server),
                client: Err(TlsFailure::Setup(why.clone())),
            })
        }
    }
}

// --- why a connection failed ------------------------------------------------

/// Why a server connection could not be secured, or ended badly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Why {
    /// TLS itself: the certificate, the protocol, the settings.
    Tls(TlsFailure),
    /// The TLS port refused the connection: a server without it.
    Refused,
    /// The TCP connection failed otherwise (offline, unreachable).
    Network(u32),
    /// The server did not finish the handshake in time.
    Timeout,
    /// The server ended the connection: during the handshake, or after it
    /// without `close_notify`.
    Closed { during_handshake: bool },
    /// The socket failed after it was connected.
    Socket(u32),
    /// The server is on a port the add-on cannot secure.
    OtherPort(u16),
    /// The server's name does not resolve.
    Unresolved,
    /// The client goes to the server through a proxy.
    Proxy,
    /// Data on a connection to the server the hooks never saw opened.
    Unseen,
}

impl Why {
    /// One line for the log and the message box.
    fn reason(&self) -> String {
        match self {
            Why::Tls(f) => f.reason(),
            Why::Refused => format!(
                "its secure port {} is closed; the server may not have it yet",
                crate::route::TLS_PORT
            ),
            Why::Network(e) => format!("the connection failed, Winsock error {e}"),
            Why::Timeout => "the server did not answer the TLS handshake in time".to_string(),
            Why::Closed {
                during_handshake: true,
            } => "the server closed the connection during the TLS handshake".to_string(),
            Why::Closed { .. } => {
                "the server closed the connection without ending TLS (close_notify)".to_string()
            }
            Why::Socket(e) => format!("Winsock error {e}"),
            Why::OtherPort(p) => format!("port {p} is not one the add-on can secure"),
            Why::Unresolved => "its name does not resolve on this computer".to_string(),
            Why::Proxy => "the client is set to reach it through a proxy, and connections \
                           through a proxy cannot be secured yet"
                .to_string(),
            Why::Unseen => "a connection was opened before the add-on could secure it".to_string(),
        }
    }

    /// Whether the user is told in a message box: what they can act on, not
    /// the network coming and going.
    fn tells_user(&self) -> bool {
        match self {
            Why::Tls(_)
            | Why::Refused
            | Why::Timeout
            | Why::OtherPort(_)
            | Why::Unresolved
            | Why::Proxy => true,
            Why::Closed { during_handshake } => *during_handshake,
            Why::Network(_) | Why::Socket(_) | Why::Unseen => false,
        }
    }
}

// --- telling the user -------------------------------------------------------

/// Reasons already shown in this run.
static SHOWN: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
/// Where the tests collect what would have been shown.
static CAPTURE: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// The text of the message box (STAGE-TLS 3.5).
fn notice_text(server: &str, why: &Why) -> String {
    let way_out = match why {
        Why::Proxy => "Turn the proxy off in the client's connection settings, or untick \"Encrypted connection to the server (TLS)\" in the patch and apply it (tls=off) to allow it anyway.",
        // The patch's row, not the ini line alone: with the row ticked the
        // patch has also moved the client's sign-in to ports only the add-on
        // reaches (STAGE-TLS 3.5.1), and unticking it puts the plain ports back.
        _ => "To allow it anyway, untick \"Encrypted connection to the server (TLS)\" in the patch and apply it (tls=off).",
    };
    format!(
        "ICQ E2E: the connection to {server} could not be secured ({}). \
         The client was not allowed to connect without encryption. {way_out}",
        why.reason()
    )
}

/// Logs the notice and shows it once per run and reason, when the user can
/// act on the failure.
fn tell(server: &str, why: &Why) {
    if !why.tells_user() {
        // The network coming and going: the caller has logged the reason.
        return;
    }
    notice(&why.reason(), notice_text(server, why));
}

/// Logs `text` and shows it in a message box once per run and `key`. The box
/// comes from a thread of its own: never the client's UI thread, and never
/// the thread inside a hook.
pub(super) fn notice(key: &str, text: String) {
    log::line(&format!("[ICQ E2E] {text}"));
    if !lock(&SHOWN).insert(key.to_string()) {
        return;
    }
    if let Some(v) = lock(&CAPTURE).as_mut() {
        v.push(text);
        return;
    }
    let _ = std::thread::Builder::new()
        .name("icq-e2e notice".into())
        .spawn(move || {
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                MessageBoxW, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MB_TOPMOST,
            };
            let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
            let body = wide(&text);
            let title = wide("ICQ E2E");
            // SAFETY: NUL-terminated strings that outlive the call; no owner.
            unsafe {
                MessageBoxW(
                    ptr::null_mut(),
                    body.as_ptr(),
                    title.as_ptr(),
                    MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
                );
            }
        });
}

/// Starts collecting the message boxes instead of showing them, and forgets
/// the reasons shown so far (the tests).
pub(super) fn capture_notices() {
    *lock(&CAPTURE) = Some(Vec::new());
    lock(&SHOWN).clear();
}

/// The message boxes collected since the last call.
pub(super) fn take_notices() -> Vec<String> {
    lock(&CAPTURE)
        .as_mut()
        .map(std::mem::take)
        .unwrap_or_default()
}

// --- one TLS socket ---------------------------------------------------------

const CONNECTING: u8 = 0;
const HANDSHAKING: u8 = 1;
const READY: u8 = 2;
const FAILED: u8 = 3;

/// The pipe and why it failed, under one lock.
struct PipeSide {
    pipe: TlsPipe,
    failure: Option<Why>,
    /// Whether the socket said the stream has ended (recv returned 0).
    socket_eof: bool,
}

/// TLS on one socket.
pub(super) struct TlsConn {
    pub(super) mapping: Mapping,
    server: String,
    /// `ip:port` the connection really goes to.
    target: String,
    pipe: Mutex<PipeSide>,
    /// Ciphertext not on the wire yet. Also the lock that keeps the
    /// ciphertext in order: it is taken before the pipe.
    wire: Mutex<Vec<u8>>,
    phase: AtomicU8,
    /// Set by `closesocket` under both locks; nothing touches the handle after.
    closed: AtomicBool,
    /// Ciphertext someone could not send because another thread held `wire`.
    owed: AtomicBool,
    /// When the ClientHello went out.
    hello_at: Mutex<Option<Instant>>,
}

impl TlsConn {
    fn phase(&self) -> u8 {
        self.phase.load(Ordering::Acquire)
    }
}

/// What the hook does with a `connect`.
pub(super) enum ConnectPlan {
    /// Not the server, or TLS not active: as before.
    Plain,
    /// Refused with this error, without connecting.
    Refuse(u32),
    /// Connect to this address instead, with TLS on the socket.
    Tls { conn: Arc<TlsConn>, addr: Vec<u8> },
    /// Connect to this address instead, in plain: a guard port of the
    /// server with `tls=off`. `original` is (the port it goes to, the port
    /// the client asked for), for `getpeername`.
    Remap { addr: Vec<u8>, original: (u16, u16) },
}

/// Decides what happens to a `connect` to `name`.
///
/// # Safety
/// `name` points to `namelen` readable bytes, or is null.
pub(super) unsafe fn plan_connect(s: Socket, name: *const u8, namelen: i32) -> ConnectPlan {
    let setup = setup();
    let active = match &*setup {
        Setup::Active(active) => active,
        Setup::OptedOut {
            server,
            guard: Some(route),
        } => return plan_guard(s, name, namelen, server, route),
        _ => return ConnectPlan::Plain,
    };
    if name.is_null() || namelen < 16 {
        return ConnectPlan::Plain;
    }
    let sa = std::slice::from_raw_parts(name, namelen as usize);
    if u16::from_le_bytes([sa[0], sa[1]]) != 2 {
        // IPv6 or anything else: the clients are IPv4 only.
        return ConnectPlan::Plain;
    }
    let port = u16::from_be_bytes([sa[2], sa[3]]);
    let ip = Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]);
    let server = active.route.server();
    let refuse = |why: Why| {
        log::line(&format!(
            "connect: socket {s} -> {ip}:{port} refused (fail closed)"
        ));
        tell(server, &why);
        ConnectPlan::Refuse(WSAECONNREFUSED)
    };
    let mapping = match active.route.target(ip, port) {
        Target::Elsewhere => return ConnectPlan::Plain,
        Target::ServerOtherPort => return refuse(Why::OtherPort(port)),
        Target::Unresolved => return refuse(Why::Unresolved),
        Target::Server(m) => m,
    };
    let client = match &active.client {
        Ok(c) => c,
        Err(f) => return refuse(Why::Tls(f.clone())),
    };
    let pipe = match client.connect(mapping.alpn) {
        Ok(p) => p,
        Err(f) => return refuse(Why::Tls(f)),
    };
    let mut addr = sa.to_vec();
    addr[2..4].copy_from_slice(&mapping.tls_port.to_be_bytes());
    ConnectPlan::Tls {
        conn: Arc::new(TlsConn {
            mapping,
            server: server.to_string(),
            target: format!("{ip}:{}", mapping.tls_port),
            pipe: Mutex::new(PipeSide {
                pipe,
                failure: None,
                socket_eof: false,
            }),
            wire: Mutex::new(Vec::new()),
            phase: AtomicU8::new(CONNECTING),
            closed: AtomicBool::new(false),
            owed: AtomicBool::new(false),
            hello_at: Mutex::new(None),
        }),
        addr,
    }
}

/// With `tls=off`: a `connect` to a guard port of the server goes to the
/// plain port it stands for (fourth review, finding G). Only the add-on does
/// this, so a client without it cannot sign in through the guard ports.
///
/// # Safety
/// As [`plan_connect`].
unsafe fn plan_guard(
    s: Socket,
    name: *const u8,
    namelen: i32,
    server: &str,
    route: &Route,
) -> ConnectPlan {
    if name.is_null() || namelen < 16 {
        return ConnectPlan::Plain;
    }
    let sa = std::slice::from_raw_parts(name, namelen as usize);
    if u16::from_le_bytes([sa[0], sa[1]]) != 2 {
        return ConnectPlan::Plain;
    }
    let port = u16::from_be_bytes([sa[2], sa[3]]);
    let ip = Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]);
    match route.guard(ip, port) {
        crate::route::Guard::NotGuard => ConnectPlan::Plain,
        crate::route::Guard::Unresolved => {
            log::line(&format!(
                "connect: socket {s} -> {ip}:{port} refused (fail closed): a guard port, and {server} does not resolve"
            ));
            tell(server, &Why::Unresolved);
            ConnectPlan::Refuse(WSAECONNREFUSED)
        }
        crate::route::Guard::Plain(plain) => {
            log::line(&format!(
                "connect: socket {s} -> {ip}:{port} is a guard port of {server}; to its plain port {plain} (tls=off)"
            ));
            let mut addr = sa.to_vec();
            addr[2..4].copy_from_slice(&plain.to_be_bytes());
            ConnectPlan::Remap {
                addr,
                original: (plain, port),
            }
        }
    }
}

/// After the original `connect` of a TLS socket: hands it to the pump, or
/// records the failure. `r` and `err` are the original's result and error.
pub(super) fn connect_started(s: Socket, sock: &Arc<Sock>, conn: &Arc<TlsConn>, r: i32, err: u32) {
    log::line(&format!(
        "TLS: socket {s} goes to {} ({}) for port {}, ALPN {}",
        conn.server,
        conn.target,
        conn.mapping.original_port,
        conn.mapping.alpn_name()
    ));
    if r == 0 || err == WSAEWOULDBLOCK {
        register(s, sock.clone());
    } else {
        fail(sock, conn, s, Why::Network(err));
    }
}

/// Records a failure once: the alert rustls queued goes out, the sending side
/// is shut, the user is told, and the client is woken to read the error.
fn fail(sock: &Sock, conn: &TlsConn, s: Socket, why: Why) {
    {
        let mut ps = lock(&conn.pipe);
        if ps.failure.is_some() || conn.closed.load(Ordering::Acquire) {
            return;
        }
        ps.failure = Some(why.clone());
    }
    let was = conn.phase.swap(FAILED, Ordering::AcqRel);
    if was != CONNECTING {
        let _ = flush(conn, s, false);
        // SAFETY: shutdown on the client's socket, which is still open (the
        // closed flag is checked above and set only under the pipe lock).
        unsafe { windows_sys::Win32::Networking::WinSock::shutdown(s, SD_SEND) };
    }
    log::line(&format!(
        "TLS: socket {s} to {} ({}) failed: {}",
        conn.server,
        conn.target,
        why.reason()
    ));
    tell(&conn.server, &why);
    post_fd_read(sock, s);
}

/// What one read of the socket gave.
enum Pulled {
    /// Ciphertext was fed to the pipe.
    Data,
    /// Nothing there now.
    Nothing,
    /// The socket's stream has ended (and the pipe knows how).
    Eof,
}

/// Whether the socket has something to read now (data, the end, or an error).
fn readable_now(s: Socket) -> bool {
    // SAFETY: plain select on one socket with stack-owned sets.
    unsafe {
        let mut r: FD_SET = std::mem::zeroed();
        r.fd_count = 1;
        r.fd_array[0] = s;
        let tv = TIMEVAL {
            tv_sec: 0,
            tv_usec: 0,
        };
        select(0, &mut r, ptr::null_mut(), ptr::null_mut(), &tv) > 0
    }
}

/// How many times the original `recv` was called on TLS sockets (the tests).
pub(super) static ORIGINAL_RECVS: AtomicUsize = AtomicUsize::new(0);

/// Whether the client's socket is non-blocking: one it gave `WSAAsyncSelect`
/// (which makes it non-blocking for good), as both clients do.
fn is_async(sock: &Sock) -> bool {
    lock(&sock.notify).is_some()
}

/// Reads what the socket has into the pipe, without ever blocking. With
/// `force` (a non-blocking socket) the original `recv` is called whatever
/// the socket holds - that call is what re-arms Winsock's `FD_READ` - and
/// otherwise the socket is asked with `select` first, so a blocking socket is
/// read only when it has something. With `wait` false the pipe lock is only
/// tried.
fn pull(conn: &TlsConn, s: Socket, wait: bool, force: bool) -> Result<Pulled, Why> {
    let mut ps = if wait {
        lock(&conn.pipe)
    } else {
        match conn.pipe.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Ok(Pulled::Nothing),
        }
    };
    if conn.closed.load(Ordering::Acquire) {
        return Ok(Pulled::Nothing);
    }
    if let Some(why) = &ps.failure {
        return Err(why.clone());
    }
    if ps.socket_eof {
        return Ok(Pulled::Eof);
    }
    if !force && !readable_now(s) {
        return Ok(Pulled::Nothing);
    }
    ORIGINAL_RECVS.fetch_add(1, Ordering::Relaxed);
    let mut tmp = vec![0u8; READ_CHUNK];
    // SAFETY: tmp is our own buffer of tmp.len() bytes.
    let n = unsafe { orig_recv()(s, tmp.as_mut_ptr(), tmp.len() as i32, 0) };
    if n > 0 {
        return match ps.pipe.feed_ciphertext(&tmp[..n as usize]) {
            Ok(()) => Ok(Pulled::Data),
            Err(f) => Err(Why::Tls(f)),
        };
    }
    if n == 0 {
        ps.socket_eof = true;
        let handshaking = ps.pipe.is_handshaking();
        return match ps.pipe.end_of_input() {
            CloseKind::Clean => Ok(Pulled::Eof),
            CloseKind::Truncated if ps.pipe.plaintext_len() > 0 => Ok(Pulled::Eof),
            CloseKind::Truncated => Err(Why::Closed {
                during_handshake: handshaking,
            }),
        };
    }
    // SAFETY: reads the calling thread's last error.
    let err = unsafe { GetLastError() };
    if err == WSAEWOULDBLOCK {
        Ok(Pulled::Nothing)
    } else {
        Err(Why::Socket(err))
    }
}

/// Sends the ciphertext the pipe has produced, in order. With `wait` the
/// socket's buffer is waited for (the client's own `send`); without it the
/// queue is only tried, and what is left is the pump's to send.
fn flush(conn: &TlsConn, s: Socket, wait: bool) -> Result<(), u32> {
    if conn.phase() == CONNECTING {
        // The pump sends the ClientHello once the socket is connected.
        return Ok(());
    }
    let mut wire = if wait {
        lock(&conn.wire)
    } else {
        match conn.wire.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                conn.owed.store(true, Ordering::Release);
                wake_pump();
                return Ok(());
            }
        }
    };
    flush_locked(conn, s, &mut wire, wait)
}

/// [`flush`] with the queue already held.
fn flush_locked(conn: &TlsConn, s: Socket, wire: &mut Vec<u8>, wait: bool) -> Result<(), u32> {
    let mut waited = 0u32;
    loop {
        {
            let mut ps = lock(&conn.pipe);
            if conn.closed.load(Ordering::Acquire) {
                return Ok(());
            }
            if ps.pipe.wants_write() {
                let more = ps.pipe.take_ciphertext();
                wire.extend_from_slice(&more);
            }
        }
        if wire.is_empty() {
            return Ok(());
        }
        let len = wire.len().min(i32::MAX as usize) as i32;
        // SAFETY: wire is our own live buffer.
        let n = unsafe { orig_send()(s, wire.as_ptr(), len, 0) };
        if n > 0 {
            wire.drain(..n as usize);
            continue;
        }
        // SAFETY: reads the calling thread's last error.
        let err = if n == 0 {
            WSAEWOULDBLOCK
        } else {
            unsafe { GetLastError() }
        };
        if err != WSAEWOULDBLOCK {
            return Err(err);
        }
        if !wait || waited >= SEND_WAIT_MS {
            if wait {
                log::line(&format!(
                    "socket {s}: send buffer full for {}s; {} bytes of TLS left to the pump",
                    SEND_WAIT_MS / 1000,
                    wire.len()
                ));
            }
            conn.owed.store(true, Ordering::Release);
            wake_pump();
            return Ok(());
        }
        wait_writable(s, 100);
        waited += 100;
    }
}

/// After the pipe was fed: sends what it produced, and notices the end of the
/// handshake. Returns whether plaintext is waiting for the client.
fn progress(sock: &Sock, conn: &TlsConn, s: Socket) -> bool {
    if let Err(e) = flush(conn, s, false) {
        fail(sock, conn, s, Why::Socket(e));
        return false;
    }
    let (ready, alpn_ok, plain) = {
        let ps = lock(&conn.pipe);
        (
            !ps.pipe.is_handshaking(),
            ps.pipe.alpn() == Some(conn.mapping.alpn),
            ps.pipe.plaintext_len() > 0,
        )
    };
    if ready
        && conn
            .phase
            .compare_exchange(HANDSHAKING, READY, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        if !alpn_ok {
            fail(
                sock,
                conn,
                s,
                Why::Tls(TlsFailure::Protocol(format!(
                    "the server did not agree to {}",
                    conn.mapping.alpn_name()
                ))),
            );
            return false;
        }
        log::line(&format!(
            "TLS: socket {s} to {} ({}) secured: TLS 1.3, ALPN {}",
            conn.server,
            conn.target,
            conn.mapping.alpn_name()
        ));
    }
    plain
}

// --- the client's calls -----------------------------------------------------

/// The client's `recv` on a TLS socket: plaintext only. `Err` is the Winsock
/// error to report.
pub(super) fn recv(
    sock: &Sock,
    conn: &TlsConn,
    s: Socket,
    buf: &mut [u8],
    peek: bool,
) -> Result<usize, u32> {
    // Every `recv` of the client reaches Winsock at least once, as it would
    // without the add-on: that call is what re-arms FD_READ. Answering from
    // what the add-on holds, or after a `select` that saw nothing, without it
    // left Winsock waiting for a `recv` that never came, and the next bytes
    // were never announced (the stall the testhost caught).
    let force = is_async(sock);
    if force {
        touch(sock, conn, s);
    }
    loop {
        {
            let mut ps = lock(&conn.pipe);
            if ps.failure.is_some() {
                return Err(WSAECONNRESET);
            }
            if ps.pipe.plaintext_len() > 0 {
                if peek {
                    return Ok(ps.pipe.peek_plaintext(buf));
                }
                let k = ps.pipe.take_plaintext(buf);
                let left = ps.pipe.plaintext_len() > 0;
                drop(ps);
                // What is left was decrypted from bytes Winsock has already
                // handed over, so it will never announce it: we do.
                if left {
                    post_fd_read(sock, s);
                }
                return Ok(k);
            }
            match ps.pipe.state() {
                TlsState::Closed(CloseKind::Clean) => return Ok(0),
                TlsState::Closed(CloseKind::Truncated) => {
                    drop(ps);
                    fail(
                        sock,
                        conn,
                        s,
                        Why::Closed {
                            during_handshake: false,
                        },
                    );
                    return Err(WSAECONNRESET);
                }
                _ => {}
            }
        }
        if conn.phase() == CONNECTING {
            return Err(WSAEWOULDBLOCK);
        }
        match pull(conn, s, true, force) {
            Ok(Pulled::Data) => {
                progress(sock, conn, s);
            }
            // The state says how it ended; the top of the loop answers.
            Ok(Pulled::Eof) => {}
            // The clients' sockets are non-blocking (WSAAsyncSelect): nothing
            // yet is the normal "would block", and Winsock posts the next
            // FD_READ because the socket was read.
            Ok(Pulled::Nothing) => return Err(WSAEWOULDBLOCK),
            Err(why) => {
                fail(sock, conn, s, why);
                return Err(WSAECONNRESET);
            }
        }
    }
}

/// One call of the original `recv` for a client `recv` that will be answered
/// from what the add-on already holds (see [`recv`]). What it reads goes into
/// the pipe. Returns whether plaintext is waiting there now.
pub(super) fn touch(sock: &Sock, conn: &TlsConn, s: Socket) -> bool {
    if conn.phase() == CONNECTING || !is_async(sock) {
        return false;
    }
    match pull(conn, s, true, true) {
        Ok(Pulled::Data) => progress(sock, conn, s),
        Ok(_) => lock(&conn.pipe).pipe.plaintext_len() > 0,
        Err(why) => {
            fail(sock, conn, s, why);
            false
        }
    }
}

/// The client's `send` on a TLS socket: all of `data` is taken.
pub(super) fn send(sock: &Sock, conn: &TlsConn, s: Socket, data: &[u8]) -> Result<(), u32> {
    {
        let mut ps = lock(&conn.pipe);
        if ps.failure.is_some() || conn.closed.load(Ordering::Acquire) {
            return Err(WSAECONNRESET);
        }
        if let Err(f) = ps.pipe.write_plaintext(data) {
            drop(ps);
            fail(sock, conn, s, Why::Tls(f));
            return Err(WSAECONNRESET);
        }
    }
    if let Err(e) = flush(conn, s, true) {
        fail(sock, conn, s, Why::Socket(e));
        return Err(e);
    }
    Ok(())
}

/// `FIONREAD` on a TLS socket: the plaintext the pipe holds, after reading what
/// the socket has now (ciphertext waiting in the socket must not be reported
/// as nothing, or a client that reads only what FIONREAD says would wait for
/// an FD_READ that Winsock has already posted).
pub(super) fn plaintext_waiting(sock: &Sock, conn: &TlsConn, s: Socket) -> u32 {
    if conn.phase() != CONNECTING {
        match pull(conn, s, false, false) {
            Ok(Pulled::Data) => {
                progress(sock, conn, s);
            }
            Ok(_) => {}
            Err(why) => fail(sock, conn, s, why),
        }
    }
    match conn.pipe.try_lock() {
        Ok(ps) => ps.pipe.plaintext_len() as u32,
        Err(_) => 0,
    }
}

/// `closesocket` on a TLS socket: one best-effort `close_notify`, then nothing
/// touches the handle again.
pub(super) fn close(conn: &TlsConn, s: Socket) {
    let mut wire = lock(&conn.wire);
    let notify = {
        let mut ps = lock(&conn.pipe);
        let ok = ps.failure.is_none() && conn.phase() == READY;
        if ok {
            ps.pipe.close();
        }
        ok
    };
    if notify {
        // Without waiting: what does not fit now is dropped with the socket.
        let _ = flush_locked(conn, s, &mut wire, false);
    }
    let _ps = lock(&conn.pipe);
    conn.closed.store(true, Ordering::Release);
}

/// The port the client asked for, for `getpeername`, when the socket really
/// goes to the TLS port.
pub(super) fn original_port(conn: &TlsConn, reported: u16) -> u16 {
    if reported == conn.mapping.tls_port {
        conn.mapping.original_port
    } else {
        reported
    }
}

// --- connections the mapping did not see ------------------------------------

/// The address a socket is connected to.
fn peer_addr(s: Socket) -> Option<(Ipv4Addr, u16)> {
    // SAFETY: getpeername into a stack buffer of the size passed.
    unsafe {
        let mut sa = [0u8; 32];
        let mut len = sa.len() as i32;
        let r = windows_sys::Win32::Networking::WinSock::getpeername(
            s,
            sa.as_mut_ptr().cast(),
            &mut len,
        );
        if r != 0 || len < 8 || u16::from_le_bytes([sa[0], sa[1]]) != 2 {
            return None;
        }
        Some((
            Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]),
            u16::from_be_bytes([sa[2], sa[3]]),
        ))
    }
}

/// Whether a socket must be refused: one the hooks never saw `connect` for
/// that talks to the server (opened before the hooks), or one that asks a
/// proxy for the server. Checked once per socket (the proxy request on its
/// first one or two sends).
pub(super) fn blocked(s: Socket, sock: &Sock, outbound: Option<&[u8]>) -> bool {
    if sock.blocked.load(Ordering::Acquire) {
        return true;
    }
    if sock.tls.get().is_some() {
        return false;
    }
    let setup = setup();
    let Setup::Active(active) = &*setup else {
        return false;
    };
    let route = &active.route;
    let block = |why: Why| {
        sock.blocked.store(true, Ordering::Release);
        log::line(&format!(
            "socket {s}: reset (fail closed): {}",
            why.reason()
        ));
        tell(route.server(), &why);
        true
    };
    if !sock.connect_seen.load(Ordering::Acquire)
        && !sock.unseen_checked.swap(true, Ordering::AcqRel)
    {
        if let Some((ip, port)) = peer_addr(s) {
            let server_port = route.ports().alpn_for(port).is_some() || port == route.ports().tls;
            if server_port && route.is_server(ip, false) {
                return block(Why::Unseen);
            }
        }
    }
    let Some(data) = outbound else {
        return false;
    };
    let state = sock.proxy_state.load(Ordering::Acquire);
    if state == PROXY_DONE {
        return false;
    }
    match crate::route::proxy_hello(data, state == PROXY_SOCKS5) {
        ProxyHello::Request { host, port } => {
            sock.proxy_state.store(PROXY_DONE, Ordering::Release);
            if route.names_server(&host) {
                log::line(&format!(
                    "socket {s}: the client asks a proxy for {host:?}:{port}"
                ));
                return block(Why::Proxy);
            }
            false
        }
        ProxyHello::Socks5Greeting => {
            sock.proxy_state.store(PROXY_SOCKS5, Ordering::Release);
            false
        }
        ProxyHello::None => {
            sock.proxy_state.store(PROXY_DONE, Ordering::Release);
            false
        }
    }
}

/// `Sock::proxy_state`: nothing seen yet, a SOCKS5 greeting seen, decided.
pub(super) const PROXY_UNSEEN: u8 = 0;
const PROXY_SOCKS5: u8 = 1;
const PROXY_DONE: u8 = 2;

/// With `tls=off`, says once per sign-on - on the connection the chats are on
/// - that the connection to the server is not encrypted (STAGE-TLS 3.5).
pub(super) fn say_if_opted_out(sock: &Sock) {
    if !sock.messages.load(Ordering::Acquire) || sock.tls_off_said.load(Ordering::Acquire) {
        return;
    }
    let setup = setup();
    let Setup::OptedOut { server, .. } = &*setup else {
        return;
    };
    let sess = lock(&sock.session).clone();
    let mode = policy().mode;
    if sess.is_none() && !matches!(mode, Mode::Plain | Mode::Encrypt) {
        return;
    }
    if sock.tls_off_said.swap(true, Ordering::AcqRel) {
        return;
    }
    log::line(&format!(
        "[ICQ E2E] The connection to the server ({server}) is not encrypted (tls=off)"
    ));
    match sess {
        Some(sess) => lock(&sess)
            .engine()
            .say(crate::policy::tls_off_note(server)),
        None if mode == Mode::Plain => {
            lock(disabled()).say(crate::policy::tls_off_plain_note(server))
        }
        None => lock(withheld()).say(crate::policy::tls_off_note(server)),
    }
}

// --- the pump thread --------------------------------------------------------

struct Pump {
    list: Mutex<Vec<(Socket, Arc<Sock>)>>,
    wake: Condvar,
}

static PUMP: LazyLock<Pump> = LazyLock::new(|| Pump {
    list: Mutex::new(Vec::new()),
    wake: Condvar::new(),
});
static PUMP_STARTED: std::sync::Once = std::sync::Once::new();

/// Gives a new TLS socket to the pump.
fn register(s: Socket, sock: Arc<Sock>) {
    PUMP_STARTED.call_once(|| {
        let _ = std::thread::Builder::new()
            .name("icq-e2e tls pump".into())
            .spawn(|| loop {
                let r = panic::catch_unwind(pump_round);
                if r.is_err() {
                    log::line("TLS pump: a round panicked; going on");
                }
            });
    });
    lock(&PUMP.list).push((s, sock));
    PUMP.wake.notify_all();
}

fn wake_pump() {
    PUMP.wake.notify_all();
}

/// Whether the pump still has something to do for this socket.
fn pump_wants(sock: &Sock) -> bool {
    let Some(conn) = sock.tls.get() else {
        return false;
    };
    if conn.closed.load(Ordering::Acquire) {
        return false;
    }
    match conn.phase() {
        CONNECTING | HANDSHAKING => true,
        FAILED => false,
        _ => {
            conn.owed.load(Ordering::Acquire)
                || conn.wire.try_lock().map_or(true, |w| !w.is_empty())
        }
    }
}

fn fd_isset(set: &FD_SET, s: Socket) -> bool {
    set.fd_array[..set.fd_count as usize].contains(&s)
}

fn fd_add(set: &mut FD_SET, s: Socket) {
    if (set.fd_count as usize) < set.fd_array.len() && !fd_isset(set, s) {
        set.fd_array[set.fd_count as usize] = s;
        set.fd_count += 1;
    }
}

/// The socket's pending error (a failed connect).
fn socket_error(s: Socket) -> u32 {
    let mut v: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as i32;
    // SAFETY: getsockopt into a stack i32 of the size passed.
    unsafe {
        windows_sys::Win32::Networking::WinSock::getsockopt(
            s,
            SOL_SOCKET,
            SO_ERROR,
            (&mut v as *mut i32).cast(),
            &mut len,
        );
    }
    v as u32
}

/// One round of the pump: waits for the sockets that are connecting, in the
/// handshake, or owe ciphertext, and moves each one on.
fn pump_round() {
    let items: Vec<(Socket, Arc<Sock>)> = {
        let mut list = lock(&PUMP.list);
        list.retain(|(_, sock)| pump_wants(sock));
        if list.is_empty() {
            let _ = PUMP
                .wake
                .wait_timeout(list, Duration::from_millis(500))
                .map(|_| ());
            return;
        }
        list.clone()
    };
    // SAFETY: zeroed FD_SETs are empty sets.
    let (mut r, mut w, mut e): (FD_SET, FD_SET, FD_SET) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed()) };
    for (s, sock) in &items {
        let Some(conn) = sock.tls.get() else { continue };
        match conn.phase() {
            CONNECTING => {
                fd_add(&mut w, *s);
                fd_add(&mut e, *s);
            }
            HANDSHAKING => {
                fd_add(&mut r, *s);
                if conn.owed.load(Ordering::Acquire) {
                    fd_add(&mut w, *s);
                }
            }
            _ => fd_add(&mut w, *s),
        }
    }
    let tv = TIMEVAL {
        tv_sec: 0,
        tv_usec: 50_000,
    };
    // SAFETY: select on our own sets; a socket closed meanwhile only makes the
    // call fail, and every handle is checked against `closed` under a lock
    // before it is used.
    let n = unsafe { select(0, &mut r, &mut w, &mut e, &tv) };
    if n < 0 {
        // A socket in the set was closed under us; the next round drops it.
        std::thread::sleep(Duration::from_millis(10));
    }
    for (s, sock) in &items {
        let s = *s;
        let Some(conn) = sock.tls.get() else { continue };
        if conn.closed.load(Ordering::Acquire) {
            continue;
        }
        match conn.phase() {
            CONNECTING if n > 0 && fd_isset(&e, s) => {
                let err = socket_error(s);
                let why = if err == WSAECONNREFUSED {
                    Why::Refused
                } else {
                    Why::Network(err)
                };
                fail(sock, conn, s, why);
            }
            CONNECTING if n > 0 && fd_isset(&w, s) => {
                conn.phase.store(HANDSHAKING, Ordering::Release);
                *lock(&conn.hello_at) = Some(Instant::now());
                if let Err(err) = flush(conn, s, false) {
                    fail(sock, conn, s, Why::Socket(err));
                }
            }
            HANDSHAKING => {
                if n > 0 && fd_isset(&r, s) {
                    match pull(conn, s, false, false) {
                        Ok(Pulled::Data) | Ok(Pulled::Eof) => {
                            if progress(sock, conn, s) {
                                post_fd_read(sock, s);
                            }
                        }
                        Ok(Pulled::Nothing) => {}
                        Err(why) => {
                            fail(sock, conn, s, why);
                            continue;
                        }
                    }
                }
                if conn.owed.swap(false, Ordering::AcqRel) {
                    let _ = flush(conn, s, false);
                }
                let late = lock(&conn.hello_at).is_some_and(|t| t.elapsed() >= HANDSHAKE_TIMEOUT);
                if late && conn.phase() == HANDSHAKING {
                    fail(sock, conn, s, Why::Timeout);
                }
            }
            READY if conn.owed.swap(false, Ordering::AcqRel) || (n > 0 && fd_isset(&w, s)) => {
                if let Err(err) = flush(conn, s, false) {
                    fail(sock, conn, s, Why::Socket(err));
                }
            }
            _ => {}
        }
    }
    if n == 0 {
        // Nothing moved: do not spin on sockets that only owe ciphertext.
        std::thread::sleep(Duration::from_millis(5));
    }
}
