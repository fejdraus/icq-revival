//! Winsock interception, installed by IAT-patching the client's own networking
//! module (coolcore59.dll on 7.2, coolcore49.dll on 6.5). We swap that module's
//! import thunks for `send`, `recv`, `connect`, `closesocket`, `WSAAsyncSelect`
//! and `ioctlsocket`, imported from `wsock32.dll` (or `ws2_32.dll`).
//!
//! Both modules import by ordinal only, and the two DLLs number a few functions
//! differently (`wsock32`: 10 `inet_addr`, 11 `inet_ntoa`, 12 `ioctlsocket`;
//! `ws2_32`: 10 `ioctlsocket`, 11 `inet_addr`, 12 `inet_ntoa`). So an ordinal
//! is turned into a name by reading the export table of the DLL the module
//! imports from, with a built-in table of the Winsock 1.1 ordinals as the
//! fallback, and slots are matched by name.
//!
//! The hooks go in synchronously: a loader notification
//! (`LdrRegisterDllNotification`) patches the networking module the moment it
//! is mapped, before its own `DllMain` runs, so no `connect` can leave before
//! the hooks. A module that is already loaded is patched at once, and the old
//! polling thread stays as the fallback.
//!
//! Patching is two-phase (fourth review, finding C): DISCOVER reads the
//! module's imports through the bounds-checked [`crate::pe`] reader, finds
//! every slot and checks that each is bound, changing nothing; COMMIT then
//! writes all of them or, if one write fails, puts back every slot it wrote.
//! Whether the hooks that went in are enough for the policy is the
//! protection gate's call ([`crate::gate`]): a hook the policy needs that is
//! missing makes the bootstrap `Fatal`, and the hooks in place then refuse
//! every `connect`, `send` and `recv` they see.
//!
//! Only that patching runs under the loader lock (from the loader stub's
//! `DllMain` and from the notification): no file is opened, nothing is
//! loaded, nothing waits, and its log lines are kept in memory
//! ([`log::defer`]). Everything else - reading `icq-e2e.ini`, logging, the
//! polling fallback, the worker threads - happens on the bootstrap thread,
//! which only starts once the loader lock is released (finding H). Until it
//! has read the settings the gate is `Starting`, and a hooked `connect`,
//! `send` or `recv` waits for it (up to [`BOOT_WAIT`]) and is refused if it
//! does not come: nothing leaves before the add-on knows what to protect.
//!
//! Every `connect` is logged with its target, and the first bytes of each
//! direction of each socket are classified (FLAP, HTTP, `CONNECT`, TLS, other)
//! without changing them, so the log shows which connections the client makes.
//! A socket that carries data although its `connect` was never seen (an
//! accepted peer connection, or one made before the hooks) is logged too.
//!
//! In observe mode (Phase 0) the original is called first with the data
//! unchanged and its result returned verbatim; the bytes are only looked at.
//!
//! In harness mode (Phase 1) the bytes of each direction go through a
//! [`StreamRewriter`] and the client gets what it emits, while seeing Winsock
//! behave exactly as before:
//!
//! - `send` accepts the client's bytes whole and returns their length; the
//!   rewritten bytes are pushed out with the original `send`, waiting for the
//!   socket to become writable on `WSAEWOULDBLOCK`, so nothing is reordered or
//!   dropped. A partial frame is held until the client sends the rest.
//! - `recv` serves bytes held for the client first and reads the socket only
//!   when there are none. With only a partial frame so far it answers
//!   `WSAEWOULDBLOCK`, the normal "nothing yet" of the client's non-blocking
//!   socket; Winsock posts the next `FD_READ` when more arrives. When the
//!   client's buffer is smaller than what is held, the rest stays and a
//!   synthetic `FD_READ` is posted to the window the client gave
//!   `WSAAsyncSelect`, since Winsock will not post one for data it no longer has.
//! - `ioctlsocket(FIONREAD)` counts the bytes held for the client.
//! - The thread's last error after a failed original call is what the client
//!   sees, whatever the add-on did in between.
//!
//! In encrypt mode (the default) the same bytes go through [`crate::session`]
//! as well: the account key is announced in the client's own `SetInfo`, the
//! token is read out of the MOTD, messages are encrypted to the recipient's
//! device, and a container that comes in is decrypted in place. Frames may be
//! added (a note for the user, a control message that keeps the ratchet moving)
//! and removed (a container this device cannot read, and the server's ack for
//! it), so the add-on keeps its own FLAP sequence numbering per direction.
//!
//! With `e2e=off` ([`Mode::Plain`], TLS only) the bytes take the same path
//! with no session and a [`crate::crypto::Disabled`] engine in its place:
//! nothing is encrypted, announced or published, the key directory is never
//! called, and only a `/e2e` command is taken out and answered.
//!
//! With `server=` in `icq-e2e.ini` (STAGE-TLS), a `connect` to the server on
//! one of its plain ports goes to its TLS 1.3 port instead, and TLS runs at the
//! bottom of that socket, under the rewriter: the rewriter and the session see
//! plaintext exactly as before, and the wire carries only TLS. A connection to
//! the server that cannot be secured fails, visibly; it never falls back to
//! plaintext. See `hook_tls.rs`.
//!
//! Each socket has separate locks per direction, so a `recv` waiting on one
//! thread never holds up a `send` on another. The session has its own lock and
//! is taken only for the length of one frame. Every hook body runs under
//! `catch_unwind`. In observe mode a panic falls back to the original call; in
//! every other mode it fails the call and refuses the socket for good
//! ([`fail_closed`]), since the original call would send or hand over bytes
//! the add-on was there to encrypt, decrypt or wrap in TLS.

use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use windows_sys::Win32::Foundation::{GetLastError, SetLastError, HMODULE, HWND};
use windows_sys::Win32::Networking::WinSock::{select, FD_SET, TIMEVAL};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetModuleHandleW};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
use windows_sys::Win32::System::Threading::{CreateThread, GetCurrentProcess, Sleep};
use windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW;

use crate::config::{Mode, Policy};
use crate::gate::{self, Bootstrap, CryptoState, HookMask, Verdict};
use crate::icbm::Direction;
use crate::log;
use crate::pe;
use crate::session::{self, Session};
use crate::stream::StreamRewriter;

#[path = "hook_tls.rs"]
mod tlsio;

#[path = "hook_calls.rs"]
mod calls_io;

#[path = "hook_files.rs"]
mod filesio;

type Socket = usize;

const SOCKET_ERROR: i32 = -1;
const WSAEWOULDBLOCK: u32 = 10035;
const MSG_OOB: i32 = 0x1;
const MSG_PEEK: i32 = 0x2;
const FIONREAD: u32 = 0x4004_667F;
const FD_READ: i32 = 0x01;

/// How much `recv` asks the socket for at least.
const READ_CHUNK: usize = 16 * 1024;
/// How long `send` keeps waiting for a full socket buffer to drain before it
/// keeps the rest for the client's next `send`.
const SEND_WAIT_MS: u32 = 30_000;
/// How long a hooked call made while the add-on is still starting waits for
/// it before it is refused.
#[cfg(not(test))]
const BOOT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const BOOT_WAIT: std::time::Duration = std::time::Duration::from_millis(200);
/// How long the bootstrap waits for the networking module before the add-on
/// is given up as unable to protect anything.
const INSTALL_WAIT_ATTEMPTS: u32 = 600;
/// How long a state file that could not be opened is not tried again.
const RETRY_STATE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

// Original function pointers, kept as raw addresses and transmuted on call.
static ORIG_SEND: AtomicUsize = AtomicUsize::new(0);
static ORIG_RECV: AtomicUsize = AtomicUsize::new(0);
static ORIG_CONNECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_CLOSE: AtomicUsize = AtomicUsize::new(0);
static ORIG_ASYNC_SELECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_IOCTL: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETPEERNAME: AtomicUsize = AtomicUsize::new(0);
static ORIG_ACCEPT: AtomicUsize = AtomicUsize::new(0);

static INSTALLED: AtomicBool = AtomicBool::new(false);

// Log the first observed bytes in each direction once, so the log confirms the
// hooks are live even before any instant message is exchanged.
static FIRST_SEND: AtomicBool = AtomicBool::new(false);
static FIRST_RECV: AtomicBool = AtomicBool::new(false);

/// The policy, set once at start. A pointer to a leaked box rather than a
/// `OnceLock` only so the test host can switch it between runs
/// ([`testing::set_policy`]); a replaced policy is never freed, because a hook
/// on another thread may still be reading it.
static POLICY: AtomicPtr<Policy> = AtomicPtr::new(ptr::null_mut());

fn policy() -> &'static Policy {
    #[cfg(test)]
    if let Some(p) = test_env::policy() {
        return p;
    }
    let p = POLICY.load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: only ever a leaked box, never freed.
        return unsafe { &*p };
    }
    // Not read yet. Before the bootstrap has read it the gate is
    // `Starting` and the hooks ask nothing else; whatever does gets observe
    // without it being fixed, so the real policy still goes in when it is
    // read (it used to be pinned to observe for good here).
    static UNSET: std::sync::LazyLock<Policy> = std::sync::LazyLock::new(Policy::observe);
    &UNSET
}

/// Whether the bootstrap has read the policy.
fn policy_is_set() -> bool {
    #[cfg(test)]
    if test_env::policy().is_some() {
        return true;
    }
    !POLICY.load(Ordering::Acquire).is_null()
}

/// Per-thread stand-ins for the process's settings, so the fault matrix can
/// run many cases in one test process (each on its own thread).
#[cfg(test)]
mod test_env {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static POLICY: RefCell<Option<&'static Policy>> = const { RefCell::new(None) };
        static DIRECTORY: RefCell<Option<Option<Arc<dyn crate::directory::DirectoryApi>>>> =
            const { RefCell::new(None) };
        static UIN: RefCell<Option<Option<String>>> = const { RefCell::new(None) };
    }

    pub(super) fn policy() -> Option<&'static Policy> {
        POLICY.with(|p| *p.borrow())
    }

    pub(super) fn directory() -> Option<Option<Arc<dyn crate::directory::DirectoryApi>>> {
        DIRECTORY.with(|d| d.borrow().clone())
    }

    pub(super) fn uin() -> Option<Option<String>> {
        UIN.with(|u| u.borrow().clone())
    }

    /// This thread's policy, key directory and account.
    pub(super) fn set(
        p: Policy,
        dir: Option<Arc<dyn crate::directory::DirectoryApi>>,
        uin: Option<&str>,
    ) {
        POLICY.with(|t| *t.borrow_mut() = Some(Box::leak(Box::new(p))));
        DIRECTORY.with(|t| *t.borrow_mut() = Some(dir));
        UIN.with(|t| *t.borrow_mut() = Some(uin.map(str::to_string)));
    }

    pub(super) fn clear() {
        POLICY.with(|t| *t.borrow_mut() = None);
        DIRECTORY.with(|t| *t.borrow_mut() = None);
        UIN.with(|t| *t.borrow_mut() = None);
    }
}

/// Sets the policy unless one is set already; whether this call set it.
fn set_policy_once(p: Policy) -> bool {
    let b = Box::into_raw(Box::new(p));
    match POLICY.compare_exchange(ptr::null_mut(), b, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => true,
        Err(_) => {
            // SAFETY: never shared; this call made it.
            drop(unsafe { Box::from_raw(b) });
            false
        }
    }
}

/// The engine of `e2e=off` ([`Mode::Plain`]): it encrypts nothing and only
/// answers `/e2e` commands. One for the process; it holds nothing but notes.
fn disabled() -> &'static Mutex<crate::crypto::Disabled> {
    static D: std::sync::LazyLock<Mutex<crate::crypto::Disabled>> =
        std::sync::LazyLock::new(Default::default);
    &D
}

/// The engine of encrypt mode while the account has no session
/// ([`gate::Withheld`]): every message is held with a note, never sent in
/// clear. One for the process; it holds the reason and the notes.
fn withheld() -> &'static Mutex<gate::Withheld> {
    static W: std::sync::LazyLock<Mutex<gate::Withheld>> =
        std::sync::LazyLock::new(Default::default);
    &W
}

/// Feeds bytes through a direction that has no session, as the gate says
/// (fourth review, finding A): in encrypt mode the [`gate::Withheld`] engine,
/// which holds every message and shows no container - never the plain
/// rewriter, which would send the message as typed; with `e2e=off` the path
/// that only takes out `/e2e` commands; the harness transform in harness
/// mode. `why` is the crypto state's reason, for the notes. Nothing reads
/// what these paths find about contacts or the account key, so it is dropped
/// here rather than piling up.
fn push_without_session(
    rw: &mut StreamRewriter,
    bytes: &[u8],
    out: &mut Vec<u8>,
    why: Option<String>,
) -> Vec<String> {
    let p = policy();
    let now = crate::crypto::unix_now();
    let lines = match p.mode {
        Mode::Plain => rw.push_crypto(bytes, &mut *lock(disabled()), now, p, out),
        Mode::Encrypt => {
            let mut w = lock(withheld());
            w.set_reason(why.unwrap_or_else(|| {
                "end-to-end encryption is not available in this ICQ".to_string()
            }));
            rw.push_crypto(bytes, &mut *w, now, p, out)
        }
        Mode::Harness | Mode::Observe => return rw.push(bytes, p, out),
    };
    let _ = (rw.take_contacts(), rw.take_departed(), rw.take_announce());
    lines
}

// --- per-socket state -------------------------------------------------------

/// Outbound: the rewriter and bytes it emitted that are not on the wire yet.
struct OutSide {
    rw: StreamRewriter,
    pending: Vec<u8>,
}

/// Inbound: the rewriter, bytes ready for the client, and whether the socket
/// reported the end of the stream.
struct InSide {
    rw: StreamRewriter,
    ready: Vec<u8>,
    eof: bool,
}

/// What the client asked `WSAAsyncSelect` to post.
#[derive(Clone, Copy)]
struct Notify {
    hwnd: usize,
    msg: u32,
    events: i32,
}

struct Sock {
    peer: Mutex<Option<String>>,
    notify: Mutex<Option<Notify>>,
    out: Mutex<OutSide>,
    inb: Mutex<InSide>,
    /// This connection's cryptography: the account's session, shared with
    /// every other connection of the same account.
    ///
    /// Behind its own lock because the two directions are locked separately and
    /// must not hold each other up; it is taken only for the length of one
    /// frame.
    session: Mutex<Option<Arc<Mutex<Session>>>>,
    /// Whether the add-on has already said it has no UIN to work with, so that
    /// is said once rather than on every frame.
    waited_for_uin: AtomicBool,
    /// Whether this connection has carried an instant message: the one the
    /// chats live on, where a note may be put.
    messages: AtomicBool,
    /// A token that arrived before there was a session to give it to.
    ///
    /// The MOTD with the token comes before the user info that names the
    /// account, and the session cannot be opened without the account, so the
    /// token waits here and is applied the moment one is there. Dropping it
    /// instead would leave the add-on permanently without a key directory.
    pending_token: Mutex<Option<Vec<u8>>>,
    /// Whether the client's `connect` for this socket went through the hook.
    connect_seen: AtomicBool,
    /// Whether the socket's traffic was already reported as "no connect seen".
    orphan_noted: AtomicBool,
    /// Whether the first outbound / inbound bytes were already classified.
    classified_out: AtomicBool,
    classified_in: AtomicBool,
    /// TLS to the server, when the `connect` was mapped to its TLS port.
    tls: OnceLock<Arc<tlsio::TlsConn>>,
    /// Refused for good (fail closed): a connection to the server the hooks
    /// never saw opened, or one through a proxy.
    blocked: AtomicBool,
    /// Whether a socket without a seen `connect` was checked for that.
    unseen_checked: AtomicBool,
    /// How far the check for a proxy request in the first bytes has got.
    proxy_state: AtomicU8,
    /// Whether `tls=off` was already said on this connection.
    tls_off_said: AtomicBool,
    /// The pipe of a file transfer both add-ons agreed to encrypt (or we
    /// offered and wait for), at the bottom of the socket (`hook_files.rs`).
    file: OnceLock<Arc<filesio::FileConn>>,
    /// Whether the first outbound / inbound bytes were looked at for a file
    /// transfer.
    file_checked: AtomicBool,
    file_in_checked: AtomicBool,
    /// `files_log=on`: what the socket's transfer does, and whether the
    /// socket was found not to be one.
    file_watch: Mutex<Option<crate::files::Watch>>,
    file_watch_off: AtomicBool,
    /// Accepted from a listening socket (a peer connected to us).
    accepted: AtomicBool,
    /// Whether the gate's refusal of this socket was logged.
    gate_noted: AtomicBool,
    /// A guard port mapped to the server's plain port (`tls=off`): the port
    /// the connection really goes to, and the one the client asked for.
    remapped: OnceLock<(u16, u16)>,
}

impl Sock {
    fn new() -> Self {
        // One pair, so the two directions share the server's answers they look
        // after: an ack hidden or owed on one side is acted on by the other.
        let (out, inb) = StreamRewriter::pair();
        Sock {
            peer: Mutex::new(None),
            notify: Mutex::new(None),
            out: Mutex::new(OutSide {
                rw: out,
                pending: Vec::new(),
            }),
            inb: Mutex::new(InSide {
                rw: inb,
                ready: Vec::new(),
                eof: false,
            }),
            session: Mutex::new(None),
            waited_for_uin: AtomicBool::new(false),
            messages: AtomicBool::new(false),
            pending_token: Mutex::new(None),
            connect_seen: AtomicBool::new(false),
            orphan_noted: AtomicBool::new(false),
            classified_out: AtomicBool::new(false),
            classified_in: AtomicBool::new(false),
            tls: OnceLock::new(),
            blocked: AtomicBool::new(false),
            unseen_checked: AtomicBool::new(false),
            proxy_state: AtomicU8::new(tlsio::PROXY_UNSEEN),
            tls_off_said: AtomicBool::new(false),
            file: OnceLock::new(),
            file_checked: AtomicBool::new(false),
            file_in_checked: AtomicBool::new(false),
            file_watch: Mutex::new(None),
            file_watch_off: AtomicBool::new(false),
            accepted: AtomicBool::new(false),
            gate_noted: AtomicBool::new(false),
            remapped: OnceLock::new(),
        }
    }
}

/// The key directory, built once and shared by every session.
///
/// `None` when the policy names no directory: encrypt mode without one has
/// nothing to publish to and no token will ever arrive, so the add-on stays
/// passive and says so rather than pretending to be encrypted.
fn directory() -> Option<Arc<dyn crate::directory::DirectoryApi>> {
    #[cfg(test)]
    if let Some(d) = test_env::directory() {
        return d;
    }
    if let Some(d) = lock(test_directory()).clone() {
        return Some(d);
    }
    static D: OnceLock<Option<Arc<dyn crate::directory::DirectoryApi>>> = OnceLock::new();
    D.get_or_init(|| {
        if policy().mode != Mode::Encrypt {
            return None;
        }
        session::linked(policy()).map(|d| Arc::new(d) as Arc<dyn crate::directory::DirectoryApi>)
    })
    .clone()
}

/// A directory to use instead of the configured one, set by the tests.
#[cfg_attr(not(test), allow(dead_code))]
fn test_directory() -> &'static Mutex<Option<Arc<dyn crate::directory::DirectoryApi>>> {
    static T: std::sync::LazyLock<Mutex<Option<Arc<dyn crate::directory::DirectoryApi>>>> =
        std::sync::LazyLock::new(|| Mutex::new(None));
    &T
}

/// Where the UIN an outgoing sign-on named is kept.
fn signed_on_slot() -> &'static Mutex<Option<String>> {
    static SEEN: std::sync::LazyLock<Mutex<Option<String>>> =
        std::sync::LazyLock::new(|| Mutex::new(None));
    &SEEN
}

/// The account this process is signed on as.
///
/// Two sources, in order: the `-uin <number>` the ICQ clients take on their
/// command line, and the screen name of the sign-on that goes out over the
/// connection. The second matters because a client started from a shortcut
/// carries no `-uin`, and there was nothing to fall back on: the account stayed
/// unknown for the whole sign-on, no session was opened, and the MOTD's token
/// had nobody to give it to.
///
/// The command line is read once because it cannot change. A sign-on can, so
/// the answer is remembered as soon as one is seen and never guessed: a device
/// with a wrong identity would publish a key nobody can tie to this connection.
fn signed_on_uin() -> Option<String> {
    #[cfg(test)]
    if let Some(u) = test_env::uin() {
        return u;
    }
    static CMDLINE: OnceLock<Option<String>> = OnceLock::new();
    CMDLINE
        .get_or_init(uin_from_command_line)
        .clone()
        .or_else(|| lock(signed_on_slot()).clone())
}

/// Remembers the UIN an outgoing sign-on named.
fn remember_signed_on_uin(uin: String) {
    let mut slot = lock(signed_on_slot());
    if slot.is_none() {
        log::line(&format!("[ICQ E2E] signed on as {uin}"));
        *slot = Some(uin);
    }
}

/// The one session per account, shared by every connection that account has.
///
/// An ICQ client opens several: the BOS connection, which carries the token
/// and announces the account key, and one per service. A session on each
/// socket meant a service connection's MOTD - which has no token, because the
/// server sends one only on the BOS connection - reset the engine to "no
/// token yet, encryption off", and messages left in clear while the account
/// sat right there already published. The account is what holds keys, the
/// token and what has been published, so the session belongs to the account.
fn sessions_by_account() -> &'static Mutex<HashMap<String, Arc<Mutex<Session>>>> {
    static S: std::sync::LazyLock<Mutex<HashMap<String, Arc<Mutex<Session>>>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
    &S
}

/// Sessions whose account turned out locked out (another process holds the
/// state file), by the session's address.
fn locked_sessions() -> &'static Mutex<std::collections::HashSet<usize>> {
    static L: std::sync::LazyLock<Mutex<std::collections::HashSet<usize>>> =
        std::sync::LazyLock::new(Default::default);
    &L
}

/// Accounts whose state file could not be opened, with why and when; tried
/// again after [`RETRY_STATE_AFTER`].
fn failed_accounts() -> &'static Mutex<HashMap<String, (String, std::time::Instant)>> {
    static F: std::sync::LazyLock<Mutex<HashMap<String, (String, std::time::Instant)>>> =
        std::sync::LazyLock::new(Default::default);
    &F
}

/// The session for `uin`, opening it the first time it is asked for; why
/// there is none otherwise. A failure is said once and not retried for a
/// minute, so a state file that cannot be read is not read on every frame.
fn account_session(
    dir: Arc<dyn crate::directory::DirectoryApi>,
    uin: &str,
) -> Result<Arc<Mutex<Session>>, String> {
    if let Some((why, at)) = lock(failed_accounts()).get(uin) {
        if at.elapsed() < RETRY_STATE_AFTER {
            return Err(why.clone());
        }
    }
    let mut sessions = lock(sessions_by_account());
    if let Some(s) = sessions.get(uin) {
        return Ok(s.clone());
    }
    match Session::open(dir, &policy().home, uin) {
        Ok(mut sess) => {
            sess.engine().set_calls_encrypt(policy().encrypts_calls());
            sess.engine()
                .set_calls_required(policy().encrypts_calls() && policy().calls_required);
            sess.engine().set_files_encrypt(policy().encrypts_files());
            sess.engine()
                .set_files_required(policy().encrypts_files() && policy().files_required);
            sess.engine().set_auditors(policy().auditors.clone());
            let locked = sess.locked_out().is_some();
            match sess.locked_out() {
                Some(why) => log::line(&format!(
                    "[ICQ E2E] encryption held for {uin}: {why}; its state file is \
                     locked by the other one, so messages are held, not sent in clear"
                )),
                None => log::line(&format!(
                    "[ICQ E2E] device keys ready for {uin} (encrypt mode)"
                )),
            }
            let s = Arc::new(Mutex::new(sess));
            if locked {
                lock(locked_sessions()).insert(Arc::as_ptr(&s) as usize);
            }
            sessions.insert(uin.to_string(), s.clone());
            lock(failed_accounts()).remove(uin);
            Ok(s)
        }
        Err(why) => {
            let why = format!("the encryption keys of {uin} cannot be used ({why})");
            let mut failed = lock(failed_accounts());
            if !failed.contains_key(uin) {
                log::line(&format!(
                    "[ICQ E2E] {why}; messages are held with a note, never sent in clear"
                ));
            }
            failed.insert(uin.to_string(), (why.clone(), std::time::Instant::now()));
            Err(why)
        }
    }
}

/// Applies a token that arrived before there was a session to give it to.
///
/// The token is only taken out of the socket once there is somewhere to put
/// it. Taking it first and giving up because there was no session yet threw it
/// away for good: the account is learned from the server's own user info,
/// which arrives after the MOTD, so the only order in which a token and an
/// account ever meet is token first - and that is the order that lost it.
fn drain_pending_token(sock: &Sock) -> Vec<String> {
    let session = lock(&sock.session).clone();
    let Some(sess) = session else {
        return Vec::new();
    };
    let Some(raw) = lock(&sock.pending_token).take() else {
        return Vec::new();
    };
    log::line("[ICQ E2E] applying the MOTD token that arrived first");
    let lines = lock(&sess).on_token(&raw, crate::crypto::unix_now());
    lines
}

/// The `-uin` argument of the current process's command line, if it has one.
///
/// `GetCommandLineW` is UTF-16; it was read as a C string of bytes, which
/// stopped at the first zero byte - after the first character - so `-uin`
/// was never found (fourth review, finding F). It is now read as UTF-16 and
/// split as `CommandLineToArgvW` does.
fn uin_from_command_line() -> Option<String> {
    // SAFETY: GetCommandLineW returns a NUL-terminated string that is valid
    // for the life of the process; it is read up to its NUL, at most 32767
    // units (the limit of a command line).
    let units = unsafe {
        let wide = windows_sys::Win32::System::Environment::GetCommandLineW();
        if wide.is_null() {
            return None;
        }
        let mut n = 0usize;
        while n < 32_767 && *wide.add(n) != 0 {
            n += 1;
        }
        std::slice::from_raw_parts(wide, n)
    };
    uin_from_args(&split_command_line(&String::from_utf16_lossy(units)))
}

/// A command line split into arguments by the rules of
/// `CommandLineToArgvW`: white space separates, double quotes group,
/// `2n` backslashes before a quote are `n` backslashes and the quote still
/// groups, `2n+1` are `n` and a literal quote; other backslashes are kept.
fn split_command_line(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_arg = false;
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut n = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    n += 1;
                }
                if chars.peek() == Some(&'"') {
                    cur.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        chars.next();
                        cur.push('"');
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', n));
                }
                in_arg = true;
            }
            '"' => {
                if quoted && chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                } else {
                    quoted = !quoted;
                }
                in_arg = true;
            }
            c if c.is_whitespace() && !quoted => {
                if in_arg {
                    args.push(std::mem::take(&mut cur));
                    in_arg = false;
                }
            }
            c => {
                cur.push(c);
                in_arg = true;
            }
        }
    }
    if in_arg {
        args.push(cur);
    }
    args
}

/// The UIN after `-uin` or `/uin`; a UIN is decimal, anything else is none.
fn uin_from_args(args: &[String]) -> Option<String> {
    let at = args
        .iter()
        .position(|a| a.eq_ignore_ascii_case("-uin") || a.eq_ignore_ascii_case("/uin"))?;
    let v = args.get(at + 1)?;
    v.parse::<u64>().ok().map(|n| n.to_string())
}

fn sockets() -> &'static Mutex<HashMap<Socket, Arc<Sock>>> {
    static S: OnceLock<Mutex<HashMap<Socket, Arc<Sock>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Locks a mutex even if a panic poisoned it; the state stays usable.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn sock_for(s: Socket) -> Arc<Sock> {
    lock(sockets())
        .entry(s)
        .or_insert_with(|| Arc::new(Sock::new()))
        .clone()
}

fn existing_sock(s: Socket) -> Option<Arc<Sock>> {
    lock(sockets()).get(&s).cloned()
}

/// A session as the gate sees it: locked out, or ready.
fn state_of(s: Arc<Mutex<Session>>) -> CryptoState<Arc<Mutex<Session>>> {
    if lock(locked_sessions()).contains(&(Arc::as_ptr(&s) as usize)) {
        CryptoState::LockedOut(s)
    } else {
        CryptoState::Ready(s)
    }
}

/// This socket's crypto state, pointing it at the account's session the
/// first time there is one (fourth review, finding A).
///
/// Every way of not having a session is a state with a reason, never a
/// silent "no session" that the bytes pass through as typed: no key
/// directory, an account not known yet, a state file that cannot be read.
/// The gate then holds the messages ([`push_without_session`]).
fn ensure_session(sock: &Sock) -> CryptoState<Arc<Mutex<Session>>> {
    if let Some(s) = lock(&sock.session).clone() {
        return state_of(s);
    }
    if policy().mode != Mode::Encrypt {
        return CryptoState::Unavailable("end-to-end encryption is off".to_string());
    }
    let Some(dir) = directory() else {
        return CryptoState::Unavailable(
            "no key directory is configured for it (no directory= in icq-e2e.ini)".to_string(),
        );
    };
    let Some(uin) = signed_on_uin() else {
        // Nothing known yet. The server's own user info (`0x0001/0x000F`) says
        // which account this is, and it has not arrived; saying so once beats
        // a silent no-op that looks like the add-on is not running.
        if !sock.waited_for_uin.swap(true, Ordering::AcqRel) {
            log::line(
                "[ICQ E2E] no UIN yet: no -uin on the command line and no \
                 user info (0x0001/0x000F) seen yet; messages wait for it",
            );
        }
        return CryptoState::WaitingForIdentity;
    };
    let sess = match account_session(dir, &uin) {
        Ok(s) => s,
        Err(why) => return CryptoState::Unavailable(why),
    };
    *lock(&sock.session) = Some(sess.clone());
    // A MOTD token that arrived before the account was known goes in now.
    for line in drain_pending_token(sock) {
        log::line(&line);
    }
    state_of(sess)
}

fn log_lines(sock: &Sock, lines: Vec<String>) {
    if lines.is_empty() {
        return;
    }
    let via = lock(&sock.peer).clone();
    for mut line in lines {
        if let Some(p) = &via {
            line.push_str(&format!(" via={p}"));
        }
        log::line(&line);
    }
}

fn first_bytes_note(dir: Direction, s: Socket, n: usize) {
    let first = match dir {
        Direction::Outbound => &FIRST_SEND,
        Direction::Inbound => &FIRST_RECV,
    };
    if !first.swap(true, Ordering::AcqRel) {
        log::line(&format!(
            "hook live: first {} bytes on socket {} (n={})",
            match dir {
                Direction::Outbound => "outbound",
                Direction::Inbound => "inbound",
            },
            s,
            n
        ));
    }
}

/// What the first bytes of one direction of a connection look like, for the
/// log. Never the content itself: an HTTP request is named by its verb and path
/// without the query string, anything else by its first byte.
fn classify_first_bytes(data: &[u8]) -> String {
    if data.is_empty() {
        return "empty".to_string();
    }
    if data[0] == 0x2A {
        let channel = data.get(1).copied().unwrap_or(0);
        return format!("FLAP (channel {channel})");
    }
    if data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 {
        return format!("TLS handshake (record version 3.{})", data[2]);
    }
    if data.starts_with(b"HTTP/") {
        let line = first_line(data, 16);
        return format!("HTTP response \"{line}\"");
    }
    if data.starts_with(b"CONNECT ") {
        return "HTTP proxy CONNECT".to_string();
    }
    for verb in ["GET ", "POST ", "HEAD ", "PUT ", "OPTIONS "] {
        if data.starts_with(verb.as_bytes()) {
            let line = first_line(data, 80);
            let path = line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .split('?')
                .next()
                .unwrap_or("");
            return format!("HTTP {} {path}", verb.trim_end());
        }
    }
    if data[0] == 0x04 || data[0] == 0x05 {
        return format!("SOCKS{}?", data[0]);
    }
    format!("other (first byte {:#04x}, {} bytes)", data[0], data.len())
}

/// The first line of `data`, at most `max` characters, printable ASCII only.
fn first_line(data: &[u8], max: usize) -> String {
    data.iter()
        .take_while(|&&b| b != b'\r' && b != b'\n')
        .take(max)
        .map(|&b| {
            if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// The address the socket is connected to, asked of Winsock itself (for a
/// socket whose `connect` the hook never saw).
fn peer_of(s: Socket) -> Option<String> {
    // SAFETY: getpeername on a socket handle with a stack buffer of the size
    // passed; a bad handle only makes it fail.
    unsafe {
        let mut sa = [0u8; 32];
        let mut len = sa.len() as i32;
        let r = windows_sys::Win32::Networking::WinSock::getpeername(
            s,
            sa.as_mut_ptr().cast(),
            &mut len,
        );
        if r != 0 {
            return None;
        }
        parse_sockaddr(sa.as_ptr(), len)
    }
}

/// Logs, once per socket and direction, what the first bytes look like, and
/// once per socket when it carries data although its `connect` was never seen.
/// Nothing is changed. Keeps the thread's last error.
fn note_traffic(s: Socket, data: &[u8], dir: Direction) {
    // SAFETY: reads and restores the calling thread's last error.
    let err = unsafe { GetLastError() };
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let sock = sock_for(s);
        filesio::watch(s, &sock, dir, data);
        let flag = match dir {
            Direction::Outbound => &sock.classified_out,
            Direction::Inbound => &sock.classified_in,
        };
        if flag.swap(true, Ordering::AcqRel) {
            return;
        }
        let seen = sock.connect_seen.load(Ordering::Acquire);
        let peer = lock(&sock.peer).clone().or_else(|| peer_of(s));
        let peer = peer.unwrap_or_else(|| "?".to_string());
        if !seen && !sock.orphan_noted.swap(true, Ordering::AcqRel) {
            log::line(&format!(
                "socket {s} ({peer}): data without a connect the hooks saw \
                 (an accepted peer connection, or one opened before the hooks)"
            ));
        }
        log::line(&format!(
            "socket {s} ({peer}): first {} bytes: {}",
            match dir {
                Direction::Outbound => "outbound",
                Direction::Inbound => "inbound",
            },
            classify_first_bytes(data)
        ));
    }));
    // SAFETY: restores the calling thread's last error.
    unsafe { SetLastError(err) };
}

// --- Winsock function types (all __stdcall on x86) --------------------------

type SendFn = unsafe extern "system" fn(Socket, *const u8, i32, i32) -> i32;
type RecvFn = unsafe extern "system" fn(Socket, *mut u8, i32, i32) -> i32;
type ConnectFn = unsafe extern "system" fn(Socket, *const u8, i32) -> i32;
type CloseFn = unsafe extern "system" fn(Socket) -> i32;
type AsyncSelectFn = unsafe extern "system" fn(Socket, usize, u32, i32) -> i32;
type IoctlFn = unsafe extern "system" fn(Socket, i32, *mut u32) -> i32;
type PeerNameFn = unsafe extern "system" fn(Socket, *mut u8, *mut i32) -> i32;
type AcceptFn = unsafe extern "system" fn(Socket, *mut u8, *mut i32) -> Socket;

unsafe fn orig_send() -> SendFn {
    std::mem::transmute(ORIG_SEND.load(Ordering::Acquire))
}

unsafe fn orig_recv() -> RecvFn {
    std::mem::transmute(ORIG_RECV.load(Ordering::Acquire))
}

// --- hook bodies ------------------------------------------------------------

/// Whether the protection gate lets traffic through the hooked sockets now
/// (fourth review, findings D and H): `Err` with the reason when it does
/// not. While the add-on is still starting the call waits for it, up to
/// [`BOOT_WAIT`], so a `connect` made in the first moments is held rather
/// than let out before the add-on knows what to protect - and refused if
/// the bootstrap does not come.
fn admitted() -> Result<(), String> {
    let g = gate::current();
    let mut boot = g.bootstrap();
    if boot == Bootstrap::Starting {
        boot = g.wait(BOOT_WAIT);
    }
    match gate::admit(policy(), &boot) {
        Verdict::Block(why) => Err(why),
        _ => Ok(()),
    }
}

/// Logs, once per socket, that the gate refused it.
fn refused_by_gate(s: Socket, what: &str, why: &str) {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let sock = sock_for(s);
        if !sock.gate_noted.swap(true, Ordering::AcqRel) {
            log::line(&format!(
                "socket {s}: {what} refused (fail closed): the add-on cannot protect this ICQ: {why}"
            ));
        }
    }));
}

/// What comes before everything else in `send` and `recv`: a socket refused
/// for good (fail closed), and the cases a TLS socket answers itself (`MSG_OOB`,
/// empty buffers). `None` lets the call go on.
unsafe fn tls_gate(s: Socket, buf: *const u8, len: i32, flags: i32, outbound: bool) -> Option<i32> {
    if let Err(why) = admitted() {
        refused_by_gate(s, if outbound { "send" } else { "recv" }, &why);
        SetLastError(tlsio::WSAECONNRESET);
        return Some(SOCKET_ERROR);
    }
    let r = panic::catch_unwind(AssertUnwindSafe(|| {
        let sock = sock_for(s);
        let data = (outbound && len > 0 && !buf.is_null())
            .then(|| std::slice::from_raw_parts(buf, len as usize));
        if tlsio::blocked(s, &sock, data) {
            return Some((SOCKET_ERROR, tlsio::WSAECONNRESET));
        }
        // A file transfer's encrypted connection closed for failing (fail
        // closed), and what it answers itself.
        if let Some(fc) = sock.file.get() {
            if filesio::refused(fc) {
                return Some((SOCKET_ERROR, tlsio::WSAECONNRESET));
            }
            if flags & MSG_OOB != 0 {
                return Some((SOCKET_ERROR, tlsio::WSAEOPNOTSUPP));
            }
            if len <= 0 || buf.is_null() {
                return Some((0, 0));
            }
        }
        if sock.tls.get().is_some() {
            if flags & MSG_OOB != 0 {
                return Some((SOCKET_ERROR, tlsio::WSAEOPNOTSUPP));
            }
            if len <= 0 || buf.is_null() {
                return Some((0, 0));
            }
        }
        None
    }));
    match r {
        Ok(Some((v, err))) => {
            if v < 0 {
                SetLastError(err);
            }
            Some(v)
        }
        Ok(None) => None,
        // A panic here may have skipped the check that refuses this socket:
        // only observe mode, which never has TLS, lets the call go on.
        Err(_) if policy().mode == Mode::Observe => None,
        Err(_) => Some(fail_closed(s, "socket check")),
    }
}

/// After a panic in a hook that may rewrite, encrypt or wrap the bytes in TLS
/// (every mode but observe): the client's own buffer must never go out as it
/// is, and bytes read from the socket must never reach the client as they
/// came - either would be plaintext, or ciphertext the client cannot use, past
/// every check. The call fails with `WSAECONNRESET`, the socket is refused for
/// good (every later call on it fails the same way, see `tlsio::blocked`), and
/// the user is told why. The client reconnects on a fresh socket.
fn fail_closed(s: Socket, what: &str) -> i32 {
    close_for_good(
        s,
        &format!("the add-on's {what} hook failed"),
        format!(
            "[ICQ E2E] The connection was closed: the add-on hit an internal error in its {what} hook, and nothing is sent or shown unprotected because of it. The client reconnects on its own."
        ),
    )
}

/// A FLAP stream that lost its framing after it was recognised (fourth
/// review, finding B): what follows is not let through raw, the connection
/// is reset.
fn reset_broken_stream(s: Socket) -> i32 {
    close_for_good(
        s,
        "its FLAP framing broke after it was recognised",
        "[ICQ E2E] The connection was closed: its data stopped making sense to the add-on, and nothing more of it is sent or shown unchecked. The client reconnects on its own.".to_string(),
    )
}

/// Refuses socket `s` for good: this call and every later one fail with
/// `WSAECONNRESET` (`tlsio::blocked` checks the flag first), the log says
/// why once, and `note` goes into the chat.
fn close_for_good(s: Socket, why: &str, note: String) -> i32 {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let sock = sock_for(s);
        if sock.blocked.swap(true, Ordering::AcqRel) {
            return;
        }
        log::line(&format!(
            "socket {s}: reset (fail closed): {why}; nothing of this connection goes past it unprotected"
        ));
        let session = lock(&sock.session).clone();
        match session {
            Some(sess) => {
                if let Ok(mut g) = sess.try_lock() {
                    g.engine().say(note);
                }
            }
            None if policy().mode == Mode::Plain => {
                if let Ok(mut d) = disabled().try_lock() {
                    d.say(note);
                }
            }
            None if policy().mode == Mode::Encrypt => {
                if let Ok(mut w) = withheld().try_lock() {
                    w.say(note);
                }
            }
            None => {}
        };
    }));
    // SAFETY: sets the calling thread's last error.
    unsafe { SetLastError(tlsio::WSAECONNRESET) };
    SOCKET_ERROR
}

/// Sockets whose next `send` or `recv` body panics, for the tests of
/// [`fail_closed`].
#[cfg(test)]
fn panic_sockets() -> &'static Mutex<std::collections::HashSet<Socket>> {
    static P: std::sync::LazyLock<Mutex<std::collections::HashSet<Socket>>> =
        std::sync::LazyLock::new(Default::default);
    &P
}

#[cfg(test)]
fn maybe_panic(s: Socket) {
    if lock(panic_sockets()).remove(&s) {
        panic!("a panic injected by the test");
    }
}

unsafe extern "system" fn hook_send(s: Socket, buf: *const u8, len: i32, flags: i32) -> i32 {
    if let Some(r) = tls_gate(s, buf, len, flags, true) {
        return r;
    }
    if len > 0 && !buf.is_null() && flags & MSG_OOB == 0 {
        note_traffic(
            s,
            std::slice::from_raw_parts(buf, len as usize),
            Direction::Outbound,
        );
    }
    if policy().mode == Mode::Observe || len <= 0 || buf.is_null() || flags & MSG_OOB != 0 {
        let n = orig_send()(s, buf, len, flags);
        if n > 0 && !buf.is_null() && flags & MSG_OOB == 0 {
            let data = std::slice::from_raw_parts(buf, n as usize);
            let _ = panic::catch_unwind(AssertUnwindSafe(|| observe(s, data, Direction::Outbound)));
        }
        return n;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    match panic::catch_unwind(AssertUnwindSafe(|| harness_send(s, data, flags))) {
        Ok(n) => n,
        // Never the client's own buffer: it is the plaintext the rewriter
        // was there to encrypt, and on a TLS socket it would skip the TLS.
        Err(_) => fail_closed(s, "send"),
    }
}

unsafe extern "system" fn hook_recv(s: Socket, buf: *mut u8, len: i32, flags: i32) -> i32 {
    if let Some(r) = tls_gate(s, buf, len, flags, false) {
        return r;
    }
    if policy().mode == Mode::Observe || len <= 0 || buf.is_null() || flags & MSG_OOB != 0 {
        let n = orig_recv()(s, buf, len, flags);
        if n > 0 && !buf.is_null() && flags & (MSG_OOB | MSG_PEEK) == 0 {
            let err = GetLastError();
            let data = std::slice::from_raw_parts(buf, n as usize);
            note_traffic(s, data, Direction::Inbound);
            let _ = panic::catch_unwind(AssertUnwindSafe(|| observe(s, data, Direction::Inbound)));
            SetLastError(err);
        }
        return n;
    }
    let n = match panic::catch_unwind(AssertUnwindSafe(|| {
        harness_recv(s, buf, len as usize, flags)
    })) {
        Ok(n) => n,
        // Never the socket's own bytes: undecrypted containers, or TLS
        // records the client cannot read.
        Err(_) => fail_closed(s, "recv"),
    };
    if n > 0 && flags & MSG_PEEK == 0 {
        note_traffic(
            s,
            std::slice::from_raw_parts(buf, n as usize),
            Direction::Inbound,
        );
    }
    n
}

unsafe extern "system" fn hook_connect(s: Socket, name: *const u8, namelen: i32) -> i32 {
    let orig: ConnectFn = std::mem::transmute(ORIG_CONNECT.load(Ordering::Acquire));
    // Before anything is decided: whether the add-on is in place at all.
    if let Err(why) = admitted() {
        refused_by_gate(s, "connect", &why);
        SetLastError(tlsio::WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    // A panic while deciding must not let a connection out unmapped in a
    // policy that protects anything: it is refused (the gate's rule, not a
    // fallback of this hook's own).
    let plan = panic::catch_unwind(AssertUnwindSafe(|| tlsio::plan_connect(s, name, namelen)))
        .unwrap_or_else(|_| {
            if gate::protecting(policy()) {
                tlsio::ConnectPlan::Refuse(tlsio::WSAECONNREFUSED)
            } else {
                tlsio::ConnectPlan::Plain
            }
        });
    // A handle carries one connection. An entry left from an earlier one
    // (closed past the hooks) must not lend this one its state.
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut map = lock(sockets());
        if let Some(old) = map.get(&s) {
            if old.connect_seen.load(Ordering::Acquire)
                || old.tls.get().is_some()
                || old.file.get().is_some()
            {
                map.insert(s, Arc::new(Sock::new()));
            }
        }
    }));
    let (r, err) = match &plan {
        tlsio::ConnectPlan::Refuse(e) => {
            let _ = panic::catch_unwind(AssertUnwindSafe(|| {
                sock_for(s).connect_seen.store(true, Ordering::Release);
            }));
            SetLastError(*e);
            return SOCKET_ERROR;
        }
        tlsio::ConnectPlan::Tls { conn, addr } => {
            let _ = panic::catch_unwind(AssertUnwindSafe(|| {
                let _ = sock_for(s).tls.set(conn.clone());
            }));
            let r = orig(s, addr.as_ptr(), addr.len() as i32);
            (r, GetLastError())
        }
        tlsio::ConnectPlan::Remap { addr, original } => {
            let _ = panic::catch_unwind(AssertUnwindSafe(|| {
                let _ = sock_for(s).remapped.set(*original);
            }));
            let r = orig(s, addr.as_ptr(), addr.len() as i32);
            (r, GetLastError())
        }
        tlsio::ConnectPlan::Plain => {
            let r = orig(s, name, namelen);
            (r, GetLastError())
        }
    };
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let peer = parse_sockaddr(name, namelen);
        let sock = sock_for(s);
        sock.connect_seen.store(true, Ordering::Release);
        log::line(&format!(
            "connect: socket {s} -> {} ({})",
            peer.as_deref().unwrap_or("non-IPv4 address"),
            if r == 0 {
                "connected".to_string()
            } else if err == WSAEWOULDBLOCK {
                "in progress".to_string()
            } else {
                format!("error {err}")
            }
        ));
        {
            let mut p = lock(&sock.peer);
            if p.is_none() {
                *p = peer;
            }
        }
        if let tlsio::ConnectPlan::Tls { conn, .. } = &plan {
            tlsio::connect_started(s, &sock, conn, r, err);
        }
        // A file transfer's connection to an address the peer proposed.
        if let tlsio::ConnectPlan::Plain = &plan {
            filesio::on_connect(s, &sock, name, namelen, r, err);
        }
    }));
    SetLastError(err);
    r
}

unsafe extern "system" fn hook_closesocket(s: Socket) -> i32 {
    let orig: CloseFn = std::mem::transmute(ORIG_CLOSE.load(Ordering::Acquire));
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let sock = lock(sockets()).remove(&s);
        if let Some(conn) = sock.as_ref().and_then(|k| k.tls.get()) {
            tlsio::close(conn, s);
        }
        if let Some(k) = sock.as_ref() {
            if let Some(fc) = k.file.get() {
                filesio::close(fc, s);
            }
            filesio::closed(s, k);
        }
    }));
    orig(s)
}

/// `accept`: a peer connected to a port the client listens on - for these
/// clients, a file transfer's direct or reverse stage. The new socket is
/// looked at for a transfer it belongs to (`hook_files.rs`); the call itself
/// is the original's. Its data is the gate's business on `send` and `recv`.
unsafe extern "system" fn hook_accept(s: Socket, addr: *mut u8, addrlen: *mut i32) -> Socket {
    let orig: AcceptFn = std::mem::transmute(ORIG_ACCEPT.load(Ordering::Acquire));
    let new = orig(s, addr, addrlen);
    if new != usize::MAX {
        let err = GetLastError();
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            // A handle carries one connection: nothing of an earlier one.
            let sock = Arc::new(Sock::new());
            // Seen opened: by the accept, not by a connect.
            sock.connect_seen.store(true, Ordering::Release);
            lock(sockets()).insert(new, sock);
            log::line(&format!("accept: socket {new} from listening socket {s}"));
            filesio::on_accept(s, new);
        }));
        SetLastError(err);
    }
    new
}

unsafe extern "system" fn hook_async_select(s: Socket, hwnd: usize, msg: u32, events: i32) -> i32 {
    let orig: AsyncSelectFn = std::mem::transmute(ORIG_ASYNC_SELECT.load(Ordering::Acquire));
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        *lock(&sock_for(s).notify) = Some(Notify { hwnd, msg, events });
    }));
    orig(s, hwnd, msg, events)
}

/// `getpeername` on a socket mapped to the TLS port, or to a guard port's
/// plain port, reports the port the client asked for, so nothing in the
/// client sees the mapping.
unsafe extern "system" fn hook_getpeername(s: Socket, name: *mut u8, namelen: *mut i32) -> i32 {
    let orig: PeerNameFn = std::mem::transmute(ORIG_GETPEERNAME.load(Ordering::Acquire));
    let r = orig(s, name, namelen);
    if r == 0 && !name.is_null() && !namelen.is_null() && *namelen >= 4 {
        let err = GetLastError();
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            let Some(sock) = existing_sock(s) else {
                return;
            };
            let sa = std::slice::from_raw_parts_mut(name, 4);
            if u16::from_le_bytes([sa[0], sa[1]]) != 2 {
                return;
            }
            let reported = u16::from_be_bytes([sa[2], sa[3]]);
            let port = match (sock.tls.get(), sock.remapped.get()) {
                (Some(conn), _) => tlsio::original_port(conn, reported),
                (None, Some((to, from))) if *to == reported => *from,
                _ => return,
            };
            sa[2..4].copy_from_slice(&port.to_be_bytes());
        }));
        SetLastError(err);
    }
    r
}

unsafe extern "system" fn hook_ioctlsocket(s: Socket, cmd: i32, argp: *mut u32) -> i32 {
    let orig: IoctlFn = std::mem::transmute(ORIG_IOCTL.load(Ordering::Acquire));
    let r = orig(s, cmd, argp);
    // The client asks how many bytes are waiting for it. In harness and encrypt
    // modes there are bytes the socket does not know about: a partial frame in
    // harness mode, and an added note or control message in encrypt mode. Not
    // counting them would leave the client waiting for an FD_READ that Winsock
    // has no reason to post.
    if r == 0 && cmd as u32 == FIONREAD && !argp.is_null() && policy().mode != Mode::Observe {
        let err = GetLastError();
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            if let Some(sock) = existing_sock(s) {
                // try_lock: a recv blocked on another thread must not block this.
                let held = sock
                    .inb
                    .try_lock()
                    .map_or(0, |side| side.ready.len() as u32);
                *argp = match (sock.tls.get(), sock.file.get()) {
                    // The socket holds ciphertext: only plaintext counts.
                    (Some(conn), _) => {
                        held.saturating_add(tlsio::plaintext_waiting(&sock, conn, s))
                    }
                    (None, Some(fc)) => {
                        held.saturating_add(filesio::plaintext_waiting(&sock, fc, s))
                    }
                    (None, None) => (*argp).saturating_add(held),
                };
            }
        }));
        SetLastError(err);
    }
    r
}

/// Observe mode: feeds bytes that already went through to the rewriter, only
/// for the log. `try_lock`, so a re-entrant call is skipped rather than
/// deadlocking.
fn observe(s: Socket, bytes: &[u8], dir: Direction) {
    first_bytes_note(dir, s, bytes.len());
    let sock = sock_for(s);
    let mut discard = Vec::new();
    let lines = match dir {
        Direction::Outbound => match sock.out.try_lock() {
            Ok(mut side) => side.rw.push(bytes, policy(), &mut discard),
            Err(_) => return,
        },
        Direction::Inbound => match sock.inb.try_lock() {
            Ok(mut side) => side.rw.push(bytes, policy(), &mut discard),
            Err(_) => return,
        },
    };
    log_lines(&sock, lines);
}

/// Harness `send`: rewrite, push out, report the client's length as sent.
fn harness_send(s: Socket, data: &[u8], flags: i32) -> i32 {
    #[cfg(test)]
    maybe_panic(s);
    first_bytes_note(Direction::Outbound, s, data.len());
    let sock = sock_for(s);
    let crypto = ensure_session(&sock);
    let mut side = lock(&sock.out);
    if side.rw.is_raw() && side.pending.is_empty() {
        return transport_send(&sock, s, data, flags);
    }
    let OutSide { rw, pending } = &mut *side;
    // The message class goes where the gate says: through the account's
    // session, or held by the engine that stands in without keys.
    let lines = match crypto.session() {
        Some(sess) => session::pump(
            rw,
            Direction::Outbound,
            &mut lock(sess),
            data,
            crate::crypto::unix_now(),
            policy(),
            pending,
        ),
        None => push_without_session(rw, data, pending, crypto.why_not()),
    };
    if let Some(uin) = rw.take_sign_on_uin() {
        remember_signed_on_uin(uin);
    }
    log_lines(&sock, lines);
    if rw.is_broken() {
        // Nothing of this connection goes on: not what was rewritten before
        // the bad header in this call either.
        pending.clear();
        drop(side);
        return reset_broken_stream(s);
    }
    if rw.carries_messages() {
        sock.messages.store(true, Ordering::Release);
    }
    let sent = flush(&sock, s, pending, flags);
    // Released before the notes are delivered, so this thread never holds the
    // outbound side while it reaches for the inbound one.
    drop(side);
    // A note about what was just sent - the answer to a `/e2e` command, a
    // message held back, the status of the chat - goes into the chat now
    // rather than waiting for the server's next frame, which may be minutes
    // away. Before this a note about a message going out unencrypted reached
    // only the log, or the chat of whoever wrote next.
    deliver_notes(&sock, s);
    match sent {
        Ok(()) => data.len() as i32,
        Err(err) => {
            // SAFETY: sets the calling thread's last error.
            unsafe { SetLastError(err) };
            SOCKET_ERROR
        }
    }
}

/// Puts the notes waiting for the chat into this connection's inbound
/// bytes and tells the client there is something to read: the session's,
/// or those of the engine that stands in without one, and the gate's own.
///
/// The inbound side is only tried, never waited for: a `recv` holding it is
/// about to emit the notes itself after the frame it is reading. The lock
/// order is the one `recv` uses - inbound side, then session.
fn deliver_notes(sock: &Sock, s: Socket) {
    // Only the connection the chats are on: the one that got the token or
    // carried a message. A service connection's client would not show it.
    let mode = policy().mode;
    if !matches!(mode, Mode::Plain | Mode::Encrypt) || !sock.messages.load(Ordering::Acquire) {
        return;
    }
    let sess = lock(&sock.session).clone();
    let Ok(mut side) = sock.inb.try_lock() else {
        return;
    };
    let InSide { rw, ready, eof } = &mut *side;
    if *eof {
        return;
    }
    let mut lines = Vec::new();
    let gate_notes = gate::current().take_notes();
    let put = match &sess {
        Some(sess) => {
            let mut g = lock(sess);
            for n in gate_notes {
                g.engine().say(n);
            }
            rw.put_notes(g.engine(), policy(), ready, &mut lines)
        }
        None if mode == Mode::Plain => {
            let mut d = lock(disabled());
            for n in gate_notes {
                d.say(n);
            }
            rw.put_notes(&mut *d, policy(), ready, &mut lines)
        }
        None => {
            let mut w = lock(withheld());
            for n in gate_notes {
                w.say(n);
            }
            rw.put_notes(&mut *w, policy(), ready, &mut lines)
        }
    };
    drop(side);
    log_lines(sock, lines);
    if put {
        post_fd_read(sock, s);
    }
}

/// The client's bytes into a file transfer's pipe, for a socket that has one
/// (or whose first bytes show it should: `hook_files.rs`). `None` for every
/// other socket.
fn file_send(sock: &Sock, s: Socket, data: &[u8]) -> Option<Result<(), u32>> {
    if sock.file.get().is_none() && !sock.file_checked.load(Ordering::Acquire) {
        filesio::on_first_out(s, &sock_for(s), data);
    }
    let fc = sock.file.get()?;
    Some(filesio::send(sock, fc, s, data))
}

/// The client's bytes onto the socket as they are, or into its TLS, or into
/// a file transfer's pipe.
fn transport_send(sock: &Sock, s: Socket, data: &[u8], flags: i32) -> i32 {
    if let Some(r) = file_send(sock, s, data) {
        return match r {
            Ok(()) => data.len() as i32,
            Err(e) => {
                // SAFETY: sets the calling thread's last error.
                unsafe { SetLastError(e) };
                SOCKET_ERROR
            }
        };
    }
    match sock.tls.get() {
        // SAFETY: data is the client's buffer, valid for the call.
        None => unsafe { orig_send()(s, data.as_ptr(), data.len() as i32, flags) },
        Some(conn) => match tlsio::send(sock, conn, s, data) {
            Ok(()) => data.len() as i32,
            Err(e) => {
                // SAFETY: sets the calling thread's last error.
                unsafe { SetLastError(e) };
                SOCKET_ERROR
            }
        },
    }
}

/// Bytes for the client from the socket as they are, or the plaintext of its
/// TLS. Winsock's answer: a count, 0 at the end, or `SOCKET_ERROR` with the
/// thread's last error set.
fn transport_recv(sock: &Sock, s: Socket, buf: *mut u8, len: usize, flags: i32) -> i32 {
    if let Some(fc) = sock.file.get() {
        // SAFETY: the caller's buffer, valid for len bytes.
        let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        return match filesio::recv(sock, fc, s, out, flags & MSG_PEEK != 0) {
            Ok(n) => n as i32,
            Err(e) => {
                // SAFETY: sets the calling thread's last error.
                unsafe { SetLastError(e) };
                SOCKET_ERROR
            }
        };
    }
    match sock.tls.get() {
        None => {
            // SAFETY: the caller's buffer, valid for len bytes.
            let n = unsafe { orig_recv()(s, buf, len as i32, flags) };
            // A key hello on a connection not tied to a transfer: closed,
            // never handed to the client (`hook_files.rs`).
            if n > 0 && flags & MSG_PEEK == 0 && !sock.file_in_checked.swap(true, Ordering::AcqRel)
            {
                // SAFETY: the original wrote n bytes into the caller's buffer.
                let got = unsafe { std::slice::from_raw_parts(buf, n as usize) };
                match filesio::first_in(s, &sock_for(s), got) {
                    filesio::FirstIn::Pass => {}
                    // The hello went into the transfer's pipe: the client
                    // gets what the pipe has for it.
                    filesio::FirstIn::Taken => return transport_recv(sock, s, buf, len, flags),
                    filesio::FirstIn::Refuse => {
                        // SAFETY: sets the calling thread's last error.
                        unsafe { SetLastError(tlsio::WSAECONNRESET) };
                        return SOCKET_ERROR;
                    }
                }
            }
            n
        }
        Some(conn) => {
            // SAFETY: the caller's buffer, valid for len bytes.
            let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
            match tlsio::recv(sock, conn, s, out, flags & MSG_PEEK != 0) {
                Ok(n) => n as i32,
                Err(e) => {
                    // SAFETY: sets the calling thread's last error.
                    unsafe { SetLastError(e) };
                    SOCKET_ERROR
                }
            }
        }
    }
}

/// Sends `pending` out with the original `send`, waiting for room on
/// `WSAEWOULDBLOCK`. What went out is removed. A hard error is returned; a
/// buffer that stays full past [`SEND_WAIT_MS`] leaves the rest pending for the
/// next call. On a TLS socket all of it goes into the TLS, which keeps its own
/// queue of ciphertext.
fn flush(sock: &Sock, s: Socket, pending: &mut Vec<u8>, flags: i32) -> Result<(), u32> {
    if pending.is_empty() {
        return Ok(());
    }
    if let Some(r) = file_send(sock, s, pending) {
        pending.clear();
        return r;
    }
    if let Some(conn) = sock.tls.get() {
        let r = tlsio::send(sock, conn, s, pending);
        pending.clear();
        return r;
    }
    let mut sent = 0usize;
    let mut waited = 0u32;
    let result = loop {
        if sent >= pending.len() {
            break Ok(());
        }
        let chunk = &pending[sent..];
        let len = chunk.len().min(i32::MAX as usize) as i32;
        // SAFETY: chunk is our own live buffer.
        let n = unsafe { orig_send()(s, chunk.as_ptr(), len, flags) };
        if n > 0 {
            sent += n as usize;
            continue;
        }
        // SAFETY: reads the calling thread's last error.
        let err = if n == 0 {
            WSAEWOULDBLOCK
        } else {
            unsafe { GetLastError() }
        };
        if err != WSAEWOULDBLOCK {
            break Err(err);
        }
        if waited >= SEND_WAIT_MS {
            log::line(&format!(
                "socket {s}: send buffer full for {}s; {} bytes kept for the next send",
                SEND_WAIT_MS / 1000,
                pending.len() - sent
            ));
            break Ok(());
        }
        wait_writable(s, 100);
        waited += 100;
    };
    pending.drain(..sent);
    result
}

/// Waits up to `ms` for the socket to take more bytes.
fn wait_writable(s: Socket, ms: u32) {
    // SAFETY: plain select on one socket with stack-owned sets.
    unsafe {
        let mut w: FD_SET = std::mem::zeroed();
        w.fd_count = 1;
        w.fd_array[0] = s;
        let mut e: FD_SET = std::mem::zeroed();
        e.fd_count = 1;
        e.fd_array[0] = s;
        let tv = TIMEVAL {
            tv_sec: 0,
            tv_usec: (ms * 1000) as i32,
        };
        select(0, ptr::null_mut(), &mut w, &mut e, &tv);
    }
}

/// Harness `recv`: serve held bytes, else read and rewrite until there is
/// something for the client, the stream ends, or the socket has nothing more.
fn harness_recv(s: Socket, buf: *mut u8, len: usize, flags: i32) -> i32 {
    #[cfg(test)]
    maybe_panic(s);
    let sock = sock_for(s);
    let mut side = lock(&sock.inb);
    // Answered from what is held: on a TLS socket the original `recv` is still
    // called once, because that call is what re-arms Winsock's FD_READ (see
    // `tlsio::recv`). What it brings stays in the TLS for the next call, which
    // is announced.
    let touched = match (sock.tls.get(), sock.file.get()) {
        (Some(conn), _) if !side.ready.is_empty() => tlsio::touch(&sock, conn, s),
        (None, Some(fc)) if !side.ready.is_empty() => filesio::touch(&sock, fc, s),
        _ => false,
    };
    // The session is opened from the read loop below, once the bytes have said
    // which account this is.
    if side.ready.is_empty() {
        if side.rw.is_raw() || side.eof {
            let n = transport_recv(&sock, s, buf, len, flags);
            if n > 0 {
                let err = unsafe { GetLastError() };
                first_bytes_note(Direction::Inbound, s, n as usize);
                unsafe { SetLastError(err) };
            }
            return n;
        }
        let mut tmp = vec![0u8; len.max(READ_CHUNK)];
        loop {
            let n = transport_recv(&sock, s, tmp.as_mut_ptr(), tmp.len(), flags & !MSG_PEEK);
            if n > 0 {
                first_bytes_note(Direction::Inbound, s, n as usize);
                let crypto = ensure_session(&sock);
                let InSide { rw, ready, .. } = &mut *side;
                let mut lines = match crypto.session() {
                    Some(sess) => session::pump(
                        rw,
                        Direction::Inbound,
                        &mut lock(sess),
                        &tmp[..n as usize],
                        crate::crypto::unix_now(),
                        policy(),
                        ready,
                    ),
                    None => push_without_session(rw, &tmp[..n as usize], ready, crypto.why_not()),
                };
                if rw.is_broken() {
                    // What was rewritten before the bad header goes too: the
                    // connection is reset, and the client reconnects.
                    ready.clear();
                    log_lines(&sock, lines);
                    drop(side);
                    return reset_broken_stream(s);
                }
                // The stream read the token and our own account out of the
                // OService SNACs whether or not a session exists yet; without
                // a session it has nowhere to put them, so they wait here.
                if let Some(uin) = rw.take_sign_on_uin() {
                    remember_signed_on_uin(uin);
                }
                if let Some(token) = rw.take_token().filter(|_| policy().mode == Mode::Encrypt) {
                    let mut slot = lock(&sock.pending_token);
                    if slot.is_none() {
                        log::line(&format!(
                            "[ICQ E2E] MOTD token ({} bytes) held until the account is known",
                            token.len()
                        ));
                        *slot = Some(token);
                    }
                }
                if rw.carries_messages() {
                    sock.messages.store(true, Ordering::Release);
                }
                let _ = ensure_session(&sock);
                lines.extend(drain_pending_token(&sock));
                tlsio::say_if_opted_out(&sock);
                log_lines(&sock, lines);
                if side.ready.is_empty() {
                    // Only part of a frame so far; ask the socket again.
                    continue;
                }
                break;
            }
            if n == 0 {
                let InSide { rw, ready, eof } = &mut *side;
                let dropped = rw.finish(ready);
                *eof = true;
                if dropped > 0 {
                    log_lines(
                        &sock,
                        vec![format!(
                            "end of stream with {dropped} byte(s) of an unfinished frame: dropped, never handed to the client"
                        )],
                    );
                }
                if side.ready.is_empty() {
                    return 0;
                }
                break;
            }
            // Nothing for the client yet: pass the socket's answer on, normally
            // WSAEWOULDBLOCK. Nothing ran since the call, so its last error
            // stands.
            return SOCKET_ERROR;
        }
    }
    let k = len.min(side.ready.len());
    // SAFETY: the client's buffer holds len >= k bytes.
    unsafe { ptr::copy_nonoverlapping(side.ready.as_ptr(), buf, k) };
    let peek = flags & MSG_PEEK != 0;
    if !peek {
        side.ready.drain(..k);
    }
    let more = !peek && (!side.ready.is_empty() || touched);
    drop(side);
    if more {
        post_fd_read(&sock, s);
    }
    k as i32
}

/// Tells the client there is more to read, as Winsock would.
fn post_fd_read(sock: &Sock, s: Socket) {
    let Some(n) = *lock(&sock.notify) else {
        return;
    };
    if n.events & FD_READ == 0 || n.hwnd == 0 {
        return;
    }
    // SAFETY: posting a message to the client's own window; lParam is
    // WSAMAKESELECTREPLY(FD_READ, 0).
    unsafe {
        PostMessageW(n.hwnd as HWND, n.msg, s, FD_READ as isize);
    }
}

/// Parses a sockaddr_in into "a.b.c.d:port" for log context. Returns None for
/// anything that is not a 4-byte IPv4 address.
unsafe fn parse_sockaddr(name: *const u8, namelen: i32) -> Option<String> {
    if name.is_null() || namelen < 8 {
        return None;
    }
    let sa = std::slice::from_raw_parts(name, namelen as usize);
    let family = u16::from_le_bytes([sa[0], sa[1]]);
    if family != 2 {
        // AF_INET only.
        return None;
    }
    let port = u16::from_be_bytes([sa[2], sa[3]]);
    Some(format!("{}.{}.{}.{}:{}", sa[4], sa[5], sa[6], sa[7], port))
}

// --- installation -----------------------------------------------------------

/// Runs the publish and refill steps that are due, on every open socket.
///
/// A separate thread because those steps must happen even when the client goes
/// quiet: the directory only learns our keys from calls we make, and a client
/// that signs on and sits still would otherwise never be able to receive a
/// message at all. It sleeps between rounds and does nothing at all when no
/// socket has a session or nothing is due.
fn poll_worker() {
    loop {
        // SAFETY: sleeping the calling thread; this is our own worker.
        unsafe { Sleep(2_000) };
        // Only encryption has keys to refill and a directory to call; the
        // test host may switch the policy away from it.
        if policy().mode != Mode::Encrypt {
            continue;
        }
        let now = crate::crypto::unix_now();
        // A connection that was handed a token before the account was known, and
        // has not sent anything since, would hold that token until its next
        // send - which for a client that signs on and sits still is never.
        let waiting: Vec<Arc<Sock>> = lock(sockets())
            .values()
            .filter(|s| lock(&s.session).is_none() && lock(&s.pending_token).is_some())
            .cloned()
            .collect();
        for sock in waiting {
            let _ = ensure_session(&sock);
            for line in drain_pending_token(&sock) {
                log::line(&line);
            }
        }
        let accounts: Vec<Arc<Mutex<Session>>> =
            lock(sessions_by_account()).values().cloned().collect();
        for sess in accounts {
            let Ok(mut s) = sess.try_lock() else {
                // A frame is being handled with this session; try next time.
                continue;
            };
            for line in s.poll(now) {
                log::line(&line);
            }
        }
        // Notes nothing has carried into a chat yet - one made while the
        // inbound side was busy - go out on the connection the chats are on.
        let chats: Vec<(Socket, Arc<Sock>)> = lock(sockets())
            .iter()
            .filter(|(_, s)| s.messages.load(Ordering::Acquire))
            .map(|(k, s)| (*k, s.clone()))
            .collect();
        // The calls' timers (the callee's wait for confirmation, the keys
        // kept after a BYE), whose notes the delivery below carries.
        calls_io::tick();
        filesio::tick();
        for (s, sock) in chats {
            deliver_notes(&sock, s);
        }
    }
}

/// What the loader stub asks to be run first on the bootstrap thread (its
/// own work that must stay out of `DllMain`).
static PREWARM: AtomicUsize = AtomicUsize::new(0);

/// Starts the add-on from the loader stub's `DllMain` (fourth review,
/// finding H). Only what is safe under the loader lock happens here:
///
/// 1. the loader notification is registered (`LdrRegisterDllNotification`,
///    looked up in ntdll, which is always loaded): the networking module is
///    patched the moment it is mapped, before any of its code runs;
/// 2. a networking module that is already mapped is patched at once;
/// 3. the bootstrap thread is created. It runs once the loader lock is
///    released and does everything else: `prewarm` (the loader's own lazy
///    work), reading `icq-e2e.ini`, logging, the polling fallback, settling
///    the gate.
///
/// Patching is memory work only (the PE reader, `VirtualProtect`, writes of
/// the import slots); nothing is loaded, no file is opened, nothing waits,
/// and log lines are kept in memory until the bootstrap thread writes them.
/// Until the bootstrap has read the policy the gate is `Starting`, and a
/// hooked call waits for it and is refused if it does not come, so no
/// `connect` can leave before the add-on knows what to protect. Safe to call
/// more than once; only the first call does anything.
pub fn start_from_loader(prewarm: Option<fn()>) {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Some(f) = prewarm {
        PREWARM.store(f as usize, Ordering::Release);
    }
    register_dll_notification();
    install_now_if_loaded();
    spawn(bootstrap_thread);
}

/// The bootstrap: everything the loader lock must not see.
unsafe extern "system" fn bootstrap_thread(_: *mut core::ffi::c_void) -> u32 {
    let _ = panic::catch_unwind(|| {
        let f = PREWARM.load(Ordering::Acquire);
        if f != 0 {
            // SAFETY: only ever a `fn()` stored by `start_from_loader`.
            let f: fn() = std::mem::transmute::<usize, fn()>(f);
            f();
        }
        log::flush_deferred();
        let p = Policy::from_env();
        log::line(&format!("Phase 1 add-on loading: {}", p.describe()));
        let encrypting = p.mode == Mode::Encrypt;
        set_policy_once(p);
        crate::alert::enable(policy().security_popups);
        // The call modules are loaded and patched before the gate opens, so
        // no call can start before their hooks are in (fifth audit of
        // 2026-10, finding 5).
        calls_io::start();
        // A networking module patched before the policy was known is
        // settled now; one that was not is waited for below.
        gate::current().settle(policy());
        filesio::start();
        if encrypting {
            spawn(poll_thread);
        }
        wait_for_install();
    });
    if gate::current().bootstrap() == Bootstrap::Starting {
        // A panic above must not leave the hooks waiting for good.
        gate::current().fail("the add-on failed while starting".to_string());
    }
    log::flush_deferred();
    0
}

/// The polling fallback, then the gate's verdict on the install: `Ready`, or
/// `Fatal` with the reason - said in the log and, in a policy that protects
/// anything, in a message box: from then on every `connect`, `send` and
/// `recv` the hooks see is refused (finding D).
fn wait_for_install() {
    let g = gate::current();
    if g.install_outcome().is_none() {
        log::line("install worker running; searching for the networking module (coolcore5x/4x)");
        log_named_lookups();
        let mut warned = false;
        let mut last_reason = None;
        for attempt in 0..INSTALL_WAIT_ATTEMPTS {
            if matches!(g.install_outcome(), Some(Ok(_))) {
                break;
            }
            match find_networking_module(attempt == 0) {
                Some((name, base)) => {
                    match install_into(&name, base, "polling", true) {
                        Ok(_) => break,
                        Err(why) => last_reason = Some(why),
                    }
                    log::flush_deferred();
                }
                None if !warned => {
                    log::line("networking module not loaded yet; waiting for it");
                    warned = true;
                }
                None if attempt % 100 == 0 && attempt > 0 => log::line(&format!(
                    "still waiting for the networking module ({}s)",
                    attempt / 10
                )),
                None => {}
            }
            // SAFETY: sleeping our own thread.
            unsafe { Sleep(100) };
        }
        if g.install_outcome().is_none() {
            g.installed(Err(last_reason.unwrap_or_else(|| {
                "no coolcore5x/4x networking module appeared within 60 s".to_string()
            })));
        }
    }
    log::flush_deferred();
    match g.settle(policy()) {
        Bootstrap::Ready(mask) => log::line(&format!(
            "protection gate: ready; hooks in place: {}{}",
            mask.names().join(", "),
            {
                let missing = mask.missing(HookMask::ALL);
                if missing.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (not imported, not needed by this setup: {})",
                        missing.names().join(", ")
                    )
                }
            }
        )),
        Bootstrap::Fatal(why) => {
            log::line(&format!(
                "protection gate: FATAL: {why}; {}",
                if gate::protecting(policy()) {
                    "every connection, send and receive the hooks see is refused"
                } else {
                    "nothing in this setup is protected, so nothing is refused"
                }
            ));
            if gate::protecting(policy()) {
                tlsio::notice(
                    &format!("fatal:{why}"),
                    format!(
                        "ICQ E2E: the add-on cannot protect this ICQ ({why}). The client is not allowed to connect without the protection it was set up with. Apply the patch again, or untick the E2E rows to go without it."
                    ),
                );
            }
        }
        Bootstrap::Starting => {}
    }
}

/// The thread entry point for [`poll_worker`], which takes no argument.
unsafe extern "system" fn poll_thread(_: *mut core::ffi::c_void) -> u32 {
    poll_worker();
    0
}

/// Starts a thread on a plain function with no argument.
fn spawn(f: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32) {
    // SAFETY: CreateThread with a plain function; no captured state.
    unsafe {
        let h = CreateThread(ptr::null(), 0, Some(f), ptr::null(), 0, ptr::null_mut());
        if !h.is_null() {
            windows_sys::Win32::Foundation::CloseHandle(h);
        }
    }
}

/// The networking modules of the two clients, by file name.
const NETWORKING_MODULES: [&str; 2] = ["coolcore59.dll", "coolcore49.dll"];

/// Patches the networking module right away if it is already loaded. Runs
/// under the loader lock: memory work only, log lines deferred.
fn install_now_if_loaded() {
    for name in NETWORKING_MODULES {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated name; GetModuleHandleW takes no reference.
        let base = unsafe { GetModuleHandleW(w.as_ptr()) } as usize;
        if base != 0 {
            let _ = install_into(name, base, "already loaded at start", true);
            return;
        }
    }
}

/// `LDR_DLL_NOTIFICATION_DATA` (the "loaded" and "unloaded" shapes are the same).
#[repr(C)]
struct LdrDllNotificationData {
    flags: u32,
    full_dll_name: *const UnicodeString,
    base_dll_name: *const UnicodeString,
    dll_base: *mut core::ffi::c_void,
    size_of_image: u32,
}

/// `UNICODE_STRING`: the length is in bytes, not characters.
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

const LDR_DLL_NOTIFICATION_REASON_LOADED: u32 = 1;

type LdrDllNotificationFn =
    unsafe extern "system" fn(u32, *const LdrDllNotificationData, *mut core::ffi::c_void);
type LdrRegisterDllNotificationFn = unsafe extern "system" fn(
    u32,
    LdrDllNotificationFn,
    *mut core::ffi::c_void,
    *mut *mut core::ffi::c_void,
) -> i32;

/// Asks the loader to call [`dll_notification`] for every DLL loaded from now
/// on. `LdrRegisterDllNotification` is not in any import library, so it is
/// looked up in ntdll by name. Always registered: the call modules are
/// patched from it too, and whether they are needed is known only once the
/// bootstrap has read the policy. Runs under the loader lock; logs deferred.
fn register_dll_notification() {
    let ntdll: Vec<u16> = "ntdll.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: ntdll is always loaded; the looked-up export has the documented
    // signature, and the callback lives as long as the process (the loaders
    // pin themselves).
    unsafe {
        let h = GetModuleHandleW(ntdll.as_ptr());
        if h.is_null() {
            log::defer("loader notification: ntdll not found; relying on polling".to_string());
            return;
        }
        let Some(p) = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            h,
            c"LdrRegisterDllNotification".as_ptr().cast(),
        ) else {
            log::defer("loader notification: not available; relying on polling".to_string());
            return;
        };
        let register: LdrRegisterDllNotificationFn = std::mem::transmute(p);
        let mut cookie: *mut core::ffi::c_void = ptr::null_mut();
        let status = register(0, dll_notification, ptr::null_mut(), &mut cookie);
        if status < 0 {
            log::defer(format!(
                "loader notification: registration failed ({status:#010x}); relying on polling"
            ));
        }
    }
}

/// Runs inside the loader (under its lock) for each DLL that gets loaded. Does
/// nothing but patch a networking module (or a call module), and never waits
/// for the install lock: whoever holds it is installing already. A call
/// module that loads before the bootstrap has read the policy is handed to a
/// thread that waits for it.
unsafe extern "system" fn dll_notification(
    reason: u32,
    data: *const LdrDllNotificationData,
    _context: *mut core::ffi::c_void,
) {
    if reason != LDR_DLL_NOTIFICATION_REASON_LOADED || data.is_null() {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let d = &*data;
        if d.base_dll_name.is_null() || d.dll_base.is_null() {
            return;
        }
        let u = &*d.base_dll_name;
        if u.buffer.is_null() {
            return;
        }
        let name =
            String::from_utf16_lossy(std::slice::from_raw_parts(u.buffer, u.length as usize / 2));
        if name.to_ascii_lowercase().starts_with("coolcore") {
            if !INSTALLED.load(Ordering::Acquire) {
                let _ = install_into(&name, d.dll_base as usize, "on load", false);
            }
        } else if policy_is_set() {
            calls_io::on_load(&name, d.dll_base as usize, "on load", true);
        } else {
            calls_io::later(&name);
        }
    }));
}

/// Serialises the three ways in, so a module is patched once.
static INSTALL_LOCK: Mutex<()> = Mutex::new(());

/// The networking module's hooks.
fn networking_hooks() -> [HookSpec; 8] {
    [
        HookSpec::new("send", hook_send as SendFn as usize, &ORIG_SEND),
        HookSpec::new("recv", hook_recv as RecvFn as usize, &ORIG_RECV),
        HookSpec::new("connect", hook_connect as ConnectFn as usize, &ORIG_CONNECT),
        HookSpec::new(
            "closesocket",
            hook_closesocket as CloseFn as usize,
            &ORIG_CLOSE,
        ),
        HookSpec::new(
            "WSAAsyncSelect",
            hook_async_select as AsyncSelectFn as usize,
            &ORIG_ASYNC_SELECT,
        ),
        HookSpec::new(
            "ioctlsocket",
            hook_ioctlsocket as IoctlFn as usize,
            &ORIG_IOCTL,
        ),
        HookSpec::new(
            "getpeername",
            hook_getpeername as PeerNameFn as usize,
            &ORIG_GETPEERNAME,
        ),
        HookSpec::new("accept", hook_accept as AcceptFn as usize, &ORIG_ACCEPT),
    ]
}

/// Patches `name` at `base`: DISCOVER, then COMMIT all or nothing. With
/// `wait` false (under the loader lock) the install lock is only tried.
/// Records the hooks that went in with the gate and settles it if the
/// policy is known. Its log lines are deferred: it may run under the loader
/// lock.
fn install_into(name: &str, base: usize, via: &str, wait: bool) -> Result<HookMask, String> {
    let _guard = if wait {
        lock(&INSTALL_LOCK)
    } else {
        match INSTALL_LOCK.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err("another thread is installing".to_string())
            }
        }
    };
    if INSTALLED.load(Ordering::Acquire) {
        if let Some(Ok(mask)) = gate::current().install_outcome() {
            return Ok(mask);
        }
    }
    match patch_with(base, &networking_hooks(), &resolve_ordinal, &mut LiveThunks) {
        Ok((mask, report)) => {
            INSTALLED.store(true, Ordering::Release);
            gate::current().installed(Ok(mask));
            log::defer(format!(
                "hooks installed in {name} at {base:#010x} ({via}): {report}"
            ));
            if policy_is_set() {
                gate::current().settle(policy());
            }
            Ok(mask)
        }
        Err(reason) => {
            log::defer(format!("{name} ({via}): could not patch: {reason}"));
            Err(format!("{name} could not be patched: {reason}"))
        }
    }
}

/// Logs what name-based module lookups return, to catch a name/case or
/// ANSI-vs-wide mismatch directly.
fn log_named_lookups() {
    for name in [
        "coolcore59.dll",
        "coolcore49.dll",
        "coolcore59",
        "coolcore49",
    ] {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: valid NUL-terminated pointers for the duration of the calls.
        let hw = unsafe { GetModuleHandleW(w.as_ptr()) } as usize;
        let ha = match std::ffi::CString::new(name) {
            Ok(c) => (unsafe { GetModuleHandleA(c.as_ptr() as *const u8) }) as usize,
            Err(_) => 0,
        };
        log::line(&format!(
            "lookup {name:<16} GetModuleHandleW={hw:#010x} GetModuleHandleA={ha:#010x}"
        ));
    }
}

/// Enumerates the current process's loaded modules and returns the first whose
/// base name starts with "coolcore", together with its base address. When
/// `verbose` is set, logs the coolcore modules seen and the total module count,
/// so a wrong name never hides a module that is actually present.
fn find_networking_module(verbose: bool) -> Option<(String, usize)> {
    // SAFETY: standard psapi enumeration of our own process.
    unsafe {
        let proc = GetCurrentProcess();
        let mut mods = [core::ptr::null_mut::<core::ffi::c_void>(); 1024];
        let mut needed: u32 = 0;
        let cb = (mods.len() * core::mem::size_of::<HMODULE>()) as u32;
        if EnumProcessModules(proc, mods.as_mut_ptr() as *mut HMODULE, cb, &mut needed) == 0 {
            if verbose {
                log::line("EnumProcessModules failed; cannot enumerate loaded modules");
            }
            return None;
        }
        let count = ((needed as usize) / core::mem::size_of::<HMODULE>()).min(mods.len());
        let mut coolcore: Vec<String> = Vec::new();
        let mut hit: Option<(String, usize)> = None;
        for &h in mods.iter().take(count) {
            let mut buf = [0u16; 260];
            let n = GetModuleBaseNameW(proc, h as HMODULE, buf.as_mut_ptr(), buf.len() as u32);
            if n == 0 {
                continue;
            }
            let name = String::from_utf16_lossy(&buf[..n as usize]);
            if name.to_ascii_lowercase().starts_with("coolcore") {
                coolcore.push(name.clone());
                if hit.is_none() {
                    hit = Some((name.clone(), h as usize));
                }
            }
        }
        if verbose {
            log::line(&format!(
                "loaded modules: {count}; coolcore modules: [{}]",
                if coolcore.is_empty() {
                    "none".to_string()
                } else {
                    coolcore.join(", ")
                }
            ));
        }
        hit
    }
}

// --- import table patching: DISCOVER, then COMMIT ---------------------------

/// The DLLs whose imports carry the Winsock functions we hook.
const SOCKET_DLLS: [&str; 2] = ["wsock32.dll", "ws2_32.dll"];

/// One function to hook: its export name, the hook, and where the original
/// pointer is kept.
struct HookSpec {
    name: &'static str,
    hook: usize,
    orig: &'static AtomicUsize,
}

impl HookSpec {
    fn new(name: &'static str, hook: usize, orig: &'static AtomicUsize) -> Self {
        HookSpec { name, hook, orig }
    }
}

/// The Winsock 1.1 export ordinals, as both DLLs number them. They agree
/// except for 10-12: `wsock32` has `inet_addr`, `inet_ntoa`, `ioctlsocket`,
/// `ws2_32` has `ioctlsocket`, `inet_addr`, `inet_ntoa`. Used only when the
/// DLL's own export table cannot be read.
fn known_ordinal_name(dll: &str, ordinal: u16) -> Option<&'static str> {
    let ws2 = dll.eq_ignore_ascii_case("ws2_32.dll");
    if !ws2 && !dll.eq_ignore_ascii_case("wsock32.dll") {
        return None;
    }
    Some(match ordinal {
        1 => "accept",
        2 => "bind",
        3 => "closesocket",
        4 => "connect",
        5 => "getpeername",
        6 => "getsockname",
        7 => "getsockopt",
        8 => "htonl",
        9 => "htons",
        10 if ws2 => "ioctlsocket",
        10 => "inet_addr",
        11 if ws2 => "inet_addr",
        11 => "inet_ntoa",
        12 if ws2 => "inet_ntoa",
        12 => "ioctlsocket",
        13 => "listen",
        14 => "ntohl",
        15 => "ntohs",
        16 => "recv",
        17 => "recvfrom",
        18 => "select",
        19 => "send",
        20 => "sendto",
        21 => "setsockopt",
        22 => "shutdown",
        23 => "socket",
        101 => "WSAAsyncSelect",
        _ => return None,
    })
}

/// The name behind `ordinal` in `dll`: read from the export table of the DLL
/// as it is loaded in this process, else from [`known_ordinal_name`].
fn resolve_ordinal(dll: &str, ordinal: u16) -> Option<String> {
    let loaded = std::ffi::CString::new(dll).ok().and_then(|c| {
        // SAFETY: a NUL-terminated name; the handle is only read from.
        let h = unsafe { GetModuleHandleA(c.as_ptr() as *const u8) } as usize;
        if h == 0 {
            return None;
        }
        // SAFETY: h is a loaded module's base.
        unsafe { export_name_by_ordinal(h, ordinal) }
    });
    loaded.or_else(|| known_ordinal_name(dll, ordinal).map(str::to_string))
}

/// The image of a module loaded at `base`: `[base, base + SizeOfImage)`,
/// read with the bounds-checked reader.
///
/// # Safety
/// `base` is the base of a module mapped in this process (or of a buffer of
/// at least `SizeOfImage` bytes, in the tests), and the image stays mapped
/// for `'a`.
unsafe fn loaded_image<'a>(base: usize) -> Result<pe::Image<'a>, pe::PeError> {
    // The headers are in the first page of every mapped image.
    let head = std::slice::from_raw_parts(base as *const u8, 0x1000);
    let size = pe::Image::size_of_image(head)?;
    pe::Image::parse(std::slice::from_raw_parts(base as *const u8, size))
}

/// The name the export table of the module at `base` gives `ordinal`.
///
/// # Safety
/// As [`loaded_image`].
unsafe fn export_name_by_ordinal(base: usize, ordinal: u16) -> Option<String> {
    loaded_image(base).ok()?.export_name(ordinal)
}

/// One slot DISCOVER found: where it is, what it holds, what goes there.
struct PlannedSlot {
    addr: usize,
    current: u32,
    hook: u32,
    orig: &'static AtomicUsize,
    label: String,
}

/// What COMMIT is to write, and what it amounts to.
struct PatchPlan {
    slots: Vec<PlannedSlot>,
    mask: HookMask,
    labels: Vec<String>,
}

/// DISCOVER: every slot of the module's Winsock imports ([`SOCKET_DLLS`])
/// that one of `hooks` is for, each checked to be bound. Changes nothing. An
/// ordinal import is turned into a name with `resolve(dll, ordinal)`, so the
/// same ordinal means what it means in the DLL it is imported from.
fn discover(
    img: &pe::Image<'_>,
    base: usize,
    hooks: &[HookSpec],
    resolve: &dyn Fn(&str, u16) -> Option<String>,
) -> Result<PatchPlan, String> {
    let dlls = img.imports().map_err(|e| e.to_string())?;
    let mut dll_found = false;
    let mut unbound: Vec<String> = Vec::new();
    let mut plan = PatchPlan {
        slots: Vec::new(),
        mask: HookMask::NONE,
        labels: Vec::new(),
    };
    for dll in &dlls {
        // Names come from the INT; without one (a bound-only import) there
        // is nothing to tell the slots apart by.
        if !SOCKET_DLLS.iter().any(|d| dll.name.eq_ignore_ascii_case(d)) || !dll.has_lookup {
            continue;
        }
        dll_found = true;
        for t in &dll.thunks {
            let (name, label) = match &t.import {
                pe::Import::Name(n) => (Some(n.clone()), n.clone()),
                pe::Import::Ordinal(o) => {
                    let n = resolve(&dll.name, *o);
                    let label = format!("{}#{o}", n.as_deref().unwrap_or("?"));
                    (n, label)
                }
            };
            let Some(h) = name.and_then(|n| hooks.iter().find(|h| h.name == n)) else {
                continue;
            };
            if !t.is_bound() {
                // The loader has not filled the slot yet: there is no
                // original to keep, and it would write over the hook anyway.
                unbound.push(label);
                continue;
            }
            let addr = base
                .checked_add(t.slot_rva)
                .ok_or_else(|| "an import slot's address overflows".to_string())?;
            plan.mask = plan.mask.with(HookMask::of(h.name));
            plan.labels.push(label.clone());
            plan.slots.push(PlannedSlot {
                addr,
                current: t.bound,
                hook: h.hook as u32,
                orig: h.orig,
                label,
            });
        }
    }
    if !dll_found {
        let seen: Vec<&str> = dlls.iter().map(|d| d.name.as_str()).collect();
        return Err(format!(
            "no Winsock DLL among the imports of the module; imports seen: [{}]",
            seen.join(", ")
        ));
    }
    if !unbound.is_empty() {
        return Err(format!("imports not bound yet: [{}]", unbound.join(", ")));
    }
    if plan.slots.is_empty() {
        return Err(
            "Winsock imported but no send/recv/connect/closesocket thunk matched".to_string(),
        );
    }
    Ok(plan)
}

/// Writes one import slot. The real one goes through `VirtualProtect`; the
/// tests inject failures.
trait ThunkWriter {
    fn write(&mut self, addr: usize, value: u32) -> bool;
}

/// The slots of a loaded module: made writable, written in one aligned
/// store (a thread calling through the slot sees the old or the new
/// pointer, never half of each), and given their protection back.
struct LiveThunks;

impl ThunkWriter for LiveThunks {
    fn write(&mut self, addr: usize, value: u32) -> bool {
        let p = addr as *const core::ffi::c_void;
        let mut old: PAGE_PROTECTION_FLAGS = 0;
        // SAFETY: addr is an import slot DISCOVER found inside the image;
        // its page is made writable for the one store and restored.
        unsafe {
            if VirtualProtect(p, 4, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
                return false;
            }
            if addr % 4 == 0 {
                (*(addr as *const std::sync::atomic::AtomicU32)).store(value, Ordering::SeqCst);
            } else {
                ptr::write_unaligned(addr as *mut u32, value);
            }
            let mut tmp: PAGE_PROTECTION_FLAGS = 0;
            let _ = VirtualProtect(p, 4, old, &mut tmp);
        }
        true
    }
}

/// COMMIT: the originals are kept first (a hook that runs the moment its
/// slot is written finds its original), then every slot is written. If one
/// write fails, every slot written so far is put back as it was and nothing
/// counts as installed (fourth review, finding C: no half-patched module).
fn commit(plan: &PatchPlan, w: &mut dyn ThunkWriter) -> Result<HookMask, String> {
    for s in &plan.slots {
        if s.current != s.hook {
            s.orig.store(s.current as usize, Ordering::Release);
        }
    }
    let mut written: Vec<&PlannedSlot> = Vec::new();
    for s in &plan.slots {
        if s.current == s.hook {
            continue; // ours already
        }
        if w.write(s.addr, s.hook) {
            written.push(s);
            continue;
        }
        let mut stuck = Vec::new();
        for d in written.iter().rev() {
            if !w.write(d.addr, d.current) {
                stuck.push(d.label.clone());
            }
        }
        return Err(format!(
            "the slot of {} could not be written; {} slot(s) written before it put back{}",
            s.label,
            written.len() - stuck.len(),
            if stuck.is_empty() {
                String::new()
            } else {
                format!(" ({} could not be: they keep the hook)", stuck.join(", "))
            }
        ));
    }
    Ok(plan.mask)
}

/// DISCOVER and COMMIT over the module at `base`: the hooks that went in and
/// a report, or why none did.
fn patch_with(
    base: usize,
    hooks: &[HookSpec],
    resolve: &dyn Fn(&str, u16) -> Option<String>,
    w: &mut dyn ThunkWriter,
) -> Result<(HookMask, String), String> {
    let plan = {
        // SAFETY: base is a loaded module (or the tests' buffer); the slice
        // is dropped before anything is written.
        let img = unsafe { loaded_image(base) }.map_err(|e| e.to_string())?;
        discover(&img, base, hooks, resolve)?
    };
    let mask = commit(&plan, w)?;
    Ok((mask, format!("patched [{}]", plan.labels.join(", "))))
}

/// [`patch_with`] through `VirtualProtect`, with the report only (the tests).
#[cfg(test)]
fn patch_iat(
    base: usize,
    hooks: &[HookSpec],
    resolve: &dyn Fn(&str, u16) -> Option<String>,
) -> Result<String, String> {
    patch_with(base, hooks, resolve, &mut LiveThunks).map(|(_, r)| r)
}

/// The hooks driven from a process that is not a client: the test host and
/// the tests. They call the hook bodies directly, with the real Winsock
/// functions as the originals, which is what the networking module's patched
/// imports amount to.
#[doc(hidden)]
pub mod testing {
    use super::*;
    use windows_sys::Win32::Networking::WinSock;

    pub use super::tlsio::{Active, Setup};

    /// Sets the policy (the first call in a process wins) and points the hooks
    /// at the real Winsock functions. Starts the publish and refill worker in
    /// encrypt mode, as `start` does.
    pub fn init(p: Policy) {
        let encrypting = p.mode == Mode::Encrypt;
        let first = set_policy_once(p);
        ORIG_SEND.store(WinSock::send as *const () as usize, Ordering::Release);
        ORIG_RECV.store(WinSock::recv as *const () as usize, Ordering::Release);
        ORIG_CONNECT.store(WinSock::connect as *const () as usize, Ordering::Release);
        ORIG_CLOSE.store(
            WinSock::closesocket as *const () as usize,
            Ordering::Release,
        );
        ORIG_ASYNC_SELECT.store(
            WinSock::WSAAsyncSelect as *const () as usize,
            Ordering::Release,
        );
        ORIG_IOCTL.store(
            WinSock::ioctlsocket as *const () as usize,
            Ordering::Release,
        );
        ORIG_GETPEERNAME.store(
            WinSock::getpeername as *const () as usize,
            Ordering::Release,
        );
        ORIG_ACCEPT.store(WinSock::accept as *const () as usize, Ordering::Release);
        // Every hook is "installed": the protection gate is ready.
        gate::global().installed(Ok(HookMask::ALL));
        gate::global().force(Bootstrap::Ready(HookMask::ALL));
        if first && encrypting {
            spawn(poll_thread);
        }
    }

    /// Replaces the policy [`init`] set, for a run in another mode in the
    /// same process. The old one is leaked: a hook may still be reading it.
    pub fn set_policy(p: Policy) {
        POLICY.store(Box::into_raw(Box::new(p)), Ordering::Release);
    }

    /// Replaces what the add-on does about TLS.
    pub fn set_tls(setup: Setup) {
        tlsio::replace_setup(setup);
    }

    /// The key directory every session uses.
    pub fn set_directory(dir: Arc<dyn crate::directory::DirectoryApi>) {
        *lock(test_directory()) = Some(dir);
    }

    /// Collects the message boxes instead of showing them, and forgets the
    /// reasons shown so far.
    pub fn capture_notices() {
        tlsio::capture_notices();
    }

    /// The message boxes collected since the last call.
    pub fn take_notices() -> Vec<String> {
        tlsio::take_notices()
    }

    /// The account key of an open session, as the client announces it.
    pub fn account_key(uin: &str) -> Option<[u8; 32]> {
        use crate::crypto::Crypto;
        let sess = lock(sessions_by_account()).get(uin).cloned()?;
        let mut g = lock(&sess);
        g.engine().account_key()
    }

    fn last_error() -> u32 {
        // SAFETY: reads the calling thread's last error.
        unsafe { GetLastError() }
    }

    /// How many times the original `recv` was called on TLS sockets.
    pub fn original_recvs() -> usize {
        tlsio::ORIGINAL_RECVS.load(Ordering::Relaxed)
    }

    /// `connect` through the hook: (result, last error).
    pub fn connect(s: usize, addr: std::net::SocketAddrV4) -> (i32, u32) {
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_le_bytes());
        sa[2..4].copy_from_slice(&addr.port().to_be_bytes());
        sa[4..8].copy_from_slice(&addr.ip().octets());
        // SAFETY: a sockaddr_in on the stack, valid for the call.
        let r = unsafe { hook_connect(s, sa.as_ptr(), sa.len() as i32) };
        (r, last_error())
    }

    /// `send` through the hook: (result, last error).
    pub fn send(s: usize, data: &[u8]) -> (i32, u32) {
        // SAFETY: data is valid for the call.
        let r = unsafe { hook_send(s, data.as_ptr(), data.len() as i32, 0) };
        (r, last_error())
    }

    /// `recv` through the hook: (result, last error).
    pub fn recv(s: usize, buf: &mut [u8], flags: i32) -> (i32, u32) {
        // SAFETY: buf is valid for the call.
        let r = unsafe { hook_recv(s, buf.as_mut_ptr(), buf.len() as i32, flags) };
        (r, last_error())
    }

    /// `closesocket` through the hook.
    pub fn close(s: usize) -> i32 {
        // SAFETY: closing a socket the caller owns.
        unsafe { hook_closesocket(s) }
    }

    /// `WSAAsyncSelect` through the hook.
    pub fn async_select(s: usize, hwnd: usize, msg: u32, events: i32) -> i32 {
        // SAFETY: the caller's socket and window.
        unsafe { hook_async_select(s, hwnd, msg, events) }
    }

    /// `ioctlsocket(FIONREAD)` through the hook.
    pub fn fionread(s: usize) -> u32 {
        let mut n = 0u32;
        // SAFETY: n is a live u32.
        unsafe { hook_ioctlsocket(s, FIONREAD as i32, &mut n) };
        n
    }

    /// The port `getpeername` reports through the hook.
    pub fn peer_port(s: usize) -> Option<u16> {
        let mut sa = [0u8; 16];
        let mut len = sa.len() as i32;
        // SAFETY: a stack buffer of the size passed.
        let r = unsafe { hook_getpeername(s, sa.as_mut_ptr(), &mut len) };
        (r == 0).then(|| u16::from_be_bytes([sa[2], sa[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ordinals both DLLs agree on.
    const ORD_SEND: u16 = 19;
    const ORD_RECV: u16 = 16;
    const ORD_CONNECT: u16 = 4;
    const ORD_CLOSE: u16 = 3;
    /// Where the two DLLs differ.
    const WSOCK32_INET_ADDR: u16 = 10;
    const WSOCK32_INET_NTOA: u16 = 11;
    const WSOCK32_IOCTLSOCKET: u16 = 12;
    const WS2_32_IOCTLSOCKET: u16 = 10;

    /// An entry in an import lookup table: a name is an RVA to a hint/name
    /// struct; an ordinal import has the high bit set with the ordinal below.
    fn named_entry(rva: usize) -> u32 {
        rva as u32
    }

    pub(super) fn ordinal_entry(ordinal: u16) -> u32 {
        0x8000_0000 | ordinal as u32
    }

    /// Builds a minimal PE32 image whose single import descriptor points at
    /// `dll_name` with `entries` in the INT and recognisable bound addresses in
    /// the IAT.
    pub(super) fn synthetic_pe(dll_name: &str, entries: &[u32]) -> Vec<u8> {
        const IMAGE_BASE_RVA: usize = 0x1000;
        let mut img = vec![0u8; 0x4000];

        // DOS header: MZ, e_lfanew -> 0x80.
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature + COFF header (i386).
        img[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        img[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        // Optional header magic PE32, SizeOfImage (the whole buffer: the
        // reader never reads past it) and the number of data directories.
        img[0x80 + 0x18..0x80 + 0x1A].copy_from_slice(&0x010Bu16.to_le_bytes());
        let len = img.len() as u32;
        img[0x80 + 0x18 + 0x38..0x80 + 0x18 + 0x3C].copy_from_slice(&len.to_le_bytes());
        img[0x80 + 0x18 + 0x5C..0x80 + 0x18 + 0x60].copy_from_slice(&16u32.to_le_bytes());
        // Import directory RVA -> data directory entry 1.
        let import_rva = IMAGE_BASE_RVA;
        img[0x80 + 0x80..0x80 + 0x84].copy_from_slice(&(import_rva as u32).to_le_bytes());

        // Import descriptor: name, INT, IAT, all at known RVAs.
        let name_rva = IMAGE_BASE_RVA + 0x40;
        let int_rva = IMAGE_BASE_RVA + 0x80;
        let iat_rva = IMAGE_BASE_RVA + 0x100;
        img[import_rva + 12..import_rva + 16].copy_from_slice(&(name_rva as u32).to_le_bytes());
        img[import_rva + 16..import_rva + 20].copy_from_slice(&(iat_rva as u32).to_le_bytes());
        img[import_rva..import_rva + 4].copy_from_slice(&(int_rva as u32).to_le_bytes());

        img[name_rva..name_rva + dll_name.len()].copy_from_slice(dll_name.as_bytes());
        img[name_rva + dll_name.len()] = 0;

        for (i, e) in entries.iter().enumerate() {
            img[int_rva + i * 4..int_rva + i * 4 + 4].copy_from_slice(&e.to_le_bytes());
            // IAT is pre-filled with a recognisable fake address; write_thunk
            // must overwrite it.
            img[iat_rva + i * 4..iat_rva + i * 4 + 4]
                .copy_from_slice(&(0x7FFF_0000u32 + i as u32).to_le_bytes());
        }
        // Both tables are NUL-terminated.
        let n = entries.len();
        img[int_rva + n * 4..int_rva + n * 4 + 4].copy_from_slice(&0u32.to_le_bytes());
        img[iat_rva + n * 4..iat_rva + n * 4 + 4].copy_from_slice(&0u32.to_le_bytes());

        img
    }

    pub(super) const IAT: usize = 0x1000 + 0x100;

    pub(super) fn iat_value(img: &[u8], i: usize) -> usize {
        let at = IAT + i * 4;
        u32::from_le_bytes(img[at..at + 4].try_into().unwrap()) as usize
    }

    /// Original-pointer slots of one test, so tests running in parallel (and
    /// the real hooks' slots) never share them.
    type Slots = [AtomicUsize; 5];
    #[allow(clippy::declare_interior_mutable_const)] // only to fill the slot arrays
    const EMPTY: AtomicUsize = AtomicUsize::new(0);

    fn hooks(slots: &'static Slots) -> Vec<HookSpec> {
        // Hook addresses are arbitrary distinct non-zero values; only that they
        // differ from the IAT contents matters.
        vec![
            HookSpec::new("send", 0x1000_1000, &slots[0]),
            HookSpec::new("recv", 0x1000_2000, &slots[1]),
            HookSpec::new("connect", 0x1000_3000, &slots[2]),
            HookSpec::new("closesocket", 0x1000_4000, &slots[3]),
            HookSpec::new("ioctlsocket", 0x1000_5000, &slots[4]),
        ]
    }

    /// The fixed table only, so these tests do not depend on the machine.
    fn table(dll: &str, ordinal: u16) -> Option<String> {
        known_ordinal_name(dll, ordinal).map(str::to_string)
    }

    /// The real shape of coolcore59.dll and coolcore49.dll: every wsock32
    /// import is by ordinal. `inet_addr` (10) and `inet_ntoa` (11) are left
    /// alone, `ioctlsocket` is 12.
    #[test]
    fn wsock32_ordinal_imports_are_patched() {
        let img = synthetic_pe(
            "WSOCK32.dll",
            &[
                ordinal_entry(ORD_CONNECT),
                ordinal_entry(ORD_CLOSE),
                ordinal_entry(WSOCK32_INET_ADDR),
                ordinal_entry(WSOCK32_INET_NTOA),
                ordinal_entry(WSOCK32_IOCTLSOCKET),
                ordinal_entry(ORD_RECV),
                ordinal_entry(ORD_SEND),
            ],
        );
        static SLOTS: Slots = [EMPTY; 5];
        let report = patch_iat(img.as_ptr() as usize, &hooks(&SLOTS), &table)
            .expect("ordinal imports should be patched");
        assert_eq!(
            report,
            "patched [connect#4, closesocket#3, ioctlsocket#12, recv#16, send#19]"
        );

        // The pre-patch addresses were saved into the test's slots.
        assert_eq!(SLOTS[0].load(Ordering::Acquire), 0x7FFF_0006);
        assert_eq!(SLOTS[1].load(Ordering::Acquire), 0x7FFF_0005);
        assert_eq!(SLOTS[2].load(Ordering::Acquire), 0x7FFF_0000);
        assert_eq!(SLOTS[3].load(Ordering::Acquire), 0x7FFF_0001);
        assert_eq!(SLOTS[4].load(Ordering::Acquire), 0x7FFF_0004);

        // The IAT itself now holds the hook addresses, and inet_addr and
        // inet_ntoa still hold theirs.
        assert_eq!(iat_value(&img, 0), 0x1000_3000);
        assert_eq!(iat_value(&img, 1), 0x1000_4000);
        assert_eq!(iat_value(&img, 2), 0x7FFF_0002, "inet_addr untouched");
        assert_eq!(iat_value(&img, 3), 0x7FFF_0003, "inet_ntoa untouched");
        assert_eq!(iat_value(&img, 4), 0x1000_5000);
        assert_eq!(iat_value(&img, 5), 0x1000_2000);
        assert_eq!(iat_value(&img, 6), 0x1000_1000);
    }

    /// The same ordinals imported from ws2_32 mean something else: 10 is
    /// `ioctlsocket` there, and 12 is `inet_ntoa`.
    #[test]
    fn ws2_32_ordinal_imports_are_patched_by_their_own_numbering() {
        let img = synthetic_pe(
            "WS2_32.dll",
            &[
                ordinal_entry(WS2_32_IOCTLSOCKET),
                ordinal_entry(11),
                ordinal_entry(12),
                ordinal_entry(ORD_SEND),
            ],
        );
        static SLOTS: Slots = [EMPTY; 5];
        let report = patch_iat(img.as_ptr() as usize, &hooks(&SLOTS), &table).unwrap();
        assert_eq!(report, "patched [ioctlsocket#10, send#19]");
        assert_eq!(iat_value(&img, 0), 0x1000_5000);
        assert_eq!(iat_value(&img, 1), 0x7FFF_0001, "inet_addr untouched");
        assert_eq!(iat_value(&img, 2), 0x7FFF_0002, "inet_ntoa untouched");
    }

    /// A named import (the shape some modules use) is matched by name.
    #[test]
    fn named_imports_are_patched() {
        let mut img = synthetic_pe("WSOCK32.dll", &[named_entry(0x200), named_entry(0x240)]);
        // Write the two hint/name structs the INT points at.
        let put = |img: &mut Vec<u8>, rva: usize, name: &str| {
            img[rva..rva + 2].copy_from_slice(&0u16.to_le_bytes());
            img[rva + 2..rva + 2 + name.len()].copy_from_slice(name.as_bytes());
            img[rva + 2 + name.len()] = 0;
        };
        put(&mut img, 0x200, "send");
        put(&mut img, 0x240, "recv");

        static SLOTS: Slots = [EMPTY; 5];
        let report = patch_iat(img.as_ptr() as usize, &hooks(&SLOTS), &table)
            .expect("named imports should be patched");
        assert_eq!(report, "patched [send, recv]");
    }

    /// A wsock32 import that contains none of the hooked functions is reported
    /// as unmatched rather than silently "succeeding". 10 and 11 are
    /// `inet_addr` and `inet_ntoa` in wsock32.
    #[test]
    fn unhooked_wsock32_ordinals_do_not_patch() {
        let img = synthetic_pe(
            "WSOCK32.dll",
            &[
                ordinal_entry(WSOCK32_INET_ADDR),
                ordinal_entry(WSOCK32_INET_NTOA),
            ],
        );
        static SLOTS: Slots = [EMPTY; 5];
        let err = patch_iat(img.as_ptr() as usize, &hooks(&SLOTS), &table)
            .expect_err("no hooked function is present");
        assert!(
            err.contains("no send/recv/connect/closesocket thunk matched"),
            "{err}"
        );
        assert_eq!(iat_value(&img, 0), 0x7FFF_0000);
        assert_eq!(iat_value(&img, 1), 0x7FFF_0001);
    }

    /// Slots the loader has not filled yet (the IAT still equals the INT) are
    /// not patched: the loader would write over the hook, and there is no
    /// original to keep.
    #[test]
    fn unbound_imports_are_left_for_later() {
        let mut img = synthetic_pe("WSOCK32.dll", &[ordinal_entry(ORD_SEND)]);
        img[IAT..IAT + 4].copy_from_slice(&ordinal_entry(ORD_SEND).to_le_bytes());
        static SLOTS: Slots = [EMPTY; 5];
        let err = patch_iat(img.as_ptr() as usize, &hooks(&SLOTS), &table)
            .expect_err("unbound slots are refused");
        assert!(err.contains("not bound yet"), "{err}");
        assert_eq!(SLOTS[0].load(Ordering::Acquire), 0);
        assert_eq!(iat_value(&img, 0), ordinal_entry(ORD_SEND) as usize);
    }

    /// The fixed table agrees with the real DLLs of this machine (the 32-bit
    /// ones, as the tests run under WOW64 like the clients), and the export
    /// table reader gives the same names.
    #[test]
    fn ordinals_match_the_real_winsock_dlls() {
        for dll in SOCKET_DLLS {
            let w: Vec<u16> = dll.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: loading a system DLL by name.
            let h = unsafe { windows_sys::Win32::System::LibraryLoader::LoadLibraryW(w.as_ptr()) };
            assert!(!h.is_null(), "{dll} loads");
            for ordinal in [1u16, 2, 3, 4, 5, 10, 11, 12, 16, 19, 23, 101] {
                // SAFETY: h is the loaded module.
                let real = unsafe { export_name_by_ordinal(h as usize, ordinal) };
                assert_eq!(
                    real.as_deref(),
                    known_ordinal_name(dll, ordinal),
                    "{dll} ordinal {ordinal}"
                );
                assert_eq!(resolve_ordinal(dll, ordinal), real, "{dll} #{ordinal}");
            }
        }
        assert_eq!(
            resolve_ordinal("wsock32.dll", 12).as_deref(),
            Some("ioctlsocket")
        );
        assert_eq!(
            resolve_ordinal("wsock32.dll", 10).as_deref(),
            Some("inet_addr")
        );
        assert_eq!(
            resolve_ordinal("wsock32.dll", 11).as_deref(),
            Some("inet_ntoa")
        );
        assert_eq!(
            resolve_ordinal("ws2_32.dll", 10).as_deref(),
            Some("ioctlsocket")
        );
        assert_eq!(
            resolve_ordinal("ws2_32.dll", 11).as_deref(),
            Some("inet_addr")
        );
        assert_eq!(
            resolve_ordinal("ws2_32.dll", 12).as_deref(),
            Some("inet_ntoa")
        );
    }

    /// Whether the first import slot of the module at `base` holds an address
    /// rather than its INT entry. `None` when it has no INT to compare with.
    unsafe fn first_import_bound(base: usize) -> Option<bool> {
        let rd32 = |off: usize| ptr::read_unaligned((base + off) as *const u32) as usize;
        let e_lfanew = rd32(0x3C);
        let data_dirs = match ptr::read_unaligned((base + e_lfanew + 0x18) as *const u16) {
            0x010B => e_lfanew + 0x18 + 0x60,
            _ => return None,
        };
        let mut desc = rd32(data_dirs + 8);
        loop {
            let (int, name, iat) = (rd32(desc), rd32(desc + 12), rd32(desc + 16));
            if name == 0 {
                return None;
            }
            if int != 0 && rd32(int) != 0 {
                return Some(rd32(int) != rd32(iat));
            }
            desc += 20;
        }
    }

    static NOTIFIED: Mutex<Option<(String, Option<bool>)>> = Mutex::new(None);

    unsafe extern "system" fn record_notification(
        reason: u32,
        data: *const LdrDllNotificationData,
        _: *mut core::ffi::c_void,
    ) {
        if reason != LDR_DLL_NOTIFICATION_REASON_LOADED {
            return;
        }
        let d = &*data;
        let u = &*d.base_dll_name;
        let name =
            String::from_utf16_lossy(std::slice::from_raw_parts(u.buffer, u.length as usize / 2));
        if name.eq_ignore_ascii_case("msimg32.dll") {
            *lock(&NOTIFIED) = Some((name, first_import_bound(d.dll_base as usize)));
        }
    }

    /// What the synchronous install relies on: the loader calls the
    /// notification for a DLL with its imports already bound, so the original
    /// pointers can be taken and the hooks written before any of its code runs.
    #[test]
    fn loader_notification_comes_with_bound_imports() {
        let ntdll: Vec<u16> = "ntdll.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let name: Vec<u16> = "msimg32.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: as in register_dll_notification; the callback is a plain
        // function and is unregistered with the cookie before returning.
        unsafe {
            if !GetModuleHandleW(name.as_ptr()).is_null() {
                eprintln!("msimg32.dll already loaded in the test process; nothing to observe");
                return;
            }
            let h = GetModuleHandleW(ntdll.as_ptr());
            let reg = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                h,
                c"LdrRegisterDllNotification".as_ptr().cast(),
            )
            .unwrap();
            let unreg = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                h,
                c"LdrUnregisterDllNotification".as_ptr().cast(),
            )
            .unwrap();
            let reg: LdrRegisterDllNotificationFn = std::mem::transmute(reg);
            let unreg: unsafe extern "system" fn(*mut core::ffi::c_void) -> i32 =
                std::mem::transmute(unreg);
            let mut cookie = ptr::null_mut();
            assert!(reg(0, record_notification, ptr::null_mut(), &mut cookie) >= 0);
            let m = windows_sys::Win32::System::LibraryLoader::LoadLibraryW(name.as_ptr());
            unreg(cookie);
            assert!(!m.is_null());
        }
        let seen = lock(&NOTIFIED).clone();
        let (_, bound) = seen.expect("the loader notified the load");
        assert_eq!(bound, Some(true), "imports were bound at notification time");
    }

    #[test]
    fn first_bytes_are_classified_without_content() {
        assert_eq!(classify_first_bytes(&[0x2A, 1, 0, 0]), "FLAP (channel 1)");
        assert_eq!(
            classify_first_bytes(b"POST /auth/clientLogin?a=secret HTTP/1.0\r\n"),
            "HTTP POST /auth/clientLogin"
        );
        assert_eq!(
            classify_first_bytes(b"GET /aim/startOSCARSession?k=x&a=token HTTP/1.0\r\n"),
            "HTTP GET /aim/startOSCARSession"
        );
        assert_eq!(
            classify_first_bytes(b"CONNECT host:5190 HTTP/1.0\r\n"),
            "HTTP proxy CONNECT"
        );
        assert_eq!(
            classify_first_bytes(b"HTTP/1.1 200 OK\r\n"),
            "HTTP response \"HTTP/1.1 200 OK\""
        );
        assert_eq!(
            classify_first_bytes(&[0x16, 3, 1, 0, 5]),
            "TLS handshake (record version 3.1)"
        );
        assert_eq!(classify_first_bytes(&[5, 1, 0]), "SOCKS5?");
        assert_eq!(
            classify_first_bytes(&[0xFF, 0]),
            "other (first byte 0xff, 2 bytes)"
        );
    }
}

/// The session belongs to the account, not to the connection.
///
/// An ICQ client opens several: the BOS connection, which carries the token and
/// announces the account key, and one per service whose MOTD has no token. With
/// a session per socket, that second MOTD reset the engine to "no token yet,
/// encryption stays off" and messages left in clear while the account sat
/// there already published. This is the regression for that.
#[cfg(test)]
mod session_tests {
    use super::*;
    use crate::directory::MemoryDirectory;

    /// The map is the thing under test, so this goes through it directly rather
    /// than through `ensure_session`, which also needs a policy this module's
    /// other tests have already set.
    #[test]
    fn two_sockets_of_one_account_share_one_session() {
        let home = std::env::temp_dir().join("icqe2e-shared-session");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let dir: Arc<dyn crate::directory::DirectoryApi> = Arc::new(MemoryDirectory::new());
        lock(sessions_by_account()).clear();

        // What `ensure_session` does for each connection: ask the account's
        // registry, which opens the session the first time and hands back the
        // same one afterwards.
        let open = || {
            let mut sessions = lock(sessions_by_account());
            if let Some(s) = sessions.get("100001") {
                return s.clone();
            }
            let s = Arc::new(Mutex::new(
                crate::session::Session::open(dir.clone(), &home, "100001").unwrap(),
            ));
            sessions.insert("100001".to_string(), s.clone());
            s
        };
        let a = open();
        let b = open();

        assert!(
            Arc::ptr_eq(&a, &b),
            "both connections of 100001 share the account's session"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}

/// The hooks over a real loopback TCP connection, standing in for the client's
/// non-blocking socket: what the server end reads and what the hooked `recv`
/// hands back are compared with frames built independently.
#[cfg(test)]
mod socket_tests {
    use super::*;
    use crate::harness::apply_charset;
    use crate::test_frames::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::windows::io::AsRawSocket;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Networking::WinSock;

    fn setup() -> (TcpStream, TcpStream, Socket) {
        let _ = set_policy_once(Policy::harness());
        ORIG_SEND.store(WinSock::send as *const () as usize, Ordering::Release);
        ORIG_RECV.store(WinSock::recv as *const () as usize, Ordering::Release);
        ORIG_IOCTL.store(
            WinSock::ioctlsocket as *const () as usize,
            Ordering::Release,
        );
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        client.set_nonblocking(true).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let s = client.as_raw_socket() as Socket;
        (client, server, s)
    }

    fn hooked_send(s: Socket, data: &[u8]) {
        let n = unsafe { hook_send(s, data.as_ptr(), data.len() as i32, 0) };
        assert_eq!(n, data.len() as i32);
    }

    /// One hooked recv into a buffer of `size`: `Some(bytes)`, `Some(empty)` at
    /// the end of the stream, `None` on WSAEWOULDBLOCK.
    fn hooked_recv(s: Socket, size: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let n = unsafe { hook_recv(s, buf.as_mut_ptr(), size as i32, 0) };
        if n < 0 {
            assert_eq!(unsafe { GetLastError() }, WSAEWOULDBLOCK);
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }

    /// Reads through the hook with `size`-byte buffers until `want` bytes came
    /// or the stream ended, polling as a client would on FD_READ.
    fn read(s: Socket, want: usize, size: usize) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut out = Vec::new();
        while out.len() < want {
            match hooked_recv(s, size) {
                Some(b) if b.is_empty() => break,
                Some(b) => out.extend(b),
                None => {
                    assert!(Instant::now() < deadline, "timed out with {out:?}");
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        out
    }

    #[test]
    fn rewrite_over_a_real_socket() {
        let (_client, mut server, s) = setup();

        // Out: the client's stream in pieces cut inside frames.
        let hello_text = b"Hello".as_slice();
        let hi_text = ucs2be("<b>Hi</b>");
        let stream = [
            hello(1),
            out_ch1(2, "100002", 0, hello_text),
            out_ch1(3, "100002", 2, &hi_text),
        ]
        .concat();
        let wire = [
            hello(1),
            out_ch1(2, "100002", 0, &apply_charset(0, hello_text).unwrap()),
            out_ch1(3, "100002", 2, &apply_charset(2, &hi_text).unwrap()),
        ]
        .concat();
        for piece in [&stream[..5], &stream[5..20], &stream[20..]] {
            hooked_send(s, piece);
        }
        let mut got = vec![0u8; wire.len()];
        server.read_exact(&mut got).unwrap();
        assert_eq!(got, wire);

        // In: nothing yet is the socket's own WSAEWOULDBLOCK.
        assert_eq!(hooked_recv(s, 64), None);

        // Half a frame is held back: the client is told "nothing yet".
        let back = b"Hello back".as_slice();
        let wire_in = [
            hello(1),
            in_ch1(2, "100002", 0, &apply_charset(0, back).unwrap()),
        ]
        .concat();
        let cut = hello(1).len() + 10;
        server.write_all(&wire_in[..cut]).unwrap();
        assert_eq!(read(s, hello(1).len(), 7), hello(1));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(hooked_recv(s, 64), None);

        // The rest completes it, delivered restored through a small buffer.
        server.write_all(&wire_in[cut..]).unwrap();
        let restored = in_ch1(2, "100002", 0, back);
        assert_eq!(read(s, restored.len(), 7), restored);

        // FIONREAD counts what the add-on holds for the client.
        let next = in_ch1(3, "100002", 0, b"counted");
        server.write_all(&next).unwrap();
        assert_eq!(read(s, 3, 3), next[..3]);
        let mut avail = 0u32;
        let r = unsafe { hook_ioctlsocket(s, FIONREAD as i32, &mut avail) };
        assert_eq!(r, 0);
        assert!(avail as usize >= next.len() - 3, "FIONREAD said {avail}");
        assert_eq!(read(s, next.len() - 3, 1024), next[3..]);

        // At the end of the stream a partial frame is dropped, never handed
        // to the client, and the end is reported (fifth audit of 2026-10,
        // finding 3: it used to be released as it was).
        let partial = &in_ch1(4, "1", 0, b"cut short")[..8];
        server.write_all(partial).unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(hooked_recv(s, 64), Some(Vec::new()));
        assert_eq!(hooked_recv(s, 64), Some(Vec::new()));
    }

    /// Whether the server end reads anything within a short wait.
    fn server_got_anything(server: &mut TcpStream) -> bool {
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut b = [0u8; 256];
        matches!(server.read(&mut b), Ok(n) if n > 0)
    }

    /// Audit 2026-10, finding 1: a panic in the `send` body used to call the
    /// original `send` with the client's own buffer - the plaintext the
    /// add-on was there to encrypt, past the TLS too.
    #[test]
    fn a_panic_in_send_sends_nothing_and_the_socket_stays_refused() {
        let (_client, mut server, s) = setup();
        hooked_send(s, &hello(1));
        let mut got = vec![0u8; hello(1).len()];
        server.read_exact(&mut got).unwrap();

        lock(panic_sockets()).insert(s);
        let secret = out_ch1(2, "100002", 0, b"secret text");
        let n = unsafe { hook_send(s, secret.as_ptr(), secret.len() as i32, 0) };
        assert_eq!(n, SOCKET_ERROR);
        assert_eq!(unsafe { GetLastError() }, tlsio::WSAECONNRESET);
        assert!(
            !server_got_anything(&mut server),
            "the client's buffer never reaches the wire"
        );

        // No panic this time, and still nothing: the socket is refused.
        let n = unsafe { hook_send(s, secret.as_ptr(), secret.len() as i32, 0) };
        assert_eq!(n, SOCKET_ERROR);
        assert_eq!(unsafe { GetLastError() }, tlsio::WSAECONNRESET);
        assert!(!server_got_anything(&mut server));
        let mut buf = [0u8; 64];
        let n = unsafe { hook_recv(s, buf.as_mut_ptr(), buf.len() as i32, 0) };
        assert_eq!(n, SOCKET_ERROR);
    }

    /// The same for `recv`: what the socket holds is never handed to the
    /// client unprocessed - undecrypted containers, or TLS records.
    #[test]
    fn a_panic_in_recv_hands_over_nothing_and_the_socket_stays_refused() {
        let (_client, mut server, s) = setup();
        let wire = [hello(1), in_ch1(2, "100002", 0, b"as it came")].concat();
        server.write_all(&wire).unwrap();
        std::thread::sleep(Duration::from_millis(50));

        lock(panic_sockets()).insert(s);
        let mut buf = vec![0u8; 256];
        let n = unsafe { hook_recv(s, buf.as_mut_ptr(), buf.len() as i32, 0) };
        assert_eq!(n, SOCKET_ERROR);
        assert_eq!(unsafe { GetLastError() }, tlsio::WSAECONNRESET);
        assert!(buf.iter().all(|&b| b == 0), "nothing was copied out");

        let n = unsafe { hook_recv(s, buf.as_mut_ptr(), buf.len() as i32, 0) };
        assert_eq!(n, SOCKET_ERROR, "the socket stays refused");
        assert!(buf.iter().all(|&b| b == 0));
        let n = unsafe { hook_send(s, wire.as_ptr(), wire.len() as i32, 0) };
        assert_eq!(n, SOCKET_ERROR);
    }
}

/// A token that arrives before the account does is kept until there is
/// somewhere to put it.
#[cfg(test)]
mod pending_token_tests {
    use super::*;
    use crate::directory::MemoryDirectory;

    /// The MOTD with the token arrives before the user info that names the
    /// account, so at that moment there is no session and nowhere to put the
    /// token. It has to wait there: taking it and finding no session threw it
    /// away for good, and the client then went out for the rest of its life
    /// with "no token yet; encryption stays off".
    #[test]
    fn a_token_that_arrives_before_the_account_is_kept() {
        let home = std::env::temp_dir().join("icqe2e-pending-token");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let dir: Arc<dyn crate::directory::DirectoryApi> = Arc::new(MemoryDirectory::new());

        let sock = Sock::new();
        // No session on this socket yet: this is the moment the MOTD landed.
        assert!(
            drain_pending_token(&sock).is_empty(),
            "there is nothing to apply it to yet"
        );

        // The token is set aside, as the MOTD handler does.
        *lock(&sock.pending_token) = Some(crate::token::unsigned("100001", u32::MAX));

        // Still no session: asking again must not consume it.
        assert!(
            drain_pending_token(&sock).is_empty(),
            "still nowhere to put it"
        );
        assert!(
            lock(&sock.pending_token).is_some(),
            "the token survived a drain with no session, which is the whole point"
        );

        // Now the account is known and the socket has its session.
        *lock(&sock.session) = Some(Arc::new(Mutex::new(
            crate::session::Session::open(dir, &home, "100001").unwrap(),
        )));
        let lines = drain_pending_token(&sock);
        assert!(
            lock(&sock.pending_token).is_none(),
            "now it is consumed: {:?}",
            lines
        );
    }

    /// The same socket, asked once more after the token was applied.
    #[test]
    fn a_token_is_applied_once_and_not_twice() {
        let home = std::env::temp_dir().join("icqe2e-pending-token-twice");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let dir: Arc<dyn crate::directory::DirectoryApi> = Arc::new(MemoryDirectory::new());

        let sock = Sock::new();
        *lock(&sock.pending_token) = Some(Vec::new());
        *lock(&sock.session) = Some(Arc::new(Mutex::new(
            crate::session::Session::open(dir, &home, "100001").unwrap(),
        )));

        drain_pending_token(&sock);
        assert!(
            drain_pending_token(&sock).is_empty(),
            "a token is taken once; there is no second one to apply"
        );
    }
}

/// Fourth review of 2026-10 (bootstrap and interception): two-phase
/// patching with rollback, the UTF-16 command line, and the fault matrix
/// through the real hook bodies over loopback sockets.
#[cfg(test)]
mod fourth_review {
    use super::tests::{iat_value, ordinal_entry, synthetic_pe};
    use super::*;
    use crate::config::{Settings, TlsPolicy};
    use crate::directory::MemoryDirectory;
    use crate::route::{Ports, Route};
    use crate::test_frames::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
    use std::os::windows::io::AsRawSocket;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Networking::WinSock;

    // --- two-phase patching -----------------------------------------------

    /// Writes the slots like `VirtualProtect` would, failing the `fail_at`th
    /// write (1-based; 0 never).
    struct FailingWriter {
        fail_at: usize,
        writes: usize,
    }

    impl ThunkWriter for FailingWriter {
        fn write(&mut self, addr: usize, value: u32) -> bool {
            self.writes += 1;
            if self.writes == self.fail_at {
                return false;
            }
            // SAFETY: addr is a slot of the test's own buffer.
            unsafe { ptr::write_unaligned(addr as *mut u32, value) };
            true
        }
    }

    type Slots = [AtomicUsize; 5];
    #[allow(clippy::declare_interior_mutable_const)]
    const EMPTY: AtomicUsize = AtomicUsize::new(0);

    fn specs(slots: &'static Slots) -> Vec<HookSpec> {
        vec![
            HookSpec::new("send", 0x1000_1000, &slots[0]),
            HookSpec::new("recv", 0x1000_2000, &slots[1]),
            HookSpec::new("connect", 0x1000_3000, &slots[2]),
            HookSpec::new("closesocket", 0x1000_4000, &slots[3]),
            HookSpec::new("accept", 0x1000_5000, &slots[4]),
        ]
    }

    fn table(dll: &str, ordinal: u16) -> Option<String> {
        known_ordinal_name(dll, ordinal).map(str::to_string)
    }

    /// Finding C: a write that fails half way puts back every slot written
    /// before it, and nothing counts as installed; the old `patch_iat` left
    /// the module half patched (and returned `Ok` when `VirtualProtect`
    /// failed for a slot).
    #[test]
    fn a_failed_write_half_way_rolls_every_slot_back() {
        let entries = [
            ordinal_entry(4),
            ordinal_entry(3),
            ordinal_entry(16),
            ordinal_entry(19),
            ordinal_entry(1),
        ];
        for fail_at in 1..=5 {
            let mut img = synthetic_pe("WSOCK32.dll", &entries);
            let before: Vec<usize> = (0..5).map(|i| iat_value(&img, i)).collect();
            let slots: &'static Slots = Box::leak(Box::new([EMPTY; 5]));
            let mut w = FailingWriter { fail_at, writes: 0 };
            let r = patch_with(img.as_mut_ptr() as usize, &specs(slots), &table, &mut w);
            let err = r.expect_err("a failed write is no install");
            assert!(err.contains("put back"), "{err}");
            let after: Vec<usize> = (0..5).map(|i| iat_value(&img, i)).collect();
            assert_eq!(
                after, before,
                "fail at write {fail_at}: every slot as it was"
            );
        }
        // With no failure every slot is written, and the mask says which.
        let mut img = synthetic_pe("WSOCK32.dll", &entries);
        let slots: &'static Slots = Box::leak(Box::new([EMPTY; 5]));
        let (mask, _) = patch_with(
            img.as_mut_ptr() as usize,
            &specs(slots),
            &table,
            &mut FailingWriter {
                fail_at: 0,
                writes: 0,
            },
        )
        .unwrap();
        assert_eq!(
            mask,
            HookMask::SEND
                .with(HookMask::RECV)
                .with(HookMask::CONNECT)
                .with(HookMask::CLOSE)
                .with(HookMask::ACCEPT)
        );
        assert_eq!(iat_value(&img, 0), 0x1000_3000);
        assert_eq!(slots[2].load(Ordering::Acquire), 0x7FFF_0000);
    }

    /// DISCOVER changes nothing when one slot is not bound yet, even if the
    /// others are.
    #[test]
    fn discovery_changes_nothing_when_one_slot_is_unbound() {
        let mut img = synthetic_pe("WSOCK32.dll", &[ordinal_entry(19), ordinal_entry(16)]);
        let at = super::tests::IAT + 4;
        img[at..at + 4].copy_from_slice(&ordinal_entry(16).to_le_bytes());
        let slots: &'static Slots = Box::leak(Box::new([EMPTY; 5]));
        let err = patch_with(
            img.as_mut_ptr() as usize,
            &specs(slots),
            &table,
            &mut FailingWriter {
                fail_at: 0,
                writes: 0,
            },
        )
        .unwrap_err();
        assert!(err.contains("not bound yet"), "{err}");
        assert_eq!(iat_value(&img, 0), 0x7FFF_0000, "send untouched");
        assert_eq!(slots[0].load(Ordering::Acquire), 0, "no original taken");
    }

    // --- the command line (finding F) -------------------------------------

    #[test]
    fn the_uin_is_read_from_a_utf16_command_line() {
        let line = "\"C:\\Program Files (x86)\\ICQ7.2\\ICQ.exe\" -uin 123456 -tray";
        assert_eq!(
            uin_from_args(&split_command_line(line)).as_deref(),
            Some("123456")
        );
        let units: Vec<u16> =
            "\"C:\\Users\\\u{424}\u{451}\u{434}\u{43e}\u{440}\\ICQ\\ICQ.exe\" /UIN 777"
                .encode_utf16()
                .collect();
        assert_eq!(
            uin_from_args(&split_command_line(&String::from_utf16_lossy(&units))).as_deref(),
            Some("777")
        );
        // What the old code read: the UTF-16 taken as a C string of bytes
        // ends after the first character, so -uin was never seen.
        let bytes: Vec<u8> = units
            .iter()
            .flat_map(|u| u.to_le_bytes())
            .chain([0, 0])
            .collect();
        // SAFETY: a NUL-terminated buffer of our own.
        let old = unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr().cast()) };
        assert_eq!(old.to_bytes(), b"\"");
        // CommandLineToArgvW's quoting rules.
        assert_eq!(
            split_command_line(r#"a "b c" d\"e "f\\" g"#),
            vec!["a", "b c", "d\"e", "f\\", "g"]
        );
        assert_eq!(
            uin_from_args(&split_command_line("x -uin notanumber")),
            None
        );
        assert_eq!(uin_from_args(&split_command_line("x -uin")), None);
        assert_eq!(uin_from_args(&split_command_line("x")), None);
    }

    // --- the fault matrix -------------------------------------------------

    /// Every internal failure, as the hooks meet it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        Healthy,
        NoDirectory,
        NoUin,
        UnreadableState,
        CorruptState,
        LockedState,
        StillStarting,
        Fatal,
        RequiredHookMissing,
        RolledBack,
        PanicInSend,
        PanicInRecv,
        FlapDesync,
        CallHooksMissing,
        /// The call modules not loaded and patched yet (fifth audit of
        /// 2026-10, finding 5).
        CallModulesNotPatched,
        FileHooksMissing,
    }

    const FAULTS: [Fault; 16] = [
        Fault::Healthy,
        Fault::NoDirectory,
        Fault::NoUin,
        Fault::UnreadableState,
        Fault::CorruptState,
        Fault::LockedState,
        Fault::StillStarting,
        Fault::Fatal,
        Fault::RequiredHookMissing,
        Fault::RolledBack,
        Fault::PanicInSend,
        Fault::PanicInRecv,
        Fault::FlapDesync,
        Fault::CallHooksMissing,
        Fault::CallModulesNotPatched,
        Fault::FileHooksMissing,
    ];

    impl Fault {
        /// Whether the add-on has no keys for the account.
        fn no_keys(self) -> bool {
            matches!(
                self,
                Fault::NoDirectory
                    | Fault::NoUin
                    | Fault::UnreadableState
                    | Fault::CorruptState
                    | Fault::LockedState
            )
        }

        /// Whether the bootstrap refuses everything.
        fn not_in_place(self) -> bool {
            matches!(
                self,
                Fault::StillStarting
                    | Fault::Fatal
                    | Fault::RequiredHookMissing
                    | Fault::RolledBack
                    | Fault::FileHooksMissing
            )
        }

        /// Whether the connection is reset by the fault itself.
        fn resets(self) -> bool {
            matches!(
                self,
                Fault::PanicInSend | Fault::PanicInRecv | Fault::FlapDesync
            )
        }
    }

    /// What the test sends, and the policy it needs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Traffic {
        /// A message to an automatic contact.
        MessageAuto,
        /// A message to a contact under `/e2e on`.
        MessageOn,
        /// A call's INVITE with `calls_encrypt=required`.
        CallRequired,
        /// A call's INVITE with `calls_encrypt=on` to a contact under
        /// `/e2e on`.
        CallStrict,
        /// A call's INVITE with `calls_encrypt=on` to an automatic contact.
        CallAuto,
        /// A file proposal with `files_encrypt=required`.
        FileRequired,
    }

    const TRAFFIC: [Traffic; 6] = [
        Traffic::MessageAuto,
        Traffic::MessageOn,
        Traffic::CallRequired,
        Traffic::CallStrict,
        Traffic::CallAuto,
        Traffic::FileRequired,
    ];

    const SECRET: &[u8] = b"SECRET-only-for-100002";
    const INVITE: &[u8] = b"INVITE sip:100002@h SIP/2.0";

    fn policy_for(t: Traffic, home: &Path) -> Policy {
        let mut p = Policy::from_settings(Settings {
            mode: Some("encrypt"),
            e2e: Some("on"),
            directory: Some("https://example.invalid/e2e/v1/"),
            home: Some(home.to_str().unwrap()),
            server: Some(""),
            no_inject: Some("0"),
            ..Default::default()
        });
        p.peers = None;
        p.tls = TlsPolicy::NoServer;
        p.calls_log = false;
        p.files_log = false;
        p.calls_encrypt = matches!(
            t,
            Traffic::CallRequired | Traffic::CallStrict | Traffic::CallAuto
        );
        p.calls_required = t == Traffic::CallRequired;
        p.files_encrypt = t == Traffic::FileRequired;
        p.files_required = t == Traffic::FileRequired;
        p.auditors = None;
        p
    }

    /// The gate a fault leaves.
    fn gate_for(f: Fault, p: &Policy) -> &'static gate::Gate {
        let g: &'static gate::Gate = Box::leak(Box::new(gate::Gate::new()));
        match f {
            Fault::StillStarting => {}
            Fault::Fatal => g.fail("no coolcore5x/4x networking module appeared".into()),
            Fault::RequiredHookMissing => {
                g.installed(Ok(HookMask::ALL.missing(HookMask::CONNECT)));
                g.settle(p);
            }
            Fault::RolledBack => {
                g.installed(Err("VirtualProtect failed; every slot put back".into()));
                g.settle(p);
            }
            Fault::FileHooksMissing => {
                g.installed(Ok(HookMask::ALL.missing(HookMask::ACCEPT)));
                g.settle(p);
            }
            _ => {
                g.installed(Ok(HookMask::ALL));
                g.settle(p);
            }
        }
        // The bootstrap loads and patches the call modules before the gate
        // opens; this fault is the state before that.
        if f != Fault::CallModulesNotPatched {
            g.set_media(0, gate::MediaHooks::Ready);
            g.set_media(1, gate::MediaHooks::Ready);
        }
        if f == Fault::CallHooksMissing {
            g.set_media(
                1,
                gate::MediaHooks::Failed("sipXmediaLib.dll not patched".into()),
            );
        }
        g
    }

    fn sip_out(seq: u16) -> Vec<u8> {
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8];
        body.extend_from_slice(&crate::calls::CHANNEL_SIP.to_be_bytes());
        body.push(6);
        body.extend_from_slice(b"100002");
        let sip = [INVITE, b"\r\nCall-ID: m\r\nCSeq: 1 INVITE\r\n\r\n"].concat();
        body.extend_from_slice(&tlv(crate::calls::TLV_SIP, &sip));
        data(seq, &snac(0x0004, 0x0006, &body))
    }

    fn file_out(seq: u16) -> Vec<u8> {
        data(
            seq,
            &crate::direct::tests::rdv(
                Direction::Outbound,
                "100002",
                crate::files::RDV_PROPOSE,
                [9; 8],
                crate::files::CAP_FILE_TRANSFER,
            ),
        )
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn utf16be(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    fn point_at_winsock() {
        ORIG_SEND.store(WinSock::send as *const () as usize, Ordering::Release);
        ORIG_RECV.store(WinSock::recv as *const () as usize, Ordering::Release);
        ORIG_CONNECT.store(WinSock::connect as *const () as usize, Ordering::Release);
        ORIG_IOCTL.store(
            WinSock::ioctlsocket as *const () as usize,
            Ordering::Release,
        );
        ORIG_GETPEERNAME.store(
            WinSock::getpeername as *const () as usize,
            Ordering::Release,
        );
    }

    fn pair() -> (TcpStream, TcpStream, Socket) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        client.set_nonblocking(true).unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(60)))
            .unwrap();
        let s = client.as_raw_socket() as Socket;
        // The connect above is not the hooked one, which would drop what an
        // earlier connection left under this handle. Tests running alongside
        // close their sockets past the hooks, and Windows reuses handles, so
        // a case could inherit another test's socket state; drop it here as
        // the hooked connect does.
        lock(sockets()).remove(&s);
        lock(panic_sockets()).remove(&s);
        (client, server, s)
    }

    /// Everything the server end can read now.
    fn wire(server: &mut TcpStream) -> Vec<u8> {
        let mut all = Vec::new();
        let mut b = [0u8; 4096];
        while let Ok(n) = server.read(&mut b) {
            if n == 0 {
                break;
            }
            all.extend_from_slice(&b[..n]);
        }
        all
    }

    /// Everything the client gets through the hooked `recv` now.
    fn shown(s: Socket) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut all = Vec::new();
        while Instant::now() < deadline {
            let mut b = vec![0u8; 4096];
            // SAFETY: b is valid for the call.
            let n = unsafe { hook_recv(s, b.as_mut_ptr(), b.len() as i32, 0) };
            if n > 0 {
                all.extend_from_slice(&b[..n as usize]);
                continue;
            }
            // SAFETY: reads the thread's last error.
            if n == 0 || unsafe { GetLastError() } != WSAEWOULDBLOCK {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        all
    }

    fn send(s: Socket, bytes: &[u8]) -> i32 {
        // SAFETY: bytes is valid for the call.
        unsafe { hook_send(s, bytes.as_ptr(), bytes.len() as i32, 0) }
    }

    struct Outcome {
        wire: Vec<u8>,
        shown: Vec<u8>,
        sent: i32,
    }

    /// One case: a fresh account, its fault prepared, a connection through
    /// the hooks that has opened both ways, then the traffic out and a
    /// container in.
    fn run(f: Fault, t: Traffic, n: usize) -> Outcome {
        point_at_winsock();
        let home: PathBuf = std::env::temp_dir().join(format!("icqe2e-matrix-{n}"));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let uin = format!("{}", 500_000 + n);
        let dir: Arc<dyn crate::directory::DirectoryApi> = Arc::new(MemoryDirectory::new());
        let mut _holder = None;
        match f {
            Fault::UnreadableState => {
                std::fs::create_dir_all(home.join(format!("{uin}.state"))).unwrap();
            }
            Fault::CorruptState => {
                std::fs::write(home.join(format!("{uin}.state")), b"\x00corrupt state\xFF")
                    .unwrap();
            }
            Fault::LockedState => {
                _holder = Some(Session::open(dir.clone(), &home, &uin).unwrap());
            }
            _ => {}
        }
        let p = policy_for(t, &home);
        let g = gate_for(f, &p);
        gate::use_for_this_thread(Some(g));
        tlsio::TEST_SETUP.with(|s| *s.borrow_mut() = Some(Arc::new(tlsio::Setup::Inactive)));
        test_env::set(
            p,
            (f != Fault::NoDirectory).then(|| dir.clone()),
            (f != Fault::NoUin).then_some(uin.as_str()),
        );

        let (_client, mut server, s) = pair();
        server.write_all(&hello(1)).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let _ = shown(s);
        let _ = send(s, &hello(1));
        let _ = wire(&mut server);
        if matches!(t, Traffic::MessageOn | Traffic::CallStrict) {
            let _ = send(s, &out_ch1(2, "100002", 0, b"/e2e on"));
            let _ = shown(s);
        }
        if f == Fault::PanicInSend {
            lock(panic_sockets()).insert(s);
        }
        if f == Fault::PanicInRecv {
            // The next read panics: the connection is refused for good
            // before the traffic is sent.
            lock(panic_sockets()).insert(s);
            server.write_all(&in_ch1(2, "100002", 0, b"hello")).unwrap();
            std::thread::sleep(Duration::from_millis(20));
            let _ = shown(s);
        }
        let traffic = match t {
            Traffic::MessageAuto | Traffic::MessageOn => out_ch1(3, "100002", 0, SECRET),
            Traffic::CallRequired | Traffic::CallStrict | Traffic::CallAuto => sip_out(3),
            Traffic::FileRequired => file_out(3),
        };
        let traffic = if f == Fault::FlapDesync {
            [b"\x2A\x09 not a frame ".to_vec(), traffic].concat()
        } else {
            traffic
        };
        let sent = send(s, &traffic);
        let mut shown_bytes = shown(s);
        // A container from the contact, which must never reach the client
        // undecrypted.
        let armor = crate::container::armor(
            &crate::container::Container {
                flags: 0,
                sender_device: 7,
                wraps: Vec::new(),
                ciphertext: vec![1, 2, 3, 4],
            }
            .to_bytes(),
        );
        let _ = server.write_all(&in_ch1(2, "100002", 0, armor.as_bytes()));
        std::thread::sleep(Duration::from_millis(20));
        shown_bytes.extend(shown(s));
        assert!(
            !contains(&shown_bytes, armor.as_bytes()),
            "{f:?}/{t:?}: a container reached the client undecrypted"
        );
        let out = Outcome {
            wire: wire(&mut server),
            shown: shown_bytes,
            sent,
        };
        lock(sockets()).remove(&s);
        lock(panic_sockets()).remove(&s);
        test_env::clear();
        gate::use_for_this_thread(None);
        tlsio::TEST_SETUP.with(|s| *s.borrow_mut() = None);
        drop(_holder);
        let _ = std::fs::remove_dir_all(&home);
        out
    }

    /// The invariant (fourth review): for every internal failure x traffic,
    /// nothing the policy requires to be protected crosses the boundary in
    /// the clear because of the failure; control traffic passes exactly when
    /// the add-on is in place; and when everything is healthy the
    /// compatibility paths still work - a message to an automatic contact
    /// without the add-on goes plain WITH a note, a call with an automatic
    /// contact goes as it is when only the call hooks failed, with a note.
    #[test]
    fn no_internal_failure_lets_protected_traffic_out() {
        let mut n = 0;
        let mut ran = 0;
        for f in FAULTS {
            for t in TRAFFIC {
                n += 1;
                let o = run(f, t, n);
                ran += 1;
                let case = format!(
                    "{f:?} / {t:?}: sent {} wire {:?} shown {:?}",
                    o.sent,
                    String::from_utf8_lossy(&o.wire),
                    String::from_utf8_lossy(&o.shown)
                );
                let note = utf16be("[ICQ E2E]");
                match t {
                    Traffic::MessageAuto | Traffic::MessageOn => {
                        let plain_ok = f == Fault::Healthy && t == Traffic::MessageAuto
                            || matches!(f, Fault::CallHooksMissing | Fault::CallModulesNotPatched)
                                && t == Traffic::MessageAuto;
                        assert_eq!(contains(&o.wire, SECRET), plain_ok, "{case}");
                        if plain_ok {
                            assert!(
                                contains(&o.shown, &utf16be("are sent unencrypted")),
                                "compatibility: plain WITH a note: {case}"
                            );
                        }
                    }
                    Traffic::CallRequired | Traffic::CallStrict | Traffic::CallAuto => {
                        let plain_ok = matches!(
                            f,
                            Fault::Healthy | Fault::CallHooksMissing | Fault::CallModulesNotPatched
                        ) && t == Traffic::CallAuto
                            || f == Fault::Healthy;
                        assert_eq!(contains(&o.wire, INVITE), plain_ok, "{case}");
                    }
                    Traffic::FileRequired => {
                        let proposal = &file_out(3)[6..];
                        let plain_ok = matches!(
                            f,
                            Fault::Healthy | Fault::CallHooksMissing | Fault::CallModulesNotPatched
                        );
                        assert_eq!(contains(&o.wire, proposal), plain_ok, "{case}");
                    }
                }
                if f.not_in_place() || f.resets() {
                    assert_eq!(o.sent, SOCKET_ERROR, "{case}");
                    assert!(o.wire.is_empty(), "nothing at all: {case}");
                }
                let message = matches!(t, Traffic::MessageAuto | Traffic::MessageOn);
                if message && (f.no_keys() || (f == Fault::Healthy && t == Traffic::MessageOn)) {
                    assert!(contains(&o.shown, &note), "said in the chat: {case}");
                }
            }
        }
        assert_eq!(ran, FAULTS.len() * TRAFFIC.len());
    }

    // --- connect: TLS on, and the guard ports with tls=off ----------------

    fn raw_socket() -> Socket {
        // SAFETY: a plain TCP socket of our own (std has started Winsock).
        unsafe { WinSock::socket(2, 1, 6) as Socket }
    }

    fn accepted_within(l: &TcpListener, ms: u64) -> bool {
        l.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            if l.accept().is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn with_setup<T>(setup: tlsio::Setup, f: Fault, body: impl FnOnce() -> T) -> T {
        point_at_winsock();
        tlsio::capture_notices();
        let home = std::env::temp_dir().join("icqe2e-matrix-connect");
        let mut p = policy_for(Traffic::MessageAuto, &home);
        p.tls = TlsPolicy::Off {
            server: "icq.example.org".into(),
        };
        let g = gate_for(f, &p);
        gate::use_for_this_thread(Some(g));
        tlsio::TEST_SETUP.with(|s| *s.borrow_mut() = Some(Arc::new(setup)));
        test_env::set(p, None, None);
        let r = body();
        test_env::clear();
        gate::use_for_this_thread(None);
        tlsio::TEST_SETUP.with(|s| *s.borrow_mut() = None);
        r
    }

    /// Finding G, in the add-on: with `tls=off` the guard port of the server
    /// goes to its plain port, and `getpeername` reports the guard port;
    /// with the add-on not in place nothing is connected at all.
    #[test]
    fn a_guard_port_goes_to_the_plain_port_only_through_the_add_on() {
        for f in [
            Fault::Healthy,
            Fault::Fatal,
            Fault::StillStarting,
            Fault::RolledBack,
        ] {
            let plain = TcpListener::bind("127.0.0.1:0").unwrap();
            let plain_port = plain.local_addr().unwrap().port();
            let guard = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let route = Route::new(
                "icq.example.org",
                Ports {
                    flap: Vec::new(),
                    http: Vec::new(),
                    tls: 0,
                    guard: vec![(guard, plain_port)],
                },
                Box::new(|_| vec![Ipv4Addr::LOCALHOST]),
            );
            let setup = tlsio::Setup::OptedOut {
                server: "icq.example.org".into(),
                guard: Some(route),
            };
            let s = raw_socket();
            let (r, peer) = with_setup(setup, f, || {
                let (r, _) = testing::connect(s, SocketAddrV4::new(Ipv4Addr::LOCALHOST, guard));
                (r, testing::peer_port(s))
            });
            let reached = accepted_within(&plain, 300);
            if f == Fault::Healthy {
                assert_eq!(r, 0, "{f:?}");
                assert!(reached, "{f:?}: the plain port was reached");
                assert_eq!(peer, Some(guard), "getpeername reports the guard port");
            } else {
                assert_eq!(r, SOCKET_ERROR, "{f:?}");
                assert!(!reached, "{f:?}: nothing connected");
            }
            lock(sockets()).remove(&s);
            // SAFETY: our own socket.
            unsafe { WinSock::closesocket(s) };
        }
    }

    /// With TLS on, a connection to the server never leaves in plain: a
    /// failure of the add-on refuses it before the mapping is asked, and a
    /// TLS client that cannot be made refuses it at the mapping.
    #[test]
    fn with_tls_on_no_connection_to_the_server_leaves_plain() {
        for f in [Fault::Healthy, Fault::Fatal, Fault::StillStarting] {
            let server = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = server.local_addr().unwrap().port();
            let route = Route::new(
                "icq.example.org",
                Ports {
                    flap: vec![port],
                    http: Vec::new(),
                    tls: port,
                    guard: Vec::new(),
                },
                Box::new(|_| vec![Ipv4Addr::LOCALHOST]),
            );
            let setup = tlsio::Setup::Active(tlsio::Active {
                route,
                client: Err(crate::tls::TlsFailure::Setup(
                    "no TLS client in this test".into(),
                )),
            });
            let s = raw_socket();
            let (r, err) = with_setup(setup, f, || {
                testing::connect(s, SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            });
            assert_eq!(r, SOCKET_ERROR, "{f:?}");
            assert_eq!(err, tlsio::WSAECONNREFUSED, "{f:?}");
            assert!(!accepted_within(&server, 200), "{f:?}: nothing connected");
            lock(sockets()).remove(&s);
            // SAFETY: our own socket.
            unsafe { WinSock::closesocket(s) };
        }
        let _ = tlsio::take_notices();
    }
}
