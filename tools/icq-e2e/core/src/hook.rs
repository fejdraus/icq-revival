//! Winsock interception, installed by IAT-patching the client's own networking
//! module (coolcore59.dll on 7.2, coolcore49.dll on 6.5). We swap that module's
//! import thunks for `wsock32.dll` `send`, `recv`, `connect`, `closesocket`,
//! `WSAAsyncSelect` and `ioctlsocket` (6.5 only imports the last).
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
//! Each socket has separate locks per direction, so a `recv` waiting on one
//! thread never holds up a `send` on another. Every hook body runs under
//! `catch_unwind`; a panic falls back to the original call.

use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
use crate::icbm::Direction;
use crate::log;
use crate::stream::StreamRewriter;

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

// Original function pointers, kept as raw addresses and transmuted on call.
static ORIG_SEND: AtomicUsize = AtomicUsize::new(0);
static ORIG_RECV: AtomicUsize = AtomicUsize::new(0);
static ORIG_CONNECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_CLOSE: AtomicUsize = AtomicUsize::new(0);
static ORIG_ASYNC_SELECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_IOCTL: AtomicUsize = AtomicUsize::new(0);

static INSTALLED: AtomicBool = AtomicBool::new(false);

// Log the first observed bytes in each direction once, so the log confirms the
// hooks are live even before any instant message is exchanged.
static FIRST_SEND: AtomicBool = AtomicBool::new(false);
static FIRST_RECV: AtomicBool = AtomicBool::new(false);

static POLICY: OnceLock<Policy> = OnceLock::new();

fn policy() -> &'static Policy {
    POLICY.get_or_init(Policy::observe)
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
}

impl Sock {
    fn new() -> Self {
        Sock {
            peer: Mutex::new(None),
            notify: Mutex::new(None),
            out: Mutex::new(OutSide {
                rw: StreamRewriter::new(Direction::Outbound),
                pending: Vec::new(),
            }),
            inb: Mutex::new(InSide {
                rw: StreamRewriter::new(Direction::Inbound),
                ready: Vec::new(),
                eof: false,
            }),
        }
    }
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

// --- Winsock function types (all __stdcall on x86) --------------------------

type SendFn = unsafe extern "system" fn(Socket, *const u8, i32, i32) -> i32;
type RecvFn = unsafe extern "system" fn(Socket, *mut u8, i32, i32) -> i32;
type ConnectFn = unsafe extern "system" fn(Socket, *const u8, i32) -> i32;
type CloseFn = unsafe extern "system" fn(Socket) -> i32;
type AsyncSelectFn = unsafe extern "system" fn(Socket, usize, u32, i32) -> i32;
type IoctlFn = unsafe extern "system" fn(Socket, i32, *mut u32) -> i32;

unsafe fn orig_send() -> SendFn {
    std::mem::transmute(ORIG_SEND.load(Ordering::Acquire))
}

unsafe fn orig_recv() -> RecvFn {
    std::mem::transmute(ORIG_RECV.load(Ordering::Acquire))
}

// --- hook bodies ------------------------------------------------------------

unsafe extern "system" fn hook_send(s: Socket, buf: *const u8, len: i32, flags: i32) -> i32 {
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
        Err(_) => orig_send()(s, buf, len, flags),
    }
}

unsafe extern "system" fn hook_recv(s: Socket, buf: *mut u8, len: i32, flags: i32) -> i32 {
    if policy().mode == Mode::Observe || len <= 0 || buf.is_null() || flags & MSG_OOB != 0 {
        let n = orig_recv()(s, buf, len, flags);
        if n > 0 && !buf.is_null() && flags & (MSG_OOB | MSG_PEEK) == 0 {
            let err = GetLastError();
            let data = std::slice::from_raw_parts(buf, n as usize);
            let _ = panic::catch_unwind(AssertUnwindSafe(|| observe(s, data, Direction::Inbound)));
            SetLastError(err);
        }
        return n;
    }
    match panic::catch_unwind(AssertUnwindSafe(|| {
        harness_recv(s, buf, len as usize, flags)
    })) {
        Ok(n) => n,
        Err(_) => orig_recv()(s, buf, len, flags),
    }
}

unsafe extern "system" fn hook_connect(s: Socket, name: *const u8, namelen: i32) -> i32 {
    let orig: ConnectFn = std::mem::transmute(ORIG_CONNECT.load(Ordering::Acquire));
    let r = orig(s, name, namelen);
    let err = GetLastError();
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let peer = parse_sockaddr(name, namelen);
        let sock = sock_for(s);
        let mut p = lock(&sock.peer);
        if p.is_none() {
            *p = peer;
        }
    }));
    SetLastError(err);
    r
}

unsafe extern "system" fn hook_closesocket(s: Socket) -> i32 {
    let orig: CloseFn = std::mem::transmute(ORIG_CLOSE.load(Ordering::Acquire));
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        lock(sockets()).remove(&s);
    }));
    orig(s)
}

unsafe extern "system" fn hook_async_select(s: Socket, hwnd: usize, msg: u32, events: i32) -> i32 {
    let orig: AsyncSelectFn = std::mem::transmute(ORIG_ASYNC_SELECT.load(Ordering::Acquire));
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        *lock(&sock_for(s).notify) = Some(Notify { hwnd, msg, events });
    }));
    orig(s, hwnd, msg, events)
}

unsafe extern "system" fn hook_ioctlsocket(s: Socket, cmd: i32, argp: *mut u32) -> i32 {
    let orig: IoctlFn = std::mem::transmute(ORIG_IOCTL.load(Ordering::Acquire));
    let r = orig(s, cmd, argp);
    if r == 0 && cmd as u32 == FIONREAD && !argp.is_null() && policy().mode == Mode::Harness {
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            if let Some(sock) = existing_sock(s) {
                // try_lock: a recv blocked on another thread must not block this.
                if let Ok(side) = sock.inb.try_lock() {
                    *argp = (*argp).saturating_add(side.ready.len() as u32);
                }
            }
        }));
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
    first_bytes_note(Direction::Outbound, s, data.len());
    let sock = sock_for(s);
    let mut side = lock(&sock.out);
    if side.rw.is_raw() && side.pending.is_empty() {
        // SAFETY: data is the client's buffer, valid for the call.
        return unsafe { orig_send()(s, data.as_ptr(), data.len() as i32, flags) };
    }
    let OutSide { rw, pending } = &mut *side;
    let lines = rw.push(data, policy(), pending);
    log_lines(&sock, lines);
    match flush(s, pending, flags) {
        Ok(()) => data.len() as i32,
        Err(err) => {
            // SAFETY: sets the calling thread's last error.
            unsafe { SetLastError(err) };
            SOCKET_ERROR
        }
    }
}

/// Sends `pending` out with the original `send`, waiting for room on
/// `WSAEWOULDBLOCK`. What went out is removed. A hard error is returned; a
/// buffer that stays full past [`SEND_WAIT_MS`] leaves the rest pending for the
/// next call.
fn flush(s: Socket, pending: &mut Vec<u8>, flags: i32) -> Result<(), u32> {
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
    let sock = sock_for(s);
    let mut side = lock(&sock.inb);
    if side.ready.is_empty() {
        if side.rw.is_raw() || side.eof {
            // SAFETY: the client's buffer, valid for len bytes.
            let n = unsafe { orig_recv()(s, buf, len as i32, flags) };
            if n > 0 {
                let err = unsafe { GetLastError() };
                first_bytes_note(Direction::Inbound, s, n as usize);
                unsafe { SetLastError(err) };
            }
            return n;
        }
        let mut tmp = vec![0u8; len.max(READ_CHUNK)];
        loop {
            // SAFETY: tmp is our own buffer of tmp.len() bytes.
            let n =
                unsafe { orig_recv()(s, tmp.as_mut_ptr(), tmp.len() as i32, flags & !MSG_PEEK) };
            if n > 0 {
                first_bytes_note(Direction::Inbound, s, n as usize);
                let InSide { rw, ready, .. } = &mut *side;
                let lines = rw.push(&tmp[..n as usize], policy(), ready);
                log_lines(&sock, lines);
                if side.ready.is_empty() {
                    // Only part of a frame so far; ask the socket again.
                    continue;
                }
                break;
            }
            if n == 0 {
                let InSide { rw, ready, eof } = &mut *side;
                rw.finish(ready);
                *eof = true;
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
    let more = !peek && !side.ready.is_empty();
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

/// Starts a background thread that waits for the networking module to load and
/// then installs the hooks. Safe to call more than once; only the first install
/// takes effect. Called from each loader's DllMain with the policy read from
/// the environment.
pub fn start(p: Policy) {
    let _ = POLICY.set(p);
    // SAFETY: CreateThread with a plain function; no captured state.
    unsafe {
        let h = CreateThread(
            ptr::null(),
            0,
            Some(install_thread),
            ptr::null(),
            0,
            ptr::null_mut(),
        );
        if !h.is_null() {
            windows_sys::Win32::Foundation::CloseHandle(h);
        }
    }
}

unsafe extern "system" fn install_thread(_: *mut core::ffi::c_void) -> u32 {
    log::line("install worker running; searching for the networking module (coolcore5x/4x)");
    // A quick sanity line comparing name-based lookups, since a wrong name/case
    // or ANSI-vs-wide lookup would explain a module that is loaded but not found.
    log_named_lookups();

    // The networking module may not be loaded yet (load order). Poll for it,
    // logging what happens at each stage.
    let mut warned_not_loaded = false;
    for attempt in 0..600u32 {
        if INSTALLED.load(Ordering::Acquire) {
            return 0;
        }
        match find_networking_module(attempt == 0) {
            Some((name, base)) => {
                log::line(&format!(
                    "networking module found: {name} at base {base:#010x}"
                ));
                match patch_iat(
                    base,
                    "wsock32.dll",
                    &[
                        // (name, wsock32 ordinal, hook, original-pointer slot).
                        // coolcore59.dll and coolcore49.dll import WSOCK32.dll by
                        // ordinal only, so the ordinal is what identifies a slot.
                        ("send", 19u16, hook_send as SendFn as usize, &ORIG_SEND),
                        ("recv", 16u16, hook_recv as RecvFn as usize, &ORIG_RECV),
                        (
                            "connect",
                            4u16,
                            hook_connect as ConnectFn as usize,
                            &ORIG_CONNECT,
                        ),
                        (
                            "closesocket",
                            3u16,
                            hook_closesocket as CloseFn as usize,
                            &ORIG_CLOSE,
                        ),
                        (
                            "WSAAsyncSelect",
                            101u16,
                            hook_async_select as AsyncSelectFn as usize,
                            &ORIG_ASYNC_SELECT,
                        ),
                        // Imported by coolcore49.dll (6.5) only.
                        (
                            "ioctlsocket",
                            10u16,
                            hook_ioctlsocket as IoctlFn as usize,
                            &ORIG_IOCTL,
                        ),
                    ],
                ) {
                    Ok(report) => {
                        if ORIG_SEND.load(Ordering::Acquire) != 0
                            && ORIG_RECV.load(Ordering::Acquire) != 0
                        {
                            INSTALLED.store(true, Ordering::Release);
                            log::line(&format!(
                                "hooks installed in {name}: {report}; {}",
                                policy().describe()
                            ));
                        } else {
                            log::line(&format!(
                                "giving up: {name} parsed but send/recv thunks were not patched ({report})"
                            ));
                        }
                        return 0;
                    }
                    Err(reason) => {
                        log::line(&format!("giving up: could not patch {name}: {reason}"));
                        return 0;
                    }
                }
            }
            None => {
                if !warned_not_loaded {
                    log::line("networking module not loaded yet; waiting for it");
                    warned_not_loaded = true;
                } else if attempt % 100 == 0 && attempt > 0 {
                    log::line(&format!(
                        "still waiting for the networking module ({}s)",
                        attempt / 10
                    ));
                }
            }
        }
        Sleep(100);
    }
    log::line("gave up after 60s: no coolcore5x/4x module appeared among the loaded modules");
    0
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

/// Patches the named module's import thunks for the given functions of `dll`.
/// Returns a report string of what was patched, or an error reason. Logs the
/// intermediate findings so a partial or failed patch is explained.
fn patch_iat(
    base: usize,
    dll: &str,
    funcs: &[(&str, u16, usize, &AtomicUsize)],
) -> Result<String, String> {
    // SAFETY: base is a loaded module; all reads are bounds-guarded by the PE
    // structure and stay within the mapped image.
    unsafe {
        let rd32 = |off: usize| ptr::read_unaligned((base + off) as *const u32);
        if rd32(0) & 0xFFFF != 0x5A4D {
            return Err("no MZ signature".to_string());
        }
        let e_lfanew = ptr::read_unaligned((base + 0x3C) as *const u32) as usize;
        if rd32(e_lfanew) != 0x0000_4550 {
            return Err("no PE signature".to_string());
        }
        let magic = ptr::read_unaligned((base + e_lfanew + 0x18) as *const u16);
        if magic != 0x010B {
            return Err(format!("not PE32 (optional header magic {magic:#06x})"));
        }
        let import_rva = rd32(e_lfanew + 0x80) as usize;
        if import_rva == 0 {
            return Err("no import directory".to_string());
        }
        let mut imported_dlls: Vec<String> = Vec::new();
        let mut dll_found = false;
        let mut matched: Vec<&str> = Vec::new();
        let mut desc = base + import_rva;
        loop {
            let name_rva = ptr::read_unaligned((desc + 12) as *const u32) as usize;
            let first_thunk = ptr::read_unaligned((desc + 16) as *const u32) as usize;
            if name_rva == 0 && first_thunk == 0 {
                break;
            }
            let dll_name = read_cstr(base + name_rva);
            imported_dlls.push(dll_name.clone());
            if dll_name.eq_ignore_ascii_case(dll) {
                dll_found = true;
                let orig_thunk = ptr::read_unaligned(desc as *const u32) as usize;
                let int_rva = if orig_thunk != 0 {
                    orig_thunk
                } else {
                    first_thunk
                };
                let by_int = orig_thunk != 0; // names come from the INT (unbound)
                let mut i = 0usize;
                loop {
                    let int_entry = ptr::read_unaligned((base + int_rva + i * 4) as *const u32);
                    if int_entry == 0 {
                        break;
                    }
                    // The INT is present for every wsock32 import in these
                    // clients, but the entries are ordinal imports (high bit
                    // set), not names - so match on the ordinal number.
                    if by_int {
                        let (fname, hook, orig_slot) = if int_entry & 0x8000_0000 == 0 {
                            let name_ptr = base + int_entry as usize + 2;
                            match funcs
                                .iter()
                                .find(|(fname, _, _, _)| cstr_eq_ci(name_ptr, fname))
                            {
                                Some(f) => (f.0, f.2, f.3),
                                None => {
                                    i += 1;
                                    continue;
                                }
                            }
                        } else {
                            let ordinal = (int_entry & 0x7FFF_FFFF) as u16;
                            match funcs.iter().find(|(_, want, _, _)| *want == ordinal) {
                                Some(f) => (f.0, f.2, f.3),
                                None => {
                                    i += 1;
                                    continue;
                                }
                            }
                        };
                        let slot = base + first_thunk + i * 4;
                        if write_thunk(slot, hook, orig_slot) {
                            matched.push(fname);
                        }
                    }
                    i += 1;
                }
            }
            desc += 20;
        }
        if !dll_found {
            return Err(format!(
                "{dll} not among imports of the module; imports seen: [{}]",
                imported_dlls.join(", ")
            ));
        }
        if matched.is_empty() {
            return Err(format!(
                "{dll} imported but no send/recv/connect/closesocket thunk matched (bound or ordinal imports?)"
            ));
        }
        Ok(format!("patched [{}]", matched.join(", ")))
    }
}

/// Reads a NUL-terminated ASCII C string at `ptr` into a String.
unsafe fn read_cstr(ptr: usize) -> String {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        let c = ptr::read_unaligned((ptr + i) as *const u8);
        if c == 0 || i > 260 {
            break;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Saves the current thunk value into `orig_slot` and writes `hook` in its
/// place. Returns true on success.
unsafe fn write_thunk(slot: usize, hook: usize, orig_slot: &AtomicUsize) -> bool {
    let current = ptr::read_unaligned(slot as *const u32) as usize;
    if current == hook {
        return true; // already ours
    }
    let addr = slot as *const core::ffi::c_void;
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    if VirtualProtect(addr, 4, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return false;
    }
    orig_slot.store(current, Ordering::Release);
    ptr::write_unaligned(slot as *mut u32, hook as u32);
    let mut tmp: PAGE_PROTECTION_FLAGS = 0;
    let _ = VirtualProtect(addr, 4, old, &mut tmp);
    true
}

/// Case-insensitive comparison of a NUL-terminated C string at `ptr` with `s`.
unsafe fn cstr_eq_ci(ptr: usize, s: &str) -> bool {
    let bytes = s.as_bytes();
    for (i, &want) in bytes.iter().enumerate() {
        let c = ptr::read_unaligned((ptr + i) as *const u8);
        if c == 0 {
            return false;
        }
        if c.to_ascii_lowercase() != want.to_ascii_lowercase() {
            return false;
        }
    }
    ptr::read_unaligned((ptr + bytes.len()) as *const u8) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// wsock32.dll exports the Winsock 1.1 entry points by these ordinals; both
    /// coolcore59.dll and coolcore49.dll import them that way (no names).
    const ORD_SEND: u16 = 19;
    const ORD_RECV: u16 = 16;
    const ORD_CONNECT: u16 = 4;
    const ORD_CLOSE: u16 = 3;

    /// An entry in an import lookup table: a name is an RVA to a hint/name
    /// struct; an ordinal import has the high bit set with the ordinal below.
    fn named_entry(rva: usize) -> u32 {
        rva as u32
    }

    fn ordinal_entry(ordinal: u16) -> u32 {
        0x8000_0000 | ordinal as u32
    }

    /// Builds a minimal PE32 image whose single import descriptor points at
    /// `dll_name` with `entries` in both the INT and the IAT, and returns the
    /// image bytes plus the RVA the image is mapped at.
    fn synthetic_pe(dll_name: &str, entries: &[u32]) -> Vec<u8> {
        const IMAGE_BASE_RVA: usize = 0x1000;
        let mut img = vec![0u8; 0x4000];

        // DOS header: MZ, e_lfanew -> 0x80.
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature + COFF header (i386).
        img[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        img[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        // Optional header magic PE32.
        img[0x80 + 0x18..0x80 + 0x1A].copy_from_slice(&0x010Bu16.to_le_bytes());
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

    /// Original-pointer slots of one test, so tests running in parallel (and
    /// the real hooks' slots) never share them.
    type Slots = [AtomicUsize; 4];
    #[allow(clippy::declare_interior_mutable_const)] // only to fill the slot arrays
    const EMPTY: AtomicUsize = AtomicUsize::new(0);

    fn funcs_table(slots: &'static Slots) -> Vec<(&'static str, u16, usize, &'static AtomicUsize)> {
        // Hook addresses are arbitrary distinct non-zero values; only that they
        // differ from the IAT contents matters.
        vec![
            ("send", ORD_SEND, 0x1000_1000, &slots[0]),
            ("recv", ORD_RECV, 0x1000_2000, &slots[1]),
            ("connect", ORD_CONNECT, 0x1000_3000, &slots[2]),
            ("closesocket", ORD_CLOSE, 0x1000_4000, &slots[3]),
        ]
    }

    /// The real shape of coolcore59.dll: every wsock32 import is by ordinal, so
    /// name matching must not be required and every slot must be found.
    #[test]
    fn ordinal_imports_are_patched() {
        let img = synthetic_pe(
            "WSOCK32.dll",
            &[
                ordinal_entry(ORD_CONNECT),
                ordinal_entry(ORD_CLOSE),
                ordinal_entry(11), // inet_addr - not hooked
                ordinal_entry(ORD_RECV),
                ordinal_entry(ORD_SEND),
            ],
        );
        static SLOTS: Slots = [EMPTY; 4];
        let funcs = funcs_table(&SLOTS);
        let report = patch_iat(img.as_ptr() as usize, "wsock32.dll", &funcs)
            .expect("ordinal imports should be patched");
        assert_eq!(report, "patched [connect, closesocket, recv, send]");

        // The IAT now holds the hook addresses; the pre-patch addresses were
        // saved into the test's slots (asserted below).
        let iat = 0x1000 + 0x100;
        let slot = |i: usize| iat + i * 4;

        assert_eq!(SLOTS[0].load(Ordering::Acquire), 0x7FFF_0004);
        assert_eq!(SLOTS[1].load(Ordering::Acquire), 0x7FFF_0003);
        assert_eq!(SLOTS[2].load(Ordering::Acquire), 0x7FFF_0000);
        assert_eq!(SLOTS[3].load(Ordering::Acquire), 0x7FFF_0001);

        // The IAT itself now holds the hook addresses.
        let patched =
            |i: usize| u32::from_le_bytes(img[slot(i)..slot(i) + 4].try_into().unwrap()) as usize;
        assert_eq!(patched(0), 0x1000_3000);
        assert_eq!(patched(1), 0x1000_4000);
        assert_eq!(patched(3), 0x1000_2000);
        assert_eq!(patched(4), 0x1000_1000);
    }

    /// A named import (the shape some modules use) must still be matched by
    /// name, so the ordinal path did not regress the existing behaviour.
    #[test]
    fn named_imports_are_still_patched() {
        let mut img = synthetic_pe("WSOCK32.dll", &[named_entry(0x200), named_entry(0x240)]);
        // Write the two hint/name structs the INT points at.
        let put = |img: &mut Vec<u8>, rva: usize, name: &str| {
            img[rva..rva + 2].copy_from_slice(&0u16.to_le_bytes());
            img[rva + 2..rva + 2 + name.len()].copy_from_slice(name.as_bytes());
            img[rva + 2 + name.len()] = 0;
        };
        put(&mut img, 0x200, "send");
        put(&mut img, 0x240, "recv");

        static SLOTS: Slots = [EMPTY; 4];
        let funcs = funcs_table(&SLOTS);
        let report = patch_iat(img.as_ptr() as usize, "wsock32.dll", &funcs)
            .expect("named imports should be patched");
        assert_eq!(report, "patched [send, recv]");
    }

    /// A wsock32 import that contains none of the hooked ordinals must be
    /// reported as unmatched rather than silently "succeeding".
    #[test]
    fn unrelated_ordinals_do_not_patch() {
        let img = synthetic_pe("WSOCK32.dll", &[ordinal_entry(11), ordinal_entry(12)]);
        static SLOTS: Slots = [EMPTY; 4];
        let funcs = funcs_table(&SLOTS);
        let err = patch_iat(img.as_ptr() as usize, "wsock32.dll", &funcs)
            .expect_err("no hooked ordinal is present");
        assert!(
            err.contains("no send/recv/connect/closesocket thunk matched"),
            "{err}"
        );
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
        let _ = POLICY.set(Policy::harness());
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

        // At the end of the stream a partial frame is released as it was, then
        // the end is reported.
        let partial = &in_ch1(4, "1", 0, b"cut short")[..8];
        server.write_all(partial).unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        assert_eq!(read(s, usize::MAX, 64), partial);
        assert_eq!(hooked_recv(s, 64), Some(Vec::new()));
    }
}
