//! The call media sockets: observed (stage C0 of
//! `docs/e2e/CALLS-RESEARCH.md`, `calls_log=on`) and, for a call both add-ons
//! agreed to encrypt, encrypted (stage C2, `calls_encrypt=on`).
//!
//! With either switch on the loader notification that patches the networking
//! module also patches the two modules a call runs in, the moment either is
//! mapped: `sipXtapi.dll` (6.5 and 7.2: SIP, STUN/TURN, ICE, and on 6.5 the
//! GIPS engine itself) and `sipXmediaLib.dll` (7.2: the GIPS engine). Both are
//! loaded only when a call starts. Their Winsock imports are by ordinal, from
//! `wsock32.dll` or `ws2_32.dll`, and are matched by name exactly as for the
//! networking module.
//!
//! Hooked: `sendto`, `recvfrom`, and `send`/`recv` for a connected UDP socket,
//! `WSASendTo`/`WSARecvFrom` where a module has them (the research found
//! none), `bind` and `closesocket` for bookkeeping.
//!
//! Observation: every hook calls the original first, with the client's own
//! arguments, and returns its result and last error untouched; only then are
//! the bytes that went through handed to [`crate::calls`] to be classified. A
//! panic while looking falls back to having looked at nothing.
//!
//! Encryption ([`crate::callneg`], [`crate::callmedia`]): only while some call
//! has agreed keys, and only for a datagram socket of that call (a port of its
//! SDP, or any while it is the only one). Everything else - any datagram while
//! no call is agreed, any socket of another flow, STUN and TURN control -
//! takes exactly the observation path above, byte for byte.
//!
//! - `sendto`/`send`: RTP and RTCP (bare or in TURN framing) go out encrypted
//!   and the client is told its own length was sent; a packet that cannot be
//!   encrypted is dropped and reported as sent. Never plain.
//! - `recvfrom`/`recv`: the datagram is read into a buffer of the add-on's own
//!   and the client gets the decrypted one (or the datagram as it was, for
//!   anything that is not media), with Winsock's own `WSAEMSGSIZE` if its
//!   buffer is too small. A packet that does not decrypt (plain media in an
//!   encrypted call, a forgery, a replay) is dropped: the next datagram is
//!   read if one is waiting (or comes within 20 ms), else the client gets a
//!   zero-length datagram, which RTP code discards as too short.
//! - A panic while deciding drops the packet if the socket belongs to an
//!   agreed call, and passes it untouched otherwise.
//! - `WSASendTo` with media of an agreed call is dropped (reported as sent):
//!   it cannot be encrypted in place, and must not go plain. The research
//!   found no module that imports it.
//!
//! Each module has its own slots for the originals, so a hook always calls
//! the function its own module imported (`wsock32`'s `recvfrom` is not
//! assumed to be `ws2_32`'s).

use super::*;

use std::net::Ipv4Addr;

use windows_sys::Win32::Networking::WinSock;
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

use crate::callmedia::Verdict;
use crate::callneg::{self, CallTable};
use crate::calls::{self, FlowKey};

/// The modules a call runs in, by file name.
pub(super) const CALL_MODULES: [&str; 2] = ["sipXtapi.dll", "sipXmediaLib.dll"];

const F_SENDTO: usize = 0;
const F_RECVFROM: usize = 1;
const F_SEND: usize = 2;
const F_RECV: usize = 3;
const F_WSASENDTO: usize = 4;
const F_WSARECVFROM: usize = 5;
const F_CLOSE: usize = 6;
const F_BIND: usize = 7;
const FUNCS: usize = 8;

/// The originals, per module and function.
static ORIG: [[AtomicUsize; FUNCS]; 2] = [const { [const { AtomicUsize::new(0) }; FUNCS] }; 2];

/// Serialises patching; the loader notification only tries it.
static PATCH_LOCK: Mutex<()> = Mutex::new(());

const WSA_IO_PENDING: u32 = 997;
const WSAEMSGSIZE: u32 = 10040;
/// How many dropped datagrams one `recvfrom` reads past at most.
const DROP_RETRIES: usize = 32;
/// How long a `recvfrom` whose datagram was dropped waits for the next one.
const DROP_WAIT_MS: i32 = 20;
/// The add-on's own receive buffer: the largest UDP datagram.
const OWN_BUF: usize = 65_536;
const SOL_SOCKET: i32 = 0xFFFF;
const SO_TYPE: i32 = 0x1008;
const SOCK_DGRAM: i32 = 2;
/// The most of a gathered `WSASendTo`/`WSARecvFrom` that is looked at.
const MAX_GATHER: usize = 64 * 1024;

type SendToFn = unsafe extern "system" fn(Socket, *const u8, i32, i32, *const u8, i32) -> i32;
type RecvFromFn = unsafe extern "system" fn(Socket, *mut u8, i32, i32, *mut u8, *mut i32) -> i32;
type BindFn = unsafe extern "system" fn(Socket, *const u8, i32) -> i32;
type WsaSendToFn = unsafe extern "system" fn(
    Socket,
    *const WsaBuf,
    u32,
    *mut u32,
    u32,
    *const u8,
    i32,
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
) -> i32;
type WsaRecvFromFn = unsafe extern "system" fn(
    Socket,
    *const WsaBuf,
    u32,
    *mut u32,
    *mut u32,
    *mut u8,
    *mut i32,
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
) -> i32;

/// `WSABUF`.
#[repr(C)]
pub(super) struct WsaBuf {
    len: u32,
    buf: *mut u8,
}

/// The original `f` of module `m`, as the function type `F`.
unsafe fn orig<F: Copy>(m: usize, f: usize) -> F {
    let p = ORIG[m][f].load(Ordering::Acquire);
    std::mem::transmute_copy::<usize, F>(&p)
}

// --- what is known about a socket ---------------------------------------------

#[derive(Clone, Copy)]
struct SockInfo {
    local_port: u16,
    udp: bool,
    /// Whether a TCP socket was already said to be one.
    tcp_noted: bool,
}

fn infos() -> &'static Mutex<HashMap<Socket, SockInfo>> {
    static I: std::sync::LazyLock<Mutex<HashMap<Socket, SockInfo>>> =
        std::sync::LazyLock::new(Default::default);
    &I
}

/// The socket's local port and type, asked of Winsock once.
fn info(s: Socket) -> SockInfo {
    if let Some(i) = lock(infos()).get(&s) {
        return *i;
    }
    let i = SockInfo {
        local_port: local_port(s),
        udp: is_udp(s),
        tcp_noted: false,
    };
    lock(infos()).insert(s, i);
    i
}

fn local_port(s: Socket) -> u16 {
    // SAFETY: getsockname into a stack buffer of the size passed.
    unsafe {
        let mut sa = [0u8; 32];
        let mut len = sa.len() as i32;
        if WinSock::getsockname(s, sa.as_mut_ptr().cast(), &mut len) != 0 || len < 4 {
            return 0;
        }
        u16::from_be_bytes([sa[2], sa[3]])
    }
}

fn is_udp(s: Socket) -> bool {
    // SAFETY: getsockopt into a stack i32 of the size passed.
    unsafe {
        let mut t: i32 = 0;
        let mut len = 4i32;
        WinSock::getsockopt(
            s,
            SOL_SOCKET,
            SO_TYPE,
            (&mut t as *mut i32).cast(),
            &mut len,
        ) == 0
            && t == SOCK_DGRAM
    }
}

/// An IPv4 `sockaddr_in`.
unsafe fn sockaddr_v4(sa: *const u8, len: i32) -> Option<(Ipv4Addr, u16)> {
    if sa.is_null() || len < 8 {
        return None;
    }
    let b = std::slice::from_raw_parts(sa, 8);
    (u16::from_le_bytes([b[0], b[1]]) == 2).then(|| {
        (
            Ipv4Addr::new(b[4], b[5], b[6], b[7]),
            u16::from_be_bytes([b[2], b[3]]),
        )
    })
}

/// The address a connected socket talks to.
fn peer_v4(s: Socket) -> Option<(Ipv4Addr, u16)> {
    // SAFETY: getpeername into a stack buffer of the size passed.
    unsafe {
        let mut sa = [0u8; 32];
        let mut len = sa.len() as i32;
        if WinSock::getpeername(s, sa.as_mut_ptr().cast(), &mut len) != 0 {
            return None;
        }
        sockaddr_v4(sa.as_ptr(), len)
    }
}

// --- encryption ------------------------------------------------------------------

#[cfg(test)]
thread_local! {
    /// A call table for this thread only: the tests play two endpoints in one
    /// process, each with its own table.
    static TEST_TABLE: std::cell::RefCell<Option<Arc<Mutex<CallTable>>>> =
        const { std::cell::RefCell::new(None) };
}

/// The call table the hooks use.
fn table() -> Arc<Mutex<CallTable>> {
    #[cfg(test)]
    if let Some(t) = TEST_TABLE.with(|c| c.borrow().clone()) {
        return t;
    }
    callneg::shared()
}

/// Whether calls are encrypted (`calls_encrypt=on` in effect).
fn encrypting() -> bool {
    // In the unit tests only a thread with a table of its own encrypts; the
    // policy is not asked, so these tests never set the process's policy
    // under the feet of the socket tests in `hook.rs`.
    #[cfg(test)]
    return TEST_TABLE.with(|c| c.borrow().is_some());
    #[cfg(not(test))]
    policy().encrypts_calls()
}

/// Whether datagrams are classified for the log (`calls_log=on`; always in
/// the unit tests, which count them).
fn observing() -> bool {
    cfg!(test) || policy().calls_log
}

/// Unix time in milliseconds, the clock of the call table.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn log_table(t: &mut CallTable) {
    for l in t.take_log() {
        log::line(&l);
    }
}

/// The local port of a datagram socket an agreed call uses, if `s` is one.
/// Never panics out: after a panic the socket counts as an agreed call's
/// whenever [`keyed_after_panic`] cannot rule it out, so its media goes the
/// encrypted path - which drops what it cannot handle - and never out plain
/// or in to the client undecrypted.
fn keyed_socket(s: Socket) -> Option<u16> {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let i = info(s);
        if !i.udp {
            return None;
        }
        let t = table();
        let g = lock(&t);
        g.covers(i.local_port).then_some(i.local_port)
    })) {
        Ok(port) => port,
        Err(_) => keyed_after_panic(s).then_some(0),
    }
}

/// After a panic: whether the socket belongs to an agreed call - or, with
/// `calls_encrypt=required`, to any call - asked as simply as possible.
/// Unknown counts as yes (the packet is then dropped, never sent plain).
fn keyed_after_panic(s: Socket) -> bool {
    panic::catch_unwind(AssertUnwindSafe(|| {
        let t = table();
        let g = lock(&t);
        g.blocks_plain() || (g.keyed() && g.covers(local_port(s)))
    }))
    .unwrap_or(true)
}

/// Whether unagreed media is held back now ([`CallTable::blocks_plain`]:
/// `calls_encrypt=required`, or a call with a contact under `/e2e on` or
/// verified) for datagram socket `s`: then every datagram of it goes the
/// encrypted path, which drops the media of a call that did not agree on
/// keys (audit 2026-10, finding 8). A stream socket keeps its own path.
/// Unknown counts as yes.
fn required_now(s: Socket) -> bool {
    panic::catch_unwind(AssertUnwindSafe(|| {
        let blocks = lock(&table()).blocks_plain();
        blocks && info(s).udp
    }))
    .unwrap_or(true)
}

/// The send side with `calls_encrypt=on`. `None` when the datagram is not
/// media of an agreed call: the caller then goes on exactly as without
/// encryption. Otherwise Winsock's answer for what was sent instead.
unsafe fn media_send(
    m: usize,
    s: Socket,
    data: &[u8],
    remote: Option<(Ipv4Addr, u16)>,
    connected: bool,
    send: &dyn Fn(&[u8]) -> i32,
) -> Option<i32> {
    let err = GetLastError();
    let decided = panic::catch_unwind(AssertUnwindSafe(|| {
        let i = info(s);
        if !i.udp {
            return None;
        }
        let t = table();
        let mut g = lock(&t);
        if !g.keyed() && !g.blocks_plain() {
            return None;
        }
        let v = g.media_out(i.local_port, data, now_ms());
        log_table(&mut g);
        Some(v)
    }));
    let verdict = match decided {
        Ok(None) | Ok(Some(Verdict::Pass)) => {
            SetLastError(err);
            return None;
        }
        Ok(Some(v)) => v,
        Err(_) if keyed_after_panic(s) => Verdict::Drop("panic in the hook"),
        Err(_) => {
            SetLastError(err);
            return None;
        }
    };
    match verdict {
        Verdict::Replace(wire) => {
            SetLastError(err);
            let r = send(&wire);
            if r > 0 {
                if observing() {
                    watch(m, s, &wire, true, remote, connected);
                }
                // The client's own datagram is what it asked to send.
                Some(data.len() as i32)
            } else {
                Some(r)
            }
        }
        _ => {
            SetLastError(err);
            Some(data.len() as i32)
        }
    }
}

/// The receive side with `calls_encrypt=on`, for a socket of an agreed call:
/// reads into a buffer of its own and hands the client what it may see.
#[allow(clippy::too_many_arguments)]
unsafe fn media_recv(
    m: usize,
    s: Socket,
    buf: *mut u8,
    len: i32,
    from: *mut u8,
    fromlen: *mut i32,
    connected: bool,
    recv: &dyn Fn(*mut u8, i32) -> i32,
) -> i32 {
    let mut own = vec![0u8; OWN_BUF];
    for _ in 0..DROP_RETRIES {
        let r = recv(own.as_mut_ptr(), own.len() as i32);
        if r < 0 {
            // Winsock's error, with its last error.
            return r;
        }
        let err = GetLastError();
        let wire = &own[..r as usize];
        if observing() {
            let remote = if fromlen.is_null() {
                None
            } else {
                sockaddr_v4(from, *fromlen)
            };
            watch(m, s, wire, false, remote, connected);
        }
        let verdict = panic::catch_unwind(AssertUnwindSafe(|| {
            let i = info(s);
            let t = table();
            let mut g = lock(&t);
            let v = g.media_in(i.local_port, wire, now_ms());
            log_table(&mut g);
            v
        }))
        .unwrap_or(Verdict::Drop("panic in the hook"));
        match verdict {
            Verdict::Pass => return deliver(buf, len, wire, err),
            Verdict::Replace(p) => return deliver(buf, len, &p, err),
            Verdict::Drop(_) => {
                if more_waiting(s) {
                    continue;
                }
                SetLastError(err);
                return 0;
            }
        }
    }
    0
}

/// Copies a datagram into the client's buffer as Winsock would: truncated
/// with `WSAEMSGSIZE` when it does not fit.
unsafe fn deliver(buf: *mut u8, len: i32, bytes: &[u8], err: u32) -> i32 {
    let room = len.max(0) as usize;
    let k = bytes.len().min(room);
    ptr::copy_nonoverlapping(bytes.as_ptr(), buf, k);
    if bytes.len() > room {
        SetLastError(WSAEMSGSIZE);
        SOCKET_ERROR
    } else {
        SetLastError(err);
        bytes.len() as i32
    }
}

/// Whether another datagram is waiting on `s`, or arrives within
/// [`DROP_WAIT_MS`].
fn more_waiting(s: Socket) -> bool {
    // SAFETY: ioctlsocket and select on the client's socket, with stack
    // arguments of the sizes passed.
    unsafe {
        let mut n: u32 = 0;
        if WinSock::ioctlsocket(s, FIONREAD as i32, &mut n) == 0 && n > 0 {
            return true;
        }
        let mut set: FD_SET = std::mem::zeroed();
        set.fd_count = 1;
        set.fd_array[0] = s;
        let tv = TIMEVAL {
            tv_sec: 0,
            tv_usec: DROP_WAIT_MS * 1000,
        };
        select(0, &mut set, ptr::null_mut(), ptr::null_mut(), &tv) > 0
    }
}

/// The calls' timers, from the worker every two seconds.
pub(super) fn tick() {
    if !policy().encrypts_calls() {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let t = table();
        let mut g = lock(&t);
        g.tick(now_ms());
        log_table(&mut g);
    }));
}

/// Looks at one datagram that went through: classifies it and logs what the
/// tracker says. Keeps the thread's last error; never panics out.
fn watch(
    m: usize,
    s: Socket,
    data: &[u8],
    outbound: bool,
    remote: Option<(Ipv4Addr, u16)>,
    connected: bool,
) {
    // SAFETY: reads and restores the calling thread's last error.
    let err = unsafe { GetLastError() };
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let i = info(s);
        if !i.udp {
            if connected && !i.tcp_noted {
                if let Some(e) = lock(infos()).get_mut(&s) {
                    e.tcp_noted = true;
                }
                log::line(&format!(
                    "call media: {} sock={s} L:{} is not a datagram socket; its {} bytes are not classified",
                    CALL_MODULES[m],
                    i.local_port,
                    if outbound { "outbound" } else { "inbound" }
                ));
            }
            if connected {
                return;
            }
        }
        let remote = remote.or_else(|| peer_v4(s)).map_or_else(
            || "?".to_string(),
            |(ip, port)| calls::addr_label(ip, port, calls::server_addrs()),
        );
        let packet = calls::classify(data);
        // SAFETY: no arguments.
        let now = unsafe { GetTickCount64() };
        let key = FlowKey {
            socket: s,
            remote,
            outbound,
        };
        let lines = lock(calls::tracker()).packet(
            CALL_MODULES[m],
            key,
            i.local_port,
            &packet,
            data.len(),
            now,
        );
        for l in lines {
            log::line(&l);
        }
    }));
    // SAFETY: restores the calling thread's last error.
    unsafe { SetLastError(err) };
}

// --- hook bodies (one set per module) -----------------------------------------

unsafe extern "system" fn hook_sendto<const M: usize>(
    s: Socket,
    buf: *const u8,
    len: i32,
    flags: i32,
    to: *const u8,
    tolen: i32,
) -> i32 {
    if !buf.is_null() && len > 0 && encrypting() {
        let data = std::slice::from_raw_parts(buf, len as usize);
        let send = |w: &[u8]| {
            orig::<SendToFn>(M, F_SENDTO)(s, w.as_ptr(), w.len() as i32, flags, to, tolen)
        };
        if let Some(r) = media_send(M, s, data, sockaddr_v4(to, tolen), to.is_null(), &send) {
            return r;
        }
    }
    let r = orig::<SendToFn>(M, F_SENDTO)(s, buf, len, flags, to, tolen);
    if r > 0 && !buf.is_null() && observing() {
        let remote = sockaddr_v4(to, tolen);
        watch(
            M,
            s,
            std::slice::from_raw_parts(buf, r as usize),
            true,
            remote,
            to.is_null(),
        );
    }
    r
}

unsafe extern "system" fn hook_recvfrom<const M: usize>(
    s: Socket,
    buf: *mut u8,
    len: i32,
    flags: i32,
    from: *mut u8,
    fromlen: *mut i32,
) -> i32 {
    if !buf.is_null()
        && len > 0
        && flags & MSG_PEEK == 0
        && encrypting()
        && (keyed_socket(s).is_some() || required_now(s))
    {
        let recv =
            |p: *mut u8, n: i32| orig::<RecvFromFn>(M, F_RECVFROM)(s, p, n, flags, from, fromlen);
        return media_recv(M, s, buf, len, from, fromlen, from.is_null(), &recv);
    }
    let r = orig::<RecvFromFn>(M, F_RECVFROM)(s, buf, len, flags, from, fromlen);
    if r > 0 && !buf.is_null() && flags & MSG_PEEK == 0 && observing() {
        let remote = if fromlen.is_null() {
            None
        } else {
            sockaddr_v4(from, *fromlen)
        };
        watch(
            M,
            s,
            std::slice::from_raw_parts(buf, r as usize),
            false,
            remote,
            from.is_null(),
        );
    }
    r
}

unsafe extern "system" fn hook_send<const M: usize>(
    s: Socket,
    buf: *const u8,
    len: i32,
    flags: i32,
) -> i32 {
    if !buf.is_null() && len > 0 && encrypting() {
        let data = std::slice::from_raw_parts(buf, len as usize);
        let send = |w: &[u8]| orig::<SendFn>(M, F_SEND)(s, w.as_ptr(), w.len() as i32, flags);
        if let Some(r) = media_send(M, s, data, None, true, &send) {
            return r;
        }
    }
    let r = orig::<SendFn>(M, F_SEND)(s, buf, len, flags);
    if r > 0 && !buf.is_null() && observing() {
        watch(
            M,
            s,
            std::slice::from_raw_parts(buf, r as usize),
            true,
            None,
            true,
        );
    }
    r
}

unsafe extern "system" fn hook_recv<const M: usize>(
    s: Socket,
    buf: *mut u8,
    len: i32,
    flags: i32,
) -> i32 {
    if !buf.is_null()
        && len > 0
        && flags & MSG_PEEK == 0
        && encrypting()
        && (keyed_socket(s).is_some() || required_now(s))
    {
        let recv = |p: *mut u8, n: i32| orig::<RecvFn>(M, F_RECV)(s, p, n, flags);
        return media_recv(
            M,
            s,
            buf,
            len,
            ptr::null_mut(),
            ptr::null_mut(),
            true,
            &recv,
        );
    }
    let r = orig::<RecvFn>(M, F_RECV)(s, buf, len, flags);
    if r > 0 && !buf.is_null() && flags & MSG_PEEK == 0 && observing() {
        watch(
            M,
            s,
            std::slice::from_raw_parts(buf, r as usize),
            false,
            None,
            true,
        );
    }
    r
}

/// The bytes of a list of `WSABUF`s, up to `limit`.
unsafe fn gather(bufs: *const WsaBuf, count: u32, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if bufs.is_null() {
        return out;
    }
    for b in std::slice::from_raw_parts(bufs, count as usize) {
        if out.len() >= limit.min(MAX_GATHER) {
            break;
        }
        if b.buf.is_null() {
            continue;
        }
        let take = (b.len as usize).min(limit.min(MAX_GATHER) - out.len());
        out.extend_from_slice(std::slice::from_raw_parts(b.buf, take));
    }
    out
}

unsafe extern "system" fn hook_wsasendto<const M: usize>(
    s: Socket,
    bufs: *const WsaBuf,
    count: u32,
    sent: *mut u32,
    flags: u32,
    to: *const u8,
    tolen: i32,
    overlapped: *mut core::ffi::c_void,
    completion: *const core::ffi::c_void,
) -> i32 {
    // Media of an agreed call cannot be encrypted in place here and must not
    // go plain: it is dropped and reported as sent.
    if encrypting() && (keyed_socket(s).is_some() || required_now(s)) {
        let err = GetLastError();
        let total = panic::catch_unwind(AssertUnwindSafe(|| {
            let data = gather(bufs, count, usize::MAX);
            crate::callmedia::split(&data).map(|_| data.len())
        }))
        .unwrap_or(Some(0));
        if let Some(n) = total {
            if !sent.is_null() {
                *sent = n as u32;
            }
            log::line(&format!(
                "call media: {} WSASendTo of an agreed call's media dropped ({n} B): not encrypted on this path",
                CALL_MODULES[M]
            ));
            SetLastError(err);
            return 0;
        }
        SetLastError(err);
    }
    let r = orig::<WsaSendToFn>(M, F_WSASENDTO)(
        s, bufs, count, sent, flags, to, tolen, overlapped, completion,
    );
    let err = GetLastError();
    if (r == 0 || err == WSA_IO_PENDING) && observing() {
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            let data = gather(bufs, count, usize::MAX);
            if !data.is_empty() {
                watch(M, s, &data, true, sockaddr_v4(to, tolen), to.is_null());
            }
        }));
    }
    SetLastError(err);
    r
}

unsafe extern "system" fn hook_wsarecvfrom<const M: usize>(
    s: Socket,
    bufs: *const WsaBuf,
    count: u32,
    received: *mut u32,
    flags: *mut u32,
    from: *mut u8,
    fromlen: *mut i32,
    overlapped: *mut core::ffi::c_void,
    completion: *const core::ffi::c_void,
) -> i32 {
    let r = orig::<WsaRecvFromFn>(M, F_WSARECVFROM)(
        s, bufs, count, received, flags, from, fromlen, overlapped, completion,
    );
    // Only a call that completed at once has its bytes in the buffers now.
    if r == 0
        && observing()
        && overlapped.is_null()
        && !received.is_null()
        && *received > 0
        && (flags.is_null() || *flags as i32 & MSG_PEEK == 0)
    {
        let err = GetLastError();
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            let data = gather(bufs, count, *received as usize);
            let remote = if fromlen.is_null() {
                None
            } else {
                sockaddr_v4(from, *fromlen)
            };
            watch(M, s, &data, false, remote, from.is_null());
        }));
        SetLastError(err);
    }
    r
}

unsafe extern "system" fn hook_bind<const M: usize>(
    s: Socket,
    name: *const u8,
    namelen: i32,
) -> i32 {
    let r = orig::<BindFn>(M, F_BIND)(s, name, namelen);
    if r == 0 {
        let err = GetLastError();
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            // The port is asked again: it is what ties a socket to a call.
            lock(infos()).remove(&s);
            if !observing() {
                return;
            }
            let i = info(s);
            log::line(&format!(
                "call media: {} bind sock={s} -> L:{} ({})",
                CALL_MODULES[M],
                i.local_port,
                if i.udp { "udp" } else { "tcp" }
            ));
        }));
        SetLastError(err);
    }
    r
}

unsafe extern "system" fn hook_close<const M: usize>(s: Socket) -> i32 {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        lock(infos()).remove(&s);
        let lines = lock(calls::tracker()).close(s);
        for l in lines {
            log::line(&l);
        }
    }));
    orig::<CloseFn>(M, F_CLOSE)(s)
}

/// The hooks of module `M`.
fn specs<const M: usize>() -> [HookSpec; FUNCS] {
    [
        HookSpec::new(
            "sendto",
            hook_sendto::<M> as SendToFn as usize,
            &ORIG[M][F_SENDTO],
        ),
        HookSpec::new(
            "recvfrom",
            hook_recvfrom::<M> as RecvFromFn as usize,
            &ORIG[M][F_RECVFROM],
        ),
        HookSpec::new("send", hook_send::<M> as SendFn as usize, &ORIG[M][F_SEND]),
        HookSpec::new("recv", hook_recv::<M> as RecvFn as usize, &ORIG[M][F_RECV]),
        HookSpec::new(
            "WSASendTo",
            hook_wsasendto::<M> as WsaSendToFn as usize,
            &ORIG[M][F_WSASENDTO],
        ),
        HookSpec::new(
            "WSARecvFrom",
            hook_wsarecvfrom::<M> as WsaRecvFromFn as usize,
            &ORIG[M][F_WSARECVFROM],
        ),
        HookSpec::new(
            "closesocket",
            hook_close::<M> as CloseFn as usize,
            &ORIG[M][F_CLOSE],
        ),
        HookSpec::new("bind", hook_bind::<M> as BindFn as usize, &ORIG[M][F_BIND]),
    ]
}

// --- installation -------------------------------------------------------------

/// Which call module `name` is.
fn module_index(name: &str) -> Option<usize> {
    CALL_MODULES
        .iter()
        .position(|m| m.eq_ignore_ascii_case(name))
}

/// Patches a call module that was just mapped (`in_loader`: from the loader
/// notification, under the loader lock), or found loaded. Does nothing for
/// another module or with both `calls_log` and `calls_encrypt` off. Patching
/// is idempotent, so a module that is unloaded after a call and loaded again
/// for the next is patched again. Returns whether the module is patched.
pub(super) fn on_load(name: &str, base: usize, via: &str, in_loader: bool) -> bool {
    if !policy().hooks_calls() {
        return false;
    }
    let Some(m) = module_index(name) else {
        return false;
    };
    let _guard = if in_loader {
        match PATCH_LOCK.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                retry_later(m);
                return false;
            }
        }
    } else {
        lock(&PATCH_LOCK)
    };
    let hooks = match m {
        0 => specs::<0>(),
        _ => specs::<1>(),
    };
    // DISCOVER and COMMIT, all or nothing (fourth review, finding C); the
    // outcome goes to the protection gate, which refuses a call that must be
    // encrypted while its media hooks are not in place (finding E).
    let say = |line: String| {
        if in_loader {
            log::defer(line);
        } else {
            log::line(&line);
        }
    };
    match patch_with(base, &hooks, &resolve_ordinal, &mut LiveThunks) {
        Ok((_, report)) => {
            gate::current().set_media(m, gate::MediaHooks::Ready);
            say(format!(
                "call hooks installed in {name} at {base:#010x} ({via}): {report}; {}",
                if policy().encrypts_calls() {
                    "media of a call both add-ons agreed on is encrypted, all else untouched"
                } else {
                    "observation only, nothing is changed"
                }
            ));
            true
        }
        Err(reason) => {
            say(format!(
                "call hooks: {name} ({via}): could not patch: {reason}"
            ));
            if in_loader && reason.contains("not bound") {
                retry_later(m);
            } else {
                failed(m, &reason);
            }
            false
        }
    }
}

/// The call module `m` could not be patched for good: the gate refuses the
/// calls that must be encrypted, and the chat is told once.
fn failed(m: usize, why: &str) {
    gate::current().set_media(
        m,
        gate::MediaHooks::Failed(format!("{} could not be patched: {why}", CALL_MODULES[m])),
    );
    if policy().encrypts_calls() {
        let now = now_ms() / 1000;
        if gate::current().once(&format!("call-hooks:{m}"), now, 3600) {
            gate::current().say(format!(
                "{}The add-on could not take over the media of calls ({} could not be patched). A call with a contact under /e2e on or verified, or any call with calls_encrypt=required, is not let through; other calls go as they are and are not end-to-end encrypted.",
                crate::policy::PREFIX,
                CALL_MODULES[m]
            ));
        }
    }
}

/// A call module that loaded before the bootstrap read the policy: patched
/// from a thread of its own once the policy is known.
pub(super) fn later(name: &str) {
    if let Some(m) = module_index(name) {
        retry_later(m);
    }
}

/// Patches module `m` from a thread of its own once the loader is done with
/// it: a thread starts only after the load that made it has finished.
fn retry_later(m: usize) {
    unsafe extern "system" fn retry(arg: *mut core::ffi::c_void) -> u32 {
        let m = arg as usize;
        let name = CALL_MODULES[m];
        // The policy first: it says whether the module is hooked at all.
        let _ = gate::current().wait(BOOT_WAIT);
        if !policy().hooks_calls() {
            return 0;
        }
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        for _ in 0..100 {
            let base = GetModuleHandleW(w.as_ptr()) as usize;
            if base != 0 && on_load(name, base, "after load", false) {
                return 0;
            }
            Sleep(50);
        }
        log::line(&format!("call hooks: gave up patching {name}"));
        failed(m, "its imports were never bound");
        0
    }
    // SAFETY: a plain function; the argument is an index, not a pointer.
    unsafe {
        let h = CreateThread(
            ptr::null(),
            0,
            Some(retry),
            m as *const core::ffi::c_void,
            0,
            ptr::null_mut(),
        );
        if !h.is_null() {
            windows_sys::Win32::Foundation::CloseHandle(h);
        }
    }
}

/// At start: patches a call module that is somehow loaded already, and learns
/// the server's addresses (so they show as `server` in the log) on a thread of
/// its own, away from the loader lock.
pub(super) fn start() {
    if !policy().hooks_calls() {
        return;
    }
    if policy().calls_log {
        log::line(
            "calls_log=on: call media and signalling are observed (classes, sizes, \
             ports; never content)",
        );
    }
    if policy().encrypts_calls() {
        log::line(
            "calls_encrypt=on: a call is encrypted end to end when both add-ons agree on \
             its keys through the E2E session; any other call is left exactly as it is",
        );
    }
    for name in CALL_MODULES {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated name.
        let base = unsafe { GetModuleHandleW(w.as_ptr()) } as usize;
        if base != 0 {
            on_load(name, base, "already loaded at start", false);
        }
    }
    if !policy().calls_log {
        return;
    }
    unsafe extern "system" fn resolve(_: *mut core::ffi::c_void) -> u32 {
        use std::net::ToSocketAddrs;
        let Some(server) = policy().tls.server() else {
            calls::set_server_addrs(Vec::new());
            return 0;
        };
        let addrs: Vec<Ipv4Addr> = (server, 3478u16)
            .to_socket_addrs()
            .map(|it| {
                it.filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect()
            })
            .unwrap_or_default();
        log::line(&format!(
            "calls_log: the server resolves to {} IPv4 address(es); they show as `server`",
            addrs.len()
        ));
        calls::set_server_addrs(addrs);
        0
    }
    spawn(resolve);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket;

    fn point_at_winsock(m: usize) {
        ORIG[m][F_SENDTO].store(WinSock::sendto as *const () as usize, Ordering::Release);
        ORIG[m][F_RECVFROM].store(WinSock::recvfrom as *const () as usize, Ordering::Release);
        ORIG[m][F_CLOSE].store(
            WinSock::closesocket as *const () as usize,
            Ordering::Release,
        );
        ORIG[m][F_BIND].store(WinSock::bind as *const () as usize, Ordering::Release);
    }

    /// The hooks hand the original exactly the client's arguments and give the
    /// client exactly the original's answer: a datagram arrives as it was
    /// sent, and is counted on the way.
    #[test]
    fn datagrams_pass_unchanged_and_are_counted() {
        point_at_winsock(1);
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        b.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let to = match b.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_le_bytes());
        sa[2..4].copy_from_slice(&to.port().to_be_bytes());
        sa[4..8].copy_from_slice(&to.ip().octets());
        let mut pkt = vec![0x80, 103, 0, 1, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF];
        pkt.extend_from_slice(&[0x5A; 61]);
        let (sa_raw, sb_raw) = (a.as_raw_socket() as usize, b.as_raw_socket() as usize);
        for _ in 0..3 {
            // SAFETY: live buffers of the sizes passed, real sockets.
            let n = unsafe {
                hook_sendto::<1>(sa_raw, pkt.as_ptr(), pkt.len() as i32, 0, sa.as_ptr(), 16)
            };
            assert_eq!(n, pkt.len() as i32);
            let mut buf = [0u8; 1500];
            let mut from = [0u8; 16];
            let mut fromlen = 16i32;
            // SAFETY: as above.
            let n = unsafe {
                hook_recvfrom::<1>(
                    sb_raw,
                    buf.as_mut_ptr(),
                    buf.len() as i32,
                    0,
                    from.as_mut_ptr(),
                    &mut fromlen,
                )
            };
            assert_eq!(
                &buf[..n as usize],
                &pkt[..],
                "the datagram is the client's own"
            );
            assert_eq!(fromlen, 16);
        }
        // An error is the original's, with its last error.
        let mut buf = [0u8; 4];
        b.set_nonblocking(true).unwrap();
        // SAFETY: as above.
        let n = unsafe {
            hook_recvfrom::<1>(
                sb_raw,
                buf.as_mut_ptr(),
                4,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(n, SOCKET_ERROR);
        assert_eq!(unsafe { GetLastError() }, WSAEWOULDBLOCK);
        let closed_a = lock(calls::tracker()).close(sa_raw);
        assert_eq!(closed_a.len(), 1);
        assert!(
            closed_a[0].contains("OUT -> loopback:") && closed_a[0].contains("rtp 3 pkt 219 B"),
            "{}",
            closed_a[0]
        );
        let closed_b = lock(calls::tracker()).close(sb_raw);
        assert!(closed_b[0].contains("IN  <- loopback:"), "{}", closed_b[0]);
    }

    #[test]
    fn the_call_modules_are_known_by_name_only() {
        assert_eq!(module_index("SIPXTAPI.DLL"), Some(0));
        assert_eq!(module_index("sipXmediaLib.dll"), Some(1));
        assert_eq!(module_index("sipxtapi"), None);
        assert_eq!(module_index("coolcore49.dll"), None);
    }

    // --- encryption over real sockets -------------------------------------------

    use crate::callneg::{Me, Msg, PeerInfo, Sip};

    fn set_table(t: Option<Arc<Mutex<CallTable>>>) {
        TEST_TABLE.with(|c| *c.borrow_mut() = t);
    }

    fn sip(text: String) -> Sip {
        Sip::parse(text.as_bytes()).unwrap()
    }

    fn sdp_msg(first: &str, call: &str, port: u16) -> Sip {
        sip(format!(
            "{first}\r\nCall-ID: {call}\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\n\
             v=0\r\nm=audio {port} RTP/AVP 103\r\n"
        ))
    }

    /// A and B agree on `call` through their tables (the control payloads
    /// handed over as the Olm session would), A's media on `pa`, B's on `pb`.
    fn agree(a: &Arc<Mutex<CallTable>>, b: &Arc<Mutex<CallTable>>, call: &str, pa: u16, pb: u16) {
        let info = PeerInfo::default();
        let me_a = Me {
            uin: "100001".into(),
            device: 1,
            key: [1; 32],
        };
        let me_b = Me {
            uin: "100002".into(),
            device: 2,
            key: [2; 32],
        };
        let mut ga = || Ok(me_a.clone());
        let mut gb = || Ok(me_b.clone());
        let inv = sdp_msg("INVITE sip:100002@h SIP/2.0", call, pa);
        let ok = sdp_msg("SIP/2.0 200 OK", call, pb);
        let (mut a, mut b) = (lock(a), lock(b));
        for p in a.sip(Direction::Outbound, "100002", &inv, info, &mut ga, 0) {
            b.control("100001", 1, Msg::decode(&p).unwrap(), 0);
        }
        b.sip(Direction::Inbound, "100001", &inv, info, &mut gb, 0);
        for p in b.sip(Direction::Outbound, "100001", &ok, info, &mut gb, 0) {
            a.control("100002", 2, Msg::decode(&p).unwrap(), 0);
        }
        a.sip(Direction::Inbound, "100002", &ok, info, &mut ga, 0);
        let ack = sip(format!(
            "ACK sip:x SIP/2.0\r\nCall-ID: {call}\r\nCSeq: 1 ACK\r\n\r\n"
        ));
        for p in a.sip(Direction::Outbound, "100002", &ack, info, &mut ga, 0) {
            b.control("100001", 1, Msg::decode(&p).unwrap(), 0);
        }
        assert_eq!(a.state_of(call), Some("agreed"));
        assert_eq!(b.state_of(call), Some("agreed"));
    }

    fn sockaddr(s: &UdpSocket) -> [u8; 16] {
        let to = match s.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_le_bytes());
        sa[2..4].copy_from_slice(&to.port().to_be_bytes());
        sa[4..8].copy_from_slice(&to.ip().octets());
        sa
    }

    fn port(s: &UdpSocket) -> u16 {
        s.local_addr().unwrap().port()
    }

    unsafe fn send_via_hook(from: &UdpSocket, to: &UdpSocket, p: &[u8]) -> i32 {
        let sa = sockaddr(to);
        hook_sendto::<0>(
            from.as_raw_socket() as usize,
            p.as_ptr(),
            p.len() as i32,
            0,
            sa.as_ptr(),
            16,
        )
    }

    unsafe fn recv_via_hook(on: &UdpSocket, buf: &mut [u8]) -> i32 {
        let mut from = [0u8; 16];
        let mut fromlen = 16i32;
        hook_recvfrom::<0>(
            on.as_raw_socket() as usize,
            buf.as_mut_ptr(),
            buf.len() as i32,
            0,
            from.as_mut_ptr(),
            &mut fromlen,
        )
    }

    fn rtp(seq: u16) -> Vec<u8> {
        let mut p = vec![0x80, 103];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0x0B, 0xAD, 0xF0, 0x0D]);
        p.extend_from_slice(b"spoken words, in clear only at the two ends");
        p
    }

    /// Two endpoints in one process, each with its own call table, over real
    /// loopback UDP sockets through the hooks: an agreed call is encrypted on
    /// the wire and comes out of the other hook as it was sent; a plain packet
    /// in that call is dropped; a call that is not agreed passes byte for byte.
    #[test]
    fn two_endpoints_encrypt_an_agreed_call_and_leave_the_rest_alone() {
        point_at_winsock(0);
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        for s in [&a, &b] {
            s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
        }
        let ta: Arc<Mutex<CallTable>> = Default::default();
        let tb: Arc<Mutex<CallTable>> = Default::default();

        // Not agreed (no call at all): the datagram on the wire is the
        // client's own, and so is what the receiving hook hands up.
        set_table(Some(ta.clone()));
        let p = rtp(1);
        // SAFETY: real sockets, live buffers.
        assert_eq!(unsafe { send_via_hook(&a, &b, &p) }, p.len() as i32);
        let mut wire = [0u8; 1500];
        let (n, _) = b.recv_from(&mut wire).unwrap();
        assert_eq!(&wire[..n], &p[..], "byte for byte while nothing is agreed");

        agree(&ta, &tb, "loop@h", port(&a), port(&b));

        // Agreed: on the wire the header is clear and the payload is not.
        // SAFETY: as above.
        assert_eq!(
            unsafe { send_via_hook(&a, &b, &rtp(2)) },
            rtp(2).len() as i32
        );
        let (n, _) = b.recv_from(&mut wire).unwrap();
        assert_eq!(n, rtp(2).len() + crate::callmedia::OVERHEAD);
        assert_eq!(&wire[..12], &rtp(2)[..12]);
        assert!(!wire[..n].windows(12).any(|w| w == b"spoken words"));

        // Through B's hook the packet comes out as A's client sent it.
        // SAFETY: as above.
        unsafe { send_via_hook(&a, &b, &rtp(3)) };
        set_table(Some(tb.clone()));
        let mut buf = [0u8; 1500];
        // SAFETY: as above.
        let n = unsafe { recv_via_hook(&b, &mut buf) };
        assert_eq!(&buf[..n as usize], &rtp(3)[..]);

        // A plain packet in the agreed call (sent around the hook, as a
        // downgrade would be) is dropped; the encrypted one behind it is
        // what the client gets.
        a.send_to(&rtp(4), b.local_addr().unwrap()).unwrap();
        set_table(Some(ta.clone()));
        // SAFETY: as above.
        unsafe { send_via_hook(&a, &b, &rtp(5)) };
        set_table(Some(tb.clone()));
        std::thread::sleep(std::time::Duration::from_millis(50));
        // SAFETY: as above.
        let n = unsafe { recv_via_hook(&b, &mut buf) };
        assert_eq!(&buf[..n as usize], &rtp(5)[..], "the plain one was skipped");
        // A lone plain packet: dropped, the client gets a zero-length datagram.
        a.send_to(&rtp(6), b.local_addr().unwrap()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        // SAFETY: as above.
        assert_eq!(unsafe { recv_via_hook(&b, &mut buf) }, 0);
        // A buffer too small for the plain packet: truncated, WSAEMSGSIZE,
        // as Winsock itself does.
        set_table(Some(ta.clone()));
        // SAFETY: as above.
        unsafe { send_via_hook(&a, &b, &rtp(7)) };
        set_table(Some(tb.clone()));
        let mut small = [0u8; 20];
        // SAFETY: as above.
        assert_eq!(unsafe { recv_via_hook(&b, &mut small) }, SOCKET_ERROR);
        assert_eq!(unsafe { GetLastError() }, WSAEMSGSIZE);
        assert_eq!(&small[..], &rtp(7)[..20]);
        let st = lock(&tb).stats_of("loop@h").unwrap();
        assert_eq!(
            (st.rtp_in, st.plain_dropped + st.auth_failed),
            (3, 2),
            "{st:?}"
        );

        // STUN on the call's socket passes byte for byte even now.
        let stun = [
            0u8, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        set_table(Some(ta.clone()));
        // SAFETY: as above.
        unsafe { send_via_hook(&a, &b, &stun) };
        let (n, _) = b.recv_from(&mut wire).unwrap();
        assert_eq!(&wire[..n], &stun[..]);
        set_table(None);
    }

    /// Audit 2026-10, finding 8, over real sockets: with
    /// `calls_encrypt=required` and no agreed call, the client's media never
    /// reaches the wire and media that comes in plain never reaches the
    /// client; STUN passes both ways.
    #[test]
    fn with_calls_required_no_media_passes_plain() {
        point_at_winsock(0);
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        b.set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let t: Arc<Mutex<CallTable>> = Default::default();
        lock(&t).set_required(true);
        set_table(Some(t.clone()));

        let p = rtp(1);
        // SAFETY: real sockets, live buffers.
        assert_eq!(
            unsafe { send_via_hook(&a, &b, &p) },
            p.len() as i32,
            "the client is told it went"
        );
        let mut wire = [0u8; 1500];
        assert!(b.recv_from(&mut wire).is_err(), "but nothing was sent");

        b.send_to(&rtp(2), a.local_addr().unwrap()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut buf = [0u8; 1500];
        // SAFETY: as above.
        assert_eq!(unsafe { recv_via_hook(&a, &mut buf) }, 0, "dropped");
        assert!(!buf.windows(12).any(|w| w == b"spoken words"));

        let stun = [
            0u8, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        // SAFETY: as above.
        unsafe { send_via_hook(&a, &b, &stun) };
        let (n, _) = b.recv_from(&mut wire).unwrap();
        assert_eq!(&wire[..n], &stun[..]);
        set_table(None);
    }
}
