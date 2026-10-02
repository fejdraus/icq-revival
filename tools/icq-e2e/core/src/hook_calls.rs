//! The call media sockets, observed (stage C0 of `docs/e2e/CALLS-RESEARCH.md`).
//!
//! With `calls_log=on` the loader notification that patches the networking
//! module also patches the two modules a call runs in, the moment either is
//! mapped: `sipXtapi.dll` (6.5 and 7.2: SIP, STUN/TURN, ICE, and on 6.5 the
//! GIPS engine itself) and `sipXmediaLib.dll` (7.2: the GIPS engine). Both are
//! loaded only when a call starts. Their Winsock imports are by ordinal, from
//! `wsock32.dll` or `ws2_32.dll`, and are matched by name exactly as for the
//! networking module.
//!
//! Hooked: `sendto`, `recvfrom`, and `send`/`recv` for a connected UDP socket,
//! `WSASendTo`/`WSARecvFrom` where a module has them (the research found
//! none), `bind` and `closesocket` for bookkeeping. Every hook calls the
//! original first, with the client's own arguments, and returns its result and
//! last error untouched; only then are the bytes that went through handed to
//! [`crate::calls`] to be classified. Nothing is ever changed, held or
//! dropped. A panic while looking falls back to having looked at nothing.
//!
//! Each module has its own slots for the originals, so a hook always calls
//! the function its own module imported (`wsock32`'s `recvfrom` is not
//! assumed to be `ws2_32`'s).

use super::*;

use std::net::Ipv4Addr;

use windows_sys::Win32::Networking::WinSock;
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

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
    let r = orig::<SendToFn>(M, F_SENDTO)(s, buf, len, flags, to, tolen);
    if r > 0 && !buf.is_null() {
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
    let r = orig::<RecvFromFn>(M, F_RECVFROM)(s, buf, len, flags, from, fromlen);
    if r > 0 && !buf.is_null() && flags & MSG_PEEK == 0 {
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
    let r = orig::<SendFn>(M, F_SEND)(s, buf, len, flags);
    if r > 0 && !buf.is_null() {
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
    let r = orig::<RecvFn>(M, F_RECV)(s, buf, len, flags);
    if r > 0 && !buf.is_null() && flags & MSG_PEEK == 0 {
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
    let r = orig::<WsaSendToFn>(M, F_WSASENDTO)(
        s, bufs, count, sent, flags, to, tolen, overlapped, completion,
    );
    let err = GetLastError();
    if r == 0 || err == WSA_IO_PENDING {
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
            lock(infos()).remove(&s);
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
/// another module or with `calls_log` off. Patching is idempotent, so a module
/// that is unloaded after a call and loaded again for the next is patched
/// again. Returns whether the module is patched.
pub(super) fn on_load(name: &str, base: usize, via: &str, in_loader: bool) -> bool {
    if !policy().calls_log {
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
    match patch_iat(base, &hooks, &resolve_ordinal) {
        Ok(report) => {
            log::line(&format!(
                "call hooks installed in {name} at {base:#010x} ({via}): {report}; \
                 observation only, nothing is changed"
            ));
            true
        }
        Err(reason) => {
            log::line(&format!(
                "call hooks: {name} ({via}): could not patch: {reason}"
            ));
            if in_loader && reason.contains("not bound") {
                retry_later(m);
            }
            false
        }
    }
}

/// Patches module `m` from a thread of its own once the loader is done with
/// it: a thread starts only after the load that made it has finished.
fn retry_later(m: usize) {
    unsafe extern "system" fn retry(arg: *mut core::ffi::c_void) -> u32 {
        let m = arg as usize;
        let name = CALL_MODULES[m];
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        for _ in 0..100 {
            let base = GetModuleHandleW(w.as_ptr()) as usize;
            if base != 0 && on_load(name, base, "after load", false) {
                return 0;
            }
            Sleep(50);
        }
        log::line(&format!("call hooks: gave up patching {name}"));
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
    if !policy().calls_log {
        return;
    }
    log::line(
        "calls_log=on: call media and signalling are observed (classes, sizes, \
         ports; never content); nothing is changed",
    );
    for name in CALL_MODULES {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: a NUL-terminated name.
        let base = unsafe { GetModuleHandleW(w.as_ptr()) } as usize;
        if base != 0 {
            on_load(name, base, "already loaded at start", false);
        }
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
}
