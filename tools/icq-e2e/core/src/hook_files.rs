//! The data connections of file transfers: observed (stage F0 of
//! `docs/e2e/FILES-RESEARCH.md`, `files_log=on`) and, for a transfer both
//! add-ons agreed to encrypt, encrypted at the bottom of the socket (stage
//! F3, `files_encrypt=on`), as `hook_tls.rs` does TLS for the server:
//!
//! ```text
//! client --send--> [FilePipe: hello, records] --> original send
//! client <--recv-- [FilePipe: hello, records] <-- original recv
//! ```
//!
//! Which socket is which transfer's (`filesneg::FileTable` holds what the
//! rendezvous ICBMs said):
//!
//! - a `connect` to an address and port one of the peer's proposals named
//!   (the receiver in the direct stage, the sender in the reverse stage);
//! - an accepted socket on the port one of our proposals named (`accept` is
//!   hooked for this; its local port is the listening port);
//! - a socket whose first outbound bytes are an ARS `INIT_SEND` or
//!   `INIT_RECV` naming the cookie (the proxy stage), or an OFT2 header
//!   naming it (the sender, should the address not have matched).
//!
//! Only a socket of a transfer that is agreed (or offered by us, waiting for
//! the answer) gets a pipe; every other socket - FLAP, a transfer not agreed,
//! encryption off - takes exactly the path it took before, byte for byte.
//! The exception is a transfer that must be encrypted (a contact under
//! `/e2e on` or verified, or `files_encrypt = required`) and did not agree
//! on keys: its sockets get a pipe closed from the start, and nothing of it
//! passes (second audit of 2026-10, finding 4).
//!
//! The clients' sockets are non-blocking with `WSAAsyncSelect`, so the hooks
//! do what `hook_tls.rs` does: every `recv` reaches Winsock once (that is what
//! re-arms `FD_READ`), plaintext left over is announced with a synthetic
//! `FD_READ`, `FIONREAD` counts plaintext, `MSG_PEEK` is served from it. A
//! pump thread completes connects (the answerer's hello goes out the moment
//! the connection is up), sends what the socket could not take, and runs the
//! offerer's wait for the hello.
//!
//! Fail closed: once agreed, a connection that sees anything but the agreed
//! stream is shut down both ways and the client gets `WSAECONNRESET`; a panic
//! inside these hooks on a socket with a pipe does the same - never are the
//! client's bytes sent as they are, or the peer's passed on undecrypted.

use super::*;

use std::sync::{Condvar, LazyLock};
use std::time::Duration;

use crate::files::{self, ArsRead, OftRead, Watch};
use crate::filesneg::{self, FileTable, Found};
use crate::filestream::{FilePipe, Phase, PreambleReader, Role};

const SD_BOTH: i32 = 2;

#[cfg(test)]
thread_local! {
    /// A file table for this thread only: the tests play two endpoints in one
    /// process, each with its own table.
    static TEST_TABLE: std::cell::RefCell<Option<Arc<Mutex<FileTable>>>> =
        const { std::cell::RefCell::new(None) };
}

/// The file table the hooks use.
fn table() -> Arc<Mutex<FileTable>> {
    #[cfg(test)]
    if let Some(t) = TEST_TABLE.with(|c| c.borrow().clone()) {
        return t;
    }
    filesneg::shared()
}

/// Whether file transfers are encrypted (`files_encrypt=on` in effect).
fn encrypting() -> bool {
    // In the unit tests only a thread with a table of its own encrypts, so
    // these tests never set the process's policy under the other tests.
    #[cfg(test)]
    return TEST_TABLE.with(|c| c.borrow().is_some());
    #[cfg(not(test))]
    policy().encrypts_files()
}

/// Whether file transfers are logged (`files_log=on`; always in the tests).
fn observing() -> bool {
    cfg!(test) || policy().files_log
}

fn log_table(t: &mut FileTable) {
    for l in t.take_log() {
        log::line(&l);
    }
}

// --- one encrypted (or waiting) data connection ------------------------------------

/// The pipe of one data connection.
pub(super) struct FileConn {
    pub(super) cookie: [u8; 8],
    role: Role,
    stage: &'static str,
    how: &'static str,
    pipe: Mutex<FilePipe>,
    /// Held across one original `recv` and the feeding of what it read, so
    /// bytes reach the pipe in the order they came. Taken before the pipe.
    read: Mutex<()>,
    /// Bytes for the wire the socket has not taken yet. Taken before the
    /// pipe, never the other way round.
    wire: Mutex<Vec<u8>>,
    /// The connect is still in progress.
    connecting: AtomicBool,
    closed: AtomicBool,
    owed: AtomicBool,
    /// Shut after a panic in these hooks (fail closed).
    broken: AtomicBool,
    table: Arc<Mutex<FileTable>>,
    /// The phase the last look saw, to notice a change.
    seen: AtomicU8,
}

fn phase_code(p: Phase) -> u8 {
    match p {
        Phase::Connecting => 0,
        Phase::Preamble => 1,
        Phase::Hello => 2,
        Phase::Encrypted => 3,
        Phase::Plain => 4,
        Phase::Failed => 5,
    }
}

impl FileConn {
    /// Runs `f` on the pipe with the table as its key source (lock order:
    /// pipe, then table), logs what the table says, and acts on a change of
    /// phase.
    fn with<R>(
        &self,
        sock: &Sock,
        s: Socket,
        f: impl FnOnce(&mut FilePipe, &mut FileTable) -> R,
    ) -> R {
        let (r, phase) = {
            let mut p = lock(&self.pipe);
            let mut t = filesneg::lock(&self.table);
            let r = f(&mut p, &mut t);
            log_table(&mut t);
            (r, p.phase())
        };
        self.changed(sock, s, phase);
        r
    }

    fn changed(&self, sock: &Sock, s: Socket, phase: Phase) {
        let code = phase_code(phase);
        if self.seen.swap(code, Ordering::AcqRel) == code {
            return;
        }
        match phase {
            Phase::Failed => {
                // Fail closed: shut both ways; the client reads the error.
                if !self.closed.load(Ordering::Acquire) {
                    // SAFETY: shutdown on the client's open socket.
                    unsafe { windows_sys::Win32::Networking::WinSock::shutdown(s, SD_BOTH) };
                }
                log::line(&format!(
                    "file transfer {}: socket {s} shut down (fail closed)",
                    files::cookie_tag(&self.cookie)
                ));
                post_fd_read(sock, s);
            }
            Phase::Plain | Phase::Encrypted => post_fd_read(sock, s),
            _ => {}
        }
    }

    fn failed(&self) -> bool {
        self.broken.load(Ordering::Acquire) || lock(&self.pipe).phase() == Phase::Failed
    }
}

/// Makes the pipe for `s`, a socket of the transfer `found` names, if the
/// transfer is to be encrypted (or offered by us and waiting).
fn make(
    s: Socket,
    sock: &Arc<Sock>,
    found: &Found,
    how: &'static str,
    via_proxy: bool,
    connected: bool,
) -> Option<Arc<FileConn>> {
    if sock.tls.get().is_some() || sock.file.get().is_some() {
        return None;
    }
    if let Some(why) = &found.blocked {
        refuse(s, sock, found, how, why);
        return None;
    }
    let role = found.role?;
    let fc = Arc::new(FileConn {
        cookie: found.cookie,
        role,
        stage: if via_proxy { "proxy" } else { found.stage },
        how,
        pipe: Mutex::new(FilePipe::new(
            found.cookie,
            role,
            via_proxy.then_some(files::ars_preamble as PreambleReader),
        )),
        read: Mutex::new(()),
        wire: Mutex::new(Vec::new()),
        connecting: AtomicBool::new(!connected),
        closed: AtomicBool::new(false),
        owed: AtomicBool::new(false),
        broken: AtomicBool::new(false),
        table: table(),
        seen: AtomicU8::new(0),
    });
    if sock.file.set(fc.clone()).is_err() {
        return None;
    }
    log::line(&format!(
        "file transfer {}: socket {s} ({how}, {} stage) carries it, {}: key hello and \
         encryption below the client",
        files::cookie_tag(&found.cookie),
        fc.stage,
        role.name()
    ));
    if connected {
        fc.with(sock, s, |p, t| p.connected(t, filesneg::now_ms()));
        let _ = flush(&fc, s, false);
    }
    register(s, sock.clone(), fc.clone());
    Some(fc)
}

/// A socket of a transfer that is not let through (it must be encrypted -
/// a contact under `/e2e on` or verified, or `files_encrypt = required` -
/// and did not agree on keys): it gets a pipe that is closed from the start,
/// so the client's `send` and `recv` fail and no byte passes either way, and
/// the socket is shut down.
fn refuse(s: Socket, sock: &Arc<Sock>, found: &Found, how: &'static str, why: &str) {
    let role = match filesneg::lock(&table()).we_send(&found.cookie) {
        Some(true) => Role::Offerer,
        _ => Role::Answerer,
    };
    let fc = Arc::new(FileConn {
        cookie: found.cookie,
        role,
        stage: found.stage,
        how,
        pipe: Mutex::new(FilePipe::refused(found.cookie, role, why)),
        read: Mutex::new(()),
        wire: Mutex::new(Vec::new()),
        connecting: AtomicBool::new(false),
        closed: AtomicBool::new(false),
        owed: AtomicBool::new(false),
        broken: AtomicBool::new(true),
        table: table(),
        seen: AtomicU8::new(phase_code(Phase::Failed)),
    });
    if sock.file.set(fc).is_err() {
        return;
    }
    // SAFETY: shutdown on the client's open socket.
    unsafe { windows_sys::Win32::Networking::WinSock::shutdown(s, SD_BOTH) };
    log::line(&format!(
        "file transfer {}: socket {s} ({how}) shut: the transfer is not let through ({why})",
        files::cookie_tag(&found.cookie)
    ));
    post_fd_read(sock, s);
}

// --- finding the sockets ----------------------------------------------------------

fn local_port(s: Socket) -> u16 {
    // SAFETY: getsockname into a stack buffer of the size passed.
    unsafe {
        let mut sa = [0u8; 32];
        let mut len = sa.len() as i32;
        if windows_sys::Win32::Networking::WinSock::getsockname(s, sa.as_mut_ptr().cast(), &mut len)
            != 0
            || len < 4
        {
            return 0;
        }
        u16::from_be_bytes([sa[2], sa[3]])
    }
}

/// After the original `connect` of a socket not mapped to TLS: a socket of
/// a transfer when it goes to an address a proposal of the peer named.
///
/// # Safety
/// `name` points to `namelen` readable bytes, or is null.
pub(super) unsafe fn on_connect(
    s: Socket,
    sock: &Arc<Sock>,
    name: *const u8,
    namelen: i32,
    r: i32,
    err: u32,
) {
    if !encrypting() || name.is_null() || namelen < 8 || (r != 0 && err != WSAEWOULDBLOCK) {
        return;
    }
    let sa = std::slice::from_raw_parts(name, 8);
    if u16::from_le_bytes([sa[0], sa[1]]) != 2 {
        return;
    }
    let ip = std::net::Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]);
    let port = u16::from_be_bytes([sa[2], sa[3]]);
    let found = filesneg::lock(&table()).find_connect(ip, port);
    if let Some(f) = found {
        make(s, sock, &f, "connected", false, r == 0);
    }
}

/// A socket the client accepted from `listening`: a socket of a transfer
/// when its local port is one our proposal named. It takes the listening
/// socket's `WSAAsyncSelect`, as Winsock gives it.
pub(super) fn on_accept(listening: Socket, s: Socket) {
    let sock = sock_for(s);
    sock.accepted.store(true, Ordering::Release);
    if let Some(n) = existing_sock(listening).and_then(|l| *lock(&l.notify)) {
        let mut mine = lock(&sock.notify);
        if mine.is_none() {
            *mine = Some(n);
        }
    }
    if !encrypting() {
        return;
    }
    let port = local_port(s);
    let found = filesneg::lock(&table()).find_local(port);
    if let Some(f) = found {
        make(s, &sock, &f, "accepted", false, true);
    }
}

/// The first outbound bytes of a socket that has no pipe: an ARS `INIT`, or
/// an OFT2 header, naming a transfer.
pub(super) fn on_first_out(s: Socket, sock: &Arc<Sock>, data: &[u8]) {
    if sock.file.get().is_some() || sock.file_checked.swap(true, Ordering::AcqRel) || !encrypting()
    {
        return;
    }
    if sock.tls.get().is_some() || data.first() == Some(&crate::stream::FLAP_MARKER) {
        return;
    }
    let (cookie, via_proxy) = match files::ars_frame(data) {
        ArsRead::Frame(f) if matches!(f.command, files::ARS_INIT_SEND | files::ARS_INIT_RECV) => {
            match f.cookie {
                Some(c) => (c, true),
                None => return,
            }
        }
        _ => match files::oft_header(data) {
            OftRead::Header(h) => (h.cookie, false),
            _ => return,
        },
    };
    let found = filesneg::lock(&table()).find_cookie(cookie, via_proxy);
    if let Some(f) = found {
        let how = if via_proxy {
            "to the proxy"
        } else {
            "found by its OFT2 header"
        };
        make(s, sock, &f, how, via_proxy, true);
    }
}

/// What the first inbound bytes of a socket without a pipe are.
pub(super) enum FirstIn {
    /// Not a key hello: the client's, as they came.
    Pass,
    /// A key hello of a transfer this side receives and has keys for, on a
    /// connection its address did not tie to the transfer: the pipe is made
    /// now and the hello is in it.
    Taken,
    /// A key hello that cannot be taken up: the connection is closed.
    Refuse,
}

/// The first inbound bytes of a socket without a pipe, when they start with
/// a key hello: the peer's add-on encrypts a transfer this side did not tie
/// to the socket. The receiving side, which has not sent a byte yet, takes
/// it up; anything else would hand the client noise, so the connection is
/// closed (the transfer fails; the client may retry).
pub(super) fn first_in(s: Socket, sock: &Arc<Sock>, data: &[u8]) -> FirstIn {
    if !encrypting() || !data.starts_with(crate::filestream::HELLO_MAGIC) {
        return FirstIn::Pass;
    }
    let found = crate::filestream::Hello::parse(data)
        .and_then(|h| filesneg::lock(&table()).find_hello(&h.cookie_hash));
    let silent = !sock.classified_out.load(Ordering::Acquire);
    if let Some(f) = &found {
        if f.role == Some(Role::Answerer) && silent {
            if let Some(fc) = make(s, sock, f, "found by the peer's key hello", false, true) {
                fc.with(sock, s, |p, t| p.feed(data, t, filesneg::now_ms()));
                let _ = flush(&fc, s, false);
                return FirstIn::Taken;
            }
        }
    }
    let what = found.map_or("an unknown transfer".to_string(), |f| {
        format!("transfer {}", files::cookie_tag(&f.cookie))
    });
    log::line(&format!(
        "socket {s}: a key hello for {what} on a connection not tied to it; closed"
    ));
    // SAFETY: shutdown on the client's open socket.
    unsafe { windows_sys::Win32::Networking::WinSock::shutdown(s, SD_BOTH) };
    FirstIn::Refuse
}

// --- the client's calls -----------------------------------------------------------

fn is_async(sock: &Sock) -> bool {
    lock(&sock.notify).is_some()
}

/// The client's `send` on a socket with a pipe: all of `data` is taken.
pub(super) fn send(sock: &Sock, fc: &FileConn, s: Socket, data: &[u8]) -> Result<(), u32> {
    let r = panic::catch_unwind(AssertUnwindSafe(|| {
        if fc.broken.load(Ordering::Acquire) {
            return Err(tlsio::WSAECONNRESET);
        }
        fc.connecting.store(false, Ordering::Release);
        let w = fc.with(sock, s, |p, t| p.write(data, t, filesneg::now_ms()));
        if w.is_err() {
            return Err(tlsio::WSAECONNRESET);
        }
        flush(fc, s, true)
    }));
    r.unwrap_or_else(|_| {
        fail_after_panic(sock, fc, s);
        Err(tlsio::WSAECONNRESET)
    })
}

/// A panic inside the hooks of a socket with a pipe: the connection is shut,
/// never passed through.
fn fail_after_panic(sock: &Sock, fc: &FileConn, s: Socket) {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        fc.broken.store(true, Ordering::Release);
        log::line(&format!(
            "file transfer {}: socket {s}: a panic in the add-on; the connection is shut (fail closed)",
            files::cookie_tag(&fc.cookie)
        ));
        // SAFETY: shutdown on the client's socket.
        unsafe { windows_sys::Win32::Networking::WinSock::shutdown(s, SD_BOTH) };
        post_fd_read(sock, s);
    }));
}

/// The client's `recv` on a socket with a pipe: plaintext only.
pub(super) fn recv(
    sock: &Sock,
    fc: &FileConn,
    s: Socket,
    buf: &mut [u8],
    peek: bool,
) -> Result<usize, u32> {
    let r = panic::catch_unwind(AssertUnwindSafe(|| recv_inner(sock, fc, s, buf, peek)));
    r.unwrap_or_else(|_| {
        fail_after_panic(sock, fc, s);
        Err(tlsio::WSAECONNRESET)
    })
}

fn recv_inner(
    sock: &Sock,
    fc: &FileConn,
    s: Socket,
    buf: &mut [u8],
    peek: bool,
) -> Result<usize, u32> {
    if fc.broken.load(Ordering::Acquire) {
        return Err(tlsio::WSAECONNRESET);
    }
    let mut read_once = false;
    loop {
        {
            let mut p = lock(&fc.pipe);
            if p.phase() == Phase::Failed {
                return Err(tlsio::WSAECONNRESET);
            }
            if p.plaintext_len() > 0 {
                if peek {
                    return Ok(p.peek_plaintext(buf));
                }
                let k = p.take_plaintext(buf);
                let left = p.plaintext_len() > 0;
                drop(p);
                // What is left was read from bytes Winsock already handed
                // over, so it will never announce it: we do. And every recv
                // of the client reaches Winsock once, to re-arm FD_READ.
                if !read_once && is_async(sock) {
                    touch(sock, fc, s);
                }
                if left || lock(&fc.pipe).plaintext_len() > 0 {
                    post_fd_read(sock, s);
                }
                return Ok(k);
            }
            if p.at_end() {
                return Ok(0);
            }
        }
        if fc.connecting.load(Ordering::Acquire) {
            return Err(WSAEWOULDBLOCK);
        }
        read_once = true;
        match pull(sock, fc, s, true) {
            Pulled::Data | Pulled::Busy => continue,
            Pulled::Eof => {
                let p = lock(&fc.pipe);
                if p.phase() == Phase::Failed {
                    return Err(tlsio::WSAECONNRESET);
                }
                if p.plaintext_len() == 0 {
                    return Ok(0);
                }
            }
            Pulled::Nothing => return Err(WSAEWOULDBLOCK),
            Pulled::Error(e) => return Err(e),
        }
    }
}

/// What one read of the socket gave.
enum Pulled {
    /// Bytes, fed to the pipe.
    Data,
    /// Nothing there now.
    Nothing,
    /// The end of the stream, told to the pipe.
    Eof,
    /// Another thread is reading this socket (only when not waiting).
    Busy,
    /// A Winsock error.
    Error(u32),
}

/// Reads the socket once into the pipe, under the socket's read lock, so two
/// readers (the client's `recv` and the pump) never feed bytes out of order.
/// Then sends what the pipe made (a hello, records).
fn pull(sock: &Sock, fc: &FileConn, s: Socket, wait: bool) -> Pulled {
    let r = {
        let _reading = if wait {
            lock(&fc.read)
        } else {
            match fc.read.try_lock() {
                Ok(g) => g,
                Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return Pulled::Busy,
            }
        };
        if fc.closed.load(Ordering::Acquire) || lock(&fc.pipe).at_end() {
            return Pulled::Eof;
        }
        let mut tmp = vec![0u8; READ_CHUNK];
        // SAFETY: tmp is our own buffer of tmp.len() bytes.
        let n = unsafe { orig_recv()(s, tmp.as_mut_ptr(), tmp.len() as i32, 0) };
        if n > 0 {
            fc.with(sock, s, |p, t| {
                p.feed(&tmp[..n as usize], t, filesneg::now_ms())
            });
            Pulled::Data
        } else if n == 0 {
            fc.with(sock, s, |p, t| p.end_of_input(t));
            Pulled::Eof
        } else {
            // SAFETY: reads the calling thread's last error.
            match unsafe { GetLastError() } {
                WSAEWOULDBLOCK => Pulled::Nothing,
                e => Pulled::Error(e),
            }
        }
    };
    if matches!(r, Pulled::Data) {
        if let Err(e) = flush(fc, s, false) {
            return Pulled::Error(e);
        }
    }
    r
}

/// One call of the original `recv` for a client `recv` answered from what
/// is held: that call re-arms Winsock's `FD_READ`. Returns whether
/// plaintext is waiting.
pub(super) fn touch(sock: &Sock, fc: &FileConn, s: Socket) -> bool {
    if fc.connecting.load(Ordering::Acquire) || !is_async(sock) || fc.closed.load(Ordering::Acquire)
    {
        return false;
    }
    let _ = pull(sock, fc, s, false);
    lock(&fc.pipe).plaintext_len() > 0
}

/// `FIONREAD` on a socket with a pipe: the plaintext the pipe holds, after
/// reading what the socket has now.
pub(super) fn plaintext_waiting(sock: &Sock, fc: &FileConn, s: Socket) -> u32 {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        if !fc.connecting.load(Ordering::Acquire) && readable_now(s) {
            let _ = pull(sock, fc, s, false);
        }
    }));
    fc.pipe.try_lock().map_or(0, |p| p.plaintext_len() as u32)
}

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

/// Sends what the pipe has for the wire, in order. With `wait` the socket's
/// buffer is waited for (the client's own `send`); without it what is left
/// is the pump's.
fn flush(fc: &FileConn, s: Socket, wait: bool) -> Result<(), u32> {
    if fc.connecting.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut wire = if wait {
        lock(&fc.wire)
    } else {
        match fc.wire.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                fc.owed.store(true, Ordering::Release);
                wake_pump();
                return Ok(());
            }
        }
    };
    flush_locked(fc, s, &mut wire, wait)
}

fn flush_locked(fc: &FileConn, s: Socket, wire: &mut Vec<u8>, wait: bool) -> Result<(), u32> {
    let mut waited = 0u32;
    loop {
        if fc.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        {
            let mut p = lock(&fc.pipe);
            if p.wants_write() {
                wire.extend_from_slice(&p.take_wire());
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
            fc.owed.store(true, Ordering::Release);
            wake_pump();
            return Ok(());
        }
        wait_writable(s, 100);
        waited += 100;
    }
}

/// `closesocket` on a socket with a pipe: the final record, best effort,
/// then nothing touches the handle again.
pub(super) fn close(fc: &FileConn, s: Socket) {
    let mut wire = lock(&fc.wire);
    {
        let mut p = lock(&fc.pipe);
        p.close();
    }
    if !fc.connecting.load(Ordering::Acquire) {
        let _ = flush_locked(fc, s, &mut wire, false);
    }
    let p = lock(&fc.pipe);
    let (out, inn) = p.records();
    log::line(&format!(
        "file transfer {}: socket {s} closed ({}, {} stage, {}): {} B from the client, {} B to it, \
         records {out} out / {inn} in, {}",
        files::cookie_tag(&fc.cookie),
        fc.how,
        fc.stage,
        match p.phase() {
            Phase::Encrypted => "encrypted",
            Phase::Plain => "unencrypted, untouched",
            Phase::Failed => "closed for failing",
            _ => "before the key hellos ended",
        },
        p.plain_out,
        p.plain_in,
        fc.role.name()
    ));
    fc.closed.store(true, Ordering::Release);
}

/// Whether the socket is closed for good (fail closed): `send` and `recv`
/// answer `WSAECONNRESET` at once.
pub(super) fn refused(fc: &FileConn) -> bool {
    fc.failed()
}

// --- the pump --------------------------------------------------------------------

struct Pump {
    list: Mutex<Vec<(Socket, Arc<Sock>, Arc<FileConn>)>>,
    wake: Condvar,
}

static PUMP: LazyLock<Pump> = LazyLock::new(|| Pump {
    list: Mutex::new(Vec::new()),
    wake: Condvar::new(),
});
static PUMP_STARTED: std::sync::Once = std::sync::Once::new();

fn register(s: Socket, sock: Arc<Sock>, fc: Arc<FileConn>) {
    PUMP_STARTED.call_once(|| {
        let _ = std::thread::Builder::new()
            .name("icq-e2e files pump".into())
            .spawn(|| loop {
                if panic::catch_unwind(pump_round).is_err() {
                    log::line("files pump: a round panicked; going on");
                }
            });
    });
    lock(&PUMP.list).push((s, sock, fc));
    PUMP.wake.notify_all();
}

fn wake_pump() {
    PUMP.wake.notify_all();
}

fn pump_wants(fc: &FileConn) -> bool {
    if fc.closed.load(Ordering::Acquire) {
        return false;
    }
    if fc.connecting.load(Ordering::Acquire) || fc.owed.load(Ordering::Acquire) {
        return true;
    }
    match fc.pipe.try_lock() {
        Ok(p) => p.phase() == Phase::Hello || p.wants_write(),
        Err(_) => true,
    }
}

/// Whether the connection is in its key hello exchange.
fn in_hello(fc: &FileConn) -> bool {
    fc.pipe
        .try_lock()
        .map(|p| p.phase() == Phase::Hello)
        .unwrap_or(false)
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

fn pump_round() {
    let items: Vec<(Socket, Arc<Sock>, Arc<FileConn>)> = {
        let mut list = lock(&PUMP.list);
        // A connection stays on the list until it is closed: one passing
        // through the proxy's frames now needs the pump again at READY.
        list.retain(|(_, _, fc)| !fc.closed.load(Ordering::Acquire));
        let wanted: Vec<_> = list
            .iter()
            .filter(|(_, _, fc)| pump_wants(fc))
            .cloned()
            .collect();
        if wanted.is_empty() {
            let _ = PUMP
                .wake
                .wait_timeout(list, Duration::from_millis(100))
                .map(|_| ());
            return;
        }
        wanted
    };
    // SAFETY: zeroed FD_SETs are empty sets.
    let (mut r, mut w, mut e): (FD_SET, FD_SET, FD_SET) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed()) };
    for (s, _, fc) in &items {
        if fc.connecting.load(Ordering::Acquire) || fc.owed.load(Ordering::Acquire) {
            fd_add(&mut w, *s);
            fd_add(&mut e, *s);
        } else if in_hello(fc) {
            // The hellos: read by the pump, whatever the client does.
            fd_add(&mut r, *s);
        }
    }
    let tv = TIMEVAL {
        tv_sec: 0,
        tv_usec: 50_000,
    };
    let n = if w.fd_count > 0 || r.fd_count > 0 {
        // SAFETY: select on our own sets; a socket closed meanwhile only
        // makes it fail, and `closed` is checked before any use.
        unsafe { select(0, &mut r, &mut w, &mut e, &tv) }
    } else {
        std::thread::sleep(Duration::from_millis(50));
        0
    };
    for (s, sock, fc) in &items {
        let s = *s;
        if fc.closed.load(Ordering::Acquire) {
            continue;
        }
        if fc.connecting.load(Ordering::Acquire) {
            if n > 0 && fd_isset(&e, s) {
                // The connect failed: the client hears it from Winsock; the
                // pipe has nothing to do.
                fc.connecting.store(false, Ordering::Release);
                fc.closed.store(true, Ordering::Release);
                continue;
            }
            if n > 0 && fd_isset(&w, s) {
                fc.connecting.store(false, Ordering::Release);
                fc.with(sock, s, |p, t| p.connected(t, filesneg::now_ms()));
                let _ = flush(fc, s, false);
            }
            continue;
        }
        if n > 0 && fd_isset(&r, s) && in_hello(fc) {
            let before = lock(&fc.pipe).plaintext_len();
            if matches!(pull(sock, fc, s, false), Pulled::Data | Pulled::Eof)
                && lock(&fc.pipe).plaintext_len() > before
            {
                post_fd_read(sock, s);
            }
        }
        let waiting = fc.pipe.try_lock().map(|p| p.waiting()).unwrap_or(false);
        if waiting {
            fc.with(sock, s, |p, t| p.tick(t, filesneg::now_ms()));
        }
        if fc.owed.swap(false, Ordering::AcqRel)
            || fc.pipe.try_lock().map(|p| p.wants_write()).unwrap_or(false)
        {
            if let Err(err) = flush(fc, s, false) {
                log::line(&format!(
                    "file transfer {}: socket {s}: send failed, Winsock error {err}",
                    files::cookie_tag(&fc.cookie)
                ));
                fc.closed.store(true, Ordering::Release);
            }
        }
    }
}

/// At start: says what the add-on does with file transfers.
pub(super) fn start() {
    if policy().files_log {
        log::line(
            "files_log=on: file transfers are observed (stages, OFT2 header types and sizes, \
             totals; never names, addresses or content)",
        );
    }
    if policy().encrypts_files() {
        log::line(
            "files_encrypt=on: a file transfer is encrypted end to end when both add-ons agree on \
             its keys through the E2E session; any other transfer is left exactly as it is,              except with a contact under /e2e on or verified (or files_encrypt=required),              whose transfer is not sent",
        );
    }
}

/// The timers of the file table (offers, cancelled transfers), from the
/// poll worker.
pub(super) fn tick() {
    let t = filesneg::shared();
    let mut g = filesneg::lock(&t);
    g.tick(filesneg::now_ms());
    log_table(&mut g);
}

// --- watching (files_log) -----------------------------------------------------------

/// `files_log=on`: the plaintext of a call on a socket that is, or may be, a
/// file transfer's, for the log. Decided on the first bytes: a FLAP socket
/// costs one look. Changes nothing.
pub(super) fn watch(s: Socket, sock: &Sock, dir: Direction, data: &[u8]) {
    if data.is_empty() || !observing() || sock.file_watch_off.load(Ordering::Acquire) {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut slot = lock(&sock.file_watch);
        if slot.is_none() {
            if sock.file.get().is_none() && !Watch::looks_like_transfer(data) {
                sock.file_watch_off.store(true, Ordering::Release);
                return;
            }
            *slot = Some(Watch::new(filesneg::now_ms()));
        }
        let w = slot.as_mut().expect("just made");
        let lines = w.feed(dir, data);
        if lines.is_empty() {
            return;
        }
        let tag = w
            .cookie
            .or_else(|| sock.file.get().map(|f| f.cookie))
            .map_or_else(|| "?".to_string(), |c| files::cookie_tag(&c));
        for l in lines {
            log::line(&format!("file transfer {tag}: socket {s}: {l}"));
        }
    }));
}

/// The socket is closing: the watch's totals, with what the table knows
/// (which way, which stage).
pub(super) fn closed(s: Socket, sock: &Sock) {
    if !observing() {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let Some(w) = lock(&sock.file_watch).take() else {
            return;
        };
        if !w.known && sock.file.get().is_none() {
            return;
        }
        let cookie = w.cookie.or_else(|| sock.file.get().map(|f| f.cookie));
        let t = table();
        let g = filesneg::lock(&t);
        let (tag, way) = match cookie {
            Some(c) => (
                files::cookie_tag(&c),
                match g.we_send(&c) {
                    Some(true) => "we send",
                    Some(false) => "they send",
                    None => "direction unknown",
                },
            ),
            None => ("?".to_string(), "direction unknown"),
        };
        let stage = match sock.file.get() {
            Some(f) => f.stage,
            None => {
                let port = local_port(s);
                let by_local = if sock.accepted.load(Ordering::Acquire) {
                    g.find_local(port).map(|f| f.stage)
                } else {
                    None
                };
                by_local.unwrap_or("stage unknown")
            }
        };
        log::line(&format!(
            "file transfer {tag}: socket {s} closed ({}, {way}, {stage}) {}",
            if sock.accepted.load(Ordering::Acquire) {
                "accepted"
            } else {
                "connected"
            },
            w.totals(filesneg::now_ms())
        ));
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callneg::{Me, PeerInfo};
    use crate::files::tests::proposal;
    use crate::filesneg::Msg;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
    use std::os::windows::io::AsRawSocket;
    use std::time::Instant;
    use windows_sys::Win32::Networking::WinSock;

    const A: &str = "100001";
    const B: &str = "100002";

    fn point_at_winsock() {
        // The process's policy, as the socket tests of hook.rs set it: the
        // first test to ask wins, and observe mode would bypass the hooks.
        let _ = set_policy_once(Policy::harness());
        ORIG_SEND.store(WinSock::send as *const () as usize, Ordering::Release);
        ORIG_RECV.store(WinSock::recv as *const () as usize, Ordering::Release);
        ORIG_CONNECT.store(WinSock::connect as *const () as usize, Ordering::Release);
        ORIG_ACCEPT.store(WinSock::accept as *const () as usize, Ordering::Release);
        ORIG_CLOSE.store(
            WinSock::closesocket as *const () as usize,
            Ordering::Release,
        );
        ORIG_IOCTL.store(
            WinSock::ioctlsocket as *const () as usize,
            Ordering::Release,
        );
    }

    fn set_table(t: Option<Arc<Mutex<FileTable>>>) {
        TEST_TABLE.with(|c| *c.borrow_mut() = t);
    }

    type Table = Arc<Mutex<FileTable>>;

    fn me(uin: &str, dev: u32, k: u8) -> Me {
        Me {
            uin: uin.into(),
            device: dev,
            key: [k; 32],
        }
    }

    fn rdv(
        dir: Direction,
        peer: &str,
        cookie: [u8; 8],
        seq: u16,
        port: u16,
        ars: bool,
    ) -> files::Rendezvous {
        files::rendezvous(
            dir,
            &proposal(dir, peer, cookie, seq, Ipv4Addr::LOCALHOST, port, ars),
        )
        .unwrap()
    }

    /// A (sends) and B (receives) see the rendezvous of `cookie`: A's
    /// proposal names `a_port` (where A accepts), B's copy names `b_port`
    /// (where B connects); with `agree`, B has the offer and keys, and A
    /// the answer when `answered`.
    fn setup(
        ta: &Table,
        tb: &Table,
        cookie: [u8; 8],
        a_port: u16,
        b_port: u16,
        agree: bool,
        answered: bool,
    ) {
        let (mut a, mut b) = (filesneg::lock(ta), filesneg::lock(tb));
        let ra = rdv(Direction::Outbound, B, cookie, 1, a_port, false);
        a.observe(&ra, 0);
        let offer = a.icbm(&ra, PeerInfo::default(), &mut || Ok(me(A, 1, 1)), 0);
        let rb = rdv(Direction::Inbound, A, cookie, 1, b_port, false);
        if agree {
            for p in offer {
                // B's copy names another port (the relay of these tests
                // stands in for the network); the offer binds the proposal
                // B is meant to see, as A's real one would.
                let mut m = Msg::decode(&p).unwrap();
                if let Msg::Offer { digest, .. } = &mut m {
                    *digest = Some(rb.digest);
                }
                b.control(A, 1, m, 0, 0);
            }
        }
        b.observe(&rb, 0);
        b.icbm(&rb, PeerInfo::default(), &mut || Ok(me(B, 2, 2)), 0);
        if agree && answered {
            let acc = files::rendezvous(
                Direction::Outbound,
                &files::tests::rdv_payload(Direction::Outbound, A, files::RDV_ACCEPT, cookie, &[]),
            )
            .unwrap();
            for p in b.icbm(&acc, PeerInfo::default(), &mut || Ok(me(B, 2, 2)), 0) {
                a.control(B, 2, Msg::decode(&p).unwrap(), 0, 0);
            }
        }
    }

    /// A TCP relay standing in for the network (or a NAT's forward): what
    /// passes each way is recorded, and either way can have bytes of its own
    /// put in.
    struct Relay {
        port: u16,
        seen: Arc<Mutex<[Vec<u8>; 2]>>,
    }

    fn relay_to(target: u16) -> Relay {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen: Arc<Mutex<[Vec<u8>; 2]>> = Default::default();
        let s2 = seen.clone();
        std::thread::spawn(move || {
            let (inbound, _) = l.accept().unwrap();
            let out = TcpStream::connect(("127.0.0.1", target)).unwrap();
            splice(inbound, out, s2);
        });
        Relay { port, seen }
    }

    /// Copies both ways until either side ends, recording.
    fn splice(a: TcpStream, b: TcpStream, seen: Arc<Mutex<[Vec<u8>; 2]>>) {
        for (mut from, mut to, i) in [
            (a.try_clone().unwrap(), b.try_clone().unwrap(), 0usize),
            (b, a, 1usize),
        ] {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match from.read(&mut buf) {
                        Ok(0) | Err(_) => {
                            let _ = to.shutdown(std::net::Shutdown::Write);
                            return;
                        }
                        Ok(n) => {
                            seen.lock().unwrap()[i].extend_from_slice(&buf[..n]);
                            if to.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    }

    /// A raw non-blocking socket, as the client makes one.
    fn raw_socket() -> Socket {
        // SAFETY: plain socket calls.
        unsafe {
            let mut d: WinSock::WSADATA = std::mem::zeroed();
            WinSock::WSAStartup(0x0202, &mut d);
            let s = WinSock::socket(2, 1, 6);
            assert_ne!(s, WinSock::INVALID_SOCKET);
            let mut one = 1u32;
            WinSock::ioctlsocket(s, WinSock::FIONBIO, &mut one);
            s
        }
    }

    fn connect_via_hook(s: Socket, port: u16) {
        let (r, err) = testing::connect(s, SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        assert!(r == 0 || err == WSAEWOULDBLOCK, "connect: {r} {err}");
    }

    /// `accept` through the hook, retried until the peer has connected.
    fn accept_via_hook(l: Socket) -> Socket {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: a listening socket of ours; no address wanted.
            let s = unsafe { hook_accept(l, ptr::null_mut(), ptr::null_mut()) };
            if s != WinSock::INVALID_SOCKET {
                let mut one = 1u32;
                // SAFETY: the new socket.
                unsafe { WinSock::ioctlsocket(s, WinSock::FIONBIO, &mut one) };
                return s;
            }
            assert!(Instant::now() < deadline, "nobody connected");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn listener() -> (TcpListener, Socket, u16) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port();
        let s = l.as_raw_socket() as Socket;
        (l, s, port)
    }

    fn client_send(s: Socket, data: &[u8]) {
        let sock = sock_for(s);
        assert_eq!(transport_send(&sock, s, data, 0), data.len() as i32);
    }

    /// Reads through the hooks until `want` bytes came, as a client polling
    /// on FD_READ would.
    fn client_read(s: Socket, want: usize) -> Result<Vec<u8>, u32> {
        let sock = sock_for(s);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 3000];
        while out.len() < want {
            let n = transport_recv(&sock, s, buf.as_mut_ptr(), buf.len(), 0);
            if n > 0 {
                out.extend_from_slice(&buf[..n as usize]);
                continue;
            }
            if n == 0 {
                break;
            }
            // SAFETY: the thread's last error.
            let e = unsafe { GetLastError() };
            if e != WSAEWOULDBLOCK {
                return Err(e);
            }
            assert!(
                Instant::now() < deadline,
                "timed out with {} of {want}",
                out.len()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(out)
    }

    fn file(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// The OFT2 conversation of one file, both ends through the hooks: the
    /// sender's prompt, the receiver's ack, the file, the done. Returns what
    /// each side's client got.
    fn talk(
        sender: Socket,
        receiver: Socket,
        cookie: [u8; 8],
        ta: &Table,
        tb: &Table,
        body: &[u8],
    ) {
        let n = body.len() as u32;
        let prompt = files::oft_build(files::OFT_PROMPT, &cookie, n, 0, "secret plans.pdf");
        set_table(Some(ta.clone()));
        client_send(sender, &prompt);
        set_table(Some(tb.clone()));
        // FIONREAD counts the plaintext, MSG_PEEK leaves it where it is.
        let rsock = sock_for(receiver);
        let fc = rsock.file.get().expect("the receiver's pipe").clone();
        let deadline = Instant::now() + Duration::from_secs(10);
        while (plaintext_waiting(&rsock, &fc, receiver) as usize) < prompt.len() {
            assert!(Instant::now() < deadline, "FIONREAD never saw the prompt");
            std::thread::sleep(Duration::from_millis(2));
        }
        let mut peek = [0u8; 4];
        let peeked = transport_recv(&rsock, receiver, peek.as_mut_ptr(), 4, MSG_PEEK);
        assert_eq!((peeked, &peek), (4, b"OFT2"));
        assert_eq!(client_read(receiver, prompt.len()).unwrap(), prompt);
        let ack = files::oft_build(files::OFT_ACK, &cookie, n, 0, "secret plans.pdf");
        client_send(receiver, &ack);
        set_table(Some(ta.clone()));
        assert_eq!(client_read(sender, ack.len()).unwrap(), ack);
        for chunk in body.chunks(7000) {
            client_send(sender, chunk);
        }
        set_table(Some(tb.clone()));
        let got = client_read(receiver, body.len()).unwrap();
        assert!(got == body, "the file arrives as it was sent");
        let done = files::oft_build(files::OFT_DONE, &cookie, n, n, "secret plans.pdf");
        client_send(receiver, &done);
        set_table(Some(ta.clone()));
        assert_eq!(client_read(sender, done.len()).unwrap(), done);
    }

    fn sha(b: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, b)
            .as_ref()
            .to_vec()
    }

    /// Direct stage: B connects (through a relay standing in for the
    /// network) to A's listening port; both agreed. The wire carries the
    /// hellos and records only - no OFT2, no file name, no file byte - and
    /// each client gets exactly what the other sent.
    #[test]
    fn direct_stage_both_on_is_encrypted_on_the_wire() {
        point_at_winsock();
        let cookie = [0xD1; 8];
        let (ta, tb): (Table, Table) = Default::default();
        let (_l, ls, a_port) = listener();
        let relay = relay_to(a_port);
        setup(&ta, &tb, cookie, a_port, relay.port, true, false);
        let bs = raw_socket();
        set_table(Some(tb.clone()));
        connect_via_hook(bs, relay.port);
        assert!(
            sock_for(bs).file.get().is_some(),
            "B's connect is the transfer's"
        );
        set_table(Some(ta.clone()));
        let as_ = accept_via_hook(ls);
        assert!(
            sock_for(as_).file.get().is_some(),
            "A's accepted socket is the transfer's"
        );
        let body = file(100_000);
        talk(as_, bs, cookie, &ta, &tb, &body);
        let seen = relay.seen.lock().unwrap().clone();
        for (i, w) in seen.iter().enumerate() {
            assert!(
                w.starts_with(crate::filestream::HELLO_MAGIC),
                "{i}: the hello first"
            );
            assert!(
                !w.windows(4).any(|x| x == b"OFT2"),
                "{i}: no OFT2 on the wire"
            );
            assert!(
                !w.windows(12).any(|x| x == b"secret plans"),
                "{i}: no file name"
            );
            assert!(
                !w.windows(64).any(|x| x == &body[1000..1064]),
                "{i}: no file bytes"
            );
        }
        assert!(
            seen[1].len() > body.len(),
            "the file went A to B, encrypted"
        );
        assert_eq!(filesneg::lock(&ta).state_of(&cookie), Some("keyed"));
        assert!(filesneg::lock(&ta)
            .take_notes()
            .iter()
            .any(|n| n.text.contains("is end-to-end encrypted")));
        set_table(Some(ta.clone()));
        let _ = testing::close(as_);
        set_table(Some(tb.clone()));
        let _ = testing::close(bs);
        set_table(None);
    }

    /// The receiver's connect went to an address no proposal named (a NAT
    /// rewrote it, say): the sender, which had the answer, speaks first, and
    /// the receiver takes its connection up by the key hello.
    #[test]
    fn a_receiver_finds_its_connection_by_the_senders_hello() {
        point_at_winsock();
        let cookie = [0xD7; 8];
        let (ta, tb): (Table, Table) = Default::default();
        let (_l, ls, a_port) = listener();
        let relay = relay_to(a_port);
        setup(&ta, &tb, cookie, a_port, 1, true, true);
        let bs = raw_socket();
        set_table(Some(tb.clone()));
        connect_via_hook(bs, relay.port);
        assert!(
            sock_for(bs).file.get().is_none(),
            "no proposal names the relay"
        );
        set_table(Some(ta.clone()));
        let as_ = accept_via_hook(ls);
        assert!(sock_for(as_).file.get().is_some());
        let prompt = files::oft_build(files::OFT_PROMPT, &cookie, 10, 0, "n");
        client_send(as_, &prompt);
        set_table(Some(tb.clone()));
        assert_eq!(client_read(bs, prompt.len()).unwrap(), prompt);
        assert!(sock_for(bs).file.get().is_some(), "taken up by the hello");
        let seen = relay.seen.lock().unwrap().clone();
        assert!(!seen[1].windows(4).any(|x| x == b"OFT2"));
        set_table(Some(ta.clone()));
        let _ = testing::close(as_);
        set_table(Some(tb.clone()));
        let _ = testing::close(bs);
        set_table(None);
    }

    /// Reverse stage: B listens (its counter-proposal), A connects; A had
    /// the answer through the chat already, so both hellos go at once.
    #[test]
    fn reverse_stage_both_on_is_encrypted() {
        point_at_winsock();
        let cookie = [0xD2; 8];
        let (ta, tb): (Table, Table) = Default::default();
        setup(&ta, &tb, cookie, 1, 2, true, true);
        let (_l, ls, b_port) = listener();
        let relay = relay_to(b_port);
        {
            let counter_out = rdv(Direction::Outbound, A, cookie, 2, b_port, false);
            filesneg::lock(&tb).observe(&counter_out, 0);
            let counter_in = rdv(Direction::Inbound, B, cookie, 2, relay.port, false);
            filesneg::lock(&ta).observe(&counter_in, 0);
        }
        let as_ = raw_socket();
        set_table(Some(ta.clone()));
        connect_via_hook(as_, relay.port);
        set_table(Some(tb.clone()));
        let bs = accept_via_hook(ls);
        let body = file(40_000);
        talk(as_, bs, cookie, &ta, &tb, &body);
        let seen = relay.seen.lock().unwrap().clone();
        assert!(!seen[0].windows(4).any(|x| x == b"OFT2"));
        set_table(Some(ta.clone()));
        let _ = testing::close(as_);
        set_table(Some(tb.clone()));
        let _ = testing::close(bs);
        set_table(None);
    }

    /// Through a (simulated) rendezvous proxy: both connect to it, the ARS
    /// frames pass untouched both ways, and the stream is encrypted after
    /// READY. The proxy sees no OFT2.
    #[test]
    fn proxy_stage_ars_in_clear_then_encrypted() {
        point_at_winsock();
        let cookie = [0xD3; 8];
        let (ta, tb): (Table, Table) = Default::default();
        setup(&ta, &tb, cookie, 1, 2, true, false);
        // The proxy: two connections, INIT from each, ACK to the first,
        // READY to both, then splice.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let pport = l.local_addr().unwrap().port();
        let seen: Arc<Mutex<[Vec<u8>; 2]>> = Default::default();
        let s2 = seen.clone();
        std::thread::spawn(move || {
            let read_frame = |s: &mut TcpStream| {
                let mut h = [0u8; 2];
                s.read_exact(&mut h).unwrap();
                let mut rest = vec![0u8; u16::from_be_bytes(h) as usize];
                s.read_exact(&mut rest).unwrap();
                [h.to_vec(), rest].concat()
            };
            let (mut x, _) = l.accept().unwrap();
            let f = read_frame(&mut x);
            assert!(
                matches!(files::ars_frame(&f), ArsRead::Frame(a) if a.command == files::ARS_INIT_SEND)
            );
            x.write_all(&files::ars_build(
                files::ARS_ACK,
                &[0x12, 0x34, 127, 0, 0, 1],
            ))
            .unwrap();
            let (mut y, _) = l.accept().unwrap();
            let f = read_frame(&mut y);
            assert!(
                matches!(files::ars_frame(&f), ArsRead::Frame(a) if a.command == files::ARS_INIT_RECV)
            );
            let ready = files::ars_build(files::ARS_READY, &[]);
            x.write_all(&ready).unwrap();
            y.write_all(&ready).unwrap();
            splice(x, y, s2);
        });
        let init_send = {
            let mut b = vec![6];
            b.extend_from_slice(A.as_bytes());
            b.extend_from_slice(&cookie);
            crate::snac::put_tlv(&mut b, 1, &files::CAP_FILE_TRANSFER);
            files::ars_build(files::ARS_INIT_SEND, &b)
        };
        let init_recv = {
            let mut b = vec![6];
            b.extend_from_slice(B.as_bytes());
            b.extend_from_slice(&0x1234u16.to_be_bytes());
            b.extend_from_slice(&cookie);
            crate::snac::put_tlv(&mut b, 1, &files::CAP_FILE_TRANSFER);
            files::ars_build(files::ARS_INIT_RECV, &b)
        };
        // A: connect, wait for it, INIT_SEND, read ACK.
        let as_ = raw_socket();
        set_table(Some(ta.clone()));
        connect_via_hook(as_, pport);
        assert!(
            sock_for(as_).file.get().is_none(),
            "the proxy is no proposal's address"
        );
        wait_writable(as_, 2000);
        client_send(as_, &init_send);
        assert!(sock_for(as_).file.get().is_some(), "found by its INIT_SEND");
        let ack = client_read(as_, 18).unwrap();
        assert!(matches!(files::ars_frame(&ack), ArsRead::Frame(a) if a.command == files::ARS_ACK));
        // B: connect, INIT_RECV.
        let bs = raw_socket();
        set_table(Some(tb.clone()));
        connect_via_hook(bs, pport);
        wait_writable(bs, 2000);
        client_send(bs, &init_recv);
        assert_eq!(
            client_read(bs, 12).unwrap(),
            files::ars_build(files::ARS_READY, &[])
        );
        set_table(Some(ta.clone()));
        assert_eq!(
            client_read(as_, 12).unwrap(),
            files::ars_build(files::ARS_READY, &[])
        );
        let body = file(20_000);
        talk(as_, bs, cookie, &ta, &tb, &body);
        let seen = seen.lock().unwrap().clone();
        for w in &seen {
            assert!(w.starts_with(crate::filestream::HELLO_MAGIC));
            assert!(!w.windows(4).any(|x| x == b"OFT2"));
        }
        set_table(Some(ta.clone()));
        let _ = testing::close(as_);
        set_table(Some(tb.clone()));
        let _ = testing::close(bs);
        set_table(None);
    }

    /// Backward compatibility: the receiver's add-on does not take part (no
    /// add-on, an older one, files off: no answer, no hello). The sender's
    /// add-on holds its first bytes for the wait, then the connection is the
    /// clients' own - on the wire byte for byte what they sent. A transfer
    /// that was never agreed is not touched at all.
    #[test]
    fn a_peer_that_does_not_take_part_gets_the_bytes_untouched() {
        point_at_winsock();
        let cookie = [0xD4; 8];
        let (ta, tb): (Table, Table) = Default::default();
        setup(&ta, &tb, cookie, 0, 0, false, false);
        let (_l, ls, a_port) = listener();
        {
            let ra = rdv(Direction::Outbound, B, cookie, 1, a_port, false);
            filesneg::lock(&ta).observe(&ra, 0);
        }
        let relay = relay_to(a_port);
        // B: no table of its own (files off), so nothing of B is touched.
        set_table(None);
        let bs = raw_socket();
        connect_via_hook(bs, relay.port);
        assert!(sock_for(bs).file.get().is_none());
        set_table(Some(ta.clone()));
        let as_ = accept_via_hook(ls);
        assert!(
            sock_for(as_).file.get().is_some(),
            "A offered: it waits for a hello"
        );
        let prompt = files::oft_build(files::OFT_PROMPT, &cookie, 30_000, 0, "plain.txt");
        let started = Instant::now();
        client_send(as_, &prompt);
        set_table(None);
        let got = client_read(bs, prompt.len()).unwrap();
        assert_eq!(got, prompt);
        assert!(started.elapsed() >= Duration::from_millis(crate::filestream::HELLO_WAIT_MS - 200));
        let body = file(30_000);
        let ack = files::oft_build(files::OFT_ACK, &cookie, 30_000, 0, "plain.txt");
        client_send(bs, &ack);
        set_table(Some(ta.clone()));
        assert_eq!(client_read(as_, ack.len()).unwrap(), ack);
        client_send(as_, &body);
        set_table(None);
        assert_eq!(sha(&client_read(bs, body.len()).unwrap()), sha(&body));
        std::thread::sleep(Duration::from_millis(100));
        let seen = relay.seen.lock().unwrap().clone();
        assert_eq!(
            seen[1],
            [prompt.clone(), body.clone()].concat(),
            "A to B byte for byte"
        );
        assert_eq!(seen[0], ack, "B to A byte for byte");
        let n = filesneg::lock(&ta).take_notes();
        assert!(
            n.iter()
                .any(|n| n.text.contains("is not end-to-end encrypted")),
            "{n:?}"
        );
        set_table(Some(ta.clone()));
        let _ = testing::close(as_);
        let _ = testing::close(bs);
        set_table(None);
    }

    /// Second audit of 2026-10, finding 4, through the hooks over real
    /// sockets: with `files_encrypt = required` (every contact strict) the
    /// sender's peer does not take part (no add-on: no answer, no hello).
    /// After the wait the connection is shut: not one byte of the prompt or
    /// the file reaches the wire, the receiving client gets nothing, the
    /// sender's client gets an error, and the chat says it was not sent.
    #[test]
    fn with_files_required_nothing_reaches_the_wire_for_a_peer_without_the_add_on() {
        point_at_winsock();
        let cookie = [0xD8; 8];
        let (ta, tb): (Table, Table) = Default::default();
        filesneg::lock(&ta).set_required(true);
        let (_l, ls, a_port) = listener();
        let relay = relay_to(a_port);
        setup(&ta, &tb, cookie, a_port, 0, false, false);
        set_table(None);
        let bs = raw_socket();
        connect_via_hook(bs, relay.port);
        set_table(Some(ta.clone()));
        let as_ = accept_via_hook(ls);
        assert!(sock_for(as_).file.get().is_some(), "A offered: it waits");
        let prompt = files::oft_build(files::OFT_PROMPT, &cookie, 30_000, 0, "plain.txt");
        client_send(as_, &prompt);
        std::thread::sleep(Duration::from_millis(
            crate::filestream::HELLO_WAIT_MS + 700,
        ));
        let sent = transport_send(&sock_for(as_), as_, &file(5000), 0);
        assert_eq!(sent, SOCKET_ERROR, "the sender's client is told");
        set_table(None);
        let got = client_read(bs, 1);
        assert!(
            matches!(&got, Ok(v) if v.is_empty()) || got.is_err(),
            "{got:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
        let seen = relay.seen.lock().unwrap().clone();
        assert!(seen[1].is_empty(), "no byte A to B: {:?}", seen[1].len());
        assert!(filesneg::lock(&ta).take_notes().iter().any(
            |n| n.text.contains("was not sent") && n.text.contains("files_encrypt = required")
        ));
        set_table(Some(ta.clone()));
        let _ = testing::close(as_);
        set_table(None);
        let _ = testing::close(bs);
    }

    /// The receiving side of the same: a verified contact (or `required`)
    /// whose proposal came without a key offer - the sender has no add-on -
    /// and whose connection is plain OFT2: the receiver's socket is refused,
    /// its client never sees the prompt, and it sends nothing.
    #[test]
    fn a_strict_receiver_refuses_a_sender_without_the_add_on() {
        point_at_winsock();
        let cookie = [0xD9; 8];
        let tb: Table = Default::default();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        {
            // B's table sees A's proposal, without a key offer, from a
            // verified contact.
            let rb = rdv(Direction::Inbound, A, cookie, 1, port, false);
            let mut b = filesneg::lock(&tb);
            b.observe(&rb, 0);
            b.icbm(
                &rb,
                PeerInfo {
                    strict: true,
                    verified: true,
                },
                &mut || Ok(me(B, 2, 2)),
                0,
            );
            assert_eq!(b.state_of(&cookie), Some("blocked"));
        }
        let prompt = files::oft_build(files::OFT_PROMPT, &cookie, 5, 0, "x");
        let p2 = prompt.clone();
        let peer = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let _ = s.write_all(&p2);
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
            rest
        });
        let bs = raw_socket();
        set_table(Some(tb.clone()));
        connect_via_hook(bs, port);
        assert!(
            sock_for(bs).file.get().is_some(),
            "refused by a closed pipe"
        );
        let r = client_read(bs, 1);
        assert!(
            matches!(r, Err(tlsio::WSAECONNRESET)) || matches!(&r, Ok(v) if v.is_empty()),
            "{r:?}"
        );
        assert_ne!(r.as_deref().ok(), Some(&prompt[..]));
        assert_eq!(
            transport_send(&sock_for(bs), bs, b"OFT2 ack", 0),
            SOCKET_ERROR
        );
        let rest = peer.join().unwrap();
        assert!(rest.is_empty(), "nothing was sent: {rest:?}");
        let _ = testing::close(bs);
        set_table(None);
    }

    /// Once agreed, plain bytes where the stream should be close the
    /// connection: the client gets an error, never the bytes.
    #[test]
    fn plain_bytes_on_an_agreed_connection_close_it() {
        point_at_winsock();
        let cookie = [0xD5; 8];
        let (ta, tb): (Table, Table) = Default::default();
        setup(&ta, &tb, cookie, 1, 0, true, false);
        // B's peer is a plain listener (an attacker, or a client whose
        // add-on went plain): it sends OFT2 in clear.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        {
            let rb = rdv(Direction::Inbound, A, cookie, 1, port, false);
            filesneg::lock(&tb).observe(&rb, 0);
        }
        let prompt = files::oft_build(files::OFT_PROMPT, &cookie, 5, 0, "x");
        let p2 = prompt.clone();
        let peer = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut hello = vec![0u8; crate::filestream::HELLO_LEN];
            s.read_exact(&mut hello).unwrap();
            assert!(
                hello.starts_with(crate::filestream::HELLO_MAGIC),
                "B said hello at once"
            );
            s.write_all(&p2).unwrap();
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
            rest
        });
        let bs = raw_socket();
        set_table(Some(tb.clone()));
        connect_via_hook(bs, port);
        let r = client_read(bs, 1);
        assert!(
            matches!(r, Err(tlsio::WSAECONNRESET)) || matches!(&r, Ok(v) if v.is_empty()),
            "{r:?}"
        );
        assert_ne!(r.as_deref().ok(), Some(&prompt[..]));
        let rest = peer.join().unwrap();
        assert!(rest.is_empty(), "nothing more was sent: {rest:?}");
        assert!(filesneg::lock(&tb)
            .take_notes()
            .iter()
            .any(|n| n.text.contains("was stopped")));
        let _ = testing::close(bs);
        set_table(None);
    }

    /// files_log: an OFT2 connection is watched and its totals logged; a
    /// FLAP connection is let go after one look.
    #[test]
    fn the_watch_follows_a_plain_transfer_and_ignores_flap() {
        let sock = Sock::new();
        let c = [0xD6; 8];
        watch(
            1,
            &sock,
            Direction::Outbound,
            &files::oft_build(files::OFT_PROMPT, &c, 10, 0, "n"),
        );
        watch(
            1,
            &sock,
            Direction::Inbound,
            &files::oft_build(files::OFT_ACK, &c, 10, 0, "n"),
        );
        watch(1, &sock, Direction::Outbound, &[1; 10]);
        let w = lock(&sock.file_watch);
        let w = w.as_ref().unwrap();
        assert_eq!(w.cookie, Some(c));
        assert!(w.totals(0).contains("10 B file data"), "{}", w.totals(0));
        let flap = Sock::new();
        watch(
            2,
            &flap,
            Direction::Outbound,
            &[0x2A, 1, 0, 1, 0, 4, 0, 0, 0, 1],
        );
        assert!(flap.file_watch_off.load(Ordering::Acquire));
        assert!(lock(&flap.file_watch).is_none());
    }
}
