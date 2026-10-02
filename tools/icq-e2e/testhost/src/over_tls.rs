//! The add-on's whole path through the real Winsock hooks, over TLS 1.3
//! (STAGE-TLS T3).
//!
//! The client side is driven the way coolcore drives its sockets: a real
//! non-blocking socket, `WSAAsyncSelect` to a hidden (message-only) window,
//! one `recv` per `FD_READ` into a small buffer, `send` whenever it likes -
//! all through the hook bodies, with the real Winsock functions as the
//! originals. The server is an in-process rustls server with an rcgen
//! certificate for `icq.example.org` on a loopback port. The route maps two
//! plain ports nobody listens on (a FLAP one and an HTTP one) to it, so a
//! connection that was not mapped would simply be refused.
//!
//! Account A is the hooked client; account B is a second device in memory
//! (the same engine, as in the in-memory run), reached through the server.
//!
//! Scenarios: the 6.5 BUCP sign-in, the 7.2 web sign-in over HTTP, BOS with
//! the token, the account key and E2E messages both ways, slow and coalesced
//! delivery, a server that cuts the connection mid-frame, a reconnect, and the
//! fail-closed cases: a wrong certificate, a TLS 1.2 server, a closed TLS
//! port, a server port the add-on cannot secure, a proxy, a connection opened
//! past the hooks. Then `tls=off`: today's bytes, and the note in the chat.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use icqe2e_core::config::{Policy, Settings};
use icqe2e_core::directory::MemoryDirectory;
use icqe2e_core::hook::testing::{self as hooks, Active, Setup};
use icqe2e_core::route::{Ports, Route};
use icqe2e_core::session::Session;
use icqe2e_core::stream::StreamRewriter;
use icqe2e_core::text;
use icqe2e_core::tls::{TlsClient, TlsSettings, Trust, ALPN_HTTP, ALPN_OSCAR};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use windows_sys::Win32::Networking::WinSock;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use crate::{
    flap, message_payload, message_text, motd, set_info, snac, tlv, to_client, to_host, Client,
    Temp,
};

const WAIT: Duration = Duration::from_secs(10);
const SERVER: &str = "icq.example.org";
const WSAEWOULDBLOCK: u32 = 10035;
const WSAECONNRESET: u32 = 10054;
const WSAECONNREFUSED: u32 = 10061;
const MSG_PEEK: i32 = 2;
const FD_READ: i32 = 0x01;
const FD_WRITE: i32 = 0x02;
const FD_CONNECT: i32 = 0x10;
const FD_CLOSE: i32 = 0x20;
const WM_SOCKET: u32 = wm::WM_USER + 0x100;

type Check = Result<(), String>;
type Scenario = fn(&mut Ctx) -> Check;

fn ensure(cond: bool, what: impl FnOnce() -> String) -> Check {
    if cond {
        Ok(())
    } else {
        Err(what())
    }
}

// --- certificates -----------------------------------------------------------

struct Pki {
    ca: CertificateDer<'static>,
    good: Arc<ServerConfig>,
    wrong_name: Arc<ServerConfig>,
    tls12_only: Arc<ServerConfig>,
}

fn pki() -> Pki {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ICQ E2E testhost CA");
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let leaf = |name: &str| {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .signed_by(&key, &ca)
            .unwrap();
        (
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    };
    let config = |name: &str, versions: &[&'static rustls::SupportedProtocolVersion]| {
        let (cert, key) = leaf(name);
        let mut cfg =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap();
        cfg.alpn_protocols = vec![ALPN_OSCAR.to_vec(), ALPN_HTTP.to_vec()];
        Arc::new(cfg)
    };
    Pki {
        ca: ca.der().clone(),
        good: config(SERVER, &[&rustls::version::TLS13]),
        wrong_name: config("other.example.org", &[&rustls::version::TLS13]),
        tls12_only: config(SERVER, &[&rustls::version::TLS12]),
    }
}

// --- the TLS server ---------------------------------------------------------

enum Cmd {
    Write(Vec<u8>),
    /// Written a few bytes at a time, so records arrive cut anywhere.
    WriteSlow(Vec<u8>),
    CloseNotify,
    /// A TCP close without `close_notify`.
    Cut,
}

enum Event {
    Data(Vec<u8>),
    End,
}

/// One accepted connection, as the scenario sees it.
struct Remote {
    alpn: Option<Vec<u8>>,
    /// Why the handshake failed, if it did.
    failed: Option<String>,
    /// Every byte the client put on the wire.
    raw: Arc<Mutex<Vec<u8>>>,
    cmd: Option<Sender<Cmd>>,
    events: Option<Receiver<Event>>,
    buf: Vec<u8>,
    ended: bool,
    /// The sequence number of the last FLAP frame the client sent.
    last_seq: Option<u16>,
}

impl Remote {
    fn fill(&mut self, deadline: Instant) -> bool {
        let Some(ev) = &self.events else {
            return false;
        };
        let left = deadline.saturating_duration_since(Instant::now());
        match ev.recv_timeout(left) {
            Ok(Event::Data(d)) => {
                self.buf.extend_from_slice(&d);
                true
            }
            Ok(Event::End) | Err(RecvTimeoutError::Disconnected) => {
                self.ended = true;
                false
            }
            Err(RecvTimeoutError::Timeout) => false,
        }
    }

    /// The next whole FLAP frame the client sent; its sequence number must
    /// follow the last one.
    fn frame(&mut self) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + WAIT;
        loop {
            if !self.buf.is_empty() && self.buf[0] != 0x2A {
                return Err(format!(
                    "not FLAP from the client: {:02x?}",
                    &self.buf[..self.buf.len().min(16)]
                ));
            }
            if self.buf.len() >= 6 {
                let n = 6 + u16::from_be_bytes([self.buf[4], self.buf[5]]) as usize;
                if self.buf.len() >= n {
                    let f: Vec<u8> = self.buf.drain(..n).collect();
                    let seq = u16::from_be_bytes([f[2], f[3]]);
                    if let Some(last) = self.last_seq {
                        ensure(seq == last.wrapping_add(1), || {
                            format!("client sequence {seq} after {last}")
                        })?;
                    }
                    self.last_seq = Some(seq);
                    return Ok(f);
                }
            }
            if self.ended || (!self.fill(deadline) && Instant::now() >= deadline) {
                return Err(format!(
                    "no frame from the client ({} bytes held)",
                    self.buf.len()
                ));
            }
        }
    }

    /// The client's frames until one with this SNAC.
    fn frame_with(&mut self, fg: u16, sg: u16) -> Result<Vec<u8>, String> {
        loop {
            let f = self.frame()?;
            if is_snac(&f, fg, sg) {
                return Ok(f);
            }
        }
    }

    /// One HTTP request: the head and a `Content-Length` body.
    fn http_request(&mut self) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(end) = find(&self.buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.buf[..end]).to_ascii_lowercase();
                let body = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if self.buf.len() >= end + 4 + body {
                    return Ok(self.buf.drain(..end + 4 + body).collect());
                }
            }
            if self.ended || (!self.fill(deadline) && Instant::now() >= deadline) {
                return Err(format!("no whole request ({} bytes held)", self.buf.len()));
            }
        }
    }

    fn send(&self, data: &[u8]) {
        if let Some(c) = &self.cmd {
            let _ = c.send(Cmd::Write(data.to_vec()));
        }
    }

    fn send_slow(&self, data: &[u8]) {
        if let Some(c) = &self.cmd {
            let _ = c.send(Cmd::WriteSlow(data.to_vec()));
        }
    }

    fn close_notify(&self) {
        if let Some(c) = &self.cmd {
            let _ = c.send(Cmd::CloseNotify);
        }
    }

    fn cut(&self) {
        if let Some(c) = &self.cmd {
            let _ = c.send(Cmd::Cut);
        }
    }

    fn raw(&self) -> Vec<u8> {
        self.raw.lock().unwrap().clone()
    }
}

struct TlsServer {
    port: u16,
    config: Arc<Mutex<Arc<ServerConfig>>>,
    accepted: Receiver<Remote>,
}

impl TlsServer {
    fn start(config: Arc<ServerConfig>) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let config = Arc::new(Mutex::new(config));
        let (tx, accepted) = mpsc::channel();
        let cfg = config.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { continue };
                let c = cfg.lock().unwrap().clone();
                let tx = tx.clone();
                std::thread::spawn(move || serve(s, c, tx));
            }
        });
        TlsServer {
            port,
            config,
            accepted,
        }
    }

    fn set_config(&self, c: Arc<ServerConfig>) {
        *self.config.lock().unwrap() = c;
    }

    fn accept(&self) -> Result<Remote, String> {
        self.accepted
            .recv_timeout(WAIT)
            .map_err(|_| "the server got no connection".to_string())
    }
}

fn feed(conn: &mut ServerConnection, data: &[u8]) -> Result<(), String> {
    let mut rest = data;
    while !rest.is_empty() {
        conn.read_tls(&mut rest).map_err(|e| e.to_string())?;
        conn.process_new_packets().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn write_out(conn: &mut ServerConnection, sock: &mut TcpStream, slow: bool) -> std::io::Result<()> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out)?;
    }
    if slow {
        for (i, piece) in out.chunks(3).enumerate() {
            sock.write_all(piece)?;
            if i % 4 == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    } else {
        sock.write_all(&out)
    }
}

fn drain_plain(conn: &mut ServerConnection, ev: &Sender<Event>) {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = conn.reader().read(&mut chunk) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    if !out.is_empty() {
        let _ = ev.send(Event::Data(out));
    }
}

/// One connection on the server: the handshake, then whatever the scenario
/// says, with what the client sends handed to it.
fn serve(mut sock: TcpStream, cfg: Arc<ServerConfig>, tx: Sender<Remote>) {
    let _ = sock.set_nodelay(true);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(20)));
    let raw = Arc::new(Mutex::new(Vec::new()));
    let failed = |why: String, raw: &Arc<Mutex<Vec<u8>>>, sock: &TcpStream| {
        // The alert is out; a FIN after it, and the client's last bytes
        // read, so no reset overtakes the alert.
        let _ = sock.shutdown(Shutdown::Write);
        let mut sink = [0u8; 4096];
        let end = Instant::now() + Duration::from_millis(500);
        while Instant::now() < end {
            match (&*sock).read(&mut sink) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        let _ = tx.send(Remote {
            alpn: None,
            failed: Some(why),
            raw: raw.clone(),
            cmd: None,
            events: None,
            buf: Vec::new(),
            ended: true,
            last_seq: None,
        });
    };
    let mut conn = ServerConnection::new(cfg).unwrap();
    let deadline = Instant::now() + WAIT;
    let mut buf = vec![0u8; 16384];
    while conn.is_handshaking() {
        if write_out(&mut conn, &mut sock, false).is_err() {
            return failed("write failed during the handshake".into(), &raw, &sock);
        }
        if Instant::now() > deadline {
            return failed("handshake timed out".into(), &raw, &sock);
        }
        match sock.read(&mut buf) {
            Ok(0) => return failed("the client closed during the handshake".into(), &raw, &sock),
            Ok(n) => {
                raw.lock().unwrap().extend_from_slice(&buf[..n]);
                if let Err(e) = feed(&mut conn, &buf[..n]) {
                    let _ = write_out(&mut conn, &mut sock, false);
                    return failed(e, &raw, &sock);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return failed(e.to_string(), &raw, &sock),
        }
    }
    let _ = write_out(&mut conn, &mut sock, false);
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (ev_tx, ev_rx) = mpsc::channel();
    let _ = tx.send(Remote {
        alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
        failed: None,
        raw: raw.clone(),
        cmd: Some(cmd_tx),
        events: Some(ev_rx),
        buf: Vec::new(),
        ended: false,
        last_seq: None,
    });
    drain_plain(&mut conn, &ev_tx);
    loop {
        loop {
            match cmd_rx.try_recv() {
                Ok(Cmd::Write(b)) => {
                    let _ = conn.writer().write_all(&b);
                    let _ = write_out(&mut conn, &mut sock, false);
                }
                Ok(Cmd::WriteSlow(b)) => {
                    let _ = conn.writer().write_all(&b);
                    let _ = write_out(&mut conn, &mut sock, true);
                }
                Ok(Cmd::CloseNotify) => {
                    conn.send_close_notify();
                    let _ = write_out(&mut conn, &mut sock, false);
                    let _ = sock.shutdown(Shutdown::Write);
                }
                Ok(Cmd::Cut) => {
                    let _ = sock.shutdown(Shutdown::Both);
                    let _ = ev_tx.send(Event::End);
                    return;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        match sock.read(&mut buf) {
            Ok(0) => {
                let _ = ev_tx.send(Event::End);
                return;
            }
            Ok(n) => {
                raw.lock().unwrap().extend_from_slice(&buf[..n]);
                if feed(&mut conn, &buf[..n]).is_err() {
                    let _ = ev_tx.send(Event::End);
                    return;
                }
                drain_plain(&mut conn, &ev_tx);
                let _ = write_out(&mut conn, &mut sock, false);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => {
                let _ = ev_tx.send(Event::End);
                return;
            }
        }
    }
}

// --- the client, driven like coolcore ---------------------------------------

/// A client socket with its own message-only window.
struct FakeClient {
    s: usize,
    hwnd: windows_sys::Win32::Foundation::HWND,
    /// What one `recv` asks for.
    chunk: usize,
    got: Vec<u8>,
    connected: Option<u32>,
    closed: Option<u32>,
    eof: bool,
    error: Option<u32>,
}

impl FakeClient {
    /// A non-blocking socket, `WSAAsyncSelect`, and `connect` - all through
    /// the hooks - to `addr`. Returns the client and what `connect` said.
    fn open(addr: SocketAddrV4, chunk: usize) -> (FakeClient, i32, u32) {
        // Winsock is started by the standard library's first socket.
        static WINSOCK: std::sync::Once = std::sync::Once::new();
        WINSOCK.call_once(|| drop(std::net::UdpSocket::bind("127.0.0.1:0")));
        // SAFETY: plain Winsock and window calls, Winsock started above.
        let (s, hwnd) = unsafe {
            let s = WinSock::socket(
                WinSock::AF_INET as i32,
                WinSock::SOCK_STREAM,
                WinSock::IPPROTO_TCP,
            );
            assert_ne!(s, WinSock::INVALID_SOCKET, "socket");
            let class: Vec<u16> = "STATIC".encode_utf16().chain(Some(0)).collect();
            let hwnd = wm::CreateWindowExW(
                0,
                class.as_ptr(),
                class.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                wm::HWND_MESSAGE,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            );
            assert!(!hwnd.is_null(), "message window");
            (s, hwnd)
        };
        let r = hooks::async_select(
            s,
            hwnd as usize,
            WM_SOCKET,
            FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE,
        );
        assert_eq!(r, 0, "WSAAsyncSelect");
        let (r, err) = hooks::connect(s, addr);
        (
            FakeClient {
                s,
                hwnd,
                chunk,
                got: Vec::new(),
                connected: None,
                closed: None,
                eof: false,
                error: None,
            },
            r,
            err,
        )
    }

    /// Opens and expects the non-blocking "in progress".
    fn connect(port: u16, chunk: usize) -> Result<FakeClient, String> {
        let (c, r, err) = FakeClient::open(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), chunk);
        ensure(r == -1 && err == WSAEWOULDBLOCK, || {
            format!("connect said {r}/{err}, not in progress")
        })?;
        Ok(c)
    }

    fn read_once(&mut self) {
        let mut buf = vec![0u8; self.chunk];
        let (n, err) = hooks::recv(self.s, &mut buf, 0);
        if n > 0 {
            self.got.extend_from_slice(&buf[..n as usize]);
        } else if n == 0 {
            self.eof = true;
        } else if err != WSAEWOULDBLOCK {
            self.error = Some(err);
        }
    }

    fn on_event(&mut self, event: i32, err: u32) {
        match event {
            FD_CONNECT => self.connected = Some(err),
            FD_READ => self.read_once(),
            FD_CLOSE => {
                self.closed = Some(err);
                // A client reads what is left when the connection closes.
                for _ in 0..1000 {
                    if self.eof || self.error.is_some() {
                        break;
                    }
                    let before = self.got.len();
                    self.read_once();
                    if self.got.len() == before && !self.eof && self.error.is_none() {
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    /// Runs the window's messages until `until` holds.
    fn pump(&mut self, what: &str, until: impl Fn(&FakeClient) -> bool) -> Check {
        let deadline = Instant::now() + WAIT;
        loop {
            if until(self) {
                return Ok(());
            }
            let mut any = false;
            // SAFETY: a zeroed MSG filled by PeekMessageW for our own window.
            unsafe {
                let mut msg: wm::MSG = std::mem::zeroed();
                while wm::PeekMessageW(&mut msg, self.hwnd, 0, 0, wm::PM_REMOVE) != 0 {
                    any = true;
                    if msg.message == WM_SOCKET && msg.wParam == self.s {
                        let event = (msg.lParam & 0xFFFF) as i32;
                        let err = ((msg.lParam >> 16) & 0xFFFF) as u32;
                        self.on_event(event, err);
                    }
                    if until(self) {
                        return Ok(());
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for {what}: got {} bytes, connected {:?}, closed {:?}, eof {}, error {:?}",
                    self.got.len(),
                    self.connected,
                    self.closed,
                    self.eof,
                    self.error
                ));
            }
            if !any {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    /// Waits for `n` whole frames in what the client got.
    fn pump_frames(&mut self, what: &str, n: usize) -> Check {
        self.pump(what, |c| frames(&c.got).0.len() >= n)
    }

    fn send(&self, data: &[u8]) -> Check {
        let (n, err) = hooks::send(self.s, data);
        ensure(n == data.len() as i32, || {
            format!("send of {} bytes said {n}/{err}", data.len())
        })
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.got)
    }
}

impl Drop for FakeClient {
    fn drop(&mut self) {
        hooks::close(self.s);
        // SAFETY: our own window.
        unsafe { wm::DestroyWindow(self.hwnd) };
    }
}

// --- frames -----------------------------------------------------------------

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The whole FLAP frames at the start of `buf`, and how many bytes they take.
fn frames(buf: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut out = Vec::new();
    let mut at = 0;
    while buf.len() >= at + 6 && buf[at] == 0x2A {
        let n = 6 + u16::from_be_bytes([buf[at + 4], buf[at + 5]]) as usize;
        if buf.len() < at + n {
            break;
        }
        out.push(buf[at..at + n].to_vec());
        at += n;
    }
    (out, at)
}

fn is_snac(frame: &[u8], fg: u16, sg: u16) -> bool {
    frame.len() >= 10
        && frame[1] == 2
        && u16::from_be_bytes([frame[6], frame[7]]) == fg
        && u16::from_be_bytes([frame[8], frame[9]]) == sg
}

/// The sequence numbers of `frames` follow one another.
fn contiguous(frames: &[Vec<u8>], what: &str) -> Check {
    for w in frames.windows(2) {
        let a = u16::from_be_bytes([w[0][2], w[0][3]]);
        let b = u16::from_be_bytes([w[1][2], w[1][3]]);
        ensure(b == a.wrapping_add(1), || {
            format!("{what}: sequence {b} after {a}")
        })?;
    }
    Ok(())
}

fn server_hello() -> Vec<u8> {
    flap(1, 1, &[0, 0, 0, 1])
}

fn user_info(uin: &str) -> Vec<u8> {
    let mut body = vec![uin.len() as u8];
    body.extend_from_slice(uin.as_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    snac(0x0001, 0x000F, &body)
}

fn http_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// --- the run ----------------------------------------------------------------

struct Ctx {
    server: TlsServer,
    pki: Pki,
    dir: Arc<MemoryDirectory>,
    client: TlsClient,
    plain_flap: u16,
    plain_http: u16,
    /// A port the route counts as the server's, with a listener the tests
    /// connect to past the hooks.
    unseen: TcpListener,
    b: Client,
    /// The server's own FLAP sequence on the BOS connection.
    seq: u16,
}

impl Ctx {
    fn setup(&self, tls_port: u16) -> Setup {
        let unseen = self.unseen.local_addr().unwrap().port();
        Setup::Active(Active {
            route: Route::new(
                SERVER,
                Ports {
                    flap: vec![self.plain_flap, self.server.port, unseen],
                    http: vec![self.plain_http],
                    tls: tls_port,
                },
                Box::new(|_| vec![Ipv4Addr::LOCALHOST]),
            ),
            client: Ok(self.client.clone()),
        })
    }

    fn next_seq(&mut self) -> u16 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    /// The message boxes, waiting a little for `want` of them: the pump
    /// thread tells the user just after the client has seen the reset.
    fn notices(&self, want: usize) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got = Vec::new();
        loop {
            got.extend(hooks::take_notices());
            if got.len() >= want || Instant::now() >= deadline {
                // Anything that comes right after is counted too.
                std::thread::sleep(Duration::from_millis(50));
                got.extend(hooks::take_notices());
                return got;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn no_notices(&self) -> Check {
        let n = hooks::take_notices();
        ensure(n.is_empty(), || format!("unexpected message box: {n:?}"))
    }
}

/// Runs every scenario; whether all of them passed.
pub fn run() -> bool {
    let home = Temp::new("tls-a");
    let home_b = Temp::new("tls-b");
    hooks::init(Policy::from_settings(Settings {
        mode: Some("encrypt"),
        home: home.0.to_str(),
        ..Default::default()
    }));
    hooks::capture_notices();
    let dir = Arc::new(MemoryDirectory::new());
    hooks::set_directory(dir.clone());
    let pki = pki();
    let server = TlsServer::start(pki.good.clone());
    let client = TlsClient::new(&TlsSettings {
        server_name: SERVER.into(),
        trust: Trust::Roots(vec![pki.ca.clone()]),
        pins: Vec::new(),
    })
    .unwrap();

    // B: a second device in memory, signed on and published.
    let (out, inb) = StreamRewriter::pair();
    let mut b = Client {
        out,
        inb,
        session: Session::open(dir.clone(), &home_b.0, "100002").unwrap(),
        uin: "100002".into(),
        label: "B",
        now: icqe2e_core::crypto::unix_now(),
    };
    let mut wire = Vec::new();
    b.feed_in(&server_hello(), &mut wire);
    b.feed_out(&crate::hello(), &mut wire);
    b.feed_in(&flap(2, 2, &motd(&dir.token("100002"))), &mut wire);
    let key = b.account_key();
    dir.announce("100002", &key);
    b.feed_out(&flap(2, 3, &set_info()), &mut wire);

    let mut ctx = Ctx {
        server,
        pki,
        dir,
        client,
        plain_flap: free_port(),
        plain_http: free_port(),
        unseen: TcpListener::bind("127.0.0.1:0").unwrap(),
        b,
        seq: 0,
    };
    hooks::set_tls(ctx.setup(ctx.server.port));

    let scenarios: [(&str, Scenario); 16] = [
        (
            "6.5 sign-in: BUCP over TLS, server speaks first",
            bucp_sign_in,
        ),
        (
            "7.2 sign-in: clientLogin and startOSCARSession over HTTP/TLS",
            web_sign_in,
        ),
        (
            "BOS: token, account key, E2E both ways, slow and coalesced records",
            bos_and_e2e,
        ),
        ("reconnect after a cut mid-frame, E2E again", reconnect),
        (
            "wrong certificate: no plaintext, one message box",
            wrong_certificate,
        ),
        ("TLS 1.2 server: refused", tls12_server),
        ("closed TLS port: refused", closed_port),
        ("another port of the server: refused", other_port),
        ("a proxy asked for the server: refused", proxy),
        ("a socket opened past the hooks: reset", unseen_socket),
        ("many small frames from both sides", stress),
        (
            "small reads of a long HTTP answer, FD_READ only",
            small_reads,
        ),
        (
            "hello right after the handshake, 40 connections",
            hello_after_handshake,
        ),
        (
            "every recv of the client reaches Winsock (FD_READ re-armed)",
            recv_reaches_winsock,
        ),
        ("tls=off: today's bytes", tls_off_bytes),
        ("tls=off: the note in the chat", tls_off_note),
    ];
    let mut ok = true;
    for (name, f) in scenarios {
        match f(&mut ctx) {
            Ok(()) => println!("ok  [TLS] {name}"),
            Err(why) => {
                eprintln!("FAIL [TLS] {name}: {why}");
                ok = false;
            }
        }
    }
    if ok {
        println!(
            "\nok: the whole path ran through the hooks over TLS 1.3, and every failure was closed"
        );
    }
    ok
}

/// 6.5: the server speaks first (no byte from the client before its hello),
/// the BUCP challenge and login pass unchanged, the login reply is followed by
/// a clean close. FIONREAD and MSG_PEEK see plaintext only; getpeername sees
/// the port the client asked for.
fn bucp_sign_in(ctx: &mut Ctx) -> Check {
    let mut c = FakeClient::connect(ctx.plain_flap, 512)?;
    let mut r = ctx.server.accept()?;
    ensure(r.failed.is_none(), || format!("handshake: {:?}", r.failed))?;
    ensure(r.alpn.as_deref() == Some(ALPN_OSCAR), || {
        format!("ALPN {:?}", r.alpn)
    })?;
    c.pump("FD_CONNECT", |c| c.connected.is_some())?;
    ensure(c.connected == Some(0), || {
        format!("FD_CONNECT error {:?}", c.connected)
    })?;
    ensure(hooks::peer_port(c.s) == Some(ctx.plain_flap), || {
        format!("getpeername said {:?}", hooks::peer_port(c.s))
    })?;

    r.send(&server_hello());
    c.pump("the server's hello", |c| c.got.len() >= 10)?;
    ensure(c.take() == server_hello(), || "hello changed".into())?;

    let hello = flap(1, 1, &[0, 0, 0, 1]);
    let challenge_req = flap(2, 2, &snac(0x0017, 0x0006, &tlv(0x0001, b"100001")));
    c.send(&[hello.clone(), challenge_req.clone()].concat())?;
    ensure(r.frame()? == hello, || "client hello changed".into())?;
    ensure(r.frame()? == challenge_req, || {
        "challenge request changed".into()
    })?;

    let mut key = vec![0u8, 10];
    key.extend_from_slice(b"0123456789");
    let challenge = flap(2, 1, &snac(0x0017, 0x0007, &key));
    r.send(&challenge);
    // FIONREAD counts plaintext (it reads the socket itself), MSG_PEEK keeps it.
    let deadline = Instant::now() + WAIT;
    while (hooks::fionread(c.s) as usize) < challenge.len() {
        ensure(Instant::now() < deadline, || {
            "FIONREAD never counted the challenge".into()
        })?;
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut peek = [0u8; 6];
    let (n, _) = hooks::recv(c.s, &mut peek, MSG_PEEK);
    ensure(n == 6 && peek[..] == challenge[..6], || {
        format!("MSG_PEEK gave {n}")
    })?;
    c.pump("the challenge", |c| c.got.len() >= challenge.len())?;
    ensure(c.take() == challenge, || "challenge changed".into())?;

    let login = flap(
        2,
        3,
        &snac(
            0x0017,
            0x0002,
            &[tlv(0x0001, b"100001"), tlv(0x0025, &[0xAB; 16])].concat(),
        ),
    );
    c.send(&login)?;
    ensure(r.frame()? == login, || "login request changed".into())?;
    let host = format!("127.0.0.1:{}", ctx.plain_flap);
    let reply = flap(
        2,
        2,
        &snac(
            0x0017,
            0x0003,
            &[
                tlv(0x0001, b"100001"),
                tlv(0x0005, host.as_bytes()),
                tlv(0x0006, &[0xC0; 256]),
            ]
            .concat(),
        ),
    );
    r.send(&reply);
    r.close_notify();
    c.pump("the end of the sign-in", |c| c.eof || c.error.is_some())?;
    ensure(c.error.is_none(), || format!("error {:?}", c.error))?;
    ensure(c.take() == reply, || "login reply changed".into())?;
    // The digest and the UIN crossed the wire only inside TLS.
    let raw = r.raw();
    ensure(
        find(&raw, &[0xAB; 16]).is_none() && find(&raw, b"100001").is_none(),
        || "plaintext on the wire".into(),
    )?;
    ctx.no_notices()
}

/// 7.2: the HTTP request is written before the handshake has even started
/// (rustls holds it), then one after FD_CONNECT. Both arrive whole over ALPN
/// http/1.1; both responses come back whole with a clean end.
fn web_sign_in(ctx: &mut Ctx) -> Check {
    let body = "devId=ic1&f=xml&s=100001&pwd=x&tokenType=longterm";
    let login = format!(
        "POST /auth/clientLogin HTTP/1.0\r\nHost: {SERVER}:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        ctx.plain_http,
        body.len()
    );
    let mut c = FakeClient::connect(ctx.plain_http, 300)?;
    // At once, while the socket is still connecting.
    c.send(login.as_bytes())?;
    let mut r = ctx.server.accept()?;
    ensure(r.alpn.as_deref() == Some(ALPN_HTTP), || {
        format!("ALPN {:?}", r.alpn)
    })?;
    ensure(r.http_request()? == login.as_bytes(), || {
        "request changed".into()
    })?;
    let answer = http_response("<response><statusCode>200</statusCode><data><token><a>t</a></token><sessionSecret>s</sessionSecret></data></response>");
    r.send(&answer);
    r.close_notify();
    c.pump("the clientLogin answer", |c| c.eof || c.error.is_some())?;
    ensure(c.error.is_none() && c.take() == answer, || {
        "answer changed".into()
    })?;
    drop(c);

    let start = format!(
        "GET /aim/startOSCARSession?a=t&f=json&k=ic1&ts=1&useTLS=0&sig_sha256=x HTTP/1.0\r\nHost: {SERVER}:{}\r\n\r\n",
        ctx.plain_http
    );
    let mut c = FakeClient::connect(ctx.plain_http, 64)?;
    c.pump("FD_CONNECT", |c| c.connected.is_some())?;
    c.send(start.as_bytes())?;
    let mut r = ctx.server.accept()?;
    ensure(r.http_request()? == start.as_bytes(), || {
        "request changed".into()
    })?;
    let answer = http_response(&format!(
        "{{\"response\":{{\"statusCode\":200,\"data\":{{\"host\":\"127.0.0.1\",\"port\":{},\"cookie\":\"c\"}}}}}}",
        ctx.plain_flap
    ));
    r.send_slow(&answer);
    r.close_notify();
    c.pump("the startOSCARSession answer", |c| {
        c.eof || c.error.is_some()
    })?;
    ensure(c.error.is_none() && c.take() == answer, || {
        "answer changed".into()
    })?;
    ctx.no_notices()
}

/// Opens a BOS connection the way a redirect does (the same plain host), and
/// signs on: hello both ways, user info and the MOTD with the token.
fn bos_sign_on(ctx: &mut Ctx) -> Result<(FakeClient, Remote), String> {
    let mut c = FakeClient::connect(ctx.plain_flap, 512)?;
    let mut r = ctx.server.accept()?;
    ensure(r.alpn.as_deref() == Some(ALPN_OSCAR), || {
        format!("ALPN {:?}", r.alpn)
    })?;
    ctx.seq = 0;
    let s = ctx.next_seq();
    r.send(&flap(1, s, &[0, 0, 0, 1]));
    c.pump_frames("the hello", 1)?;
    c.take();
    let hello = flap(
        1,
        1,
        &[[0, 0, 0, 1].as_slice(), &tlv(0x0006, &[0xC0; 64])].concat(),
    );
    c.send(&hello)?;
    ensure(r.frame()? == hello, || "BOS hello changed".into())?;
    let (s1, s2) = (ctx.next_seq(), ctx.next_seq());
    r.send(
        &[
            flap(2, s1, &user_info("100001")),
            flap(2, s2, &motd(&ctx.dir.token("100001"))),
        ]
        .concat(),
    );
    c.pump_frames("user info and the MOTD", 2)?;
    let (got, _) = frames(&c.got);
    contiguous(&got, "client side")?;
    Ok((c, r))
}

/// Sends A's message to B through the server: what the server sees is a
/// container, never the text, and B reads exactly what A typed.
fn a_to_b(
    ctx: &mut Ctx,
    c: &FakeClient,
    r: &mut Remote,
    seq: u16,
    charset: u16,
    text_: &[u8],
) -> Check {
    c.send(&flap(2, seq, &to_host("100002", charset, text_)))?;
    let want = to_client("100001", charset, text_);
    // A control message may go first; every message to B is a container.
    for _ in 0..3 {
        let frame = r.frame_with(0x0004, 0x0006)?;
        ensure(find(&frame, text_).is_none(), || {
            "the text is in the clear inside TLS".into()
        })?;
        ensure(find(&r.raw(), text_).is_none(), || {
            "the text is on the wire".into()
        })?;
        let armoured = message_text(&frame, "100002").ok_or("no message text")?;
        ensure(armoured.contains("IQE1:"), || {
            format!("no container: {armoured}")
        })?;
        let relayed = flap(
            2,
            1,
            &to_client("100001", text::CHARSET_ASCII, armoured.as_bytes()),
        );
        let mut shown = Vec::new();
        ctx.b.feed_in(&relayed, &mut shown);
        if message_payload(&shown).is_some_and(|got| got == want) {
            return Ok(());
        }
    }
    Err("B never read what A typed".into())
}

/// Sends B's reply to A through the server; A's client gets exactly what B
/// typed (notes from the add-on may come with it).
fn b_to_a(
    ctx: &mut Ctx,
    c: &mut FakeClient,
    r: &Remote,
    charset: u16,
    text_: &[u8],
    slow: bool,
) -> Check {
    let mut sent = Vec::new();
    ctx.b
        .feed_out(&flap(2, 50, &to_host("100001", charset, text_)), &mut sent);
    let (out, _) = frames(&sent);
    let msg = out
        .iter()
        .find(|f| is_snac(f, 0x0004, 0x0006))
        .ok_or("B sent no message")?;
    let armoured = message_text(msg, "100001").ok_or("no message text")?;
    ensure(armoured.contains("IQE1:"), || "B sent no container".into())?;
    let s = ctx.next_seq();
    let frame = flap(
        2,
        s,
        &to_client("100002", text::CHARSET_ASCII, armoured.as_bytes()),
    );
    if slow {
        r.send_slow(&frame);
    } else {
        r.send(&frame);
    }
    let want = to_client("100002", charset, text_);
    c.pump("B's message, decrypted", |c| {
        frames(&c.got).0.iter().any(|f| f[6..] == want[..])
    })
}

fn bos_and_e2e(ctx: &mut Ctx) -> Check {
    let (mut c, mut r) = bos_sign_on(ctx)?;
    // The session opened on the user info; the server learns the account key
    // from the SetInfo the add-on fills in.
    let deadline = Instant::now() + WAIT;
    let key = loop {
        if let Some(k) = hooks::account_key("100001") {
            break k;
        }
        ensure(Instant::now() < deadline, || "no session for 100001".into())?;
        std::thread::sleep(Duration::from_millis(10));
    };
    ctx.dir.announce("100001", &key);
    c.send(&flap(2, 2, &set_info()))?;
    let info = r.frame_with(0x0002, 0x0004)?;
    ensure(find(&info, &key).is_some(), || {
        "the account key is not in SetInfo".into()
    })?;

    let ucs2: Vec<u8> = "<font sml=\"default\">Привет, B :-)</font>"
        .encode_utf16()
        .flat_map(|u| u.to_be_bytes())
        .collect();
    a_to_b(ctx, &c, &mut r, 3, 0x0000, b"hi there over TLS")?;
    a_to_b(ctx, &c, &mut r, 4, 0x0002, &ucs2)?;
    // B answers; the first answer arrives a few bytes at a time.
    b_to_a(ctx, &mut c, &r, 0x0000, b"and back, slowly", true)?;
    b_to_a(ctx, &mut c, &r, 0x0002, &ucs2, false)?;

    // Forty frames in one write: records and frames coalesced.
    let burst: Vec<u8> = (0..40)
        .flat_map(|i| {
            let s = ctx.next_seq();
            flap(2, s, &snac(0x0009, 0x0003, &tlv(0x0001, &[i as u8; 3])))
        })
        .collect();
    r.send(&burst);
    let before = frames(&c.got).0.len();
    c.pump_frames("the burst", before + 40)?;
    let (got, _) = frames(&c.got);
    contiguous(&got, "client side after the burst")?;
    ensure(
        got.iter().filter(|f| is_snac(f, 0x0009, 0x0003)).count() == 40,
        || "frames of the burst lost".into(),
    )?;
    c.take();

    // The server cuts the connection in the middle of a frame, without
    // close_notify: the client must see a reset, never a clean end.
    let s = ctx.next_seq();
    let half = flap(2, s, &snac(0x0009, 0x0003, &[0u8; 40]));
    r.send(&half[..20]);
    std::thread::sleep(Duration::from_millis(50));
    r.cut();
    c.pump("the reset", |c| c.error.is_some() || c.eof)?;
    ensure(!c.eof && c.error == Some(WSAECONNRESET), || {
        format!("a cut stream ended with eof {} error {:?}", c.eof, c.error)
    })?;
    ctx.no_notices()
}

/// After the cut: a new connection to the same plain host, signed on again,
/// and E2E goes on with the same account.
fn reconnect(ctx: &mut Ctx) -> Check {
    let (mut c, mut r) = bos_sign_on(ctx)?;
    a_to_b(ctx, &c, &mut r, 2, 0x0000, b"after the reconnect")?;
    b_to_a(ctx, &mut c, &r, 0x0000, b"welcome back", false)?;
    r.close_notify();
    c.pump("the clean end", |c| c.eof || c.error.is_some())?;
    ensure(c.eof && c.error.is_none(), || {
        format!("error {:?}", c.error)
    })?;
    ctx.no_notices()
}

/// A certificate for another name: the handshake fails, the client gets a
/// reset, nothing it wrote leaves in plaintext - not even an HTTP request
/// written before the handshake - and the user is told once.
fn wrong_certificate(ctx: &mut Ctx) -> Check {
    hooks::take_notices();
    ctx.server.set_config(ctx.pki.wrong_name.clone());
    let result = (|| {
        let mut c = FakeClient::connect(ctx.plain_flap, 512)?;
        let r = ctx.server.accept()?;
        ensure(r.failed.is_some(), || "the handshake did not fail".into())?;
        c.pump("the failure", |c| c.error.is_some())?;
        ensure(c.got.is_empty() && c.error == Some(WSAECONNRESET), || {
            format!("got {} bytes, error {:?}", c.got.len(), c.error)
        })?;
        let notices = ctx.notices(1);
        ensure(
            notices.len() == 1 && notices[0].contains("not valid for this name"),
            || format!("message boxes: {notices:?}"),
        )?;
        ensure(notices[0].contains("tls=off"), || "no way out named".into())?;

        let mut c = FakeClient::connect(ctx.plain_http, 512)?;
        c.send(b"POST /auth/clientLogin HTTP/1.0\r\nContent-Length: 9\r\n\r\npwd=s3cr3t")?;
        let r = ctx.server.accept()?;
        ensure(r.failed.is_some(), || "the handshake did not fail".into())?;
        c.pump("the failure", |c| c.error.is_some())?;
        std::thread::sleep(Duration::from_millis(100));
        let raw = r.raw();
        ensure(
            find(&raw, b"POST").is_none() && find(&raw, b"s3cr3t").is_none(),
            || "the early request left in plaintext".into(),
        )?;
        let again = ctx.notices(0);
        ensure(again.is_empty(), || {
            format!("the same reason shown again: {again:?}")
        })
    })();
    ctx.server.set_config(ctx.pki.good.clone());
    result
}

fn tls12_server(ctx: &mut Ctx) -> Check {
    ctx.server.set_config(ctx.pki.tls12_only.clone());
    let result = (|| {
        let mut c = FakeClient::connect(ctx.plain_flap, 512)?;
        let r = ctx.server.accept()?;
        ensure(r.failed.is_some(), || {
            "a TLS 1.2 server was accepted".into()
        })?;
        c.pump("the failure", |c| c.error.is_some())?;
        let notices = ctx.notices(1);
        ensure(notices.len() == 1 && notices[0].contains("TLS 1.3"), || {
            format!("message boxes: {notices:?}")
        })
    })();
    ctx.server.set_config(ctx.pki.good.clone());
    result
}

/// The TLS port does not answer (a server without it): the client's own
/// FD_CONNECT fails, and the user is told why.
fn closed_port(ctx: &mut Ctx) -> Check {
    hooks::set_tls(ctx.setup(free_port()));
    let result = (|| {
        let mut c = FakeClient::connect(ctx.plain_flap, 512)?;
        c.pump("FD_CONNECT", |c| c.connected.is_some())?;
        ensure(c.connected == Some(WSAECONNREFUSED), || {
            format!("FD_CONNECT said {:?}", c.connected)
        })?;
        let notices = ctx.notices(1);
        ensure(
            notices.len() == 1 && notices[0].contains("secure port"),
            || format!("message boxes: {notices:?}"),
        )
    })();
    hooks::set_tls(ctx.setup(ctx.server.port));
    result
}

/// The server's address on a port that is not one of its own: refused at
/// once, never sent in plaintext.
fn other_port(ctx: &mut Ctx) -> Check {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let (_c, r, err) = FakeClient::open(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, l.local_addr().unwrap().port()),
        64,
    );
    ensure(r == -1 && err == WSAECONNREFUSED, || {
        format!("connect said {r}/{err}")
    })?;
    std::thread::sleep(Duration::from_millis(50));
    ensure(l.accept().is_err(), || "the connection was made".into())?;
    let notices = ctx.notices(1);
    ensure(
        notices.len() == 1 && notices[0].contains("not one the add-on can secure"),
        || format!("message boxes: {notices:?}"),
    )
}

/// A proxy (here on 127.0.0.2, not the server) asked to connect to the
/// server: the request never leaves.
fn proxy(ctx: &mut Ctx) -> Check {
    let l = TcpListener::bind("127.0.0.2:0").map_err(|e| format!("127.0.0.2: {e}"))?;
    let port = l.local_addr().unwrap().port();
    let mut c = FakeClient::open(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), port), 64).0;
    let (mut seen, _) = l.accept().map_err(|e| e.to_string())?;
    c.pump("FD_CONNECT", |c| c.connected.is_some())?;
    let (n, err) = hooks::send(
        c.s,
        format!("CONNECT {SERVER}:5190 HTTP/1.0\r\n\r\n").as_bytes(),
    );
    ensure(n == -1 && err == WSAECONNRESET, || {
        format!("send said {n}/{err}")
    })?;
    seen.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = [0u8; 64];
    ensure(!matches!(seen.read(&mut buf), Ok(n) if n > 0), || {
        "the proxy got the request".into()
    })?;
    let notices = ctx.notices(1);
    ensure(notices.len() == 1 && notices[0].contains("proxy"), || {
        format!("message boxes: {notices:?}")
    })
}

/// A socket connected to a server port without the hooks seeing its
/// `connect` (as one opened before them would be): its data is refused.
fn unseen_socket(ctx: &mut Ctx) -> Check {
    let port = ctx.unseen.local_addr().unwrap().port();
    // SAFETY: plain Winsock on our own socket; a blocking connect to a
    // listener that exists.
    let s = unsafe {
        let s = WinSock::socket(
            WinSock::AF_INET as i32,
            WinSock::SOCK_STREAM,
            WinSock::IPPROTO_TCP,
        );
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_le_bytes());
        sa[2..4].copy_from_slice(&port.to_be_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let r = WinSock::connect(s, sa.as_ptr().cast(), 16);
        assert_eq!(r, 0, "direct connect");
        s
    };
    let (mut seen, _) = ctx.unseen.accept().map_err(|e| e.to_string())?;
    let (n, err) = hooks::send(s, &flap(1, 1, &[0, 0, 0, 1]));
    hooks::close(s);
    ensure(n == -1 && err == WSAECONNRESET, || {
        format!("send said {n}/{err}")
    })?;
    seen.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = [0u8; 64];
    ensure(!matches!(seen.read(&mut buf), Ok(n) if n > 0), || {
        "plaintext reached the server".into()
    })?;
    // Not something the user can act on: logged, no box.
    ctx.no_notices()
}

/// Many small frames each way on one connection, the server's written in
/// tiny pieces: nothing lost, nothing reordered, the numbering contiguous.
fn stress(ctx: &mut Ctx) -> Check {
    let (mut c, mut r) = bos_sign_on(ctx)?;
    c.take();
    let mut want_in = Vec::new();
    for i in 0..200u16 {
        let s = ctx.next_seq();
        want_in.extend(flap(2, s, &snac(0x0009, 0x0003, &i.to_be_bytes())));
    }
    r.send_slow(&want_in[..want_in.len() / 2]);
    r.send(&want_in[want_in.len() / 2..]);
    for i in 0..200u16 {
        c.send(&flap(2, 2 + i, &snac(0x0001, 0x0011, &i.to_be_bytes())))?;
        if i % 16 == 0 {
            c.pump("a little", |_| true)?;
        }
    }
    for i in 0..200u16 {
        let f = r.frame()?;
        ensure(f[16..] == i.to_be_bytes(), || {
            format!("frame {i} from the client changed")
        })?;
    }
    c.pump("200 frames", |c| c.got.len() >= want_in.len())?;
    ensure(c.take() == want_in, || "the server's frames changed".into())?;
    r.close_notify();
    c.pump("the end", |c| c.eof || c.error.is_some())?;
    ctx.no_notices()
}

/// A client reading a long HTTP answer through a small buffer, one `recv`
/// per `FD_READ` and nothing else - no `FD_CLOSE` to drain on, because the
/// server keeps the connection open. Everything decrypted beyond the client's
/// buffer has to be announced with an `FD_READ` of its own: Winsock will not,
/// it has already handed the bytes over.
fn small_reads(ctx: &mut Ctx) -> Check {
    let mut c = FakeClient::connect(ctx.plain_http, 64)?;
    c.send(b"GET /aim/startOSCARSession HTTP/1.0\r\n\r\n")?;
    let mut r = ctx.server.accept()?;
    r.http_request()?;
    let body = "x".repeat(5000);
    let answer = http_response(&body);
    // The head first, so the connection is known not to be FLAP; then the
    // body in one record, far more than one read takes.
    r.send(&answer[..40]);
    c.pump("the head", |c| c.got.len() >= 40)?;
    r.send(&answer[40..]);
    c.pump("the whole answer through a 64-byte buffer", |c| {
        c.got.len() >= answer.len()
    })?;
    ensure(c.take() == answer && c.closed.is_none(), || {
        "answer changed".into()
    })?;
    r.close_notify();
    c.pump("the end", |c| c.eof || c.error.is_some())?;
    ctx.no_notices()
}

/// The server's FLAP hello sent the moment the handshake is done, on many
/// connections. The pump thread reads the end of the handshake (and the
/// session tickets) from the socket itself, so the client's own `recv` often
/// finds the socket empty; that `recv` must still reach Winsock, or Winsock
/// never arms the next `FD_READ` and the hello sits there unannounced.
fn hello_after_handshake(ctx: &mut Ctx) -> Check {
    for i in 0..40 {
        let mut c = FakeClient::connect(ctx.plain_flap, 512)?;
        let r = ctx.server.accept()?;
        r.send(&server_hello());
        c.pump_frames("the hello", 1)
            .map_err(|e| format!("connection {i}: {e}"))?;
        ensure(c.take() == server_hello(), || "hello changed".into())?;
    }
    ctx.no_notices()
}

/// The regression for the stall the testhost caught: the add-on read the
/// bytes an `FD_READ` stood for itself, the client's `recv` for that message
/// was answered without calling Winsock, and Winsock - which re-arms
/// `FD_READ` only on a `recv` call - never announced the next bytes. Every
/// `recv` of the client must reach the original once: on an empty socket, and
/// when it is answered from plaintext the add-on already holds.
fn recv_reaches_winsock(ctx: &mut Ctx) -> Check {
    let (mut c, r) = bos_sign_on(ctx)?;
    c.take();
    let calls = |what: &str, f: &mut dyn FnMut()| -> Check {
        let before = hooks::original_recvs();
        f();
        let after = hooks::original_recvs();
        ensure(after > before, || {
            format!("{what}: Winsock's recv was not called")
        })
    };
    // Nothing there.
    calls("a recv on an empty socket", &mut || {
        let mut b = [0u8; 64];
        let (n, err) = hooks::recv(c.s, &mut b, 0);
        assert!(n == -1 && err == WSAEWOULDBLOCK, "{n}/{err}");
    })?;
    // Three frames, pulled in by FIONREAD (the add-on reads the socket
    // itself), then read 8 bytes at a time: every one of those reads is
    // answered from what is held, and still reaches Winsock.
    let burst: Vec<u8> = (0..3)
        .flat_map(|i| {
            let s = ctx.next_seq();
            flap(2, s, &snac(0x0009, 0x0003, &[i as u8; 4]))
        })
        .collect();
    r.send(&burst);
    let deadline = Instant::now() + WAIT;
    while (hooks::fionread(c.s) as usize) < burst.len() {
        ensure(Instant::now() < deadline, || {
            "FIONREAD never counted the burst".into()
        })?;
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut got = Vec::new();
    while got.len() < burst.len() {
        calls("a recv answered from held plaintext", &mut || {
            let mut b = [0u8; 8];
            let (n, _) = hooks::recv(c.s, &mut b, 0);
            if n > 0 {
                got.extend_from_slice(&b[..n as usize]);
            }
        })?;
    }
    ensure(got == burst, || "the burst changed".into())?;
    // And after all that, the next bytes are announced.
    let s = ctx.next_seq();
    let next = flap(2, s, &snac(0x0009, 0x0003, &[9; 4]));
    r.send(&next);
    c.pump("the next frame, by FD_READ", |c| c.got.ends_with(&next))?;
    ctx.no_notices()
}

/// A plain server for `tls=off`.
fn plain_server() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// `tls=off`: nothing is mapped, and the bytes are today's, byte for byte.
fn tls_off_bytes(ctx: &mut Ctx) -> Check {
    hooks::set_tls(Setup::OptedOut {
        server: SERVER.into(),
    });
    let result = (|| {
        let (l, port) = plain_server();
        let mut c = FakeClient::connect(port, 512)?;
        let (mut srv, _) = l.accept().map_err(|e| e.to_string())?;
        srv.set_read_timeout(Some(WAIT)).unwrap();
        c.pump("FD_CONNECT", |c| c.connected.is_some())?;
        ensure(hooks::peer_port(c.s) == Some(port), || "getpeername".into())?;
        srv.write_all(&server_hello()).unwrap();
        c.pump("the hello", |c| c.got.len() >= 10)?;
        ensure(c.take() == server_hello(), || "hello changed".into())?;
        let out = [
            flap(1, 1, &[0, 0, 0, 1]),
            flap(2, 2, &snac(0x0017, 0x0006, &tlv(0x0001, b"100001"))),
        ]
        .concat();
        c.send(&out)?;
        let mut got = vec![0u8; out.len()];
        srv.read_exact(&mut got).map_err(|e| e.to_string())?;
        ensure(got == out, || "the client's bytes changed".into())?;
        let back = flap(2, 2, &snac(0x0017, 0x0007, &[0, 4, 1, 2, 3, 4]));
        srv.write_all(&back).unwrap();
        drop(srv);
        c.pump("the end", |c| c.eof || c.error.is_some())?;
        ensure(c.eof && c.take() == back, || {
            "the server's bytes changed".into()
        })?;
        ctx.no_notices()
    })();
    hooks::set_tls(ctx.setup(ctx.server.port));
    result
}

/// `tls=off` on the BOS connection: the chat says the connection to the
/// server is not encrypted.
fn tls_off_note(ctx: &mut Ctx) -> Check {
    hooks::set_tls(Setup::OptedOut {
        server: SERVER.into(),
    });
    let result = (|| {
        let (l, port) = plain_server();
        let mut c = FakeClient::connect(port, 512)?;
        let (mut srv, _) = l.accept().map_err(|e| e.to_string())?;
        srv.write_all(&server_hello()).unwrap();
        c.pump_frames("the hello", 1)?;
        c.send(&flap(1, 1, &[0, 0, 0, 1]))?;
        srv.write_all(
            &[
                flap(2, 2, &user_info("100001")),
                flap(2, 3, &motd(&ctx.dir.token("100001"))),
            ]
            .concat(),
        )
        .unwrap();
        c.pump_frames("user info and the MOTD", 3)?;
        // The note goes out with the next thing the client does.
        c.send(&flap(2, 2, &snac(0x0001, 0x0002, &[])))?;
        let note: Vec<u8> = "not encrypted (tls=off"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        c.pump("the note", |c| find(&c.got, &note).is_some())?;
        drop(srv);
        ctx.no_notices()
    })();
    hooks::set_tls(ctx.setup(ctx.server.port));
    result
}

// --- against a local Open OSCAR Server ----------------------------------------

/// `--go <tls-port> <ca.pem> [server-name]`: signs on through the hooks
/// against a local Open OSCAR Server with its TLS listener on `tls-port` and a
/// certificate issued by `ca.pem` for `server-name` (default `localhost`),
/// started with `DISABLE_AUTH=true`, `ENABLE_WEBAPI=1` and the plain host
/// advertised as `127.0.0.1:5190`. The plain ports 5190 and 8082 are mapped to
/// the TLS port, as the add-on does for the real server.
///
/// Checks: the FLAP hello over ALPN `oscar`, the BUCP challenge and login, the
/// redirect to the plain host landing on TLS again, the BOS `HostOnline`, and
/// an HTTP request over ALPN `http/1.1` answered by the WebAPI.
pub fn go_server(args: &[String]) -> bool {
    let run = || -> Check {
        let tls_port: u16 = args
            .first()
            .and_then(|p| p.parse().ok())
            .ok_or("usage: --go <tls-port> <ca.pem> [server-name]")?;
        let ca_path = args.get(1).ok_or("no ca.pem")?;
        let name = args.get(2).map_or("localhost", String::as_str).to_string();
        let ca = read_pem_cert(ca_path)?;
        let home = Temp::new("go");
        hooks::init(Policy::from_settings(Settings {
            mode: Some("encrypt"),
            home: home.0.to_str(),
            ..Default::default()
        }));
        hooks::capture_notices();
        let client = TlsClient::new(&TlsSettings {
            server_name: name.clone(),
            trust: Trust::Roots(vec![ca]),
            pins: Vec::new(),
        })
        .map_err(|e| e.reason())?;
        hooks::set_tls(Setup::Active(Active {
            route: Route::new(
                &name,
                Ports {
                    flap: vec![5190, tls_port],
                    http: vec![8082],
                    tls: tls_port,
                },
                Box::new(|_| vec![Ipv4Addr::LOCALHOST]),
            ),
            client: Ok(client),
        }));
        let fail_closed = |c: &FakeClient| -> String {
            format!(
                "error {:?}, message boxes {:?}",
                c.error,
                hooks::take_notices()
            )
        };

        // Sign-in on the auth connection.
        let mut c = FakeClient::connect(5190, 4096)?;
        c.pump_frames("the server's FLAP hello", 1)
            .map_err(|e| format!("{e}; {}", fail_closed(&c)))?;
        println!("ok  [Go] FLAP hello over TLS 1.3 with ALPN oscar");
        c.take();
        c.send(&flap(1, 1, &[0, 0, 0, 1]))?;
        c.send(&flap(2, 2, &snac(0x0017, 0x0006, &tlv(0x0001, b"100001"))))?;
        c.pump_frames("the challenge", 1)?;
        let (got, used) = frames(&c.got);
        c.got.drain(..used);
        ensure(is_snac(&got[0], 0x0017, 0x0007), || {
            "no BUCP challenge".into()
        })?;
        c.send(&flap(
            2,
            3,
            &snac(
                0x0017,
                0x0002,
                &[tlv(0x0001, b"100001"), tlv(0x0025, &[0xAB; 16])].concat(),
            ),
        ))?;
        c.pump_frames("the login reply", 1)?;
        let (got, _) = frames(&c.got);
        ensure(is_snac(&got[0], 0x0017, 0x0003), || "no login reply".into())?;
        let tlvs = &got[0][16..];
        let host = tlv_value(tlvs, 0x0005).ok_or("no ReconnectHere (wrong password?)")?;
        let cookie = tlv_value(tlvs, 0x0006).ok_or("no cookie")?;
        let host = String::from_utf8_lossy(&host).into_owned();
        println!("ok  [Go] BUCP sign-in over TLS; redirected to {host}");
        drop(c);

        // BOS on the advertised plain host, mapped to TLS again.
        let (ip, port) = host.rsplit_once(':').ok_or("redirect without a port")?;
        let ip: Ipv4Addr = ip
            .parse()
            .map_err(|_| format!("redirect host {ip} is not 127.0.0.1"))?;
        let port: u16 = port.parse().map_err(|_| "redirect port")?;
        let (mut c, r, err) = FakeClient::open(SocketAddrV4::new(ip, port), 4096);
        ensure(r == -1 && err == WSAEWOULDBLOCK, || {
            format!("connect {r}/{err}")
        })?;
        c.pump_frames("the BOS hello", 1)?;
        c.take();
        c.send(&flap(
            1,
            1,
            &[[0, 0, 0, 1].as_slice(), &tlv(0x0006, &cookie)].concat(),
        ))?;
        c.pump("HostOnline", |c| {
            frames(&c.got).0.iter().any(|f| is_snac(f, 0x0001, 0x0003))
        })?;
        println!("ok  [Go] BOS over TLS: HostOnline");
        drop(c);

        // The WebAPI over ALPN http/1.1.
        let mut c = FakeClient::connect(8082, 4096)?;
        c.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
        c.pump("an HTTP answer", |c| {
            c.got.starts_with(b"HTTP/1.") && (c.eof || c.got.len() > 12)
        })
        .map_err(|e| format!("{e}; {}", fail_closed(&c)))?;
        println!(
            "ok  [Go] WebAPI over TLS with ALPN http/1.1: {}",
            String::from_utf8_lossy(&c.got[..c.got.iter().position(|&b| b == b'\r').unwrap_or(12)])
        );
        let n = hooks::take_notices();
        ensure(n.is_empty(), || format!("message boxes: {n:?}"))
    };
    match run() {
        Ok(()) => {
            println!("\nok: signed on through the hooks against the Go server's TLS listener");
            true
        }
        Err(why) => {
            eprintln!("FAIL [Go]: {why}");
            false
        }
    }
}

fn tlv_value(mut tlvs: &[u8], tag: u16) -> Option<Vec<u8>> {
    while tlvs.len() >= 4 {
        let t = u16::from_be_bytes([tlvs[0], tlvs[1]]);
        let n = u16::from_be_bytes([tlvs[2], tlvs[3]]) as usize;
        let v = tlvs.get(4..4 + n)?;
        if t == tag {
            return Some(v.to_vec());
        }
        tlvs = &tlvs[4 + n..];
    }
    None
}

/// The first certificate of a PEM file.
fn read_pem_cert(path: &str) -> Result<CertificateDer<'static>, String> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_file(path).map_err(|e| format!("{path}: {e}"))
}

/// `--make-cert <dir> [name]` for the Go check: a CA (`ca.pem`) and a
/// certificate and key for `name` (default `localhost`) issued by it
/// (`cert.pem` with the chain, `key.pem`).
pub fn make_cert(args: &[String]) -> bool {
    let Some(dir) = args.first() else {
        eprintln!("usage: --make-cert <dir> [name]");
        return false;
    };
    let name = args.get(1).map_or("localhost", String::as_str);
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ICQ E2E local CA");
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![name.to_string()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    let dir = std::path::Path::new(dir);
    let _ = std::fs::create_dir_all(dir);
    let write = |f: &str, text: String| std::fs::write(dir.join(f), text).is_ok();
    let ok = write("ca.pem", ca.pem())
        && write("cert.pem", format!("{}{}", cert.pem(), ca.pem()))
        && write("key.pem", key.serialize_pem());
    if ok {
        println!(
            "wrote ca.pem, cert.pem and key.pem for {name} in {}",
            dir.display()
        );
    }
    ok
}
