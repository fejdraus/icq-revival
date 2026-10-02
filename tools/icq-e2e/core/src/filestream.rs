//! The data connection of a file transfer both add-ons agreed to encrypt
//! (stage F3 of `docs/e2e/FILES-RESEARCH.md`): a key hello from each side,
//! then a STREAM of ChaCha20-Poly1305 records. Plain Rust, no Windows: the
//! socket hooks (`hook_files.rs`) feed it bytes and send what it gives.
//!
//! ```text
//! answerer (receives the file)                  offerer (sends the file)
//! hello  ----------------------------------->   (holds its client's bytes)
//!                                               checks the hello, derives
//!        <-----------------------------------   hello, then records
//! checks the hello, derives
//! records <---------------------------------->  records
//! final record (empty, last flag) at close, each way
//! ```
//!
//! - The answerer always knows the keys before the connection exists (it had
//!   the offer, `filesneg.rs`), so it writes its hello the moment the
//!   connection is up. So does the offerer once it has the answer.
//! - The offerer without the answer yet writes nothing: it holds its client's
//!   first bytes (the OFT2 prompt) and waits for the answerer's hello at most
//!   [`HELLO_WAIT_MS`]. Bytes that are not a hello, or none in time: the peer
//!   has no add-on, an older one, or file encryption off, and the connection
//!   is the client's own, every byte untouched (backward compatibility).
//! - Once agreed, the connection fails closed: a hello that does not check
//!   out, bytes that are not records, a record that does not authenticate,
//!   anything after the final record - the connection is closed and the
//!   client's transfer fails. Nothing is ever passed on that was not
//!   authenticated, and nothing goes out unencrypted.
//! - Through the rendezvous proxy the ARS frames (`INIT_SEND`, `ACK`,
//!   `INIT_RECV`, `READY`) pass untouched; the hello starts after `READY`.
//!
//! Hello (118 bytes): `"IQFT" | version | role | cookie hash (8) | ephemeral
//! key (32) | device id (4) | device key (32) | connection number (4) | nonce
//! (16) | MAC (16)`, the MAC an HMAC-SHA256 under the transfer's confirmation
//! key. The keys of a connection bind both hellos' nonces and connection
//! numbers, so a resumed transfer or a second connection never reuses a key.
//!
//! Record: `u32 length | ciphertext | tag`, at most [`MAX_CHUNK`] bytes of
//! plaintext, nonce = 11-byte record counter of that direction || 1-byte last
//! flag. The last record is empty and carries the flag; a record of any other
//! length never does.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::hkdf;

/// What a hello starts with.
pub const HELLO_MAGIC: &[u8; 4] = b"IQFT";
pub const HELLO_VERSION: u8 = 1;
/// The length of a hello on the wire.
pub const HELLO_LEN: usize = 4 + 1 + 1 + 8 + 32 + 4 + 32 + 4 + 16 + 16;
/// The most plaintext in one record.
pub const MAX_CHUNK: usize = 16 * 1024;
/// The AEAD tag.
pub const TAG: usize = 16;
/// How long an offerer without the answer waits for the answerer's hello.
pub const HELLO_WAIT_MS: u64 = 4_000;

const ROLE_OFFERER: u8 = 0;
const ROLE_ANSWERER: u8 = 1;

/// Which side of the transfer this add-on is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends the file: made the offer.
    Offerer,
    /// Receives the file: answered.
    Answerer,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Offerer => ROLE_OFFERER,
            Role::Answerer => ROLE_ANSWERER,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::Offerer => "we send",
            Role::Answerer => "they send",
        }
    }
}

/// The keys both add-ons derived for a transfer (`filesneg::derive`).
#[derive(Clone)]
pub struct Agreement {
    /// What every connection's keys are derived from.
    pub root: [u8; 32],
    /// The key of the hello's MAC.
    pub confirm: [u8; 32],
    pub eph_offerer: [u8; 32],
    pub eph_answerer: [u8; 32],
    /// The answerer's device, as the keys bind it.
    pub answerer_device: u32,
    pub answerer_key: [u8; 32],
    /// The offerer's device.
    pub offerer_device: u32,
    pub offerer_key: [u8; 32],
}

impl Drop for Agreement {
    fn drop(&mut self) {
        self.root.fill(0);
        self.confirm.fill(0);
    }
}

impl std::fmt::Debug for Agreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Agreement(..)")
    }
}

/// The 8 bytes of a cookie a hello names it by.
pub fn cookie_hash(cookie: &[u8; 8]) -> [u8; 8] {
    let d = ring::digest::digest(
        &ring::digest::SHA256,
        &[b"icq-e2e files cookie v1".as_slice(), cookie].concat(),
    );
    let mut h = [0u8; 8];
    h.copy_from_slice(&d.as_ref()[..8]);
    h
}

// --- the hello ------------------------------------------------------------------------

/// A key hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub role: u8,
    pub cookie_hash: [u8; 8],
    pub eph: [u8; 32],
    pub device: u32,
    pub device_key: [u8; 32],
    pub conn: u32,
    pub nonce: [u8; 16],
    pub mac: [u8; 16],
}

impl Hello {
    fn body(&self) -> Vec<u8> {
        let mut b = HELLO_MAGIC.to_vec();
        b.push(HELLO_VERSION);
        b.push(self.role);
        b.extend_from_slice(&self.cookie_hash);
        b.extend_from_slice(&self.eph);
        b.extend_from_slice(&self.device.to_be_bytes());
        b.extend_from_slice(&self.device_key);
        b.extend_from_slice(&self.conn.to_be_bytes());
        b.extend_from_slice(&self.nonce);
        b
    }

    fn tag(&self, confirm: &[u8; 32]) -> [u8; 16] {
        let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, confirm);
        let t = ring::hmac::sign(
            &k,
            &[b"icq-e2e files hello v1".as_slice(), &self.body()].concat(),
        );
        let mut out = [0u8; 16];
        out.copy_from_slice(&t.as_ref()[..16]);
        out
    }

    /// The hello on the wire, with its MAC.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.mac);
        b
    }

    /// Reads a hello of this version; `None` for anything else.
    pub fn parse(b: &[u8]) -> Option<Hello> {
        if b.len() < HELLO_LEN || &b[..4] != HELLO_MAGIC || b[4] != HELLO_VERSION {
            return None;
        }
        let a = |r: std::ops::Range<usize>| b[r].to_vec();
        let mut h = Hello {
            role: b[5],
            cookie_hash: [0; 8],
            eph: [0; 32],
            device: u32::from_be_bytes([b[46], b[47], b[48], b[49]]),
            device_key: [0; 32],
            conn: u32::from_be_bytes([b[82], b[83], b[84], b[85]]),
            nonce: [0; 16],
            mac: [0; 16],
        };
        h.cookie_hash.copy_from_slice(&a(6..14));
        h.eph.copy_from_slice(&a(14..46));
        h.device_key.copy_from_slice(&a(50..82));
        h.nonce.copy_from_slice(&a(86..102));
        h.mac.copy_from_slice(&a(102..118));
        Some(h)
    }

    /// Whether the MAC is the one `confirm` gives.
    pub fn verify(&self, confirm: &[u8; 32]) -> bool {
        let t = self.tag(confirm);
        t.iter()
            .zip(&self.mac)
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
    }
}

/// `ring`'s HKDF wants the output length as a type.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// The two keys of one connection (offerer to answerer, answerer to
/// offerer), from the transfer's root and both hellos.
pub fn connection_keys(ag: &Agreement, offerer: &Hello, answerer: &Hello) -> ([u8; 32], [u8; 32]) {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"icq-e2e files connection v1").extract(&ag.root);
    let key = |label: &[u8]| {
        let oc = offerer.conn.to_be_bytes();
        let ac = answerer.conn.to_be_bytes();
        let info: [&[u8]; 6] = [
            label,
            &offerer.nonce,
            &oc,
            &answerer.nonce,
            &ac,
            b"icq-e2e files v1",
        ];
        let mut out = [0u8; 32];
        prk.expand(&info, Len(32))
            .and_then(|okm| okm.fill(&mut out))
            .expect("HKDF-SHA256 output of 32 bytes");
        out
    };
    (key(b"offerer to answerer "), key(b"answerer to offerer "))
}

// --- records --------------------------------------------------------------------------

fn nonce(counter: u64, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    Nonce::assume_unique_for_key(n)
}

/// One direction's sealing key and record counter.
pub struct Sealer {
    key: LessSafeKey,
    counter: u64,
}

impl Sealer {
    pub fn new(key: &[u8; 32]) -> Sealer {
        Sealer {
            key: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("32-byte key")),
            counter: 0,
        }
    }

    /// Appends the records of `plain` to `out`, [`MAX_CHUNK`] bytes each;
    /// with `last`, the empty final record after them.
    pub fn seal(&mut self, plain: &[u8], last: bool, out: &mut Vec<u8>) {
        for chunk in plain.chunks(MAX_CHUNK) {
            self.one(chunk, false, out);
        }
        if last {
            self.one(&[], true, out);
        }
    }

    fn one(&mut self, chunk: &[u8], last: bool, out: &mut Vec<u8>) {
        let mut buf = chunk.to_vec();
        self.key
            .seal_in_place_append_tag(nonce(self.counter, last), Aad::empty(), &mut buf)
            .expect("a record of at most 16 KiB");
        self.counter += 1;
        out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&buf);
    }

    pub fn records(&self) -> u64 {
        self.counter
    }
}

/// What reading records gave.
#[derive(Debug, PartialEq, Eq)]
pub enum Opened {
    /// This many bytes were whole records, plaintext appended; whether the
    /// final record was among them.
    Records { used: usize, last: bool },
    /// The records do not check out.
    Bad(&'static str),
}

/// One direction's opening key and record counter.
pub struct Opener {
    key: LessSafeKey,
    counter: u64,
    done: bool,
}

impl Opener {
    pub fn new(key: &[u8; 32]) -> Opener {
        Opener {
            key: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("32-byte key")),
            counter: 0,
            done: false,
        }
    }

    /// Opens the whole records at the start of `wire`, appending their
    /// plaintext to `out`. A partial record is left for later.
    pub fn open(&mut self, wire: &[u8], out: &mut Vec<u8>) -> Opened {
        let mut used = 0;
        while wire.len() - used >= 4 {
            let n = u32::from_be_bytes([wire[used], wire[used + 1], wire[used + 2], wire[used + 3]])
                as usize;
            if !(TAG..=MAX_CHUNK + TAG).contains(&n) {
                return Opened::Bad("a record of an impossible length");
            }
            if wire.len() - used - 4 < n {
                break;
            }
            if self.done {
                return Opened::Bad("data after the final record");
            }
            let last = n == TAG;
            let mut buf = wire[used + 4..used + 4 + n].to_vec();
            match self
                .key
                .open_in_place(nonce(self.counter, last), Aad::empty(), &mut buf)
            {
                Ok(p) => out.extend_from_slice(p),
                Err(_) => return Opened::Bad("a record did not authenticate"),
            }
            self.counter += 1;
            used += 4 + n;
            if last {
                self.done = true;
            }
        }
        Opened::Records {
            used,
            last: self.done,
        }
    }

    pub fn records(&self) -> u64 {
        self.counter
    }

    /// Whether the final record has come.
    pub fn finished(&self) -> bool {
        self.done
    }
}

// --- the connection -------------------------------------------------------------------

/// What the pipe asks of the transfer table (`filesneg::FileTable`).
pub trait KeySource {
    /// The transfer's agreement, once both add-ons' keys are known.
    fn agreement(&mut self, cookie: &[u8; 8]) -> Option<Agreement>;
    /// The offerer's agreement with an answerer whose hello named this
    /// ephemeral key and device. Not kept: see [`Self::keep_agreement`].
    fn try_agreement(
        &mut self,
        cookie: &[u8; 8],
        eph: &[u8; 32],
        device: u32,
        device_key: &[u8; 32],
    ) -> Option<Agreement>;
    /// Keeps an agreement whose hello checked out.
    fn keep_agreement(&mut self, cookie: &[u8; 8], ag: &Agreement);
    /// Why the transfer goes unencrypted, when that is already decided (a
    /// decline, our own refusal).
    fn plain_reason(&mut self, cookie: &[u8; 8]) -> Option<String>;
    /// The next connection number of this side for the transfer.
    fn next_conn(&mut self, cookie: &[u8; 8]) -> u32;
    /// What happened, for the chat and the log.
    fn report(&mut self, cookie: &[u8; 8], event: Event);
}

/// What the pipe reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Both hellos checked out: the connection is encrypted.
    Encrypted,
    /// The connection goes unencrypted, every byte untouched, and why.
    Plain(String),
    /// An agreed connection was closed (fail closed), and why.
    Failed(String),
    /// A line for the log only.
    Log(String),
}

/// Where a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The connect is in progress.
    Connecting,
    /// Through the proxy, before `READY`: ARS frames pass untouched.
    Ars,
    /// The hellos are being exchanged; the client's bytes are held.
    Hello,
    /// Records both ways.
    Encrypted,
    /// Not encrypted: every byte the client's own, both ways.
    Plain,
    /// Closed for good (fail closed).
    Failed,
}

/// One data connection of a transfer: what goes to the socket, what goes to
/// the client.
pub struct FilePipe {
    pub cookie: [u8; 8],
    role: Role,
    phase: Phase,
    via_proxy: bool,
    since_ms: u64,
    to_wire: Vec<u8>,
    from_wire: Vec<u8>,
    to_client: Vec<u8>,
    held: Vec<u8>,
    agreement: Option<Agreement>,
    mine: Option<Hello>,
    theirs: Option<Hello>,
    sealer: Option<Sealer>,
    opener: Option<Opener>,
    final_sent: bool,
    eof: bool,
    failure: Option<String>,
    /// Gone plain because no hello came in time: a late hello then means
    /// the peer's add-on is encrypting, and the connection is closed.
    plain_by_wait: bool,
    plain_checked: bool,
    pub plain_in: u64,
    pub plain_out: u64,
}

impl FilePipe {
    /// A pipe for a connection of the transfer `cookie`. `connected`: the
    /// connection is up already (accepted, or found by its first bytes);
    /// otherwise call [`Self::connected`] when the connect completes.
    /// `via_proxy`: the connection goes to the rendezvous proxy, whose ARS
    /// frames come first.
    pub fn new(cookie: [u8; 8], role: Role, via_proxy: bool) -> FilePipe {
        FilePipe {
            cookie,
            role,
            phase: Phase::Connecting,
            via_proxy,
            since_ms: 0,
            to_wire: Vec::new(),
            from_wire: Vec::new(),
            to_client: Vec::new(),
            held: Vec::new(),
            agreement: None,
            mine: None,
            theirs: None,
            sealer: None,
            opener: None,
            final_sent: false,
            eof: false,
            failure: None,
            plain_by_wait: false,
            plain_checked: false,
            plain_in: 0,
            plain_out: 0,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// The connection is up: through the proxy the ARS frames come first,
    /// otherwise the hellos start.
    pub fn connected(&mut self, ks: &mut dyn KeySource, now_ms: u64) {
        if self.phase != Phase::Connecting {
            return;
        }
        if self.via_proxy {
            self.phase = Phase::Ars;
        } else {
            self.begin_hello(ks, now_ms);
        }
    }

    fn begin_hello(&mut self, ks: &mut dyn KeySource, now_ms: u64) {
        self.phase = Phase::Hello;
        self.since_ms = now_ms;
        match self.role {
            Role::Answerer => match ks.agreement(&self.cookie) {
                Some(ag) => self.send_hello(ks, ag),
                // Not made for a transfer without keys; never encrypt blind.
                None => self.go_plain(ks, "this add-on has no keys for it".to_string(), true),
            },
            Role::Offerer => {
                if let Some(why) = ks.plain_reason(&self.cookie) {
                    self.go_plain(ks, why, false);
                } else if let Some(ag) = ks.agreement(&self.cookie) {
                    self.send_hello(ks, ag);
                }
                // Otherwise wait for the answerer's hello.
            }
        }
    }

    fn send_hello(&mut self, ks: &mut dyn KeySource, ag: Agreement) {
        let mut nonce = [0u8; 16];
        if getrandom::fill(&mut nonce).is_err() {
            self.fail(ks, "no random bytes for the key hello");
            return;
        }
        let (eph, device, device_key) = match self.role {
            Role::Offerer => (ag.eph_offerer, ag.offerer_device, ag.offerer_key),
            Role::Answerer => (ag.eph_answerer, ag.answerer_device, ag.answerer_key),
        };
        let mut h = Hello {
            role: self.role.byte(),
            cookie_hash: cookie_hash(&self.cookie),
            eph,
            device,
            device_key,
            conn: ks.next_conn(&self.cookie),
            nonce,
            mac: [0; 16],
        };
        h.mac = h.tag(&ag.confirm);
        self.to_wire.extend_from_slice(&h.encode());
        ks.report(
            &self.cookie,
            Event::Log(format!("key hello sent (connection {})", h.conn)),
        );
        self.mine = Some(h);
        self.agreement = Some(ag);
        self.keys_ready(ks);
    }

    /// The client's bytes.
    pub fn write(
        &mut self,
        data: &[u8],
        ks: &mut dyn KeySource,
        now_ms: u64,
    ) -> Result<(), String> {
        if self.phase == Phase::Connecting {
            // The client writes only to a connected socket.
            self.connected(ks, now_ms);
        }
        self.plain_out += data.len() as u64;
        match self.phase {
            Phase::Failed => return Err(self.failure.clone().unwrap_or_default()),
            Phase::Ars | Phase::Plain => self.to_wire.extend_from_slice(data),
            Phase::Hello | Phase::Connecting => self.held.extend_from_slice(data),
            Phase::Encrypted => {
                if self.final_sent {
                    return Err("written after the final record".to_string());
                }
                self.sealer
                    .as_mut()
                    .expect("encrypted")
                    .seal(data, false, &mut self.to_wire);
            }
        }
        Ok(())
    }

    /// Bytes from the socket.
    pub fn feed(&mut self, data: &[u8], ks: &mut dyn KeySource, now_ms: u64) {
        if self.phase == Phase::Connecting {
            self.connected(ks, now_ms);
        }
        if self.phase == Phase::Failed {
            return;
        }
        self.from_wire.extend_from_slice(data);
        self.process(ks, now_ms);
    }

    fn process(&mut self, ks: &mut dyn KeySource, now_ms: u64) {
        loop {
            if self.from_wire.is_empty() {
                return;
            }
            match self.phase {
                Phase::Connecting | Phase::Failed => return,
                Phase::Ars => match crate::files::ars_frame(&self.from_wire) {
                    crate::files::ArsRead::Frame(f) => {
                        let frame: Vec<u8> = self.from_wire.drain(..f.len).collect();
                        self.give(&frame);
                        ks.report(
                            &self.cookie,
                            Event::Log(format!(
                                "proxy {} passed",
                                crate::files::ars_name(f.command)
                            )),
                        );
                        if f.command == crate::files::ARS_READY {
                            self.begin_hello(ks, now_ms);
                        }
                    }
                    crate::files::ArsRead::NeedMore => return,
                    // Not the proxy speaking: the hello logic decides.
                    crate::files::ArsRead::Not => self.begin_hello(ks, now_ms),
                },
                Phase::Hello => {
                    if !self.hello_in(ks) {
                        return;
                    }
                }
                Phase::Encrypted => {
                    let opener = self.opener.as_mut().expect("encrypted");
                    let mut out = Vec::new();
                    match opener.open(&self.from_wire, &mut out) {
                        Opened::Records { used, .. } => {
                            self.from_wire.drain(..used);
                            self.give(&out);
                            return;
                        }
                        Opened::Bad(why) => {
                            self.fail(ks, why);
                            return;
                        }
                    }
                }
                Phase::Plain => {
                    if self.plain_by_wait && !self.plain_checked {
                        if self.from_wire.len() < 4
                            && HELLO_MAGIC.starts_with(&self.from_wire)
                            && !self.eof
                        {
                            return;
                        }
                        self.plain_checked = true;
                        if self.from_wire.starts_with(HELLO_MAGIC) {
                            self.fail(
                                ks,
                                "the other add-on's key hello came too late, after this side had \
                                 already sent unencrypted",
                            );
                            return;
                        }
                    }
                    let all = std::mem::take(&mut self.from_wire);
                    self.give(&all);
                    return;
                }
            }
        }
    }

    /// The hello phase with bytes waiting: whether to go on processing.
    fn hello_in(&mut self, ks: &mut dyn KeySource) -> bool {
        let b = &self.from_wire;
        let may_go_plain = self.role == Role::Offerer && self.mine.is_none();
        if !b.starts_with(HELLO_MAGIC) {
            if b.len() < 4 && HELLO_MAGIC.starts_with(b) && !self.eof {
                return false;
            }
            if may_go_plain {
                self.go_plain(
                    ks,
                    "the other side sent no key hello (no E2E add-on there, an older one, or file \
                     encryption off)"
                        .to_string(),
                    true,
                );
            } else {
                self.fail(
                    ks,
                    "the other side sent unencrypted data on a transfer both add-ons had agreed \
                     to encrypt",
                );
            }
            return true;
        }
        if b.len() < HELLO_LEN {
            return false;
        }
        let Some(h) = Hello::parse(&b[..HELLO_LEN]) else {
            self.fail(ks, "the other side's key hello is of another version");
            return false;
        };
        let want_role = match self.role {
            Role::Offerer => ROLE_ANSWERER,
            Role::Answerer => ROLE_OFFERER,
        };
        if h.role != want_role || h.cookie_hash != cookie_hash(&self.cookie) {
            self.fail(ks, "the key hello is not for this transfer");
            return false;
        }
        let (ag, fresh) = match (self.role, self.agreement.clone()) {
            (_, Some(ag)) => (ag, false),
            (Role::Offerer, None) => match ks.agreement(&self.cookie) {
                Some(ag) => (ag, false),
                None => match ks.try_agreement(&self.cookie, &h.eph, h.device, &h.device_key) {
                    Some(ag) => (ag, true),
                    None => {
                        self.fail(ks, "no keys can be agreed from the key hello");
                        return false;
                    }
                },
            },
            (Role::Answerer, None) => {
                self.fail(ks, "no keys for the key hello");
                return false;
            }
        };
        let (eph_ok, dev_ok) = match self.role {
            Role::Offerer => (
                h.eph == ag.eph_answerer,
                h.device == ag.answerer_device && h.device_key == ag.answerer_key,
            ),
            Role::Answerer => (
                h.eph == ag.eph_offerer,
                h.device == ag.offerer_device && h.device_key == ag.offerer_key,
            ),
        };
        if !eph_ok || !dev_ok || !h.verify(&ag.confirm) {
            self.fail(
                ks,
                "the key hello does not check out (it was not made with the keys agreed in the \
                 encrypted chat)",
            );
            return false;
        }
        if fresh {
            ks.keep_agreement(&self.cookie, &ag);
        }
        self.from_wire.drain(..HELLO_LEN);
        ks.report(
            &self.cookie,
            Event::Log(format!(
                "key hello received and checked (connection {})",
                h.conn
            )),
        );
        self.theirs = Some(h);
        if self.mine.is_none() {
            self.send_hello(ks, ag);
        } else {
            self.keys_ready(ks);
        }
        true
    }

    /// Both hellos are there: the connection's keys, and what the client
    /// wrote meanwhile goes out encrypted.
    fn keys_ready(&mut self, ks: &mut dyn KeySource) {
        let (Some(mine), Some(theirs), Some(ag)) = (&self.mine, &self.theirs, &self.agreement)
        else {
            return;
        };
        let (offerer, answerer) = match self.role {
            Role::Offerer => (mine, theirs),
            Role::Answerer => (theirs, mine),
        };
        let (mut o2a, mut a2o) = connection_keys(ag, offerer, answerer);
        let (send, recv) = match self.role {
            Role::Offerer => (&o2a, &a2o),
            Role::Answerer => (&a2o, &o2a),
        };
        self.sealer = Some(Sealer::new(send));
        self.opener = Some(Opener::new(recv));
        o2a.fill(0);
        a2o.fill(0);
        self.phase = Phase::Encrypted;
        let held = std::mem::take(&mut self.held);
        if !held.is_empty() {
            self.sealer
                .as_mut()
                .expect("just made")
                .seal(&held, false, &mut self.to_wire);
        }
        ks.report(&self.cookie, Event::Encrypted);
    }

    fn go_plain(&mut self, ks: &mut dyn KeySource, why: String, by_wait: bool) {
        self.phase = Phase::Plain;
        self.plain_by_wait = by_wait;
        let held = std::mem::take(&mut self.held);
        self.to_wire.extend_from_slice(&held);
        ks.report(&self.cookie, Event::Plain(why));
    }

    fn fail(&mut self, ks: &mut dyn KeySource, why: &str) {
        if self.phase == Phase::Failed {
            return;
        }
        self.phase = Phase::Failed;
        self.failure = Some(why.to_string());
        self.to_client.clear();
        self.held.clear();
        self.from_wire.clear();
        self.to_wire.clear();
        ks.report(&self.cookie, Event::Failed(why.to_string()));
    }

    fn give(&mut self, b: &[u8]) {
        self.plain_in += b.len() as u64;
        self.to_client.extend_from_slice(b);
    }

    /// The socket reported the end of the stream.
    pub fn end_of_input(&mut self, ks: &mut dyn KeySource) {
        if self.eof {
            return;
        }
        self.eof = true;
        match self.phase {
            Phase::Encrypted => {
                if !self.from_wire.is_empty() {
                    self.fail(ks, "the connection ended in the middle of a record");
                } else if !self.opener.as_ref().is_some_and(Opener::finished) {
                    ks.report(
                        &self.cookie,
                        Event::Log(
                            "the connection ended without the final record (truncated or \
                             cancelled; OFT2 inside it says whether the file was complete)"
                                .to_string(),
                        ),
                    );
                }
            }
            Phase::Hello if !self.from_wire.is_empty() => {
                if self.role == Role::Offerer && self.mine.is_none() {
                    // A few bytes that might have been a hello: the client's.
                    let all = std::mem::take(&mut self.from_wire);
                    self.go_plain(ks, "the other side sent no key hello".to_string(), false);
                    self.give(&all);
                } else {
                    self.fail(ks, "the connection ended during the key hello");
                }
            }
            Phase::Plain => self.process(ks, 0),
            _ => {}
        }
    }

    /// Timers: the offerer's wait for the answerer's hello, and an answer or
    /// a decline that came through the chat meanwhile.
    pub fn tick(&mut self, ks: &mut dyn KeySource, now_ms: u64) {
        if self.phase != Phase::Hello || self.role != Role::Offerer || self.mine.is_some() {
            return;
        }
        if let Some(why) = ks.plain_reason(&self.cookie) {
            self.go_plain(ks, why, false);
        } else if let Some(ag) = ks.agreement(&self.cookie) {
            self.send_hello(ks, ag);
        } else if now_ms.saturating_sub(self.since_ms) >= HELLO_WAIT_MS {
            self.go_plain(
                ks,
                format!(
                    "the other side sent no key hello within {} s (no E2E add-on there, an older \
                     one, or file encryption off)",
                    HELLO_WAIT_MS / 1000
                ),
                true,
            );
        }
    }

    /// Whether [`Self::tick`] still has something to wait for.
    pub fn waiting(&self) -> bool {
        self.phase == Phase::Hello && self.role == Role::Offerer && self.mine.is_none()
    }

    /// The client closes the socket: the final record, if encrypted.
    pub fn close(&mut self) {
        if self.phase == Phase::Encrypted && !self.final_sent {
            self.final_sent = true;
            if let Some(s) = self.sealer.as_mut() {
                s.seal(&[], true, &mut self.to_wire);
            }
        }
    }

    /// What is to go to the socket.
    pub fn take_wire(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.to_wire)
    }

    pub fn wants_write(&self) -> bool {
        !self.to_wire.is_empty()
    }

    pub fn plaintext_len(&self) -> usize {
        self.to_client.len()
    }

    pub fn take_plaintext(&mut self, buf: &mut [u8]) -> usize {
        let k = buf.len().min(self.to_client.len());
        buf[..k].copy_from_slice(&self.to_client[..k]);
        self.to_client.drain(..k);
        k
    }

    pub fn peek_plaintext(&self, buf: &mut [u8]) -> usize {
        let k = buf.len().min(self.to_client.len());
        buf[..k].copy_from_slice(&self.to_client[..k]);
        k
    }

    /// Whether the end of the stream is all the client has left to read.
    pub fn at_end(&self) -> bool {
        self.eof && self.to_client.is_empty() && self.phase != Phase::Failed
    }

    /// Records each way so far.
    pub fn records(&self) -> (u64, u64) {
        (
            self.sealer.as_ref().map_or(0, Sealer::records),
            self.opener.as_ref().map_or(0, Opener::records),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn agreement(seed: u8) -> Agreement {
        Agreement {
            root: [seed; 32],
            confirm: [seed ^ 0x5A; 32],
            eph_offerer: [1; 32],
            eph_answerer: [2; 32],
            answerer_device: 22,
            answerer_key: [3; 32],
            offerer_device: 11,
            offerer_key: [4; 32],
        }
    }

    /// A key source with a fixed agreement, as both tables would have it
    /// after the offer and the answer.
    pub(crate) struct Fixed {
        pub ag: Option<Agreement>,
        /// What `try_agreement` gives (the offerer before the answer).
        pub from_hello: Option<Agreement>,
        pub kept: bool,
        pub plain: Option<String>,
        pub conns: u32,
        pub events: Vec<Event>,
    }

    impl Fixed {
        pub(crate) fn with(ag: Option<Agreement>) -> Fixed {
            Fixed {
                ag,
                from_hello: None,
                kept: false,
                plain: None,
                conns: 0,
                events: Vec::new(),
            }
        }

        pub(crate) fn said(&self, f: impl Fn(&Event) -> bool) -> bool {
            self.events.iter().any(f)
        }
    }

    impl KeySource for Fixed {
        fn agreement(&mut self, _: &[u8; 8]) -> Option<Agreement> {
            self.ag.clone()
        }
        fn try_agreement(
            &mut self,
            _: &[u8; 8],
            eph: &[u8; 32],
            _: u32,
            _: &[u8; 32],
        ) -> Option<Agreement> {
            self.from_hello.clone().filter(|a| &a.eph_answerer == eph)
        }
        fn keep_agreement(&mut self, _: &[u8; 8], ag: &Agreement) {
            self.kept = true;
            self.ag = Some(ag.clone());
        }
        fn plain_reason(&mut self, _: &[u8; 8]) -> Option<String> {
            self.plain.clone()
        }
        fn next_conn(&mut self, _: &[u8; 8]) -> u32 {
            self.conns += 1;
            self.conns
        }
        fn report(&mut self, _: &[u8; 8], e: Event) {
            self.events.push(e);
        }
    }

    const C: [u8; 8] = [7; 8];

    /// Moves everything one pipe has for the wire into the other.
    fn pass(from: &mut FilePipe, to: &mut FilePipe, ks: &mut Fixed, now: u64) -> Vec<u8> {
        let w = from.take_wire();
        to.feed(&w, ks, now);
        w
    }

    fn read_all(p: &mut FilePipe) -> Vec<u8> {
        let mut buf = vec![0u8; p.plaintext_len()];
        p.take_plaintext(&mut buf);
        buf
    }

    #[test]
    fn records_chunk_flag_the_last_and_catch_truncation_reordering_and_tampering() {
        let key = [9u8; 32];
        let mut s = Sealer::new(&key);
        let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        let mut wire = Vec::new();
        s.seal(&data, false, &mut wire);
        assert_eq!(s.records(), 3, "16 KiB chunks");
        s.seal(&[], true, &mut wire);
        assert_eq!(wire.len(), data.len() + 4 * (4 + TAG));
        // Whole, and in pieces.
        let mut o = Opener::new(&key);
        let mut out = Vec::new();
        let mut used = 0;
        for cut in [1usize, 5, 16_000, 16_420, 30_000, wire.len()] {
            match o.open(&wire[used..cut], &mut out) {
                Opened::Records { used: u, .. } => used += u,
                Opened::Bad(w) => panic!("{w}"),
            }
        }
        assert_eq!(used, wire.len());
        assert_eq!(out, data);
        assert!(o.finished());
        // Anything after the last record.
        assert_eq!(
            o.open(&wire[..4 + 16384 + TAG], &mut out),
            Opened::Bad("data after the final record")
        );
        // Reordered: the second record first.
        let r1 = 4 + MAX_CHUNK + TAG;
        let mut swapped = wire[r1..2 * r1].to_vec();
        swapped.extend_from_slice(&wire[..r1]);
        assert!(matches!(
            Opener::new(&key).open(&swapped, &mut Vec::new()),
            Opened::Bad(_)
        ));
        // A flipped bit.
        let mut t = wire.clone();
        t[100] ^= 1;
        assert_eq!(
            Opener::new(&key).open(&t, &mut Vec::new()),
            Opened::Bad("a record did not authenticate")
        );
        // The final record dropped: no error from the records, but not finished.
        let mut o = Opener::new(&key);
        assert!(matches!(
            o.open(&wire[..wire.len() - 4 - TAG], &mut Vec::new()),
            Opened::Records { last: false, .. }
        ));
        assert!(!o.finished());
        // A short record passed off as the final one does not open as one.
        let mut fake = wire[..r1].to_vec();
        fake.extend_from_slice(&(TAG as u32).to_be_bytes());
        fake.extend_from_slice(&[0; TAG]);
        assert!(matches!(
            Opener::new(&key).open(&fake, &mut Vec::new()),
            Opened::Bad(_)
        ));
        // Another key.
        assert!(matches!(
            Opener::new(&[8; 32]).open(&wire, &mut Vec::new()),
            Opened::Bad(_)
        ));
        // An impossible length.
        assert_eq!(
            Opener::new(&key).open(&[0, 1, 0, 0, 0], &mut Vec::new()),
            Opened::Bad("a record of an impossible length")
        );
    }

    #[test]
    fn hellos_round_trip_and_connection_keys_bind_every_input() {
        let ag = agreement(1);
        let mut h = Hello {
            role: ROLE_ANSWERER,
            cookie_hash: cookie_hash(&C),
            eph: ag.eph_answerer,
            device: 22,
            device_key: [3; 32],
            conn: 1,
            nonce: [5; 16],
            mac: [0; 16],
        };
        h.mac = h.tag(&ag.confirm);
        let wire = h.encode();
        assert_eq!(wire.len(), HELLO_LEN);
        let back = Hello::parse(&wire).unwrap();
        assert_eq!(back, h);
        assert!(back.verify(&ag.confirm));
        assert!(!back.verify(&agreement(2).confirm));
        let mut bad = wire.clone();
        bad[20] ^= 1;
        assert!(!Hello::parse(&bad).unwrap().verify(&ag.confirm));
        let mut o = h.clone();
        o.role = ROLE_OFFERER;
        o.nonce = [6; 16];
        let (a, b) = connection_keys(&ag, &o, &h);
        assert_ne!(a, b, "the directions apart");
        let mut h2 = h.clone();
        h2.conn = 2;
        assert_ne!(
            connection_keys(&ag, &o, &h2).0,
            a,
            "a new connection, new keys"
        );
        let mut o2 = o.clone();
        o2.nonce[0] ^= 1;
        assert_ne!(connection_keys(&ag, &o2, &h).0, a);
        assert_ne!(connection_keys(&agreement(2), &o, &h).0, a);
        assert_ne!(cookie_hash(&C), cookie_hash(&[8; 8]));
    }

    /// Both add-ons agreed (the offerer had the answer, or not): hellos,
    /// then the client's bytes go as records and come out as they went in,
    /// both ways; the final record at close.
    #[test]
    fn two_pipes_that_agreed_carry_the_bytes_encrypted() {
        for offerer_has_answer in [true, false] {
            let mut ka = Fixed::with(offerer_has_answer.then(|| agreement(1)));
            ka.from_hello = Some(agreement(1));
            let mut kb = Fixed::with(Some(agreement(1)));
            let mut a = FilePipe::new(C, Role::Offerer, false);
            let mut b = FilePipe::new(C, Role::Answerer, false);
            // B connects to A: A accepted, B's connect completed.
            a.connected(&mut ka, 0);
            b.connected(&mut kb, 0);
            assert_eq!(
                a.wants_write(),
                offerer_has_answer,
                "an offerer with the answer speaks at once"
            );
            assert!(b.wants_write(), "the answerer's hello");
            // A's client sends the prompt: held until the hellos are done.
            let prompt = crate::files::oft_build(crate::files::OFT_PROMPT, &C, 70_000, 0, "x");
            a.write(&prompt, &mut ka, 1).unwrap();
            let w = pass(&mut b, &mut a, &mut ka, 2);
            assert!(w.starts_with(HELLO_MAGIC));
            assert_eq!(a.phase(), Phase::Encrypted);
            assert_eq!(ka.kept, !offerer_has_answer);
            let w = pass(&mut a, &mut b, &mut kb, 3);
            assert!(
                w.starts_with(HELLO_MAGIC),
                "A's hello first, then the record"
            );
            assert!(!w.windows(4).any(|x| x == b"OFT2"), "no OFT2 on the wire");
            assert_eq!(b.phase(), Phase::Encrypted);
            assert_eq!(read_all(&mut b), prompt);
            // The file, big, the other way an ack, both through.
            let file: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
            b.write(b"ack", &mut kb, 4).unwrap();
            pass(&mut b, &mut a, &mut ka, 5);
            assert_eq!(read_all(&mut a), b"ack");
            a.write(&file, &mut ka, 6).unwrap();
            let w = a.take_wire();
            for piece in w.chunks(1000) {
                b.feed(piece, &mut kb, 7);
            }
            assert_eq!(read_all(&mut b), file);
            a.close();
            pass(&mut a, &mut b, &mut kb, 8);
            b.end_of_input(&mut kb);
            assert!(b.at_end());
            assert!(!kb.said(|e| matches!(e, Event::Log(l) if l.contains("without the final"))));
            assert!(ka.said(|e| *e == Event::Encrypted) && kb.said(|e| *e == Event::Encrypted));
        }
    }

    /// An offerer whose peer has no add-on, an older one, or file encryption
    /// off: no hello comes, and the connection is the client's own, byte for
    /// byte - after the wait, or at once when the peer's first bytes are not a
    /// hello.
    #[test]
    fn an_offerer_without_a_hello_leaves_the_connection_untouched() {
        let prompt = crate::files::oft_build(crate::files::OFT_PROMPT, &C, 5, 0, "x");
        // Nothing comes: after the wait, the held bytes go as they were.
        let mut k = Fixed::with(None);
        let mut a = FilePipe::new(C, Role::Offerer, false);
        a.connected(&mut k, 1000);
        a.write(&prompt, &mut k, 1000).unwrap();
        assert!(!a.wants_write());
        a.tick(&mut k, 1000 + HELLO_WAIT_MS - 1);
        assert!(a.waiting());
        a.tick(&mut k, 1000 + HELLO_WAIT_MS);
        assert_eq!(a.phase(), Phase::Plain);
        assert_eq!(a.take_wire(), prompt, "the client's bytes, untouched");
        a.feed(b"OFT2 reply", &mut k, 6000);
        assert_eq!(read_all(&mut a), b"OFT2 reply");
        assert!(k.said(|e| matches!(e, Event::Plain(w) if w.contains("no key hello within"))));
        // The peer's first bytes are its client's: plain at once.
        let mut k = Fixed::with(None);
        let mut a = FilePipe::new(C, Role::Offerer, false);
        a.connected(&mut k, 0);
        a.write(&prompt, &mut k, 0).unwrap();
        a.feed(b"OFT2...", &mut k, 2);
        assert_eq!(a.phase(), Phase::Plain);
        assert_eq!(a.take_wire(), prompt);
        assert_eq!(read_all(&mut a), b"OFT2...");
        // Two bytes that may start a hello say nothing yet.
        let mut k = Fixed::with(None);
        let mut a = FilePipe::new(C, Role::Offerer, false);
        a.connected(&mut k, 0);
        a.feed(b"IQ", &mut k, 1);
        assert_eq!(a.phase(), Phase::Hello);
        a.feed(b"x", &mut k, 2);
        assert_eq!(a.phase(), Phase::Plain);
        assert_eq!(read_all(&mut a), b"IQx");
        // A decline through the chat: plain at the next tick, no wait.
        let mut k = Fixed::with(None);
        let mut a = FilePipe::new(C, Role::Offerer, false);
        a.connected(&mut k, 0);
        a.write(&prompt, &mut k, 0).unwrap();
        k.plain = Some("declined".into());
        a.tick(&mut k, 10);
        assert_eq!((a.phase(), a.take_wire()), (Phase::Plain, prompt.clone()));
        // An answer through the chat while waiting: the offerer speaks.
        let mut k = Fixed::with(None);
        let mut a = FilePipe::new(C, Role::Offerer, false);
        a.connected(&mut k, 0);
        k.ag = Some(agreement(1));
        a.tick(&mut k, 10);
        assert!(a.take_wire().starts_with(HELLO_MAGIC));
    }

    /// Once agreed, anything that is not the agreed stream closes the
    /// connection and nothing reaches the client.
    #[test]
    fn an_agreed_connection_fails_closed() {
        let prompt = crate::files::oft_build(crate::files::OFT_PROMPT, &C, 5, 0, "x");
        // The answerer gets plain OFT2 instead of a hello.
        let mut k = Fixed::with(Some(agreement(1)));
        let mut b = FilePipe::new(C, Role::Answerer, false);
        b.connected(&mut k, 0);
        b.feed(&prompt, &mut k, 1);
        assert_eq!(b.phase(), Phase::Failed);
        assert_eq!(b.plaintext_len(), 0);
        assert!(b.write(b"x", &mut k, 2).is_err());
        assert!(k.said(|e| matches!(e, Event::Failed(w) if w.contains("unencrypted data"))));
        // A hello made with other keys.
        let mut ka = Fixed::with(Some(agreement(1)));
        let mut kb = Fixed::with(Some(agreement(2)));
        let mut a = FilePipe::new(C, Role::Offerer, false);
        let mut b = FilePipe::new(C, Role::Answerer, false);
        a.connected(&mut ka, 0);
        b.connected(&mut kb, 0);
        pass(&mut b, &mut a, &mut ka, 1);
        assert_eq!(a.phase(), Phase::Failed);
        assert!(ka.said(|e| matches!(e, Event::Failed(w) if w.contains("does not check out"))));
        // A hello for another transfer.
        let mut ka = Fixed::with(Some(agreement(1)));
        let mut kb = Fixed::with(Some(agreement(1)));
        let mut a = FilePipe::new(C, Role::Offerer, false);
        let mut b = FilePipe::new([8; 8], Role::Answerer, false);
        a.connected(&mut ka, 0);
        b.connected(&mut kb, 0);
        pass(&mut b, &mut a, &mut ka, 1);
        assert_eq!(a.phase(), Phase::Failed);
        // A tampered record, and a record cut by the end of the stream.
        for cut in [false, true] {
            let mut ka = Fixed::with(Some(agreement(1)));
            let mut kb = Fixed::with(Some(agreement(1)));
            let mut a = FilePipe::new(C, Role::Offerer, false);
            let mut b = FilePipe::new(C, Role::Answerer, false);
            a.connected(&mut ka, 0);
            b.connected(&mut kb, 0);
            pass(&mut b, &mut a, &mut ka, 1);
            a.write(&prompt, &mut ka, 1).unwrap();
            let mut w = a.take_wire();
            if cut {
                w.truncate(w.len() - 3);
                b.feed(&w, &mut kb, 2);
                b.end_of_input(&mut kb);
            } else {
                let n = w.len();
                w[n - 5] ^= 0x40;
                b.feed(&w, &mut kb, 2);
            }
            assert_eq!(b.phase(), Phase::Failed, "cut={cut}");
            assert_eq!(b.plaintext_len(), 0);
        }
        // An offerer that went plain by the wait and then sees a hello.
        let mut k = Fixed::with(None);
        let mut a = FilePipe::new(C, Role::Offerer, false);
        a.connected(&mut k, 0);
        a.tick(&mut k, HELLO_WAIT_MS);
        assert_eq!(a.phase(), Phase::Plain);
        let mut kb = Fixed::with(Some(agreement(1)));
        let mut b = FilePipe::new(C, Role::Answerer, false);
        b.connected(&mut kb, 0);
        pass(&mut b, &mut a, &mut k, HELLO_WAIT_MS + 1);
        assert_eq!(a.phase(), Phase::Failed);
    }

    /// Through the proxy: the ARS frames pass untouched both ways, the hello
    /// starts after READY.
    #[test]
    fn through_the_proxy_ars_frames_pass_and_the_hello_follows_ready() {
        use crate::files::{ars_build, ARS_ACK, ARS_INIT_RECV, ARS_INIT_SEND, ARS_READY};
        let mut ka = Fixed::with(Some(agreement(1)));
        let mut kb = Fixed::with(Some(agreement(1)));
        let mut a = FilePipe::new(C, Role::Offerer, true);
        let mut b = FilePipe::new(C, Role::Answerer, true);
        a.connected(&mut ka, 0);
        b.connected(&mut kb, 0);
        assert_eq!((a.phase(), b.phase()), (Phase::Ars, Phase::Ars));
        let init = ars_build(ARS_INIT_SEND, &[1, b'a', 7, 7, 7, 7, 7, 7, 7, 7]);
        a.write(&init, &mut ka, 1).unwrap();
        assert_eq!(a.take_wire(), init, "INIT_SEND as the client wrote it");
        let ack = ars_build(ARS_ACK, &[0, 9, 1, 2, 3, 4]);
        a.feed(&ack, &mut ka, 2);
        assert_eq!(read_all(&mut a), ack);
        assert_eq!(a.phase(), Phase::Ars);
        let initr = ars_build(ARS_INIT_RECV, &[1, b'b', 0, 9, 7, 7, 7, 7, 7, 7, 7, 7]);
        b.write(&initr, &mut kb, 3).unwrap();
        assert_eq!(b.take_wire(), initr);
        // READY to both, the answerer's hello in the same read as READY.
        let ready = ars_build(ARS_READY, &[]);
        b.feed(&ready, &mut kb, 4);
        assert_eq!(read_all(&mut b), ready);
        assert_eq!(b.phase(), Phase::Hello);
        let mut wire = ready.clone();
        wire.extend_from_slice(&b.take_wire());
        a.feed(&wire, &mut ka, 5);
        assert_eq!(read_all(&mut a), ready);
        assert!(a.take_wire().starts_with(HELLO_MAGIC));
        assert_eq!(a.phase(), Phase::Encrypted);
    }

    /// A resumed transfer is a new connection: new numbers, new nonces, new
    /// keys - the same cookie, never the same key stream.
    #[test]
    fn a_second_connection_of_a_transfer_has_keys_of_its_own() {
        let mut first = Vec::new();
        let mut ka = Fixed::with(Some(agreement(1)));
        let mut kb = Fixed::with(Some(agreement(1)));
        for _ in 0..2 {
            let mut a = FilePipe::new(C, Role::Offerer, false);
            let mut b = FilePipe::new(C, Role::Answerer, false);
            a.connected(&mut ka, 0);
            b.connected(&mut kb, 0);
            pass(&mut b, &mut a, &mut ka, 1);
            pass(&mut a, &mut b, &mut kb, 1);
            a.write(&[0u8; 64], &mut ka, 2).unwrap();
            let w = a.take_wire();
            b.feed(&w, &mut kb, 3);
            assert_eq!(read_all(&mut b), vec![0u8; 64]);
            first.push(w);
        }
        assert_ne!(first[0], first[1], "the same plaintext, other ciphertext");
        assert_eq!((ka.conns, kb.conns), (2, 2));
    }
}
