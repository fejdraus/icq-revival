//! Agreeing on the keys of a file transfer (stages F2 and F4 of
//! `docs/e2e/FILES-RESEARCH.md`), and which sockets belong to which transfer.
//!
//! Only with `files_encrypt = on` (off by default). Off, nothing here
//! negotiates: no control message is sent, an incoming one is taken as an
//! add-on without file support takes any control message, and no socket is
//! ever touched. With `files_log = on` the table still records what the
//! rendezvous ICBMs say, so the log can tell which stage a connection is.
//!
//! The exchange rides the existing Olm session as hidden control messages
//! (`container.rs`, kind 0), payload `IQF1 | type | cookie | ...`, like the
//! calls' `IQC1`:
//!
//! ```text
//! sender (offerer, A)                               receiver (answerer, B)
//! OUT Offer {cookie, device, device key, eph A, transfer secret, suites}
//! OUT proposal ICBM (untouched)   --------------->  IN offer, IN proposal:
//!                                                   keys derived, Answer queued
//!                                                   (or Decline, or nothing
//!                                                   without an offer: plain)
//! IN Answer: keys     <---------------------------  OUT Answer, OUT accept or
//!                                                   counter-proposal (untouched)
//! data connection: key hellos, records (filestream.rs)
//! ```
//!
//! The answer may well come after the data connection has started (a
//! receiver connects first and sends its accept after), so the data
//! connection does not wait for it: the answerer's key hello carries the
//! same ephemeral key, and only an add-on that decrypted the offer (and so
//! has the transfer secret) can make one that checks out.
//!
//! Keys: X25519 of the two ephemeral keys and the offer's random 32-byte
//! transfer secret go into HKDF-SHA256 with a salt binding the cookie and
//! both sides as UIN, device id and Curve25519 device key; the Olm session
//! authenticates the offer and the answer, so the keys are as trusted as the
//! chat (the safety number). Each connection derives its own keys from both
//! hellos ([`crate::filestream::connection_keys`]).
//!
//! Backward compatibility: a peer with no add-on, an older one, or
//! `files_encrypt` off never answers, and the transfer is exactly as today -
//! for a contact that is not strict. "Encryption is on for this contact"
//! means the same for files as for text and calls (second audit of 2026-10,
//! finding 4): with a contact under `/e2e on` or verified ([`PeerInfo`]
//! `strict`), or with `files_encrypt = required` for every contact, a
//! transfer that does not agree on keys - no offer or answer, a decline, no
//! key hello in time - is not sent: its connections are closed before a byte
//! of it goes out, and the chat says why. Once agreed a transfer fails
//! closed, whoever it is with.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use ring::hkdf;
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey};

use crate::callneg::{Me, PeerInfo};
use crate::crypto::Note;
use crate::files::{self, Rendezvous, RDV_ACCEPT, RDV_CANCEL, RDV_PROPOSE};
use crate::filestream::{self, Agreement, Event, KeySource, Role};
use crate::icbm::Direction;
use crate::sign;
use crate::snac::Reader;

/// What a file control payload starts with, inside the control envelope.
pub const MAGIC: &[u8; 4] = b"IQF1";
/// ChaCha20-Poly1305 records (`filestream.rs`).
pub const SUITE_CHACHA20POLY1305: u8 = 1;
pub const SUITES: [u8; 1] = [SUITE_CHACHA20POLY1305];

const T_OFFER: u8 = 1;
const T_ANSWER: u8 = 2;
const T_DECLINE: u8 = 3;

/// Decline reasons.
pub const DECLINE_REFUSED: u8 = 1;
pub const DECLINE_NO_SUITE: u8 = 2;

/// How long an offer waits for its proposal.
pub const OFFER_TTL_MS: u64 = 60_000;
/// A transfer nobody has heard of for this long is forgotten (a user may
/// take a while to accept).
pub const IDLE_TTL_MS: u64 = 2 * 3600 * 1000;
/// How long a cancelled transfer's keys stay for connections still open.
pub const ENDED_GRACE_MS: u64 = 30_000;
/// Offers and rendezvous facts kept at most.
const MAX_OFFERS: usize = 16;
const MAX_FACTS: usize = 64;

// --- the control payloads -------------------------------------------------------------

/// A file control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Offer {
        cookie: [u8; 8],
        device: u32,
        device_key: [u8; 32],
        eph: [u8; 32],
        secret: [u8; 32],
        suites: Vec<u8>,
    },
    Answer {
        cookie: [u8; 8],
        device: u32,
        device_key: [u8; 32],
        eph: [u8; 32],
        suite: u8,
    },
    Decline {
        cookie: [u8; 8],
        reason: u8,
    },
}

fn arr<const N: usize>(r: &mut Reader) -> Option<[u8; N]> {
    let mut a = [0u8; N];
    a.copy_from_slice(r.bytes(N)?);
    Some(a)
}

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        match self {
            Msg::Offer {
                cookie,
                device,
                device_key,
                eph,
                secret,
                suites,
            } => {
                b.push(T_OFFER);
                b.extend_from_slice(cookie);
                b.extend_from_slice(&device.to_be_bytes());
                b.extend_from_slice(device_key);
                b.extend_from_slice(eph);
                b.extend_from_slice(secret);
                b.push(suites.len() as u8);
                b.extend_from_slice(suites);
            }
            Msg::Answer {
                cookie,
                device,
                device_key,
                eph,
                suite,
            } => {
                b.push(T_ANSWER);
                b.extend_from_slice(cookie);
                b.extend_from_slice(&device.to_be_bytes());
                b.extend_from_slice(device_key);
                b.extend_from_slice(eph);
                b.push(*suite);
            }
            Msg::Decline { cookie, reason } => {
                b.push(T_DECLINE);
                b.extend_from_slice(cookie);
                b.push(*reason);
            }
        }
        b
    }

    /// Reads a payload; `None` for anything that is not a file control
    /// message of this version. Bytes after the known fields are left for a
    /// later version.
    pub fn decode(b: &[u8]) -> Option<Msg> {
        let rest = b.strip_prefix(MAGIC.as_slice())?;
        let mut r = Reader::new(rest);
        let t = r.u8()?;
        let cookie = arr::<8>(&mut r)?;
        Some(match t {
            T_OFFER => {
                let device = r.u32()?;
                let device_key = arr::<32>(&mut r)?;
                let eph = arr::<32>(&mut r)?;
                let secret = arr::<32>(&mut r)?;
                let n = r.u8()? as usize;
                Msg::Offer {
                    cookie,
                    device,
                    device_key,
                    eph,
                    secret,
                    suites: r.bytes(n)?.to_vec(),
                }
            }
            T_ANSWER => Msg::Answer {
                cookie,
                device: r.u32()?,
                device_key: arr::<32>(&mut r)?,
                eph: arr::<32>(&mut r)?,
                suite: r.u8()?,
            },
            T_DECLINE => Msg::Decline {
                cookie,
                reason: r.u8()?,
            },
            _ => return None,
        })
    }

    pub fn cookie(&self) -> [u8; 8] {
        match self {
            Msg::Offer { cookie, .. }
            | Msg::Answer { cookie, .. }
            | Msg::Decline { cookie, .. } => *cookie,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Msg::Offer { .. } => "offer",
            Msg::Answer { .. } => "answer",
            Msg::Decline { .. } => "decline",
        }
    }
}

// --- the keys ---------------------------------------------------------------------------

/// One side of a transfer, as the keys bind it.
#[derive(Debug, Clone, Copy)]
pub struct Party<'a> {
    /// The UIN, normalised (`sign::ident`).
    pub uin: &'a str,
    pub device: u32,
    pub device_key: [u8; 32],
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// The transfer's keys: HKDF-SHA256 over the X25519 secret of the two
/// ephemeral keys and the offer's transfer secret, salted with the cookie and
/// both parties, expanded with both ephemeral keys.
pub fn derive(
    shared: &[u8; 32],
    secret: &[u8; 32],
    cookie: &[u8; 8],
    offerer: Party,
    answerer: Party,
    eph_offerer: &[u8; 32],
    eph_answerer: &[u8; 32],
) -> Agreement {
    let mut salt = b"icq-e2e files salt v1".to_vec();
    salt.extend_from_slice(cookie);
    for p in [&offerer, &answerer] {
        salt.push(p.uin.len() as u8);
        salt.extend_from_slice(p.uin.as_bytes());
        salt.extend_from_slice(&p.device.to_be_bytes());
        salt.extend_from_slice(&p.device_key);
    }
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(shared);
    ikm[32..].copy_from_slice(secret);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&ikm);
    ikm.fill(0);
    let expand = |label: &[u8]| {
        let info: [&[u8]; 4] = [b"icq-e2e files v1 ", label, eph_offerer, eph_answerer];
        let mut out = [0u8; 32];
        prk.expand(&info, Len(32))
            .and_then(|okm| okm.fill(&mut out))
            .expect("HKDF-SHA256 output of 32 bytes");
        out
    };
    Agreement {
        root: expand(b"root"),
        confirm: expand(b"confirm"),
        eph_offerer: *eph_offerer,
        eph_answerer: *eph_answerer,
        answerer_device: answerer.device,
        answerer_key: answerer.device_key,
        offerer_device: offerer.device,
        offerer_key: offerer.device_key,
    }
}

/// X25519 with a key that may be used again (the offerer derives once from
/// the answer or the hello, whichever comes first, and checks the other).
fn dh(sk: &Curve25519SecretKey, their: &[u8; 32]) -> Option<[u8; 32]> {
    let s = sk.diffie_hellman(&Curve25519PublicKey::from_bytes(*their))?;
    Some(*s.as_bytes())
}

// --- the table -------------------------------------------------------------------------

/// What the rendezvous ICBMs said about a transfer: enough to tell its
/// sockets and its stages, kept with or without encryption.
#[derive(Debug, Clone)]
struct Facts {
    peer_name: String,
    /// Whether the first proposal was ours.
    we_send: Option<bool>,
    /// Our proposals' ports (sockets we accept on), with their stage.
    local: Vec<(u16, &'static str)>,
    /// The peer's proposals' addresses (what we connect to), with their stage.
    remote: Vec<(Ipv4Addr, u16, &'static str)>,
    last_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TState {
    /// Offerer: the offer is out, no keys yet.
    Offered,
    /// Both add-ons' keys are known.
    Keyed,
    /// Not encrypted: no socket of it is ever touched.
    Plain(String),
    /// Not encrypted, and it must be (a strict contact, or `required`):
    /// every socket of it is closed, no byte of it passes.
    Blocked(String),
}

impl TState {
    fn name(&self) -> &'static str {
        match self {
            TState::Offered => "offered",
            TState::Keyed => "keyed",
            TState::Plain(_) => "plain",
            TState::Blocked(_) => "blocked",
        }
    }
}

struct Transfer {
    cookie: [u8; 8],
    peer_name: String,
    peer: String,
    role: Role,
    state: TState,
    /// The offerer's ephemeral key.
    sk: Option<Curve25519SecretKey>,
    my_eph: [u8; 32],
    /// The transfer secret (the offerer's own, or from the offer).
    secret: [u8; 32],
    me: Option<Me>,
    agreement: Option<Agreement>,
    conns: u32,
    info: PeerInfo,
    told: Option<bool>,
    failed_told: bool,
    outbox: Vec<Vec<u8>>,
    touched: u64,
    ended_at: Option<u64>,
}

impl Drop for Transfer {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

impl Transfer {
    fn label(&self) -> String {
        format!(
            "file transfer {} with {} ({})",
            files::cookie_tag(&self.cookie),
            self.peer_name,
            self.role.name()
        )
    }
}

struct PendingOffer {
    peer: String,
    device: u32,
    device_key: [u8; 32],
    eph: [u8; 32],
    secret: [u8; 32],
    suites: Vec<u8>,
    at: u64,
}

impl Drop for PendingOffer {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

/// Which transfer a socket belongs to, and what to do with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub cookie: [u8; 8],
    /// Our role when the socket is to carry the encrypted stream; `None`
    /// when it is left as it is (not agreed, plain, or encryption off).
    pub role: Option<Role>,
    /// `direct`, `reverse`, `proxy`, or `unknown`.
    pub stage: &'static str,
    /// The transfer is not let through (it must be encrypted and did not
    /// agree on keys), and why: the socket is closed, nothing passes.
    pub blocked: Option<String>,
}

/// Every file transfer the add-on knows of.
pub struct FileTable {
    facts: HashMap<[u8; 8], Facts>,
    transfers: HashMap<[u8; 8], Transfer>,
    offers: HashMap<[u8; 8], PendingOffer>,
    notes: Vec<Note>,
    log: Vec<String>,
    /// `files_encrypt = required`: every contact is strict - a transfer that
    /// did not agree on keys is not sent, never let through plain.
    required: bool,
}

impl Default for FileTable {
    fn default() -> Self {
        FileTable {
            facts: HashMap::new(),
            transfers: HashMap::new(),
            offers: HashMap::new(),
            notes: Vec::new(),
            log: Vec::new(),
            required: false,
        }
    }
}

/// The table the hooks and the engine share.
pub fn shared() -> Arc<Mutex<FileTable>> {
    static T: std::sync::LazyLock<Arc<Mutex<FileTable>>> =
        std::sync::LazyLock::new(|| Arc::new(Mutex::new(FileTable::default())));
    T.clone()
}

/// The table, even if a panic poisoned its lock.
pub fn lock(t: &Mutex<FileTable>) -> std::sync::MutexGuard<'_, FileTable> {
    t.lock().unwrap_or_else(|e| e.into_inner())
}

/// Unix time in milliseconds, the table's clock.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The words for why a transfer goes unencrypted.
pub mod why {
    pub fn no_offer(peer: &str) -> String {
        format!("{peer} did not offer to encrypt it (no E2E add-on there, an older one, or file encryption off)")
    }
    pub fn declined(peer: &str, reason: u8) -> String {
        match reason {
            super::DECLINE_NO_SUITE => {
                format!("{peer}'s add-on has no file cipher in common with this one")
            }
            _ => format!("{peer}'s add-on declined to encrypt it (encryption is off for this chat on their side)"),
        }
    }
}

impl FileTable {
    /// Switches the strict level on or off (`files_encrypt = required`).
    pub fn set_required(&mut self, on: bool) {
        self.required = on;
    }

    /// Whether a transfer with this contact must be encrypted or not sent:
    /// `files_encrypt = required`, or a contact under `/e2e on` or verified.
    fn strict(&self, info: &PeerInfo) -> bool {
        self.required || info.strict
    }

    /// A rendezvous ICBM seen in either direction: its facts are kept (for
    /// the log's stages and for telling the sockets apart). Changes nothing.
    pub fn observe(&mut self, rdv: &Rendezvous, now: u64) {
        if !self.facts.contains_key(&rdv.cookie) && self.facts.len() >= MAX_FACTS {
            if let Some(old) = self
                .facts
                .iter()
                .min_by_key(|(_, f)| f.last_ms)
                .map(|(k, _)| *k)
            {
                self.facts.remove(&old);
            }
        }
        let f = self.facts.entry(rdv.cookie).or_insert_with(|| Facts {
            peer_name: rdv.peer.clone(),
            we_send: None,
            local: Vec::new(),
            remote: Vec::new(),
            last_ms: now,
        });
        f.last_ms = now;
        if rdv.kind != RDV_PROPOSE {
            return;
        }
        if f.we_send.is_none() {
            f.we_send = Some(rdv.dir == Direction::Outbound);
        }
        let stage = rdv.stage();
        let Some(port) = rdv.port else { return };
        match rdv.dir {
            Direction::Outbound => {
                if !rdv.use_ars && !f.local.iter().any(|(p, _)| *p == port) {
                    f.local.push((port, stage));
                }
            }
            Direction::Inbound => {
                for ip in &rdv.ips {
                    if !f.remote.iter().any(|(i, p, _)| i == ip && *p == port) {
                        f.remote.push((*ip, port, stage));
                    }
                }
            }
        }
    }

    /// A rendezvous ICBM with `files_encrypt=on`, after [`Self::observe`].
    /// Returns the control payloads to send to the peer *before* that ICBM
    /// goes on (outbound): the offer before our first proposal, a waiting
    /// answer or decline before our accept or counter-proposal. `me` says who
    /// we are, or why this transfer must not be encrypted.
    pub fn icbm(
        &mut self,
        rdv: &Rendezvous,
        info: PeerInfo,
        me: &mut dyn FnMut() -> Result<Me, String>,
        now: u64,
    ) -> Vec<Vec<u8>> {
        let c = rdv.cookie;
        let mut out = Vec::new();
        if let Some(t) = self.transfers.get_mut(&c) {
            if t.peer != sign::ident(&rdv.peer) {
                return out;
            }
            t.touched = now;
            t.info = info;
        }
        // Who sends the file is who made the first proposal (observe() has
        // seen it): a counter-proposal of the receiver is never an offer.
        let we_send = self.facts.get(&c).and_then(|f| f.we_send);
        let new = !self.transfers.contains_key(&c);
        match (rdv.dir, rdv.kind) {
            (_, RDV_CANCEL) => self.end(c, now, "cancelled"),
            (Direction::Outbound, RDV_PROPOSE) if new && we_send != Some(false) => {
                self.offer(rdv, info, me, now, &mut out);
            }
            (Direction::Inbound, RDV_PROPOSE) if new && we_send != Some(true) => {
                self.answer(rdv, info, me, now);
            }
            _ => {}
        }
        if rdv.dir == Direction::Outbound
            && matches!(rdv.kind, RDV_PROPOSE | RDV_ACCEPT | RDV_CANCEL)
        {
            if let Some(t) = self.transfers.get_mut(&c) {
                out.append(&mut t.outbox);
            }
        }
        out
    }

    fn offer(
        &mut self,
        rdv: &Rendezvous,
        info: PeerInfo,
        me: &mut dyn FnMut() -> Result<Me, String>,
        now: u64,
        out: &mut Vec<Vec<u8>>,
    ) {
        let mut t = Transfer {
            cookie: rdv.cookie,
            peer_name: rdv.peer.clone(),
            peer: sign::ident(&rdv.peer),
            role: Role::Offerer,
            state: TState::Offered,
            sk: None,
            my_eph: [0; 32],
            secret: [0; 32],
            me: None,
            agreement: None,
            conns: 0,
            info,
            told: None,
            failed_told: false,
            outbox: Vec::new(),
            touched: now,
            ended_at: None,
        };
        match me() {
            Err(why) => {
                self.log
                    .push(format!("{}: proposal out, not encrypted: {why}", t.label()));
                self.go_plain(&mut t, &why);
            }
            Ok(m) => {
                if getrandom::fill(&mut t.secret).is_err() {
                    let why = "no random bytes for the transfer secret".to_string();
                    self.go_plain(&mut t, &why);
                } else {
                    let sk = Curve25519SecretKey::new();
                    t.my_eph = Curve25519PublicKey::from(&sk).to_bytes();
                    t.sk = Some(sk);
                    out.push(
                        Msg::Offer {
                            cookie: rdv.cookie,
                            device: m.device,
                            device_key: m.key,
                            eph: t.my_eph,
                            secret: t.secret,
                            suites: SUITES.to_vec(),
                        }
                        .encode(),
                    );
                    t.me = Some(m);
                    self.log.push(format!(
                        "{}: proposal out ({} stage), key offer sent first",
                        t.label(),
                        rdv.stage()
                    ));
                }
            }
        }
        self.transfers.insert(rdv.cookie, t);
    }

    fn answer(
        &mut self,
        rdv: &Rendezvous,
        info: PeerInfo,
        me: &mut dyn FnMut() -> Result<Me, String>,
        now: u64,
    ) {
        let peer = sign::ident(&rdv.peer);
        let offer = self.offers.remove(&rdv.cookie).filter(|o| o.peer == peer);
        let mut t = Transfer {
            cookie: rdv.cookie,
            peer_name: rdv.peer.clone(),
            peer,
            role: Role::Answerer,
            state: TState::Plain(String::new()),
            sk: None,
            my_eph: [0; 32],
            secret: [0; 32],
            me: None,
            agreement: None,
            conns: 0,
            info,
            told: None,
            failed_told: false,
            outbox: Vec::new(),
            touched: now,
            ended_at: None,
        };
        let label = t.label();
        match offer {
            None => {
                let why = why::no_offer(&t.peer_name);
                self.log
                    .push(format!("{label}: proposal in, not encrypted: {why}"));
                self.go_plain(&mut t, &why);
            }
            Some(o) if !o.suites.contains(&SUITE_CHACHA20POLY1305) => {
                t.outbox.push(
                    Msg::Decline {
                        cookie: rdv.cookie,
                        reason: DECLINE_NO_SUITE,
                    }
                    .encode(),
                );
                let why = format!(
                    "{}'s add-on offered no file cipher this one has",
                    t.peer_name
                );
                self.log.push(format!("{label}: declined: {why}"));
                self.go_plain(&mut t, &why);
            }
            Some(o) => match me() {
                Err(why) => {
                    t.outbox.push(
                        Msg::Decline {
                            cookie: rdv.cookie,
                            reason: DECLINE_REFUSED,
                        }
                        .encode(),
                    );
                    self.log.push(format!("{label}: declined: {why}"));
                    self.go_plain(&mut t, &why);
                }
                Ok(m) => {
                    let sk = Curve25519SecretKey::new();
                    let mine = Curve25519PublicKey::from(&sk).to_bytes();
                    match dh(&sk, &o.eph) {
                        Some(mut shared) => {
                            let ag = derive(
                                &shared,
                                &o.secret,
                                &rdv.cookie,
                                Party {
                                    uin: &t.peer,
                                    device: o.device,
                                    device_key: o.device_key,
                                },
                                Party {
                                    uin: &m.uin,
                                    device: m.device,
                                    device_key: m.key,
                                },
                                &o.eph,
                                &mine,
                            );
                            shared.fill(0);
                            t.outbox.push(
                                Msg::Answer {
                                    cookie: rdv.cookie,
                                    device: m.device,
                                    device_key: m.key,
                                    eph: mine,
                                    suite: SUITE_CHACHA20POLY1305,
                                }
                                .encode(),
                            );
                            t.my_eph = mine;
                            t.secret = o.secret;
                            t.agreement = Some(ag);
                            t.me = Some(m);
                            t.state = TState::Keyed;
                            self.log.push(format!(
                                "{label}: proposal in ({} stage) with a key offer; keys agreed, \
                                 answer queued for our next ICBM to them",
                                rdv.stage()
                            ));
                        }
                        None => {
                            let why = "the key agreement failed".to_string();
                            self.log.push(format!("{label}: {why}"));
                            self.go_plain(&mut t, &why);
                        }
                    }
                }
            },
        }
        self.transfers.insert(rdv.cookie, t);
    }

    /// Whether a file proposal with `cookie` in `peer`'s name is vouched for
    /// end to end (sixth audit of 2026-10, finding 3): the key offer
    /// `peer`'s add-on sends before its proposal has come over the Olm
    /// session and waits for it, or the transfer is one already known with
    /// `peer` (our own proposal, or one let through before). Nothing is
    /// consumed: the proposal takes the offer itself ([`Self::icbm`]).
    pub fn vouched(&self, peer: &str, cookie: &[u8; 8]) -> bool {
        let p = sign::ident(peer);
        self.transfers.get(cookie).is_some_and(|t| t.peer == p)
            || self.offers.get(cookie).is_some_and(|o| o.peer == p)
    }

    /// A file control message from `peer`, sent by its device `sender`.
    pub fn control(&mut self, peer: &str, sender: u32, msg: Msg, now: u64) {
        let p = sign::ident(peer);
        let c = msg.cookie();
        let what = msg.name();
        let Some(mut t) = self.transfers.remove(&c) else {
            if let Msg::Offer {
                device,
                device_key,
                eph,
                secret,
                suites,
                ..
            } = msg
            {
                if device != sender {
                    self.log.push(format!(
                        "file key offer from {peer} ignored: it names another device"
                    ));
                    return;
                }
                if self.offers.len() >= MAX_OFFERS {
                    if let Some(old) = self
                        .offers
                        .iter()
                        .min_by_key(|(_, o)| o.at)
                        .map(|(k, _)| *k)
                    {
                        self.offers.remove(&old);
                    }
                }
                self.offers.insert(
                    c,
                    PendingOffer {
                        peer: p,
                        device,
                        device_key,
                        eph,
                        secret,
                        suites,
                        at: now,
                    },
                );
            } else {
                self.log.push(format!(
                    "file key {what} from {peer} for a transfer not known here: ignored"
                ));
            }
            return;
        };
        let label = t.label();
        if t.peer != p {
            self.log.push(format!(
                "{label}: key {what} from {peer}, not the peer: ignored"
            ));
            self.transfers.insert(c, t);
            return;
        }
        t.touched = now;
        match (msg, &t.state, t.role) {
            (
                Msg::Answer {
                    device,
                    device_key,
                    eph,
                    suite,
                    ..
                },
                TState::Offered,
                Role::Offerer,
            ) if device == sender && suite == SUITE_CHACHA20POLY1305 => {
                match self.offerer_agreement(&t, &eph, device, &device_key) {
                    Some(ag) => {
                        t.agreement = Some(ag);
                        t.state = TState::Keyed;
                        self.log.push(format!(
                            "{label}: key answer in; keys agreed (ChaCha20-Poly1305)"
                        ));
                    }
                    None => {
                        let why = "the key agreement failed".to_string();
                        self.log.push(format!("{label}: {why}"));
                        self.go_plain(&mut t, &why);
                    }
                }
            }
            (Msg::Answer { eph, .. }, TState::Keyed, Role::Offerer) => {
                // The hello came first and keyed it: the answer must agree.
                if t.agreement.as_ref().is_some_and(|a| a.eph_answerer != eph) {
                    self.log.push(format!(
                        "{label}: WARNING the key answer names another key than the hello did; \
                         the connection's keys stay those of the hello"
                    ));
                } else {
                    self.log.push(format!(
                        "{label}: key answer in (keys already agreed by the hello)"
                    ));
                }
            }
            (Msg::Decline { reason, .. }, TState::Offered, Role::Offerer) => {
                let why = why::declined(&t.peer_name, reason);
                self.log.push(format!("{label}: declined: {why}"));
                self.go_plain(&mut t, &why);
            }
            (m, s, _) => {
                self.log.push(format!(
                    "{label}: key {} in state {}: ignored",
                    m.name(),
                    s.name()
                ));
            }
        }
        self.transfers.insert(c, t);
    }

    /// The offerer's keys with an answerer that named `eph` and its device.
    fn offerer_agreement(
        &self,
        t: &Transfer,
        eph: &[u8; 32],
        device: u32,
        device_key: &[u8; 32],
    ) -> Option<Agreement> {
        let sk = t.sk.as_ref()?;
        let me = t.me.as_ref()?;
        let mut shared = dh(sk, eph)?;
        let ag = derive(
            &shared,
            &t.secret,
            &t.cookie,
            Party {
                uin: &me.uin,
                device: me.device,
                device_key: me.key,
            },
            Party {
                uin: &t.peer,
                device,
                device_key: *device_key,
            },
            &t.my_eph,
            eph,
        );
        shared.fill(0);
        Some(ag)
    }

    /// A payload [`Self::icbm`] gave could not be sent: the transfer goes
    /// plain (an offer that never left), or the answer is simply missing
    /// (the hello still carries the keys).
    pub fn send_failed(&mut self, payload: &[u8], why: &str) {
        let Some(msg) = Msg::decode(payload) else {
            return;
        };
        let c = msg.cookie();
        let Some(mut t) = self.transfers.remove(&c) else {
            return;
        };
        self.log
            .push(format!("{}: key {} not sent: {why}", t.label(), msg.name()));
        if matches!(msg, Msg::Offer { .. }) {
            let w = format!("the key exchange could not be sent ({why})");
            self.go_plain(&mut t, &w);
        }
        self.transfers.insert(c, t);
    }

    /// One payload waiting for the next outbound frame to `peer`.
    pub fn take_outbox(&mut self, peer: &str) -> Option<Vec<u8>> {
        let p = sign::ident(peer);
        self.transfers
            .values_mut()
            .find(|t| t.peer == p && !t.outbox.is_empty())
            .map(|t| t.outbox.remove(0))
    }

    fn end(&mut self, c: [u8; 8], now: u64, what: &str) {
        if let Some(t) = self.transfers.get_mut(&c) {
            if t.ended_at.is_none() {
                t.ended_at = Some(now);
                let l = format!("{}: {what}; was {}", t.label(), t.state.name());
                self.log.push(l);
            }
        }
    }

    /// The transfer is not encrypted: plain for a contact that is not
    /// strict, not let through (blocked) for one that is.
    fn go_plain(&mut self, t: &mut Transfer, why: &str) {
        t.agreement = None;
        t.sk = None;
        if self.strict(&t.info) {
            t.state = TState::Blocked(why.to_string());
            self.log.push(format!(
                "{}: not encrypted, so it is not let through ({})",
                t.label(),
                if self.required {
                    "files_encrypt=required"
                } else {
                    "encryption is on for the contact"
                }
            ));
            self.say_blocked(t, why);
            return;
        }
        t.state = TState::Plain(why.to_string());
        if t.told.is_none() {
            t.told = Some(false);
            self.notes.push(Note::to(
                &t.peer_name,
                crate::policy::file_plain_note(&t.peer_name, why),
            ));
        }
    }

    /// The chat note for a transfer that is not let through, once.
    fn say_blocked(&mut self, t: &mut Transfer, why: &str) {
        if t.told.is_none() {
            t.told = Some(false);
            self.notes.push(Note::to(
                &t.peer_name,
                crate::policy::file_blocked_note(&t.peer_name, why, self.required, t.info.verified),
            ));
        }
    }

    /// The notes for the chat, oldest first.
    pub fn take_notes(&mut self) -> Vec<Note> {
        std::mem::take(&mut self.notes)
    }

    /// The lines for the log.
    pub fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    /// Timers: offers that never saw their proposal, transfers long idle or
    /// cancelled a while ago.
    pub fn tick(&mut self, now: u64) {
        self.offers
            .retain(|_, o| now.saturating_sub(o.at) < OFFER_TTL_MS);
        let done: Vec<[u8; 8]> = self
            .transfers
            .iter()
            .filter(|(_, t)| match t.ended_at {
                Some(at) => now.saturating_sub(at) >= ENDED_GRACE_MS,
                None => now.saturating_sub(t.touched) >= IDLE_TTL_MS,
            })
            .map(|(k, _)| *k)
            .collect();
        for c in done {
            if let Some(t) = self.transfers.remove(&c) {
                self.log.push(format!(
                    "{}: forgotten ({}, {} connection(s))",
                    t.label(),
                    t.state.name(),
                    t.conns
                ));
            }
        }
        self.facts
            .retain(|_, f| now.saturating_sub(f.last_ms) < IDLE_TTL_MS);
    }

    // --- which socket is which --------------------------------------------------------

    /// What to do with a socket of transfer `c`: carry the stream (our role)
    /// or leave it alone.
    fn found(&self, c: [u8; 8], stage: &'static str) -> Found {
        let t = self.transfers.get(&c);
        let role = t.and_then(|t| match (&t.state, t.role) {
            (TState::Keyed, r) => Some(r),
            (TState::Offered, Role::Offerer) => Some(Role::Offerer),
            _ => None,
        });
        let blocked = t.and_then(|t| match &t.state {
            TState::Blocked(why) => Some(why.clone()),
            _ => None,
        });
        Found {
            cookie: c,
            role,
            stage,
            blocked,
        }
    }

    /// A `connect` to `ip:port`: the address of one of the peer's proposals.
    pub fn find_connect(&self, ip: Ipv4Addr, port: u16) -> Option<Found> {
        let mut hits = self.facts.iter().filter_map(|(c, f)| {
            f.remote
                .iter()
                .find(|(i, p, _)| *i == ip && *p == port)
                .map(|(_, _, s)| (*c, *s, f.last_ms))
        });
        let best = hits
            .next()
            .map(|first| hits.fold(first, |a, b| if b.2 > a.2 { b } else { a }))?;
        Some(self.found(best.0, best.1))
    }

    /// An accepted socket on local port `port`: the port of one of our
    /// proposals.
    pub fn find_local(&self, port: u16) -> Option<Found> {
        let best = self
            .facts
            .iter()
            .filter_map(|(c, f)| {
                f.local
                    .iter()
                    .find(|(p, _)| *p == port)
                    .map(|(_, s)| (*c, *s, f.last_ms))
            })
            .max_by_key(|x| x.2)?;
        Some(self.found(best.0, best.1))
    }

    /// A socket whose first bytes name the cookie (an ARS `INIT`, an OFT2
    /// header).
    pub fn find_cookie(&self, c: [u8; 8], via_proxy: bool) -> Option<Found> {
        if !self.facts.contains_key(&c) && !self.transfers.contains_key(&c) {
            return None;
        }
        Some(self.found(c, if via_proxy { "proxy" } else { "unknown" }))
    }

    /// A hello's cookie hash, for a socket found by its first inbound bytes.
    pub fn find_hello(&self, hash: &[u8; 8]) -> Option<Found> {
        self.transfers
            .keys()
            .chain(self.facts.keys())
            .find(|c| filestream::cookie_hash(c) == *hash)
            .map(|c| self.found(*c, "unknown"))
    }

    /// Whether we send the file (`Some(true)`), receive it, or do not know.
    pub fn we_send(&self, c: &[u8; 8]) -> Option<bool> {
        self.facts.get(c).and_then(|f| f.we_send)
    }

    /// The contact of a transfer, as the client names them.
    pub fn peer_of(&self, c: &[u8; 8]) -> Option<String> {
        self.facts
            .get(c)
            .map(|f| f.peer_name.clone())
            .or_else(|| self.transfers.get(c).map(|t| t.peer_name.clone()))
    }

    /// Whether any transfer may have a socket to look after: only then is a
    /// socket looked at for encryption.
    pub fn active(&self) -> bool {
        self.transfers.values().any(|t| {
            matches!(
                t.state,
                TState::Offered | TState::Keyed | TState::Blocked(_)
            )
        })
    }

    /// The state of a transfer, for tests and the log.
    pub fn state_of(&self, c: &[u8; 8]) -> Option<&'static str> {
        self.transfers.get(c).map(|t| t.state.name())
    }
}

impl KeySource for FileTable {
    fn agreement(&mut self, cookie: &[u8; 8]) -> Option<Agreement> {
        let t = self.transfers.get(cookie)?;
        (t.state == TState::Keyed)
            .then(|| t.agreement.clone())
            .flatten()
    }

    fn try_agreement(
        &mut self,
        cookie: &[u8; 8],
        eph: &[u8; 32],
        device: u32,
        device_key: &[u8; 32],
    ) -> Option<Agreement> {
        let t = self.transfers.get(cookie)?;
        if t.role != Role::Offerer || t.state != TState::Offered {
            return None;
        }
        self.offerer_agreement(t, eph, device, device_key)
    }

    fn keep_agreement(&mut self, cookie: &[u8; 8], ag: &Agreement) {
        if let Some(t) = self.transfers.get_mut(cookie) {
            if t.state == TState::Offered {
                t.agreement = Some(ag.clone());
                t.state = TState::Keyed;
                let l = format!(
                    "{}: keys agreed from the key hello (the answer through the chat had not come yet)",
                    t.label()
                );
                self.log.push(l);
            }
        }
    }

    fn plain_reason(&mut self, cookie: &[u8; 8]) -> Option<String> {
        match &self.transfers.get(cookie)?.state {
            TState::Plain(w) | TState::Blocked(w) => Some(w.clone()),
            _ => None,
        }
    }

    fn must_encrypt(&mut self, cookie: &[u8; 8]) -> bool {
        match self.transfers.get(cookie) {
            Some(t) => self.strict(&t.info) || matches!(t.state, TState::Blocked(_)),
            None => self.required,
        }
    }

    fn next_conn(&mut self, cookie: &[u8; 8]) -> u32 {
        match self.transfers.get_mut(cookie) {
            Some(t) => {
                t.conns += 1;
                t.conns
            }
            None => 1,
        }
    }

    fn report(&mut self, cookie: &[u8; 8], event: Event) {
        let Some(mut t) = self.transfers.remove(cookie) else {
            if let Event::Log(l) | Event::Plain(l) | Event::Failed(l) | Event::Blocked(l) = event {
                self.log
                    .push(format!("file transfer {}: {l}", files::cookie_tag(cookie)));
            }
            return;
        };
        let label = t.label();
        match event {
            Event::Log(l) => self.log.push(format!("{label}: {l}")),
            Event::Encrypted => {
                self.log.push(format!(
                    "{label}: the data connection is end-to-end encrypted"
                ));
                if t.told != Some(true) {
                    t.told = Some(true);
                    self.notes.push(Note::to(
                        &t.peer_name,
                        crate::policy::file_encrypted_note(&t.peer_name, t.info.verified),
                    ));
                }
            }
            Event::Plain(why) => {
                self.log.push(format!(
                    "{label}: the data connection goes unencrypted, untouched: {why}"
                ));
                if t.state != TState::Keyed {
                    self.go_plain(&mut t, &why);
                }
            }
            Event::Blocked(why) => {
                // Said, not decided: nothing on that connection was
                // authenticated, so it changes nothing about the transfer -
                // an outsider that connected first cannot make it plain, and
                // the real peer may still connect with its key hello.
                self.log.push(format!(
                    "{label}: a data connection was closed before anything was sent, since it \
                     would have gone unencrypted: {why}"
                ));
                self.say_blocked(&mut t, &why);
            }
            Event::Failed(why) => {
                self.log
                    .push(format!("{label}: the data connection was closed: {why}"));
                if !t.failed_told {
                    t.failed_told = true;
                    self.notes.push(Note::to(
                        &t.peer_name,
                        crate::policy::file_failed_note(&t.peer_name, &why),
                    ));
                }
            }
        }
        self.transfers.insert(*cookie, t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::proposal;
    use crate::filestream::{FilePipe, Phase};

    const A: &str = "100001";
    const B: &str = "100002";
    const T0: u64 = 1_790_000_000_000;
    const C: [u8; 8] = [0xC0, 0x0C, 1, 2, 3, 4, 5, 6];

    fn me(uin: &str, dev: u32, k: u8) -> Me {
        Me {
            uin: uin.to_string(),
            device: dev,
            key: [k; 32],
        }
    }

    fn go(m: Me) -> impl FnMut() -> Result<Me, String> {
        move || Ok(m.clone())
    }

    fn rdv(dir: Direction, peer: &str, seq: u16, port: u16) -> Rendezvous {
        files::rendezvous(
            dir,
            &proposal(
                dir,
                peer,
                C,
                seq,
                Ipv4Addr::new(192, 168, 1, 20),
                port,
                false,
            ),
        )
        .unwrap()
    }

    fn accept(dir: Direction, peer: &str) -> Rendezvous {
        files::rendezvous(
            dir,
            &files::tests::rdv_payload(dir, peer, RDV_ACCEPT, C, &[]),
        )
        .unwrap()
    }

    fn deliver(to: &mut FileTable, from: &str, dev: u32, payloads: Vec<Vec<u8>>) {
        for p in payloads {
            to.control(from, dev, Msg::decode(&p).expect("a file payload"), T0);
        }
    }

    fn see(t: &mut FileTable, r: &Rendezvous, m: Me) -> Vec<Vec<u8>> {
        t.observe(r, T0);
        t.icbm(r, PeerInfo::default(), &mut go(m), T0)
    }

    fn texts(t: &mut FileTable) -> Vec<String> {
        t.take_notes().into_iter().map(|n| n.text).collect()
    }

    /// The offer and the answer between two tables, as the Olm session
    /// would carry them; returns both, keyed.
    fn agreed() -> (FileTable, FileTable) {
        let (mut a, mut b) = (FileTable::default(), FileTable::default());
        let offer = see(&mut a, &rdv(Direction::Outbound, B, 1, 5190), me(A, 1, 1));
        assert_eq!(offer.len(), 1);
        deliver(&mut b, A, 1, offer);
        assert!(see(&mut b, &rdv(Direction::Inbound, A, 1, 5190), me(B, 2, 2)).is_empty());
        assert_eq!(b.state_of(&C), Some("keyed"));
        let answer = see(&mut b, &accept(Direction::Outbound, A), me(B, 2, 2));
        assert_eq!(answer.len(), 1, "the answer goes before the accept");
        deliver(&mut a, B, 2, answer);
        assert_eq!(a.state_of(&C), Some("keyed"));
        (a, b)
    }

    fn pipes_talk(a: &mut FileTable, b: &mut FileTable) -> (FilePipe, FilePipe) {
        let mut pa = FilePipe::new(C, Role::Offerer, false);
        let mut pb = FilePipe::new(C, Role::Answerer, false);
        pa.connected(a, T0);
        pb.connected(b, T0);
        let w = pb.take_wire();
        pa.feed(&w, a, T0);
        let w = pa.take_wire();
        pb.feed(&w, b, T0);
        (pa, pb)
    }

    #[test]
    fn payloads_round_trip_and_others_are_not_file_messages() {
        let msgs = [
            Msg::Offer {
                cookie: C,
                device: 7,
                device_key: [2; 32],
                eph: [3; 32],
                secret: [4; 32],
                suites: vec![1, 9],
            },
            Msg::Answer {
                cookie: C,
                device: 8,
                device_key: [5; 32],
                eph: [6; 32],
                suite: 1,
            },
            Msg::Decline {
                cookie: C,
                reason: 2,
            },
        ];
        for m in msgs {
            let mut b = m.encode();
            assert_eq!(Msg::decode(&b), Some(m.clone()));
            b.extend_from_slice(b"later fields");
            assert_eq!(Msg::decode(&b), Some(m));
        }
        assert_eq!(Msg::decode(b""), None);
        assert_eq!(Msg::decode(b"IQC1\x01"), None, "a call message");
        assert_eq!(Msg::decode(b"IQF1\x09"), None);
    }

    #[test]
    fn the_kdf_binds_every_input() {
        let p = |u, d, k| Party {
            uin: u,
            device: d,
            device_key: [k; 32],
        };
        let base = derive(
            &[1; 32],
            &[2; 32],
            &C,
            p(A, 1, 1),
            p(B, 2, 2),
            &[3; 32],
            &[4; 32],
        );
        let others = [
            derive(
                &[9; 32],
                &[2; 32],
                &C,
                p(A, 1, 1),
                p(B, 2, 2),
                &[3; 32],
                &[4; 32],
            ),
            derive(
                &[1; 32],
                &[9; 32],
                &C,
                p(A, 1, 1),
                p(B, 2, 2),
                &[3; 32],
                &[4; 32],
            ),
            derive(
                &[1; 32],
                &[2; 32],
                &[9; 8],
                p(A, 1, 1),
                p(B, 2, 2),
                &[3; 32],
                &[4; 32],
            ),
            derive(
                &[1; 32],
                &[2; 32],
                &C,
                p("100003", 1, 1),
                p(B, 2, 2),
                &[3; 32],
                &[4; 32],
            ),
            derive(
                &[1; 32],
                &[2; 32],
                &C,
                p(A, 9, 1),
                p(B, 2, 2),
                &[3; 32],
                &[4; 32],
            ),
            derive(
                &[1; 32],
                &[2; 32],
                &C,
                p(A, 1, 9),
                p(B, 2, 2),
                &[3; 32],
                &[4; 32],
            ),
            derive(
                &[1; 32],
                &[2; 32],
                &C,
                p(A, 1, 1),
                p(B, 9, 2),
                &[3; 32],
                &[4; 32],
            ),
            derive(
                &[1; 32],
                &[2; 32],
                &C,
                p(A, 1, 1),
                p(B, 2, 2),
                &[9; 32],
                &[4; 32],
            ),
            derive(
                &[1; 32],
                &[2; 32],
                &C,
                p(A, 1, 1),
                p(B, 2, 2),
                &[3; 32],
                &[9; 32],
            ),
            derive(
                &[1; 32],
                &[2; 32],
                &C,
                p(B, 2, 2),
                p(A, 1, 1),
                &[3; 32],
                &[4; 32],
            ),
        ];
        for (i, o) in others.iter().enumerate() {
            assert_ne!(o.root, base.root, "{i}");
            assert_ne!(o.confirm, base.confirm, "{i}");
        }
        assert_ne!(base.root, base.confirm);
    }

    #[test]
    fn both_on_agree_and_the_pipes_encrypt() {
        let (mut a, mut b) = agreed();
        assert_eq!(a.agreement(&C).unwrap().root, b.agreement(&C).unwrap().root);
        let (mut pa, mut pb) = pipes_talk(&mut a, &mut b);
        assert_eq!(
            (pa.phase(), pb.phase()),
            (Phase::Encrypted, Phase::Encrypted)
        );
        pa.write(b"OFT2 prompt", &mut a, T0).unwrap();
        let w = pa.take_wire();
        pb.feed(&w, &mut b, T0);
        let mut got = vec![0u8; pb.plaintext_len()];
        pb.take_plaintext(&mut got);
        assert_eq!(got, b"OFT2 prompt");
        for t in [&mut a, &mut b] {
            let n = texts(t);
            assert_eq!(n.len(), 1, "{n:?}");
            assert!(n[0].contains("is end-to-end encrypted"), "{n:?}");
        }
        // The sockets: B connects to A's proposal, A accepts on its port.
        assert_eq!(
            b.find_connect(Ipv4Addr::new(192, 168, 1, 20), 5190),
            Some(Found {
                cookie: C,
                role: Some(Role::Answerer),
                stage: "direct",
                blocked: None,
            })
        );
        assert_eq!(a.find_local(5190).unwrap().role, Some(Role::Offerer));
        assert_eq!(a.find_local(5191), None);
        assert_eq!(b.find_connect(Ipv4Addr::new(192, 168, 1, 21), 5190), None);
        assert_eq!(
            a.find_hello(&filestream::cookie_hash(&C)).unwrap().cookie,
            C
        );
    }

    /// The hello can come before the answer: the offerer derives from it,
    /// and the answer that follows agrees.
    #[test]
    fn the_hello_keys_the_offerer_before_the_answer_arrives() {
        let (mut a, mut b) = (FileTable::default(), FileTable::default());
        let offer = see(&mut a, &rdv(Direction::Outbound, B, 1, 5190), me(A, 1, 1));
        deliver(&mut b, A, 1, offer);
        see(&mut b, &rdv(Direction::Inbound, A, 1, 5190), me(B, 2, 2));
        assert_eq!(a.state_of(&C), Some("offered"));
        let (pa, pb) = pipes_talk(&mut a, &mut b);
        assert_eq!(
            (pa.phase(), pb.phase()),
            (Phase::Encrypted, Phase::Encrypted)
        );
        assert_eq!(a.state_of(&C), Some("keyed"));
        let answer = see(&mut b, &accept(Direction::Outbound, A), me(B, 2, 2));
        deliver(&mut a, B, 2, answer);
        assert!(a
            .take_log()
            .iter()
            .any(|l| l.contains("keys already agreed by the hello")));
    }

    /// A receiver without the add-on, with an older one, or with files off
    /// never answers: for a contact that is not strict, the sender's
    /// connection waits for the hello, then goes as it is; the note says why.
    #[test]
    fn a_peer_that_never_answers_gets_an_untouched_transfer() {
        let mut a = FileTable::default();
        let r = rdv(Direction::Outbound, B, 1, 5190);
        a.observe(&r, T0);
        assert_eq!(
            a.icbm(&r, PeerInfo::default(), &mut go(me(A, 1, 1)), T0)
                .len(),
            1
        );
        let mut pa = FilePipe::new(C, Role::Offerer, false);
        pa.connected(&mut a, T0);
        pa.write(b"OFT2 prompt", &mut a, T0).unwrap();
        pa.tick(&mut a, T0 + filestream::HELLO_WAIT_MS);
        assert_eq!(pa.phase(), Phase::Plain);
        assert_eq!(pa.take_wire(), b"OFT2 prompt");
        assert_eq!(a.state_of(&C), Some("plain"));
        let n = texts(&mut a);
        assert_eq!(n.len(), 1);
        assert!(
            n[0].contains("is not end-to-end encrypted") && n[0].contains("no key hello"),
            "{n:?}"
        );
        // A second connection (resume) does not wait again.
        assert_eq!(a.find_local(5190).unwrap().role, None);
    }

    fn strict() -> PeerInfo {
        PeerInfo {
            strict: true,
            verified: false,
        }
    }

    fn verified() -> PeerInfo {
        PeerInfo {
            strict: true,
            verified: true,
        }
    }

    /// Second audit of 2026-10, finding 4: a contact under `/e2e on`, or
    /// verified, whose add-on never answers (no add-on there, an older one,
    /// files off: no answer through the chat and no key hello): after the
    /// wait the connection is closed and not one held byte reaches the wire;
    /// the chat says the file was not sent, and why. It used to go plain.
    #[test]
    fn a_strict_contact_that_never_answers_gets_nothing_sent() {
        for (info, rule) in [(strict(), "/e2e on"), (verified(), "is verified")] {
            let mut a = FileTable::default();
            let r = rdv(Direction::Outbound, B, 1, 5190);
            a.observe(&r, T0);
            assert_eq!(a.icbm(&r, info, &mut go(me(A, 1, 1)), T0).len(), 1);
            let mut pa = FilePipe::new(C, Role::Offerer, false);
            pa.connected(&mut a, T0);
            pa.write(b"OFT2 prompt", &mut a, T0).unwrap();
            pa.tick(&mut a, T0 + filestream::HELLO_WAIT_MS);
            assert_eq!(pa.phase(), Phase::Failed, "{rule}");
            assert!(pa.take_wire().is_empty(), "{rule}: no byte on the wire");
            assert!(pa.write(b"file data", &mut a, T0).is_err());
            assert!(pa.take_wire().is_empty());
            let n = texts(&mut a);
            assert_eq!(n.len(), 1, "{n:?}");
            assert!(
                n[0].contains("was not sent") && n[0].contains(rule),
                "{rule}: {n:?}"
            );
            assert!(!n[0].contains("never blocked"));
            // Nothing on that connection was authenticated, so it decides
            // nothing: the transfer is still waiting for its answer.
            assert_eq!(a.state_of(&C), Some("offered"));
            assert_eq!(a.find_local(5190).unwrap().role, Some(Role::Offerer));
        }
    }

    /// A strict contact's add-on declines (`/e2e off` on its side): the
    /// transfer is not sent; every connection of it is refused.
    #[test]
    fn a_strict_contacts_decline_means_not_sent() {
        let (mut a, mut b) = (FileTable::default(), FileTable::default());
        let r = rdv(Direction::Outbound, B, 1, 5190);
        a.observe(&r, T0);
        let offer = a.icbm(&r, verified(), &mut go(me(A, 1, 1)), T0);
        deliver(&mut b, A, 1, offer);
        let rb = rdv(Direction::Inbound, A, 1, 5190);
        b.observe(&rb, T0);
        b.icbm(
            &rb,
            PeerInfo::default(),
            &mut || Err("encryption is off in this chat (/e2e off)".to_string()),
            T0,
        );
        let decline = see(&mut b, &accept(Direction::Outbound, A), me(B, 2, 2));
        deliver(&mut a, B, 2, decline);
        assert_eq!(a.state_of(&C), Some("blocked"));
        let n = texts(&mut a);
        assert!(
            n.len() == 1 && n[0].contains("was not sent") && n[0].contains("declined"),
            "{n:?}"
        );
        let f = a.find_local(5190).unwrap();
        assert_eq!(f.role, None);
        assert!(f.blocked.is_some(), "its sockets are refused");
        assert!(
            a.active(),
            "a blocked transfer's sockets are still looked at"
        );
        // A pipe made anyway (it was already waiting) closes at once.
        let mut pa = FilePipe::new(C, Role::Offerer, false);
        pa.connected(&mut a, T0);
        pa.write(b"OFT2 prompt", &mut a, T0).unwrap_err();
        assert_eq!(pa.phase(), Phase::Failed);
        assert!(pa.take_wire().is_empty());
    }

    /// The receiving side: a proposal from a strict contact, or with
    /// `files_encrypt = required` from anyone, that came without a key offer
    /// (the sender has no add-on) is not let through: the receiver's
    /// sockets of it are refused.
    #[test]
    fn a_proposal_without_an_offer_from_a_strict_contact_is_refused() {
        for required in [false, true] {
            let mut b = FileTable::default();
            b.set_required(required);
            let info = if required {
                PeerInfo::default()
            } else {
                verified()
            };
            let r = rdv(Direction::Inbound, A, 1, 5190);
            b.observe(&r, T0);
            b.icbm(&r, info, &mut go(me(B, 2, 2)), T0);
            assert_eq!(b.state_of(&C), Some("blocked"), "required={required}");
            let f = b
                .find_connect(Ipv4Addr::new(192, 168, 1, 20), 5190)
                .unwrap();
            assert_eq!((f.role, f.blocked.is_some()), (None, true));
            let n = texts(&mut b);
            assert!(n[0].contains("was not sent") && n[0].contains("did not offer"));
            assert_eq!(n[0].contains("files_encrypt = required"), required, "{n:?}");
        }
    }

    /// `files_encrypt = required`: every contact is strict - an offerer whose
    /// peer never answers sends nothing.
    #[test]
    fn with_files_required_a_transfer_that_did_not_agree_is_not_sent() {
        let mut a = FileTable::default();
        a.set_required(true);
        let r = rdv(Direction::Outbound, B, 1, 5190);
        a.observe(&r, T0);
        a.icbm(&r, PeerInfo::default(), &mut go(me(A, 1, 1)), T0);
        let mut pa = FilePipe::new(C, Role::Offerer, false);
        pa.connected(&mut a, T0);
        pa.write(b"OFT2 prompt", &mut a, T0).unwrap();
        pa.tick(&mut a, T0 + filestream::HELLO_WAIT_MS);
        assert_eq!(pa.phase(), Phase::Failed);
        assert!(pa.take_wire().is_empty());
        assert!(texts(&mut a)[0].contains("files_encrypt = required"));
        // And an agreed one with the same table is encrypted as ever.
        let (mut a, mut b) = agreed();
        a.set_required(true);
        b.set_required(true);
        let (pa, pb) = pipes_talk(&mut a, &mut b);
        assert_eq!(
            (pa.phase(), pb.phase()),
            (Phase::Encrypted, Phase::Encrypted)
        );
    }

    /// An outsider that reaches the offerer's listening port first (the
    /// accepted socket is matched only by its local port) and sends bytes
    /// that are no key hello cannot make a strict transfer plain: that
    /// connection is closed, nothing is sent on it, the transfer stays as it
    /// was, and the real peer's connection with its key hello is encrypted.
    /// The same for an agreed transfer, whoever it is with.
    #[test]
    fn an_early_unverified_connection_does_not_turn_a_transfer_plain() {
        // Strict, offered, no answer yet.
        let (mut a, mut b) = (FileTable::default(), FileTable::default());
        let r = rdv(Direction::Outbound, B, 1, 5190);
        a.observe(&r, T0);
        let offer = a.icbm(&r, strict(), &mut go(me(A, 1, 1)), T0);
        let mut early = FilePipe::new(C, Role::Offerer, false);
        early.connected(&mut a, T0);
        early.write(b"OFT2 prompt", &mut a, T0).unwrap();
        early.feed(b"OFT2 not a hello", &mut a, T0);
        assert_eq!(early.phase(), Phase::Failed);
        assert!(early.take_wire().is_empty(), "nothing went to the outsider");
        assert_eq!(early.plaintext_len(), 0);
        assert_eq!(a.state_of(&C), Some("offered"), "not plain");
        assert_eq!(a.find_local(5190).unwrap().role, Some(Role::Offerer));
        deliver(&mut b, A, 1, offer);
        see(&mut b, &rdv(Direction::Inbound, A, 1, 5190), me(B, 2, 2));
        let (pa, pb) = pipes_talk(&mut a, &mut b);
        assert_eq!(
            (pa.phase(), pb.phase()),
            (Phase::Encrypted, Phase::Encrypted)
        );
        // Agreed (not strict): the outsider's connection fails closed and
        // the transfer stays keyed.
        let (mut a, mut b) = agreed();
        let mut early = FilePipe::new(C, Role::Offerer, false);
        early.connected(&mut a, T0);
        early.take_wire();
        early.feed(b"OFT2 not a hello", &mut a, T0);
        assert_eq!(early.phase(), Phase::Failed);
        assert_eq!(a.state_of(&C), Some("keyed"));
        let (pa, _) = pipes_talk(&mut a, &mut b);
        assert_eq!(pa.phase(), Phase::Encrypted);
    }

    /// The sender has no add-on (or files off): no offer, the receiver's
    /// table says plain and never touches a socket.
    #[test]
    fn a_proposal_without_an_offer_is_plain() {
        let mut b = FileTable::default();
        see(&mut b, &rdv(Direction::Inbound, A, 1, 5190), me(B, 2, 2));
        assert_eq!(b.state_of(&C), Some("plain"));
        assert!(texts(&mut b)[0].contains("did not offer"));
        assert_eq!(
            b.find_connect(Ipv4Addr::new(192, 168, 1, 20), 5190)
                .unwrap()
                .role,
            None
        );
        assert!(!b.active());
    }

    /// `/e2e off` (or no keys) on the receiver: a decline before its accept;
    /// the sender goes plain at once.
    #[test]
    fn a_decline_makes_both_plain() {
        let (mut a, mut b) = (FileTable::default(), FileTable::default());
        let offer = see(&mut a, &rdv(Direction::Outbound, B, 1, 5190), me(A, 1, 1));
        deliver(&mut b, A, 1, offer);
        let r = rdv(Direction::Inbound, A, 1, 5190);
        b.observe(&r, T0);
        b.icbm(
            &r,
            PeerInfo::default(),
            &mut || Err("encryption is off in this chat (/e2e off)".to_string()),
            T0,
        );
        let decline = see(&mut b, &accept(Direction::Outbound, A), me(B, 2, 2));
        assert_eq!(decline.len(), 1);
        deliver(&mut a, B, 2, decline);
        assert_eq!(a.state_of(&C), Some("plain"));
        assert!(texts(&mut a)[0].contains("declined"));
        assert!(texts(&mut b)[0].contains("/e2e off"));
        assert_eq!(a.plain_reason(&C).is_some(), true);
    }

    /// A message for another transfer, from another contact, or naming
    /// another device changes nothing.
    #[test]
    fn mismatched_cookies_peers_and_devices_are_ignored() {
        let (mut a, mut b) = (FileTable::default(), FileTable::default());
        let offer = see(&mut a, &rdv(Direction::Outbound, B, 1, 5190), me(A, 1, 1));
        // The offer claims device 1 but came from device 3.
        deliver(&mut b, A, 3, offer.clone());
        see(&mut b, &rdv(Direction::Inbound, A, 1, 5190), me(B, 2, 2));
        assert_eq!(b.state_of(&C), Some("plain"));
        // An answer from someone else.
        let mut b2 = FileTable::default();
        deliver(&mut b2, A, 1, offer);
        see(&mut b2, &rdv(Direction::Inbound, A, 1, 5190), me(B, 2, 2));
        let answer = see(&mut b2, &accept(Direction::Outbound, A), me(B, 2, 2));
        deliver(&mut a, "100009", 2, answer.clone());
        assert_eq!(a.state_of(&C), Some("offered"));
        // An answer for another cookie.
        let mut other = Msg::decode(&answer[0]).unwrap();
        if let Msg::Answer { cookie, .. } = &mut other {
            *cookie = [9; 8];
        }
        a.control(B, 2, other, T0);
        assert_eq!(a.state_of(&C), Some("offered"));
        assert_eq!(a.state_of(&[9; 8]), None);
        // The real one.
        deliver(&mut a, B, 2, answer);
        assert_eq!(a.state_of(&C), Some("keyed"));
    }

    /// A resumed transfer: a new connection of the same cookie, with the
    /// counter-proposal's addresses (reverse stage), gets keys of its own.
    #[test]
    fn a_resumed_or_reverse_connection_is_found_and_keyed_again() {
        let (mut a, mut b) = agreed();
        // B listens: its counter-proposal (seq 2) goes out, A sees it.
        let counter = rdv(Direction::Outbound, A, 2, 6000);
        b.observe(&counter, T0);
        b.icbm(&counter, PeerInfo::default(), &mut go(me(B, 2, 2)), T0);
        let seen = rdv(Direction::Inbound, B, 2, 6000);
        a.observe(&seen, T0);
        a.icbm(&seen, PeerInfo::default(), &mut go(me(A, 1, 1)), T0);
        assert_eq!(b.find_local(6000).unwrap().stage, "reverse");
        assert_eq!(
            a.find_connect(Ipv4Addr::new(192, 168, 1, 20), 6000)
                .unwrap()
                .stage,
            "reverse"
        );
        let (pa1, _) = pipes_talk(&mut a, &mut b);
        let (pa2, _) = pipes_talk(&mut a, &mut b);
        assert_eq!(
            (pa1.phase(), pa2.phase()),
            (Phase::Encrypted, Phase::Encrypted)
        );
        // One note for the transfer, not one per connection.
        assert_eq!(texts(&mut a).len(), 1);
        // A cancel keeps the keys a while, then forgets them.
        let cancel = files::rendezvous(
            Direction::Inbound,
            &files::tests::rdv_payload(Direction::Inbound, B, RDV_CANCEL, C, &[]),
        )
        .unwrap();
        a.icbm(&cancel, PeerInfo::default(), &mut go(me(A, 1, 1)), T0);
        assert!(a.agreement(&C).is_some());
        a.tick(T0 + ENDED_GRACE_MS);
        assert_eq!(a.state_of(&C), None);
    }

    /// A failure on an agreed connection says so in the chat, once.
    #[test]
    fn a_failed_connection_is_said_once() {
        let (mut a, _) = agreed();
        texts(&mut a);
        a.report(&C, Event::Failed("a record did not authenticate".into()));
        a.report(&C, Event::Failed("again".into()));
        let n = texts(&mut a);
        assert_eq!(n.len(), 1);
        assert!(
            n[0].contains("stopped") && n[0].contains("did not authenticate"),
            "{n:?}"
        );
    }
}
