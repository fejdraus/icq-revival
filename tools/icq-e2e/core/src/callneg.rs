//! Agreeing on the keys of a call (stages C1 and C3 of
//! `docs/e2e/CALLS-RESEARCH.md`), and which datagrams belong to an agreed
//! call.
//!
//! Only with `calls_encrypt = on` (off by default). Off, nothing here runs:
//! no control message is sent, an incoming one is taken as the old add-on
//! takes any control message, and the call media is never looked at for
//! encryption.
//!
//! The exchange rides the existing Olm session as hidden control messages
//! (`container.rs`, kind 0): an old add-on reads one as an ordinary control
//! message, advances its ratchet and shows nothing. The payload starts with
//! [`MAGIC`]; the server sees only an encrypted message and relays it.
//!
//! ```text
//! caller (A)                                         callee (B)
//! OUT Offer {call, device, device key, eph A, sdp A hash, suites}
//! OUT INVITE (the client's own, untouched)  ------>  IN offer, IN INVITE
//!                                                    OUT Answer {call, device, device key, eph B, sdp B hash, suite}
//! IN Answer: keys, Agreed               <------      OUT 200 OK (untouched): keys, Answered
//! IN 200 OK: "encrypted" note
//! OUT Confirm {call, tag}               ------>      IN Confirm: Agreed, "encrypted" note
//! OUT ACK (untouched)
//! ```
//!
//! Every control message goes on the wire *before* the SIP message it
//! belongs to, on the same connection, and the server relays the two in
//! order: so when the callee sees the INVITE it already knows whether there
//! was an offer, and when the caller sees the 200 OK it already knows whether
//! there was an answer. That makes the decision the same on both sides
//! without a timer:
//!
//! - No offer when the callee answers (the caller has no add-on, an older
//!   one, call encryption off, or no session with us): plain.
//! - No answer when the caller sees the 200 OK (the callee has no add-on,
//!   an older one, call encryption off): plain.
//! - A decline (the callee's add-on refuses, e.g. `/e2e off` for the
//!   caller): plain, with its reason.
//!
//! Plain is the call exactly as today: no datagram of it is ever touched.
//!
//! The callee encrypts from its 200 OK on, but it holds the call as
//! *answered* until the caller proves it has the same keys: the Confirm tag,
//! or simply the first media packet that decrypts. Should neither come within
//! [`CONFIRM_TIMEOUT_MS`] (the answer was lost, so the caller went plain),
//! the callee goes plain too and says so - never a call where one side
//! encrypts and the other does not.
//!
//! Keys: each side an ephemeral X25519 key per call, HKDF over the shared
//! secret bound to the Call-ID, both UINs and both devices
//! ([`crate::callmedia::derive`]). The Olm session authenticates the
//! ephemeral keys, and so the keys are as trusted as the chat (the safety
//! number). Keys are dropped at BYE (after a short grace for trailing
//! packets) or when the call is given up.
//!
//! Policy (C3, audit 2026-10, finding 8): "encryption is on for this
//! contact" means the same for calls as for text. With `calls_encrypt = on`,
//! a call with a contact under `/e2e on` or verified that did not agree on
//! keys is not let through; with any other contact it goes plain, with a
//! note. `calls_encrypt = required` makes every contact strict. A call that
//! is not let through has its RTP and RTCP, bare or in TURN framing, dropped
//! both ways, so nothing of it is heard in clear; STUN and TURN control
//! still pass, so a call that does agree can set up. The chat says why.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;

use crate::callmedia::{self, Media, Party, Verdict, SUITE_AES128GCM};
use crate::crypto::Note;
use crate::icbm::Direction;
use crate::sign;
use crate::snac::Reader;

/// What a call control payload starts with, inside the control envelope.
pub const MAGIC: &[u8; 4] = b"IQC1";
/// The suites this build offers and accepts.
pub const SUITES: [u8; 1] = [SUITE_AES128GCM];

const T_OFFER: u8 = 1;
const T_ANSWER: u8 = 2;
const T_CONFIRM: u8 = 3;
const T_DECLINE: u8 = 4;

/// Decline reasons.
pub const DECLINE_REFUSED: u8 = 1;
pub const DECLINE_NO_SUITE: u8 = 2;

/// How long an offer waits for its INVITE.
pub const OFFER_TTL_MS: u64 = 60_000;
/// How long a call that is not set up yet is kept.
pub const SETUP_TTL_MS: u64 = 180_000;
/// How long the callee waits for the caller's confirmation.
pub const CONFIRM_TIMEOUT_MS: u64 = 8_000;
/// How long an ended call's keys are kept for packets still on the way.
pub const ENDED_GRACE_MS: u64 = 10_000;
/// A call nobody has heard of for this long is forgotten.
pub const IDLE_TTL_MS: u64 = 4 * 3600 * 1000;
/// Offers kept for INVITEs not seen yet.
const MAX_OFFERS: usize = 16;

// --- SIP ----------------------------------------------------------------------------

/// The first line of a SIP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    Request(String),
    Response { code: u16, method: String },
}

/// What negotiation needs of a SIP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sip {
    pub start: Start,
    pub call_id: String,
    pub sdp: Option<String>,
}

impl Sip {
    /// Reads a SIP message; `None` without a start line or a Call-ID.
    pub fn parse(raw: &[u8]) -> Option<Sip> {
        let text = String::from_utf8_lossy(raw);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.split("\r\n");
        let first = lines.next()?;
        let mut call_id = None;
        let mut cseq_method = None;
        let mut sdp_type = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "call-id" | "i" => call_id = Some(value.to_string()),
                "cseq" => cseq_method = value.split_whitespace().nth(1).map(str::to_string),
                "content-type" | "c" => {
                    sdp_type = value.to_ascii_lowercase().starts_with("application/sdp")
                }
                _ => {}
            }
        }
        let start = if let Some(rest) = first.strip_prefix("SIP/2.0 ") {
            Start::Response {
                code: rest.split_whitespace().next()?.parse().ok()?,
                method: cseq_method.unwrap_or_default(),
            }
        } else if first.ends_with("SIP/2.0") {
            Start::Request(first.split(' ').next()?.to_string())
        } else {
            return None;
        };
        let sdp = (sdp_type || body.starts_with("v=0"))
            .then(|| body.to_string())
            .filter(|b| !b.is_empty());
        Some(Sip {
            start,
            call_id: call_id?,
            sdp,
        })
    }
}

/// The Call-ID's SHA-256: bound into the keys, and its first 16 bytes name
/// the call in the control messages (its first 4 are the `call=` of the log,
/// as in the C0 lines).
pub fn call_digest(call_id: &str) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, call_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn short(d: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// The first 16 bytes of an SDP's SHA-256 (zeros for none).
pub fn sdp_hash(sdp: Option<&str>) -> [u8; 16] {
    match sdp {
        Some(s) => short(ring::digest::digest(&ring::digest::SHA256, s.as_bytes()).as_ref()),
        None => [0; 16],
    }
}

/// The local ports an SDP of ours names: each `m=` port and the one after it
/// (RTCP), `a=rtcp:`, and the ports of host candidates and the base (`rport`)
/// of the others - where the client's media sockets are bound.
pub fn local_ports(sdp: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in sdp.lines() {
        let line = line.trim_end();
        if let Some(m) = line.strip_prefix("m=") {
            if let Some(p) = m
                .split_whitespace()
                .nth(1)
                .and_then(|p| p.parse::<u16>().ok())
            {
                if p != 0 {
                    ports.insert(p);
                    ports.insert(p.wrapping_add(1));
                }
            }
        } else if let Some(r) = line.strip_prefix("a=rtcp:") {
            if let Some(p) = r.split_whitespace().next().and_then(|p| p.parse().ok()) {
                ports.insert(p);
            }
        } else if let Some(c) = line.strip_prefix("a=candidate:") {
            let f: Vec<&str> = c.split_whitespace().collect();
            if f.len() >= 8 && f[6] == "typ" {
                if f[7] == "host" {
                    if let Ok(p) = f[5].parse() {
                        ports.insert(p);
                    }
                } else if let Some(i) = f.iter().position(|w| *w == "rport") {
                    if let Some(p) = f.get(i + 1).and_then(|p| p.parse().ok()) {
                        ports.insert(p);
                    }
                }
            }
        }
    }
    ports
}

// --- the control payloads -------------------------------------------------------------

/// A call control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Offer {
        call: [u8; 16],
        device: u32,
        device_key: [u8; 32],
        eph: [u8; 32],
        sdp: [u8; 16],
        suites: Vec<u8>,
    },
    Answer {
        call: [u8; 16],
        device: u32,
        device_key: [u8; 32],
        eph: [u8; 32],
        sdp: [u8; 16],
        suite: u8,
    },
    Confirm {
        call: [u8; 16],
        tag: [u8; 16],
    },
    Decline {
        call: [u8; 16],
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
                call,
                device,
                device_key,
                eph,
                sdp,
                suites,
            } => {
                b.push(T_OFFER);
                b.extend_from_slice(call);
                b.extend_from_slice(&device.to_be_bytes());
                b.extend_from_slice(device_key);
                b.extend_from_slice(eph);
                b.extend_from_slice(sdp);
                b.push(suites.len() as u8);
                b.extend_from_slice(suites);
            }
            Msg::Answer {
                call,
                device,
                device_key,
                eph,
                sdp,
                suite,
            } => {
                b.push(T_ANSWER);
                b.extend_from_slice(call);
                b.extend_from_slice(&device.to_be_bytes());
                b.extend_from_slice(device_key);
                b.extend_from_slice(eph);
                b.extend_from_slice(sdp);
                b.push(*suite);
            }
            Msg::Confirm { call, tag } => {
                b.push(T_CONFIRM);
                b.extend_from_slice(call);
                b.extend_from_slice(tag);
            }
            Msg::Decline { call, reason } => {
                b.push(T_DECLINE);
                b.extend_from_slice(call);
                b.push(*reason);
            }
        }
        b
    }

    /// Reads a payload; `None` for anything that is not a call control
    /// message of this version (an empty control message, a newer one).
    /// Bytes after the known fields are left for a later version.
    pub fn decode(b: &[u8]) -> Option<Msg> {
        let rest = b.strip_prefix(MAGIC.as_slice())?;
        let mut r = Reader::new(rest);
        let t = r.u8()?;
        let call = arr::<16>(&mut r)?;
        Some(match t {
            T_OFFER => {
                let device = r.u32()?;
                let device_key = arr::<32>(&mut r)?;
                let eph = arr::<32>(&mut r)?;
                let sdp = arr::<16>(&mut r)?;
                let n = r.u8()? as usize;
                Msg::Offer {
                    call,
                    device,
                    device_key,
                    eph,
                    sdp,
                    suites: r.bytes(n)?.to_vec(),
                }
            }
            T_ANSWER => Msg::Answer {
                call,
                device: r.u32()?,
                device_key: arr::<32>(&mut r)?,
                eph: arr::<32>(&mut r)?,
                sdp: arr::<16>(&mut r)?,
                suite: r.u8()?,
            },
            T_CONFIRM => Msg::Confirm {
                call,
                tag: arr::<16>(&mut r)?,
            },
            T_DECLINE => Msg::Decline {
                call,
                reason: r.u8()?,
            },
            _ => return None,
        })
    }

    pub fn call(&self) -> [u8; 16] {
        match self {
            Msg::Offer { call, .. }
            | Msg::Answer { call, .. }
            | Msg::Confirm { call, .. }
            | Msg::Decline { call, .. } => *call,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Msg::Offer { .. } => "offer",
            Msg::Answer { .. } => "answer",
            Msg::Confirm { .. } => "confirm",
            Msg::Decline { .. } => "decline",
        }
    }
}

// --- the table of calls -----------------------------------------------------------------

/// This device, as the key derivation binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Me {
    /// Our UIN, normalised.
    pub uin: String,
    pub device: u32,
    /// The device's Curve25519 identity key.
    pub key: [u8; 32],
}

/// What the user's settings say about the contact, for the words of a note.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerInfo {
    /// `/e2e on` by hand, or verified: a plain call is said in strong words.
    pub strict: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Caller,
    Callee,
}

/// An offer as it arrived.
#[derive(Debug, Clone)]
struct Offered {
    device: u32,
    device_key: [u8; 32],
    eph: [u8; 32],
    sdp: [u8; 16],
    suites: Vec<u8>,
}

enum State {
    /// Caller: the offer is out, no answer yet.
    OfferSent(Option<EphemeralPrivateKey>),
    /// Callee: the INVITE is in; the offer, if one came.
    Invited(Option<Offered>),
    /// Callee: the answer is out, the keys are in use, the caller has not
    /// proved it has them yet.
    Answered { since: u64 },
    /// Both sides have the keys.
    Agreed,
    /// Not encrypted: the call's media is never touched.
    Plain,
    /// BYE or a final failure; the keys stay for [`ENDED_GRACE_MS`].
    Ended { at: u64 },
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::OfferSent(_) => "offer sent",
            State::Invited(_) => "invited",
            State::Answered { .. } => "answered",
            State::Agreed => "agreed",
            State::Plain => "plain",
            State::Ended { .. } => "ended",
        }
    }
}

struct Call {
    hash: [u8; 16],
    digest: [u8; 32],
    /// The contact as the client names them, and normalised.
    peer_name: String,
    peer: String,
    role: Role,
    state: State,
    /// Our media sockets' local ports, from our SDP.
    ports: BTreeSet<u16>,
    created: u64,
    touched: u64,
    info: PeerInfo,
    me: Option<Me>,
    my_eph: [u8; 32],
    media: Option<Media>,
    /// The SDP hash the other add-on put in its control message.
    peer_sdp: Option<[u8; 16]>,
    /// The confirmation the callee expects.
    expect_confirm: Option<[u8; 16]>,
    /// Payloads waiting for the next outbound frame to the peer.
    outbox: Vec<Vec<u8>>,
    /// Whether the note for this call was given (true: encrypted).
    told: Option<bool>,
    logged_out: bool,
    logged_in: bool,
    logged_drop: bool,
    logged_mtu: bool,
}

impl Call {
    fn new(sip: &Sip, peer: &str, role: Role, info: PeerInfo, now: u64) -> Call {
        let digest = call_digest(&sip.call_id);
        Call {
            hash: short(&digest),
            digest,
            peer_name: peer.to_string(),
            peer: sign::ident(peer),
            role,
            state: State::Plain,
            ports: BTreeSet::new(),
            created: now,
            touched: now,
            info,
            me: None,
            my_eph: [0; 32],
            media: None,
            peer_sdp: None,
            expect_confirm: None,
            outbox: Vec::new(),
            told: None,
            logged_out: false,
            logged_in: false,
            logged_drop: false,
            logged_mtu: false,
        }
    }

    fn label(&self) -> String {
        let h: String = self.digest[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "call {h} with {} ({})",
            self.peer_name,
            match self.role {
                Role::Caller => "we call",
                Role::Callee => "they call",
            }
        )
    }
}

struct PendingOffer {
    peer: String,
    offered: Offered,
    at: u64,
}

/// Every call the add-on knows of, its state and its media keys.
pub struct CallTable {
    calls: HashMap<[u8; 16], Call>,
    offers: HashMap<[u8; 16], PendingOffer>,
    notes: Vec<Note>,
    log: Vec<String>,
    rng: SystemRandom,
    /// `calls_encrypt = required`: every contact is strict - the media of a
    /// call that did not agree on keys is dropped, never let through plain.
    required: bool,
}

impl Default for CallTable {
    fn default() -> Self {
        CallTable {
            calls: HashMap::new(),
            offers: HashMap::new(),
            notes: Vec::new(),
            log: Vec::new(),
            rng: SystemRandom::new(),
            required: false,
        }
    }
}

/// The note for a call that is not let through: `required` says the ini
/// lets no unencrypted call through; otherwise encryption is on for the
/// contact (`/e2e on`, or verified), for calls as for messages.
fn blocked_note(peer: &str, why: &str, required: bool, verified: bool) -> String {
    let why = why.trim_end_matches('.');
    let rule = if required {
        "calls_encrypt = required in icq-e2e.ini lets no other call through".to_string()
    } else if verified {
        format!("{peer} is verified, so a call with them is encrypted or not let through, as messages are")
    } else {
        format!("encryption is on for {peer} in this chat (/e2e on), for calls as for messages")
    };
    format!(
        "{}This call with {peer} is not let through: it is not end-to-end encrypted ({why}), and {rule} - neither side hears the other. Hang up.",
        crate::policy::PREFIX
    )
}

/// The table the hooks and the session share.
pub fn shared() -> Arc<Mutex<CallTable>> {
    static T: std::sync::LazyLock<Arc<Mutex<CallTable>>> =
        std::sync::LazyLock::new(|| Arc::new(Mutex::new(CallTable::default())));
    T.clone()
}

/// The `603 Decline` for an incoming INVITE that was not let through
/// (sixth audit of 2026-10, finding 3), as an ICBM on channel 6 to `peer`
/// (SNAC payload, request id 0), so the caller's client stops ringing. The
/// response takes the INVITE's Via headers, From, To (with a tag of ours if
/// it has none), Call-ID and CSeq, as RFC 3261 8.2.6 asks. `None` for
/// anything that is not an INVITE with those headers.
pub fn decline_to_host(peer: &str, invite: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(invite);
    let head = text.split("\r\n\r\n").next()?;
    let mut lines = head.split("\r\n");
    if !lines.next()?.starts_with("INVITE ") {
        return None;
    }
    let (mut vias, mut from, mut to, mut call_id, mut cseq) = (Vec::new(), None, None, None, None);
    for l in lines {
        let Some((name, _)) = l.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "via" | "v" => vias.push(l),
            "from" | "f" => from = Some(l),
            "to" | "t" => to = Some(l),
            "call-id" | "i" => call_id = Some(l),
            "cseq" => cseq = Some(l),
            _ => {}
        }
    }
    let (from, to, call_id, cseq) = (from?, to?, call_id?, cseq?);
    if vias.is_empty() {
        return None;
    }
    let mut tag = [0u8; 4];
    getrandom::fill(&mut tag).ok()?;
    let to = if to.to_ascii_lowercase().contains(";tag=") {
        to.to_string()
    } else {
        let t: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        format!("{to};tag=e2e{t}")
    };
    let mut sip = String::from("SIP/2.0 603 Decline\r\n");
    for v in vias {
        sip.push_str(v);
        sip.push_str("\r\n");
    }
    for h in [from, &to, call_id, cseq] {
        sip.push_str(h);
        sip.push_str("\r\n");
    }
    sip.push_str("Content-Length: 0\r\n\r\n");
    let mut cookie = [0u8; 8];
    getrandom::fill(&mut cookie).ok()?;
    let name = &peer.as_bytes()[..peer.len().min(255)];
    let mut p = crate::snac::FOOD_ICBM.to_be_bytes().to_vec();
    p.extend_from_slice(&crate::snac::ICBM_MSG_TO_HOST.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    p.extend_from_slice(&cookie);
    p.extend_from_slice(&crate::calls::CHANNEL_SIP.to_be_bytes());
    p.push(name.len() as u8);
    p.extend_from_slice(name);
    crate::snac::put_tlv(&mut p, crate::calls::TLV_SIP, sip.as_bytes());
    Some(p)
}

/// The Call-ID of an INVITE request, `None` for any other SIP message.
pub fn invite_call_id(sip: &[u8]) -> Option<String> {
    let s = Sip::parse(sip)?;
    matches!(&s.start, Start::Request(m) if m == "INVITE").then_some(s.call_id)
}

/// The words for why a call goes plain.
pub mod why {
    pub fn no_offer(peer: &str) -> String {
        format!("{peer} did not offer to encrypt it (no E2E add-on there, an older one, or call encryption off)")
    }
    pub fn no_answer(peer: &str) -> String {
        format!("{peer}'s add-on did not answer the key exchange (no E2E add-on there, an older one, or call encryption off)")
    }
    pub fn declined(peer: &str, reason: u8) -> String {
        match reason {
            super::DECLINE_NO_SUITE => {
                format!("{peer}'s add-on has no call cipher in common with this one")
            }
            _ => format!("{peer}'s add-on declined to encrypt it (encryption is off for this chat on their side)"),
        }
    }
    pub fn unconfirmed(peer: &str) -> String {
        format!("{peer}'s add-on never confirmed the call keys")
    }
}

impl CallTable {
    /// A SIP message of a call to or from `peer` (ICBM channel 6), in `dir`.
    /// Returns the control payloads to send to `peer` *before* that message
    /// goes on: an offer before our INVITE, an answer or decline before our
    /// 200 OK, a waiting confirmation before anything else. `me` is asked only
    /// when this device is about to take part in a key exchange; it says who
    /// we are, or why this call must not be encrypted.
    pub fn sip(
        &mut self,
        dir: Direction,
        peer: &str,
        sip: &Sip,
        info: PeerInfo,
        me: &mut dyn FnMut() -> Result<Me, String>,
        now: u64,
    ) -> Vec<Vec<u8>> {
        let h = short(&call_digest(&sip.call_id));
        let mut out = Vec::new();
        if let Some(c) = self.calls.get_mut(&h) {
            if c.peer != sign::ident(peer) {
                // Same Call-ID, another contact: not ours to touch.
                return out;
            }
            c.touched = now;
            c.info = info;
        }
        let invite_response = |code: u16| matches!(&sip.start, Start::Response { code: c, method } if *c == code && method.eq_ignore_ascii_case("INVITE"));
        match (dir, &sip.start) {
            (Direction::Outbound, Start::Request(m)) if m == "INVITE" => {
                if let Some(c) = self.calls.get_mut(&h) {
                    if let Some(s) = &sip.sdp {
                        c.ports.extend(local_ports(s));
                    }
                } else {
                    self.caller_invites(peer, sip, info, me, now, &mut out);
                }
            }
            (Direction::Inbound, Start::Request(m)) if m == "INVITE" => {
                if !self.calls.contains_key(&h) {
                    let mut c = Call::new(sip, peer, Role::Callee, info, now);
                    let offer = self
                        .offers
                        .remove(&h)
                        .filter(|o| o.peer == c.peer)
                        .map(|o| o.offered);
                    self.log.push(format!(
                        "{}: INVITE in, {}",
                        c.label(),
                        if offer.is_some() {
                            "with a key offer"
                        } else {
                            "without a key offer"
                        }
                    ));
                    c.state = State::Invited(offer);
                    self.calls.insert(h, c);
                }
            }
            (Direction::Outbound, Start::Response { code, .. })
                if (200..300).contains(code) && invite_response(*code) =>
            {
                self.callee_answers(h, sip, me, now, &mut out);
            }
            (Direction::Inbound, Start::Response { code, .. })
                if (200..300).contains(code) && invite_response(*code) =>
            {
                self.caller_sees_ok(h, sip);
            }
            (_, Start::Response { code, .. }) if *code >= 300 && invite_response(*code) => {
                self.end(h, now, &format!("{code} to the INVITE"));
            }
            (_, Start::Request(m)) if m == "BYE" || m == "CANCEL" => {
                self.end(h, now, m);
            }
            _ => {}
        }
        if dir == Direction::Outbound {
            if let Some(c) = self.calls.get_mut(&h) {
                out.append(&mut c.outbox);
            }
        }
        out
    }

    fn caller_invites(
        &mut self,
        peer: &str,
        sip: &Sip,
        info: PeerInfo,
        me: &mut dyn FnMut() -> Result<Me, String>,
        now: u64,
        out: &mut Vec<Vec<u8>>,
    ) {
        let mut c = Call::new(sip, peer, Role::Caller, info, now);
        if let Some(s) = &sip.sdp {
            c.ports = local_ports(s);
        }
        match me() {
            Err(why) => {
                self.log
                    .push(format!("{}: INVITE out, not encrypted: {why}", c.label()));
                self.go_plain(&mut c, &why);
            }
            Ok(m) => match EphemeralPrivateKey::generate(&X25519, &self.rng)
                .and_then(|k| k.compute_public_key().map(|p| (k, p)))
            {
                Ok((k, p)) => {
                    c.my_eph.copy_from_slice(p.as_ref());
                    out.push(
                        Msg::Offer {
                            call: c.hash,
                            device: m.device,
                            device_key: m.key,
                            eph: c.my_eph,
                            sdp: sdp_hash(sip.sdp.as_deref()),
                            suites: SUITES.to_vec(),
                        }
                        .encode(),
                    );
                    c.me = Some(m);
                    c.state = State::OfferSent(Some(k));
                    self.log.push(format!(
                        "{}: INVITE out, key offer sent first (local media ports {:?})",
                        c.label(),
                        c.ports
                    ));
                }
                Err(_) => {
                    let why = "no ephemeral key could be made".to_string();
                    self.log.push(format!("{}: {why}", c.label()));
                    self.go_plain(&mut c, &why);
                }
            },
        }
        self.calls.insert(c.hash, c);
    }

    fn callee_answers(
        &mut self,
        h: [u8; 16],
        sip: &Sip,
        me: &mut dyn FnMut() -> Result<Me, String>,
        now: u64,
        out: &mut Vec<Vec<u8>>,
    ) {
        let Some(mut c) = self.calls.remove(&h) else {
            return;
        };
        if c.role != Role::Callee {
            self.calls.insert(h, c);
            return;
        }
        if let Some(s) = &sip.sdp {
            c.ports.extend(local_ports(s));
        }
        let offer = match &mut c.state {
            State::Invited(o) => o.take(),
            // A 200 OK to a re-INVITE: the call goes on as it is.
            _ => {
                self.calls.insert(h, c);
                return;
            }
        };
        let label = c.label();
        match offer {
            None => {
                let why = why::no_offer(&c.peer_name);
                self.log
                    .push(format!("{label}: answered, not encrypted: {why}"));
                self.go_plain(&mut c, &why);
            }
            Some(o) if !o.suites.contains(&SUITE_AES128GCM) => {
                out.push(
                    Msg::Decline {
                        call: h,
                        reason: DECLINE_NO_SUITE,
                    }
                    .encode(),
                );
                let why = format!(
                    "{}'s add-on offered no call cipher this one has",
                    c.peer_name
                );
                self.log.push(format!("{label}: declined: {why}"));
                self.go_plain(&mut c, &why);
            }
            Some(o) => match me() {
                Err(why) => {
                    out.push(
                        Msg::Decline {
                            call: h,
                            reason: DECLINE_REFUSED,
                        }
                        .encode(),
                    );
                    self.log.push(format!("{label}: declined: {why}"));
                    self.go_plain(&mut c, &why);
                }
                Ok(m) => {
                    let agreed = EphemeralPrivateKey::generate(&X25519, &self.rng).and_then(|k| {
                        let p = k.compute_public_key()?;
                        let mut mine = [0u8; 32];
                        mine.copy_from_slice(p.as_ref());
                        let caller = Party {
                            uin: &c.peer,
                            device: o.device,
                            device_key: o.device_key,
                            eph: o.eph,
                        };
                        let callee = Party {
                            uin: &m.uin,
                            device: m.device,
                            device_key: m.key,
                            eph: mine,
                        };
                        let digest = c.digest;
                        agreement::agree_ephemeral(
                            k,
                            &UnparsedPublicKey::new(&X25519, o.eph),
                            |shared| callmedia::derive(shared, &digest, &caller, &callee),
                        )
                        .map(|keys| (keys, mine))
                    });
                    match agreed {
                        Ok((keys, mine)) => {
                            c.expect_confirm = Some(callmedia::confirm_tag(&keys, &h));
                            c.media = Some(Media::new(keys, false));
                            c.my_eph = mine;
                            c.peer_sdp = Some(o.sdp);
                            out.push(
                                Msg::Answer {
                                    call: h,
                                    device: m.device,
                                    device_key: m.key,
                                    eph: mine,
                                    sdp: sdp_hash(sip.sdp.as_deref()),
                                    suite: SUITE_AES128GCM,
                                }
                                .encode(),
                            );
                            c.me = Some(m);
                            c.state = State::Answered { since: now };
                            self.log.push(format!(
                                "{label}: answered; key answer sent first; media keys in use, \
                                 waiting for the caller to confirm (local media ports {:?})",
                                c.ports
                            ));
                        }
                        Err(_) => {
                            let why = "the key agreement failed".to_string();
                            self.log.push(format!("{label}: {why}"));
                            self.go_plain(&mut c, &why);
                        }
                    }
                }
            },
        }
        self.calls.insert(h, c);
    }

    fn caller_sees_ok(&mut self, h: [u8; 16], sip: &Sip) {
        let Some(mut c) = self.calls.remove(&h) else {
            return;
        };
        if c.role == Role::Caller {
            let label = c.label();
            match c.state {
                State::OfferSent(_) => {
                    let why = why::no_answer(&c.peer_name);
                    self.log
                        .push(format!("{label}: 200 OK in, not encrypted: {why}"));
                    self.go_plain(&mut c, &why);
                }
                State::Agreed => {
                    if c.peer_sdp
                        .is_some_and(|s| s != sdp_hash(sip.sdp.as_deref()))
                    {
                        self.log.push(format!(
                            "{label}: WARNING the SDP of the 200 OK is not the one the callee's add-on saw; \
                             the media stays encrypted"
                        ));
                    }
                    self.log.push(format!(
                        "{label}: 200 OK in, the call is end-to-end encrypted"
                    ));
                    self.say_encrypted(&mut c);
                }
                _ => {}
            }
        }
        self.calls.insert(h, c);
    }

    /// Whether an incoming INVITE with `call_id` in `peer`'s name is vouched
    /// for end to end (sixth audit of 2026-10, finding 3): the key offer
    /// `peer`'s add-on sends before its INVITE has come over the Olm session
    /// and waits for it, or the call is one already set up with `peer` (a
    /// re-INVITE). Nothing is consumed: the INVITE takes the offer itself
    /// when it goes on ([`Self::sip`]).
    pub fn vouched(&self, peer: &str, call_id: &str) -> bool {
        let h = short(&call_digest(call_id));
        let p = sign::ident(peer);
        self.calls.get(&h).is_some_and(|c| c.peer == p)
            || self.offers.get(&h).is_some_and(|o| o.peer == p)
    }

    /// A call control message from `peer`, sent by its device `sender`.
    pub fn control(&mut self, peer: &str, sender: u32, msg: Msg, now: u64) {
        let p = sign::ident(peer);
        let h = msg.call();
        let what = msg.name();
        let Some(mut c) = self.calls.remove(&h) else {
            if let Msg::Offer {
                device,
                device_key,
                eph,
                sdp,
                suites,
                ..
            } = msg
            {
                if device != sender {
                    self.log.push(format!(
                        "call key offer from {peer} ignored: it names another device"
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
                    h,
                    PendingOffer {
                        peer: p,
                        offered: Offered {
                            device,
                            device_key,
                            eph,
                            sdp,
                            suites,
                        },
                        at: now,
                    },
                );
            } else {
                self.log.push(format!(
                    "call key {what} from {peer} for a call not known here: ignored"
                ));
            }
            return;
        };
        let label = c.label();
        if c.peer != p {
            self.log.push(format!(
                "{label}: key {what} from {peer}, not the peer: ignored"
            ));
            self.calls.insert(h, c);
            return;
        }
        c.touched = now;
        match (msg, &mut c.state, c.role) {
            (
                Msg::Offer {
                    device,
                    device_key,
                    eph,
                    sdp,
                    suites,
                    ..
                },
                State::Invited(slot @ None),
                Role::Callee,
            ) if device == sender => {
                self.log
                    .push(format!("{label}: key offer arrived after the INVITE"));
                *slot = Some(Offered {
                    device,
                    device_key,
                    eph,
                    sdp,
                    suites,
                });
            }
            (
                Msg::Answer {
                    device,
                    device_key,
                    eph,
                    sdp,
                    suite,
                    ..
                },
                State::OfferSent(key),
                Role::Caller,
            ) if device == sender && suite == SUITE_AES128GCM && key.is_some() => {
                let k = key.take().expect("checked");
                let me = c.me.clone().expect("an offer was made");
                let caller = Party {
                    uin: &me.uin,
                    device: me.device,
                    device_key: me.key,
                    eph: c.my_eph,
                };
                let callee = Party {
                    uin: &c.peer,
                    device,
                    device_key,
                    eph,
                };
                let digest = c.digest;
                match agreement::agree_ephemeral(k, &UnparsedPublicKey::new(&X25519, eph), |s| {
                    callmedia::derive(s, &digest, &caller, &callee)
                }) {
                    Ok(keys) => {
                        let tag = callmedia::confirm_tag(&keys, &h);
                        c.media = Some(Media::new(keys, true));
                        c.peer_sdp = Some(sdp);
                        c.state = State::Agreed;
                        c.outbox.push(Msg::Confirm { call: h, tag }.encode());
                        self.log.push(format!(
                            "{label}: key answer in; media keys agreed (AES-128-GCM), confirmation queued"
                        ));
                    }
                    Err(_) => {
                        let why = "the key agreement failed".to_string();
                        self.log.push(format!("{label}: {why}"));
                        self.go_plain(&mut c, &why);
                    }
                }
            }
            (Msg::Confirm { tag, .. }, State::Answered { .. } | State::Agreed, Role::Callee) => {
                let ok = c
                    .expect_confirm
                    .is_some_and(|e| callmedia::same_tag(&e, &tag));
                if !ok {
                    let why =
                        "the caller's add-on has other keys (the confirmation does not match)"
                            .to_string();
                    self.log.push(format!("{label}: {why}"));
                    self.go_plain(&mut c, &why);
                } else if matches!(c.state, State::Answered { .. }) {
                    c.state = State::Agreed;
                    self.log.push(format!(
                        "{label}: the caller confirmed the keys; the call is end-to-end encrypted"
                    ));
                    self.say_encrypted(&mut c);
                }
            }
            (Msg::Decline { reason, .. }, State::OfferSent(_), Role::Caller) => {
                let why = why::declined(&c.peer_name, reason);
                self.log.push(format!("{label}: declined: {why}"));
                self.go_plain(&mut c, &why);
            }
            (m, s, _) => {
                self.log.push(format!(
                    "{label}: key {} in state {}: ignored",
                    m.name(),
                    s.name()
                ));
            }
        }
        self.calls.insert(h, c);
    }

    /// A payload [`Self::sip`] gave could not be sent (no session, the
    /// directory unreachable...): the call it was for goes plain.
    pub fn send_failed(&mut self, payload: &[u8], why: &str) {
        let Some(msg) = Msg::decode(payload) else {
            return;
        };
        let h = msg.call();
        let Some(mut c) = self.calls.remove(&h) else {
            return;
        };
        let label = c.label();
        self.log
            .push(format!("{label}: key {} not sent: {why}", msg.name()));
        match msg {
            Msg::Offer { .. } | Msg::Answer { .. } => {
                let w = format!("the key exchange could not be sent ({why})");
                self.go_plain(&mut c, &w);
            }
            _ => {}
        }
        self.calls.insert(h, c);
    }

    /// One payload waiting for the next outbound frame to `peer`.
    pub fn take_outbox(&mut self, peer: &str) -> Option<Vec<u8>> {
        let p = sign::ident(peer);
        self.calls
            .values_mut()
            .find(|c| c.peer == p && !c.outbox.is_empty())
            .map(|c| c.outbox.remove(0))
    }

    /// The call is over: keys kept a moment for trailing packets, or the
    /// call forgotten at once if it had none.
    fn end(&mut self, h: [u8; 16], now: u64, what: &str) {
        let Some(mut c) = self.calls.remove(&h) else {
            return;
        };
        if matches!(c.state, State::Ended { .. }) {
            self.calls.insert(h, c);
            return;
        }
        let label = c.label();
        if c.media.is_some() {
            self.log.push(format!(
                "{label}: {what}; keys kept {} s for packets on the way",
                ENDED_GRACE_MS / 1000
            ));
            c.state = State::Ended { at: now };
            self.calls.insert(h, c);
        } else {
            self.log
                .push(format!("{label}: {what}; was {}", c.state.name()));
        }
    }

    /// Switches the strict level on or off (`calls_encrypt = required`).
    pub fn set_required(&mut self, on: bool) {
        self.required = on;
    }

    /// Whether the strict level is on: no call's media goes plain.
    pub fn required(&self) -> bool {
        self.required
    }

    /// Whether a call with this contact must be encrypted or not let
    /// through: `calls_encrypt = required`, or a contact under `/e2e on` or
    /// verified.
    fn strict(&self, info: &PeerInfo) -> bool {
        self.required || info.strict
    }

    /// Whether media that no agreed call covers is dropped rather than
    /// passed: with `calls_encrypt = required`, or while a call with a strict
    /// contact is set up or went without keys. The client makes one call at
    /// a time, so all such media is that call's.
    pub fn blocks_plain(&self) -> bool {
        self.required
            || self.calls.values().any(|c| {
                c.info.strict && c.media.is_none() && !matches!(c.state, State::Ended { .. })
            })
    }

    /// A datagram no agreed call covers: passed as it is, or dropped when it
    /// carries media and a strict call is in progress.
    fn unagreed(&mut self, d: &[u8]) -> Verdict {
        if self.blocks_plain() && callmedia::split(d).is_some() {
            return Verdict::Drop("the call did not agree on keys and must be encrypted");
        }
        Verdict::Pass
    }

    fn go_plain(&mut self, c: &mut Call, why: &str) {
        if let Some(m) = &c.media {
            self.log.push(format!(
                "{}: keys dropped; media so far: {}",
                c.label(),
                m.stats.describe()
            ));
        }
        c.state = State::Plain;
        c.media = None;
        c.outbox.clear();
        if c.told != Some(false) {
            c.told = Some(false);
            let note = if self.strict(&c.info) {
                self.log.push(format!(
                    "{}: not encrypted, so its media is dropped ({})",
                    c.label(),
                    if self.required {
                        "calls_encrypt=required"
                    } else {
                        "encryption is on for the contact"
                    }
                ));
                blocked_note(&c.peer_name, why, self.required, c.info.verified)
            } else {
                crate::policy::call_plain_note(&c.peer_name, why, c.info.strict)
            };
            self.notes.push(Note::to(&c.peer_name, note));
        }
    }

    fn say_encrypted(&mut self, c: &mut Call) {
        if c.told.is_none() {
            c.told = Some(true);
            self.notes.push(Note::to(
                &c.peer_name,
                crate::policy::call_encrypted_note(&c.peer_name, c.info.verified),
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

    /// Timers: the callee's wait for confirmation, the grace after a call,
    /// offers and calls that never got anywhere.
    pub fn tick(&mut self, now: u64) {
        self.offers
            .retain(|_, o| now.saturating_sub(o.at) < OFFER_TTL_MS);
        self.expire_confirm(now);
        let done: Vec<[u8; 16]> = self
            .calls
            .iter()
            .filter(|(_, c)| match c.state {
                State::Ended { at } => now.saturating_sub(at) >= ENDED_GRACE_MS,
                State::OfferSent(_) | State::Invited(_) => {
                    now.saturating_sub(c.created) >= SETUP_TTL_MS
                }
                _ => now.saturating_sub(c.touched) >= IDLE_TTL_MS,
            })
            .map(|(h, _)| *h)
            .collect();
        for h in done {
            if let Some(c) = self.calls.remove(&h) {
                let media = c
                    .media
                    .as_ref()
                    .map(|m| format!("; media: {}", m.stats.describe()))
                    .unwrap_or_default();
                self.log.push(format!(
                    "{}: forgotten ({}){media}",
                    c.label(),
                    c.state.name()
                ));
            }
        }
    }

    fn expire_confirm(&mut self, now: u64) {
        let late: Vec<[u8; 16]> = self
            .calls
            .iter()
            .filter(|(_, c)| {
                matches!(c.state, State::Answered { since } if now.saturating_sub(since) >= CONFIRM_TIMEOUT_MS)
            })
            .map(|(h, _)| *h)
            .collect();
        for h in late {
            if let Some(mut c) = self.calls.remove(&h) {
                let why = why::unconfirmed(&c.peer_name);
                self.log.push(format!(
                    "{}: {why} in {} s",
                    c.label(),
                    CONFIRM_TIMEOUT_MS / 1000
                ));
                self.go_plain(&mut c, &why);
                self.calls.insert(h, c);
            }
        }
    }

    /// Whether any call has media keys: only then is a datagram looked at.
    pub fn keyed(&self) -> bool {
        self.calls.values().any(|c| c.media.is_some())
    }

    /// Whether a datagram on local port `port` belongs to a call with keys:
    /// a port of its SDP, or any port while exactly one call has keys (the
    /// client makes one call at a time; its sockets may be bound to ports the
    /// SDP does not name, behind ICE and TURN).
    pub fn covers(&self, port: u16) -> bool {
        self.find(port).is_some()
    }

    fn find(&self, port: u16) -> Option<[u8; 16]> {
        let keyed: Vec<&Call> = self.calls.values().filter(|c| c.media.is_some()).collect();
        keyed
            .iter()
            .find(|c| c.ports.contains(&port))
            .or_else(|| (keyed.len() == 1).then(|| &keyed[0]))
            .map(|c| c.hash)
    }

    /// A datagram the client sends from local port `port`.
    pub fn media_out(&mut self, port: u16, d: &[u8], now: u64) -> Verdict {
        self.expire_confirm(now);
        let Some(h) = self.find(port) else {
            return self.unagreed(d);
        };
        let c = self.calls.get_mut(&h).expect("found");
        c.touched = now;
        let label = c.label();
        let m = c.media.as_mut().expect("keyed");
        let before = m.stats;
        let v = m.outbound(d);
        let after = m.stats;
        match &v {
            Verdict::Replace(e) if !c.logged_out => {
                c.logged_out = true;
                self.log.push(format!(
                    "{label}: first media packet encrypted (local port {port}, {} B -> {} B)",
                    d.len(),
                    e.len()
                ));
            }
            Verdict::Drop(why) if !c.logged_drop => {
                c.logged_drop = true;
                self.log
                    .push(format!("{label}: outbound packet dropped: {why}"));
            }
            _ => {}
        }
        if after.over_mtu > before.over_mtu && !c.logged_mtu {
            c.logged_mtu = true;
            self.log.push(format!(
                "{label}: an encrypted datagram of {} B is over {} B of UDP payload; sent unfragmented by us",
                after.max_out,
                callmedia::MAX_UDP_PAYLOAD
            ));
        }
        v
    }

    /// A datagram that arrived for local port `port`.
    pub fn media_in(&mut self, port: u16, d: &[u8], now: u64) -> Verdict {
        self.expire_confirm(now);
        let Some(h) = self.find(port) else {
            return self.unagreed(d);
        };
        let mut c = self.calls.remove(&h).expect("found");
        c.touched = now;
        let label = c.label();
        let m = c.media.as_mut().expect("keyed");
        let v = m.inbound(d);
        let failed = m.stats.plain_dropped + m.stats.auth_failed + m.stats.replayed;
        match &v {
            Verdict::Replace(_) => {
                if !c.logged_in {
                    c.logged_in = true;
                    self.log.push(format!(
                        "{label}: first media packet decrypted (local port {port})"
                    ));
                }
                if matches!(c.state, State::Answered { .. }) {
                    // Only the caller's keys open it: as good as its Confirm.
                    c.state = State::Agreed;
                    self.log.push(format!(
                        "{label}: the caller's media decrypts; the call is end-to-end encrypted"
                    ));
                    self.say_encrypted(&mut c);
                }
            }
            Verdict::Drop(why) if failed == 1 || failed.is_multiple_of(500) => {
                self.log.push(format!(
                    "{label}: inbound packet dropped: {why} ({failed} so far)"
                ));
            }
            _ => {}
        }
        self.calls.insert(h, c);
        v
    }

    /// The state of a call by its Call-ID, for tests and the log.
    pub fn state_of(&self, call_id: &str) -> Option<&'static str> {
        self.calls
            .get(&short(&call_digest(call_id)))
            .map(|c| c.state.name())
    }

    /// The media counters of a call by its Call-ID.
    pub fn stats_of(&self, call_id: &str) -> Option<callmedia::Stats> {
        self.calls
            .get(&short(&call_digest(call_id)))
            .and_then(|c| c.media.as_ref().map(|m| m.stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "100001";
    const B: &str = "100002";
    const T0: u64 = 1_790_000_000_000;

    fn me(uin: &str, dev: u32, k: u8) -> Me {
        Me {
            uin: uin.to_string(),
            device: dev,
            key: [k; 32],
        }
    }

    fn invite(call_id: &str, port: u16) -> Sip {
        Sip::parse(
            format!(
                "INVITE sip:{B}@198.51.100.7:5061 SIP/2.0\r\nCall-Id: {call_id}\r\nCSeq: 1 INVITE\r\n\
                 Content-Type: application/sdp\r\n\r\nv=0\r\nm=audio {port} RTP/AVP 103\r\n\
                 a=candidate:1 1 UDP 0.9 192.168.1.20 {} typ host\r\n",
                port + 10
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn ok(call_id: &str, port: u16) -> Sip {
        Sip::parse(
            format!(
                "SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\n\
                 v=0\r\nm=audio {port} RTP/AVP 103\r\n"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn req(method: &str, call_id: &str, n: u32) -> Sip {
        Sip::parse(
            format!("{method} sip:x@h SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: {n} {method}\r\n\r\n")
                .as_bytes(),
        )
        .unwrap()
    }

    fn go(m: Me) -> impl FnMut() -> Result<Me, String> {
        move || Ok(m.clone())
    }

    fn rtp(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut p = vec![0x80, 103];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]);
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[0x5A; 60]);
        p
    }

    /// Hands control payloads from one table to the other, as the Olm
    /// session would (device 1 is A's, 2 is B's).
    fn deliver(to: &mut CallTable, from_peer: &str, dev: u32, payloads: Vec<Vec<u8>>, now: u64) {
        for p in payloads {
            to.control(
                from_peer,
                dev,
                Msg::decode(&p).expect("a call payload"),
                now,
            );
        }
    }

    /// The whole set-up between two add-ons with calls on; returns both
    /// tables with the call agreed.
    fn agreed(call: &str) -> (CallTable, CallTable) {
        let (mut a, mut b) = (CallTable::default(), CallTable::default());
        let info = PeerInfo::default();
        let offer = a.sip(
            Direction::Outbound,
            B,
            &invite(call, 16384),
            info,
            &mut go(me(A, 1, 1)),
            T0,
        );
        assert_eq!(offer.len(), 1);
        deliver(&mut b, A, 1, offer, T0);
        assert!(b
            .sip(
                Direction::Inbound,
                A,
                &invite(call, 16384),
                info,
                &mut go(me(B, 2, 2)),
                T0
            )
            .is_empty());
        let answer = b.sip(
            Direction::Outbound,
            A,
            &ok(call, 20000),
            info,
            &mut go(me(B, 2, 2)),
            T0 + 5,
        );
        assert_eq!(answer.len(), 1);
        assert_eq!(b.state_of(call), Some("answered"));
        deliver(&mut a, B, 2, answer, T0 + 6);
        assert_eq!(a.state_of(call), Some("agreed"));
        a.sip(
            Direction::Inbound,
            B,
            &ok(call, 20000),
            info,
            &mut go(me(A, 1, 1)),
            T0 + 6,
        );
        let confirm = a.sip(
            Direction::Outbound,
            B,
            &req("ACK", call, 1),
            info,
            &mut go(me(A, 1, 1)),
            T0 + 7,
        );
        assert_eq!(confirm.len(), 1, "the confirmation rides before the ACK");
        deliver(&mut b, A, 1, confirm, T0 + 8);
        assert_eq!(b.state_of(call), Some("agreed"));
        (a, b)
    }

    fn texts(t: &mut CallTable) -> Vec<String> {
        t.take_notes().into_iter().map(|n| n.text).collect()
    }

    #[test]
    fn sip_parse_and_ports() {
        let s = invite("abc@h", 16384);
        assert_eq!(s.start, Start::Request("INVITE".into()));
        assert_eq!(s.call_id, "abc@h");
        let p = local_ports(s.sdp.as_deref().unwrap());
        assert_eq!(p.into_iter().collect::<Vec<_>>(), vec![16384, 16385, 16394]);
        let o = ok("abc@h", 20000);
        assert_eq!(
            o.start,
            Start::Response {
                code: 200,
                method: "INVITE".into()
            }
        );
        let relay = "m=audio 49170 RTP/AVP 0\r\na=rtcp:49171\r\n\
                     a=candidate:3 1 UDP 0.5 203.0.113.5 49170 typ relay raddr 192.168.1.20 rport 16384\r\n";
        let p: Vec<u16> = local_ports(relay).into_iter().collect();
        assert_eq!(p, vec![16384, 49170, 49171]);
        assert!(Sip::parse(b"hello").is_none());
        assert!(
            Sip::parse(b"BYE sip:x SIP/2.0\r\nCSeq: 2 BYE\r\n\r\n").is_none(),
            "no Call-ID"
        );
    }

    #[test]
    fn payloads_round_trip_and_unknown_ones_are_not_calls() {
        let msgs = [
            Msg::Offer {
                call: [1; 16],
                device: 7,
                device_key: [2; 32],
                eph: [3; 32],
                sdp: [4; 16],
                suites: vec![1, 9],
            },
            Msg::Answer {
                call: [1; 16],
                device: 8,
                device_key: [5; 32],
                eph: [6; 32],
                sdp: [7; 16],
                suite: 1,
            },
            Msg::Confirm {
                call: [1; 16],
                tag: [8; 16],
            },
            Msg::Decline {
                call: [1; 16],
                reason: 2,
            },
        ];
        for m in msgs {
            let mut b = m.encode();
            assert_eq!(Msg::decode(&b), Some(m.clone()));
            b.extend_from_slice(b"later fields");
            assert_eq!(Msg::decode(&b), Some(m), "room for a later version");
        }
        assert_eq!(Msg::decode(b""), None, "the empty control message");
        assert_eq!(Msg::decode(b"IQC1\x09"), None);
        assert_eq!(Msg::decode(b"IQC2\x01"), None);
        assert_eq!(
            Msg::decode(
                &Msg::Confirm {
                    call: [1; 16],
                    tag: [8; 16]
                }
                .encode()[..20]
            ),
            None
        );
    }

    #[test]
    fn both_add_ons_agree_and_media_round_trips() {
        let call = "both@h";
        let (mut a, mut b) = agreed(call);
        let na = texts(&mut a);
        let nb = texts(&mut b);
        assert_eq!(na.len(), 1);
        assert!(na[0].contains("is end-to-end encrypted"), "{na:?}");
        assert!(nb[0].contains("is end-to-end encrypted"), "{nb:?}");
        // A -> B and B -> A, with loss and reordering.
        let sent: Vec<Vec<u8>> = (0..20u16)
            .map(|s| match a.media_out(16384, &rtp(s, 0xA), T0 + 100) {
                Verdict::Replace(e) => e,
                v => panic!("{v:?}"),
            })
            .collect();
        for i in [1usize, 0, 3, 2, 7, 19, 10] {
            match b.media_in(20000, &sent[i], T0 + 200) {
                Verdict::Replace(p) => assert_eq!(p, rtp(i as u16, 0xA)),
                v => panic!("{i}: {v:?}"),
            }
        }
        assert!(
            matches!(b.media_in(20000, &sent[3], T0 + 200), Verdict::Drop(_)),
            "replay"
        );
        let back = match b.media_out(20000, &rtp(1, 0xB), T0 + 300) {
            Verdict::Replace(e) => e,
            v => panic!("{v:?}"),
        };
        assert_eq!(
            a.media_in(16384, &back, T0 + 300),
            Verdict::Replace(rtp(1, 0xB))
        );
        // Downgrade: plain RTP in the agreed call is dropped.
        assert!(matches!(
            a.media_in(16384, &rtp(2, 0xB), T0 + 300),
            Verdict::Drop(_)
        ));
        // STUN on the same socket passes.
        let stun = [
            0u8, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ];
        assert_eq!(a.media_out(16384, &stun, T0), Verdict::Pass);
        // BYE: keys kept for the grace, then forgotten.
        a.sip(
            Direction::Outbound,
            B,
            &req("BYE", call, 2),
            PeerInfo::default(),
            &mut go(me(A, 1, 1)),
            T0 + 1000,
        );
        assert_eq!(a.state_of(call), Some("ended"));
        assert!(matches!(
            a.media_out(16384, &rtp(30, 0xA), T0 + 1001),
            Verdict::Replace(_)
        ));
        a.tick(T0 + 1000 + ENDED_GRACE_MS);
        assert_eq!(a.state_of(call), None);
        assert!(!a.keyed());
        assert_eq!(
            a.media_out(16384, &rtp(31, 0xA), T0 + 20_000),
            Verdict::Pass
        );
        assert!(a
            .take_log()
            .iter()
            .any(|l| l.contains("forgotten (ended); media: out: 21 RTP")));
    }

    #[test]
    fn a_callee_without_the_add_on_or_with_calls_off_gets_a_plain_call() {
        // B never answers: no add-on, an old one, or calls_encrypt off (which
        // takes the offer as an ordinary control message).
        let call = "plainB@h";
        let mut a = CallTable::default();
        let info = PeerInfo {
            strict: true,
            verified: true,
        };
        let offer = a.sip(
            Direction::Outbound,
            B,
            &invite(call, 16384),
            info,
            &mut go(me(A, 1, 1)),
            T0,
        );
        assert_eq!(offer.len(), 1);
        assert!(a
            .sip(
                Direction::Inbound,
                B,
                &ok(call, 20000),
                info,
                &mut go(me(A, 1, 1)),
                T0 + 3000
            )
            .is_empty());
        assert_eq!(a.state_of(call), Some("plain"));
        let n = texts(&mut a);
        assert_eq!(n.len(), 1);
        assert!(
            n[0].contains("not end-to-end encrypted") && n[0].contains("did not answer"),
            "{n:?}"
        );
        // A verified contact is strict: the call is not let through (audit
        // 2026-10, finding 8).
        assert!(
            n[0].contains("not let through") && n[0].contains("is verified"),
            "strict wording: {n:?}"
        );
        assert!(!a.keyed());
        let p = rtp(1, 1);
        assert!(matches!(
            a.media_out(16384, &p, T0 + 4000),
            Verdict::Drop(_)
        ));
        assert!(matches!(a.media_in(16384, &p, T0 + 4000), Verdict::Drop(_)));
        // An answer that comes late changes nothing.
        let mut b = CallTable::default();
        deliver(&mut b, A, 1, offer, T0);
        b.sip(
            Direction::Inbound,
            A,
            &invite(call, 16384),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        let late = b.sip(
            Direction::Outbound,
            A,
            &ok(call, 20000),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        deliver(&mut a, B, 2, late, T0 + 5000);
        assert_eq!(a.state_of(call), Some("plain"));
        // And B, never confirmed and never decrypting, goes plain itself.
        assert_eq!(b.state_of(call), Some("answered"));
        assert!(matches!(b.media_in(20000, &p, T0 + 100), Verdict::Drop(_)));
        b.tick(T0 + CONFIRM_TIMEOUT_MS);
        assert_eq!(b.state_of(call), Some("plain"));
        let n = texts(&mut b);
        assert!(
            n[0].contains("never confirmed") && n[0].contains("not let through"),
            "{n:?}"
        );
        // B's side is strict too (the same contact info): held back, not plain.
        assert!(matches!(b.media_in(20000, &p, T0 + 9000), Verdict::Drop(_)));
        assert!(matches!(
            b.media_out(20000, &p, T0 + 9000),
            Verdict::Drop(_)
        ));
    }

    /// Audit 2026-10, finding 8: with `calls_encrypt = required` a call that
    /// did not agree on keys is not let through - its media is dropped both
    /// ways, the chat says why - while STUN still passes and an agreed call
    /// is encrypted as with `on`.
    #[test]
    fn with_calls_required_a_call_that_did_not_agree_is_not_let_through() {
        let call = "strict@h";
        let mut a = CallTable::default();
        a.set_required(true);
        let info = PeerInfo::default();
        a.sip(
            Direction::Outbound,
            B,
            &invite(call, 16384),
            info,
            &mut go(me(A, 1, 1)),
            T0,
        );
        // No answer: B has no add-on, or calls off.
        a.sip(
            Direction::Inbound,
            B,
            &ok(call, 20000),
            info,
            &mut go(me(A, 1, 1)),
            T0 + 3000,
        );
        assert_eq!(a.state_of(call), Some("plain"));
        let n = texts(&mut a);
        assert!(
            n.len() == 1 && n[0].contains("not let through") && n[0].contains("did not answer"),
            "{n:?}"
        );
        let p = rtp(1, 1);
        assert!(matches!(
            a.media_out(16384, &p, T0 + 4000),
            Verdict::Drop(_)
        ));
        assert!(matches!(a.media_in(16384, &p, T0 + 4000), Verdict::Drop(_)));
        // Media on a port no call named, too: nothing plain at all.
        assert!(matches!(
            a.media_out(40000, &p, T0 + 4000),
            Verdict::Drop(_)
        ));
        // STUN is no media and passes, so a call can still set up.
        let mut stun = vec![0x00, 0x01, 0x00, 0x00];
        stun.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        stun.extend_from_slice(&[7; 12]);
        assert_eq!(a.media_out(16384, &stun, T0 + 4000), Verdict::Pass);

        // A callee with the strict level and no offer: the same.
        let mut b = CallTable::default();
        b.set_required(true);
        b.sip(
            Direction::Inbound,
            A,
            &invite("strict2@h", 16384),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        b.sip(
            Direction::Outbound,
            A,
            &ok("strict2@h", 20000),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        assert!(texts(&mut b)[0].contains("not let through"));
        assert!(matches!(b.media_in(20000, &p, T0), Verdict::Drop(_)));

        // `on` stays the level that never blocks.
        let mut c = CallTable::default();
        assert!(!c.required());
        assert_eq!(c.media_out(16384, &p, T0), Verdict::Pass);
    }

    /// With `calls_encrypt = on`: a contact under `/e2e on`, or verified, is
    /// strict - its unencrypted call is not let through; a plain contact's
    /// call goes plain with a note; once the strict call is over, nothing is
    /// held back any more.
    #[test]
    fn with_calls_on_a_strict_contact_is_blocked_and_a_plain_one_is_not() {
        let p = rtp(1, 1);
        for (what, info, blocked) in [
            (
                "/e2e on",
                PeerInfo {
                    strict: true,
                    verified: false,
                },
                true,
            ),
            (
                "verified",
                PeerInfo {
                    strict: true,
                    verified: true,
                },
                true,
            ),
            ("plain contact", PeerInfo::default(), false),
        ] {
            let call = format!("on-{what}@h");
            let mut a = CallTable::default();
            a.sip(
                Direction::Outbound,
                B,
                &invite(&call, 16384),
                info,
                &mut go(me(A, 1, 1)),
                T0,
            );
            a.sip(
                Direction::Inbound,
                B,
                &ok(&call, 20000),
                info,
                &mut go(me(A, 1, 1)),
                T0 + 3000,
            );
            assert_eq!(a.state_of(&call), Some("plain"), "{what}");
            let n = texts(&mut a);
            assert_eq!(n.len(), 1, "{what}: {n:?}");
            assert_eq!(n[0].contains("not let through"), blocked, "{what}: {n:?}");
            assert!(n[0].contains("not end-to-end encrypted"), "{what}: {n:?}");
            assert_eq!(a.blocks_plain(), blocked, "{what}");
            assert_eq!(
                matches!(a.media_out(16384, &p, T0 + 4000), Verdict::Drop(_)),
                blocked,
                "{what}"
            );
            assert_eq!(
                matches!(a.media_in(16384, &p, T0 + 4000), Verdict::Drop(_)),
                blocked,
                "{what}"
            );
            // BYE: the call is over and media is no longer held back.
            a.sip(
                Direction::Outbound,
                B,
                &req("BYE", &call, 2),
                info,
                &mut go(me(A, 1, 1)),
                T0 + 5000,
            );
            assert!(!a.blocks_plain(), "{what}");
            assert_eq!(a.media_out(16384, &p, T0 + 6000), Verdict::Pass, "{what}");
        }
    }

    /// An agreed call is encrypted under the strict level as under `on`.
    #[test]
    fn with_calls_required_an_agreed_call_is_encrypted() {
        let (mut a, mut b) = agreed("strict-ok@h");
        a.set_required(true);
        b.set_required(true);
        let e = match a.media_out(16384, &rtp(1, 0xA), T0 + 10) {
            Verdict::Replace(e) => e,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            b.media_in(20000, &e, T0 + 10),
            Verdict::Replace(rtp(1, 0xA))
        );
    }

    #[test]
    fn a_caller_without_the_add_on_or_with_calls_off_gets_a_plain_call() {
        let call = "plainA@h";
        let mut b = CallTable::default();
        let info = PeerInfo::default();
        b.sip(
            Direction::Inbound,
            A,
            &invite(call, 16384),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        assert_eq!(b.state_of(call), Some("invited"));
        let out = b.sip(
            Direction::Outbound,
            A,
            &ok(call, 20000),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        assert!(
            out.is_empty(),
            "nothing is sent to a caller that offered nothing"
        );
        assert_eq!(b.state_of(call), Some("plain"));
        let n = texts(&mut b);
        assert!(
            n[0].contains("did not offer") && !n[0].contains("never blocked"),
            "{n:?}"
        );
        assert_eq!(b.media_in(20000, &rtp(1, 1), T0), Verdict::Pass);
    }

    #[test]
    fn our_own_refusal_or_missing_session_is_plain_with_the_reason() {
        let call = "refuse@h";
        let mut a = CallTable::default();
        let mut no =
            || Err::<Me, String>("100002 has no encryption keys in the key directory".into());
        let out = a.sip(
            Direction::Outbound,
            B,
            &invite(call, 16384),
            PeerInfo::default(),
            &mut no,
            T0,
        );
        assert!(out.is_empty(), "no offer without a session");
        assert_eq!(a.state_of(call), Some("plain"));
        assert!(texts(&mut a)[0].contains("has no encryption keys"));

        // The callee refuses (e.g. /e2e off for the caller): a decline, and
        // the caller says why.
        let call = "decline@h";
        let (mut a, mut b) = (CallTable::default(), CallTable::default());
        let offer = a.sip(
            Direction::Outbound,
            B,
            &invite(call, 16384),
            PeerInfo::default(),
            &mut go(me(A, 1, 1)),
            T0,
        );
        deliver(&mut b, A, 1, offer, T0);
        b.sip(
            Direction::Inbound,
            A,
            &invite(call, 16384),
            PeerInfo::default(),
            &mut go(me(B, 2, 2)),
            T0,
        );
        let mut off = || Err::<Me, String>("encryption is off in this chat (/e2e off)".into());
        let decline = b.sip(
            Direction::Outbound,
            A,
            &ok(call, 20000),
            PeerInfo::default(),
            &mut off,
            T0,
        );
        assert_eq!(decline.len(), 1);
        deliver(&mut a, B, 2, decline, T0);
        assert_eq!(a.state_of(call), Some("plain"));
        assert!(texts(&mut a)[0].contains("declined"));
        assert!(texts(&mut b)[0].contains("/e2e off"));
    }

    #[test]
    fn a_mismatched_call_id_or_peer_is_ignored() {
        let (mut a, mut b) = (CallTable::default(), CallTable::default());
        let info = PeerInfo::default();
        let offer = a.sip(
            Direction::Outbound,
            B,
            &invite("one@h", 16384),
            info,
            &mut go(me(A, 1, 1)),
            T0,
        );
        deliver(&mut b, A, 1, offer, T0);
        // B's client gets another call; the offer for "one@h" does not apply.
        b.sip(
            Direction::Inbound,
            A,
            &invite("two@h", 16384),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        let out = b.sip(
            Direction::Outbound,
            A,
            &ok("two@h", 20000),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        assert!(out.is_empty());
        assert_eq!(b.state_of("two@h"), Some("plain"));
        // An answer from someone who is not the callee is ignored.
        let mut c = CallTable::default();
        let fake = {
            let o = a.sip(
                Direction::Outbound,
                B,
                &invite("three@h", 16384),
                info,
                &mut go(me(A, 1, 1)),
                T0,
            );
            deliver(&mut c, A, 1, o, T0);
            c.sip(
                Direction::Inbound,
                A,
                &invite("three@h", 1),
                info,
                &mut go(me("100003", 3, 3)),
                T0,
            );
            c.sip(
                Direction::Outbound,
                A,
                &ok("three@h", 1),
                info,
                &mut go(me("100003", 3, 3)),
                T0,
            )
        };
        deliver(&mut a, "100003", 3, fake, T0);
        assert_eq!(a.state_of("three@h"), Some("offer sent"));
        // An offer naming another device than the one that sent it is ignored.
        let mut d = CallTable::default();
        let o = a.sip(
            Direction::Outbound,
            B,
            &invite("four@h", 16384),
            info,
            &mut go(me(A, 1, 1)),
            T0,
        );
        deliver(&mut d, A, 99, o, T0);
        d.sip(
            Direction::Inbound,
            A,
            &invite("four@h", 1),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        assert!(d
            .sip(
                Direction::Outbound,
                A,
                &ok("four@h", 1),
                info,
                &mut go(me(B, 2, 2)),
                T0
            )
            .is_empty());
    }

    #[test]
    fn the_callee_counts_the_first_decrypted_packet_as_confirmation() {
        let call = "implicit@h";
        let (mut a, mut b) = (CallTable::default(), CallTable::default());
        let info = PeerInfo::default();
        let offer = a.sip(
            Direction::Outbound,
            B,
            &invite(call, 16384),
            info,
            &mut go(me(A, 1, 1)),
            T0,
        );
        deliver(&mut b, A, 1, offer, T0);
        b.sip(
            Direction::Inbound,
            A,
            &invite(call, 16384),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        let answer = b.sip(
            Direction::Outbound,
            A,
            &ok(call, 20000),
            info,
            &mut go(me(B, 2, 2)),
            T0,
        );
        deliver(&mut a, B, 2, answer, T0);
        // The confirmation is lost; A's media is not.
        let e = match a.media_out(16384, &rtp(1, 1), T0 + 10) {
            Verdict::Replace(e) => e,
            v => panic!("{v:?}"),
        };
        assert!(matches!(
            b.media_in(20000, &e, T0 + 20),
            Verdict::Replace(_)
        ));
        assert_eq!(b.state_of(call), Some("agreed"));
        b.tick(T0 + 60_000);
        assert_eq!(b.state_of(call), Some("agreed"), "no timeout after that");
        // A wrong confirmation tag, though, is a key mismatch.
        let (_, mut b2) = agreed("wrongtag@h");
        let bad = Msg::Confirm {
            call: short(&call_digest("wrongtag@h")),
            tag: [0; 16],
        };
        b2.control(A, 1, bad, T0);
        assert_eq!(b2.state_of("wrongtag@h"), Some("plain"));
    }

    #[test]
    fn a_call_that_never_starts_is_forgotten_and_offers_expire() {
        let mut a = CallTable::default();
        a.sip(
            Direction::Outbound,
            B,
            &invite("x@h", 1),
            PeerInfo::default(),
            &mut go(me(A, 1, 1)),
            T0,
        );
        a.tick(T0 + SETUP_TTL_MS);
        assert_eq!(a.state_of("x@h"), None);
        let mut b = CallTable::default();
        let o = Msg::Offer {
            call: [9; 16],
            device: 1,
            device_key: [1; 32],
            eph: [1; 32],
            sdp: [0; 16],
            suites: vec![1],
        };
        b.control(A, 1, o, T0);
        assert_eq!(b.offers.len(), 1);
        b.tick(T0 + OFFER_TTL_MS);
        assert!(b.offers.is_empty());
        // A cancelled or refused INVITE ends the call.
        a.sip(
            Direction::Outbound,
            B,
            &invite("y@h", 1),
            PeerInfo::default(),
            &mut go(me(A, 1, 1)),
            T0,
        );
        let busy =
            Sip::parse(b"SIP/2.0 486 Busy Here\r\nCall-ID: y@h\r\nCSeq: 1 INVITE\r\n\r\n").unwrap();
        a.sip(
            Direction::Inbound,
            B,
            &busy,
            PeerInfo::default(),
            &mut go(me(A, 1, 1)),
            T0,
        );
        assert_eq!(a.state_of("y@h"), None);
    }

    #[test]
    fn two_calls_are_kept_apart_by_port() {
        let (mut a1, mut b1) = agreed("p1@h");
        // A second, separate call in the same tables would need its own
        // ports; with only one keyed call any port is taken.
        assert!(a1.covers(1));
        let e = match a1.media_out(16384, &rtp(1, 1), T0) {
            Verdict::Replace(e) => e,
            v => panic!("{v:?}"),
        };
        assert!(
            matches!(b1.media_in(5, &e, T0), Verdict::Replace(_)),
            "the only keyed call"
        );
    }
}
