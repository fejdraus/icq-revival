//! The media of an agreed call, end to end (stage C2 of
//! `docs/e2e/CALLS-RESEARCH.md`).
//!
//! Only for a call both add-ons agreed on ([`crate::callneg`]); every other
//! datagram is never handed here. Plain Rust, no Winsock: the hooks in
//! `hook_calls.rs` give a datagram in and take a [`Verdict`] out.
//!
//! - **Keys** ([`derive`]): HKDF-SHA256 over the X25519 secret of the two
//!   ephemeral keys of the call; the salt binds the Call-ID, both UINs and both
//!   devices (id and Curve25519 identity key), the info both ephemeral keys and
//!   a label. One key and salt per direction (caller to callee, callee to
//!   caller) and per kind (RTP, RTCP), plus a key that confirms the agreement.
//! - **RTP** ([`Media::protect_rtp`]): AES-128-GCM as RFC 7714 lays it out:
//!   the header (12 bytes, CSRCs, extension) stays in the clear and is the
//!   associated data, the payload (with any padding) is encrypted, the 16-byte
//!   tag follows. The rollover counter is not estimated: it goes after the tag
//!   in 4 bytes of its own (authenticated, as part of the associated data), so
//!   loss, reordering or a sender that restarts its sequence numbers can never
//!   make the two sides disagree on the index. The sender never uses an index
//!   twice: a sequence number that goes back takes the next rollover counter.
//!   IV = salt XOR (`00 00` | SSRC | ROC | SEQ).
//! - **RTCP** ([`Media::protect_rtcp`]): the first 8 bytes (header and sender
//!   SSRC) in the clear, the rest encrypted, then the tag and `E | index`
//!   (31-bit SRTCP index, E set), as RFC 7714 section 9. IV = salt XOR
//!   (`00 00` | SSRC | `00 00` | index).
//! - **Replay**: a 128-packet window per SSRC and direction, for RTP (48-bit
//!   index) and RTCP (31-bit index); an old or repeated index is dropped.
//! - **Framing** ([`split`], [`rewrap`]): the media may be the whole datagram
//!   (direct path, or the relayed path after Set Active Destination), the DATA
//!   attribute of a TURN Send / Data Indication (ICQ 6.5's dialect with
//!   unpadded attributes, or RFC 5766's padded one), or RFC 5766 ChannelData.
//!   The inner datagram is transformed and the attribute and message lengths
//!   fixed. STUN and TURN control messages (Allocate, Binding, Set Active
//!   Destination...) carry no RTP and are never touched.
//!
//! Overhead: 20 bytes per RTP or RTCP packet (16 tag + 4 index).

use std::collections::HashMap;
use std::ops::Range;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf;

/// The suite of v1: AES-128-GCM over RTP/RTCP as above.
pub const SUITE_AES128GCM: u8 = 1;
/// The GCM tag.
pub const TAG_LEN: usize = 16;
/// The explicit rollover counter (RTP) or `E | index` (RTCP) after the tag.
pub const INDEX_LEN: usize = 4;
/// What encryption adds to one RTP or RTCP packet.
pub const OVERHEAD: usize = TAG_LEN + INDEX_LEN;
/// The largest UDP payload that fits an Ethernet MTU (1500 - 20 IP - 8 UDP).
pub const MAX_UDP_PAYLOAD: usize = 1472;
/// The replay window, in packets.
pub const REPLAY_WINDOW: u64 = 128;
/// How many SSRCs one direction of a call keeps state for; more are refused,
/// so a stream of forged SSRCs cannot grow the tables.
const MAX_SSRCS: usize = 16;

const KEY_LEN: usize = 16;
const SALT_LEN: usize = 12;

/// The RTCP E flag: the packet is encrypted.
const RTCP_E: u32 = 0x8000_0000;

// --- keys -----------------------------------------------------------------------

/// One side of the call, as the key derivation binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Party<'a> {
    /// The UIN, normalised (`sign::ident`).
    pub uin: &'a str,
    /// The device id in the key directory.
    pub device: u32,
    /// The device's Curve25519 identity key.
    pub device_key: [u8; 32],
    /// The ephemeral X25519 key of this call.
    pub eph: [u8; 32],
}

/// The key and salt of one direction and kind.
struct StreamKey {
    key: LessSafeKey,
    salt: [u8; SALT_LEN],
}

impl StreamKey {
    fn new(material: &[u8]) -> StreamKey {
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_128_GCM, &material[..KEY_LEN]).expect("a 16-byte AES key"),
        );
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&material[KEY_LEN..KEY_LEN + SALT_LEN]);
        StreamKey { key, salt }
    }

    fn nonce(&self, iv: [u8; SALT_LEN]) -> Nonce {
        let mut n = self.salt;
        for (a, b) in n.iter_mut().zip(iv) {
            *a ^= b;
        }
        Nonce::assume_unique_for_key(n)
    }
}

/// The keys of one direction.
struct DirectionKeys {
    rtp: StreamKey,
    rtcp: StreamKey,
}

/// Everything [`derive`] gives: both directions and the confirmation key.
pub struct CallKeys {
    caller_to_callee: DirectionKeys,
    callee_to_caller: DirectionKeys,
    /// Proves to the callee that the caller derived the same keys.
    pub confirm: [u8; 32],
}

/// `ring`'s HKDF wants the output length as a type.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// The salt: a label, the Call-ID's SHA-256, then caller and callee (UIN,
/// device id, device key), each length-prefixed where its length varies.
fn salt_bytes(call_id_digest: &[u8; 32], caller: &Party, callee: &Party) -> Vec<u8> {
    let mut s = b"icq-e2e call salt v1".to_vec();
    s.extend_from_slice(call_id_digest);
    for p in [caller, callee] {
        s.push(p.uin.len() as u8);
        s.extend_from_slice(p.uin.as_bytes());
        s.extend_from_slice(&p.device.to_be_bytes());
        s.extend_from_slice(&p.device_key);
    }
    s
}

/// The keys of a call from the X25519 secret of its two ephemeral keys.
pub fn derive(
    shared: &[u8],
    call_id_digest: &[u8; 32],
    caller: &Party,
    callee: &Party,
) -> CallKeys {
    let salt = salt_bytes(call_id_digest, caller, callee);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(shared);
    let expand = |label: &[u8], n: usize| -> Vec<u8> {
        let info: [&[u8]; 4] = [b"icq-e2e call v1 ", label, &caller.eph, &callee.eph];
        let mut out = vec![0u8; n];
        prk.expand(&info, Len(n))
            .and_then(|okm| okm.fill(&mut out))
            .expect("HKDF-SHA256 output of a few dozen bytes");
        out
    };
    let m = KEY_LEN + SALT_LEN;
    let mut confirm = [0u8; 32];
    confirm.copy_from_slice(&expand(b"confirm", 32));
    CallKeys {
        caller_to_callee: DirectionKeys {
            rtp: StreamKey::new(&expand(b"caller rtp", m)),
            rtcp: StreamKey::new(&expand(b"caller rtcp", m)),
        },
        callee_to_caller: DirectionKeys {
            rtp: StreamKey::new(&expand(b"callee rtp", m)),
            rtcp: StreamKey::new(&expand(b"callee rtcp", m)),
        },
        confirm,
    }
}

/// The key confirmation tag the caller sends: HMAC-SHA256 over the call hash
/// under the confirmation key, first 16 bytes.
pub fn confirm_tag(keys: &CallKeys, call_hash: &[u8; 16]) -> [u8; 16] {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &keys.confirm);
    let t = ring::hmac::sign(
        &k,
        &[b"icq-e2e call confirm v1".as_slice(), call_hash].concat(),
    );
    let mut out = [0u8; 16];
    out.copy_from_slice(&t.as_ref()[..16]);
    out
}

/// Whether two tags are equal, without an early exit.
pub fn same_tag(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// --- replay -----------------------------------------------------------------------

/// A sliding window of [`REPLAY_WINDOW`] indices: bit `i` is `top - i`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Replay {
    top: Option<u64>,
    bits: u128,
}

impl Replay {
    /// Whether `index` may be accepted: newer than anything seen, or inside
    /// the window and not seen yet.
    pub fn fresh(&self, index: u64) -> bool {
        match self.top {
            None => true,
            Some(t) if index > t => true,
            Some(t) => {
                let d = t - index;
                d < REPLAY_WINDOW && self.bits & (1u128 << d) == 0
            }
        }
    }

    /// Records `index` as seen. Only after the packet authenticated.
    pub fn mark(&mut self, index: u64) {
        match self.top {
            None => {
                self.top = Some(index);
                self.bits = 1;
            }
            Some(t) if index > t => {
                let shift = index - t;
                self.bits = if shift >= REPLAY_WINDOW {
                    0
                } else {
                    self.bits << shift
                };
                self.bits |= 1;
                self.top = Some(index);
            }
            Some(t) => {
                let d = t - index;
                if d < REPLAY_WINDOW {
                    self.bits |= 1u128 << d;
                }
            }
        }
    }
}

// --- packets ----------------------------------------------------------------------

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Whether `p` is shaped like RTCP: version 2, packet type 192-223
/// (RFC 5761), at least the header and the sender SSRC.
pub fn is_rtcp(p: &[u8]) -> bool {
    p.len() >= 8 && p[0] >> 6 == 2 && (192..=223).contains(&p[1])
}

/// The length of an RTP header (fixed part, CSRCs, extension), or `None` for
/// anything that is not RTP version 2.
pub fn rtp_header_len(p: &[u8]) -> Option<usize> {
    if p.len() < 12 || p[0] >> 6 != 2 || is_rtcp(p) {
        return None;
    }
    let mut h = 12 + 4 * (p[0] & 0x0F) as usize;
    if p[0] & 0x10 != 0 {
        if p.len() < h + 4 {
            return None;
        }
        h += 4 + 4 * be16(p, h + 2) as usize;
    }
    (h <= p.len()).then_some(h)
}

/// Whether `p` is RTP or RTCP.
pub fn is_media(p: &[u8]) -> bool {
    is_rtcp(p) || rtp_header_len(p).is_some()
}

/// Why a packet was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    /// Too short to carry a tag and an index: a plain packet in an encrypted
    /// call (a downgrade), or a truncated one.
    Plain,
    /// The tag did not verify: wrong key, changed bytes, or plain media that
    /// happens to be long enough.
    Auth,
    /// An index seen before, or older than the window.
    Replay,
    /// Not RTP or RTCP at all.
    NotMedia,
    /// No room for another SSRC, or the RTCP index ran out.
    Limit,
}

impl Fail {
    pub fn as_str(self) -> &'static str {
        match self {
            Fail::Plain => "plain or truncated packet in an encrypted call",
            Fail::Auth => "authentication failed",
            Fail::Replay => "replayed or too old",
            Fail::NotMedia => "not RTP/RTCP",
            Fail::Limit => "too many streams",
        }
    }
}

/// Counters for the log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub rtp_out: u64,
    pub rtcp_out: u64,
    pub rtp_in: u64,
    pub rtcp_in: u64,
    pub plain_dropped: u64,
    pub auth_failed: u64,
    pub replayed: u64,
    pub other_dropped: u64,
    /// Encrypted datagrams over [`MAX_UDP_PAYLOAD`] (sent anyway, as the
    /// client's own packet would have been).
    pub over_mtu: u64,
    pub max_out: usize,
}

impl Stats {
    pub fn describe(&self) -> String {
        format!(
            "out: {} RTP + {} RTCP encrypted (largest datagram {} B, {} over {} B); \
             in: {} RTP + {} RTCP decrypted; dropped: {} plain, {} failed authentication, \
             {} replayed, {} other",
            self.rtp_out,
            self.rtcp_out,
            self.max_out,
            self.over_mtu,
            MAX_UDP_PAYLOAD,
            self.rtp_in,
            self.rtcp_in,
            self.plain_dropped,
            self.auth_failed,
            self.replayed,
            self.other_dropped
        )
    }
}

/// The media state of one agreed call, on one side.
pub struct Media {
    send: DirectionKeys,
    recv: DirectionKeys,
    /// The last RTP index used per SSRC.
    sent_rtp: HashMap<u32, u64>,
    /// The next SRTCP index per SSRC.
    sent_rtcp: HashMap<u32, u32>,
    recv_rtp: HashMap<u32, Replay>,
    recv_rtcp: HashMap<u32, Replay>,
    pub stats: Stats,
}

impl Media {
    /// The media state of the caller (`caller` true) or the callee.
    pub fn new(keys: CallKeys, caller: bool) -> Media {
        let (send, recv) = if caller {
            (keys.caller_to_callee, keys.callee_to_caller)
        } else {
            (keys.callee_to_caller, keys.caller_to_callee)
        };
        Media {
            send,
            recv,
            sent_rtp: HashMap::new(),
            sent_rtcp: HashMap::new(),
            recv_rtp: HashMap::new(),
            recv_rtcp: HashMap::new(),
            stats: Stats::default(),
        }
    }

    /// Encrypts one RTP packet.
    pub fn protect_rtp(&mut self, p: &[u8]) -> Result<Vec<u8>, Fail> {
        let h = rtp_header_len(p).ok_or(Fail::NotMedia)?;
        let seq = be16(p, 2);
        let ssrc = be32(p, 8);
        let last = self.sent_rtp.get(&ssrc).copied();
        if last.is_none() && self.sent_rtp.len() >= MAX_SSRCS {
            return Err(Fail::Limit);
        }
        let mut roc = last.map_or(0, |l| (l >> 16) as u32);
        if let Some(l) = last {
            let lseq = (l & 0xFFFF) as u16;
            if seq < lseq && lseq - seq > 0x8000 {
                roc = roc.wrapping_add(1);
            }
        }
        let mut index = (roc as u64) << 16 | seq as u64;
        if let Some(l) = last {
            if index <= l {
                // A sequence number that went back (a restart, or the same
                // packet sent twice): the index must never repeat under this
                // key, so it takes the next rollover counter. The counter is
                // sent with the packet, so the receiver needs no guess.
                roc = ((l >> 16) as u32).wrapping_add(1);
                index = (roc as u64) << 16 | seq as u64;
            }
        }
        self.sent_rtp.insert(ssrc, index);
        let roc_b = roc.to_be_bytes();
        let mut iv = [0u8; SALT_LEN];
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[6..10].copy_from_slice(&roc_b);
        iv[10..12].copy_from_slice(&seq.to_be_bytes());
        let aad = [&p[..h], &roc_b[..]].concat();
        let mut body = p[h..].to_vec();
        let tag = self
            .send
            .rtp
            .key
            .seal_in_place_separate_tag(self.send.rtp.nonce(iv), Aad::from(&aad), &mut body)
            .map_err(|_| Fail::Limit)?;
        let mut out = Vec::with_capacity(p.len() + OVERHEAD);
        out.extend_from_slice(&p[..h]);
        out.extend_from_slice(&body);
        out.extend_from_slice(tag.as_ref());
        out.extend_from_slice(&roc_b);
        self.stats.rtp_out += 1;
        Ok(out)
    }

    /// Decrypts one RTP packet; the replay window moves only once it has
    /// authenticated.
    pub fn unprotect_rtp(&mut self, p: &[u8]) -> Result<Vec<u8>, Fail> {
        let h = rtp_header_len(p).ok_or(Fail::NotMedia)?;
        if p.len() < h + OVERHEAD {
            return Err(Fail::Plain);
        }
        let seq = be16(p, 2);
        let ssrc = be32(p, 8);
        let roc_at = p.len() - INDEX_LEN;
        let roc = be32(p, roc_at);
        let index = (roc as u64) << 16 | seq as u64;
        if let Some(w) = self.recv_rtp.get(&ssrc) {
            if !w.fresh(index) {
                return Err(Fail::Replay);
            }
        } else if self.recv_rtp.len() >= MAX_SSRCS {
            return Err(Fail::Limit);
        }
        let mut iv = [0u8; SALT_LEN];
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[6..10].copy_from_slice(&roc.to_be_bytes());
        iv[10..12].copy_from_slice(&seq.to_be_bytes());
        let aad = [&p[..h], &p[roc_at..]].concat();
        let mut body = p[h..roc_at].to_vec();
        let plain_len = self
            .recv
            .rtp
            .key
            .open_in_place(self.recv.rtp.nonce(iv), Aad::from(&aad), &mut body)
            .map_err(|_| Fail::Auth)?
            .len();
        self.recv_rtp.entry(ssrc).or_default().mark(index);
        let mut out = Vec::with_capacity(h + plain_len);
        out.extend_from_slice(&p[..h]);
        out.extend_from_slice(&body[..plain_len]);
        self.stats.rtp_in += 1;
        Ok(out)
    }

    /// Encrypts one (compound) RTCP packet.
    pub fn protect_rtcp(&mut self, p: &[u8]) -> Result<Vec<u8>, Fail> {
        if !is_rtcp(p) {
            return Err(Fail::NotMedia);
        }
        let ssrc = be32(p, 4);
        if !self.sent_rtcp.contains_key(&ssrc) && self.sent_rtcp.len() >= MAX_SSRCS {
            return Err(Fail::Limit);
        }
        let next = self.sent_rtcp.entry(ssrc).or_insert(0);
        let index = *next;
        if index >= RTCP_E {
            return Err(Fail::Limit);
        }
        *next += 1;
        let e_index = (RTCP_E | index).to_be_bytes();
        let mut iv = [0u8; SALT_LEN];
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[8..12].copy_from_slice(&index.to_be_bytes());
        let aad = [&p[..8], &e_index[..]].concat();
        let mut body = p[8..].to_vec();
        let tag = self
            .send
            .rtcp
            .key
            .seal_in_place_separate_tag(self.send.rtcp.nonce(iv), Aad::from(&aad), &mut body)
            .map_err(|_| Fail::Limit)?;
        let mut out = Vec::with_capacity(p.len() + OVERHEAD);
        out.extend_from_slice(&p[..8]);
        out.extend_from_slice(&body);
        out.extend_from_slice(tag.as_ref());
        out.extend_from_slice(&e_index);
        self.stats.rtcp_out += 1;
        Ok(out)
    }

    /// Decrypts one RTCP packet. An index without the E flag is an
    /// unencrypted SRTCP packet, which an encrypted call never takes.
    pub fn unprotect_rtcp(&mut self, p: &[u8]) -> Result<Vec<u8>, Fail> {
        if !is_rtcp(p) {
            return Err(Fail::NotMedia);
        }
        if p.len() < 8 + OVERHEAD {
            return Err(Fail::Plain);
        }
        let ssrc = be32(p, 4);
        let at = p.len() - INDEX_LEN;
        let e_index = be32(p, at);
        if e_index & RTCP_E == 0 {
            return Err(Fail::Plain);
        }
        let index = e_index & !RTCP_E;
        if let Some(w) = self.recv_rtcp.get(&ssrc) {
            if !w.fresh(index as u64) {
                return Err(Fail::Replay);
            }
        } else if self.recv_rtcp.len() >= MAX_SSRCS {
            return Err(Fail::Limit);
        }
        let mut iv = [0u8; SALT_LEN];
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[8..12].copy_from_slice(&index.to_be_bytes());
        let aad = [&p[..8], &p[at..]].concat();
        let mut body = p[8..at].to_vec();
        let plain_len = self
            .recv
            .rtcp
            .key
            .open_in_place(self.recv.rtcp.nonce(iv), Aad::from(&aad), &mut body)
            .map_err(|_| Fail::Auth)?
            .len();
        self.recv_rtcp.entry(ssrc).or_default().mark(index as u64);
        let mut out = Vec::with_capacity(8 + plain_len);
        out.extend_from_slice(&p[..8]);
        out.extend_from_slice(&body[..plain_len]);
        self.stats.rtcp_in += 1;
        Ok(out)
    }

    /// One datagram on its way out: RTP or RTCP, bare or inside TURN framing,
    /// is encrypted; everything else passes as it is.
    pub fn outbound(&mut self, d: &[u8]) -> Verdict {
        let Some((wrap, range)) = split(d) else {
            return Verdict::Pass;
        };
        if let Wrap::Turn { guarded: true, .. } = wrap {
            // A MESSAGE-INTEGRITY or FINGERPRINT after DATA cannot be kept
            // valid; the media must not go out plain either.
            self.stats.other_dropped += 1;
            return Verdict::Drop("TURN message with integrity around media");
        }
        let inner = &d[range.clone()];
        let enc = if is_rtcp(inner) {
            self.protect_rtcp(inner)
        } else {
            self.protect_rtp(inner)
        };
        match enc {
            Ok(e) => {
                let out = rewrap(d, wrap, range, &e);
                self.stats.max_out = self.stats.max_out.max(out.len());
                if out.len() > MAX_UDP_PAYLOAD {
                    self.stats.over_mtu += 1;
                }
                Verdict::Replace(out)
            }
            Err(f) => {
                self.stats.other_dropped += 1;
                Verdict::Drop(f.as_str())
            }
        }
    }

    /// One datagram that came in: RTP or RTCP, bare or inside TURN framing,
    /// must decrypt, or it is dropped; everything else passes as it is.
    pub fn inbound(&mut self, d: &[u8]) -> Verdict {
        let Some((wrap, range)) = split(d) else {
            return Verdict::Pass;
        };
        let inner = &d[range.clone()];
        let dec = if is_rtcp(inner) {
            self.unprotect_rtcp(inner)
        } else {
            self.unprotect_rtp(inner)
        };
        match dec {
            Ok(p) => {
                // A Data Indication's integrity, if it had any, is the
                // relay's and the client checks it on what it is given; there
                // is none in ICQ 6.5's dialect.
                Verdict::Replace(rewrap(d, wrap, range, &p))
            }
            Err(f) => {
                match f {
                    Fail::Plain => self.stats.plain_dropped += 1,
                    Fail::Auth => self.stats.auth_failed += 1,
                    Fail::Replay => self.stats.replayed += 1,
                    _ => self.stats.other_dropped += 1,
                }
                Verdict::Drop(f.as_str())
            }
        }
    }
}

/// What becomes of one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not media of an agreed call: the client's own bytes, untouched.
    Pass,
    /// These bytes instead.
    Replace(Vec<u8>),
    /// Nothing at all (the reason is for the log).
    Drop(&'static str),
}

// --- framing ----------------------------------------------------------------------

const AOL_TURN_COOKIE_ATTR: u16 = 0x000F;
const AOL_TURN_COOKIE: u32 = 0x72C6_4BC6;
const STUN_MAGIC: u32 = 0x2112_A442;
const ATTR_DATA: u16 = 0x0013;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_FINGERPRINT: u16 = 0x8028;

/// How the media sits in a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrap {
    /// The datagram is the media.
    Raw,
    /// The value of the DATA attribute of a TURN message. `padded`: RFC 5389
    /// attributes padded to four bytes; otherwise ICQ 6.5's unpadded ones.
    /// `guarded`: an integrity or fingerprint attribute covers it.
    Turn { padded: bool, guarded: bool },
    /// RFC 5766 ChannelData; `padded` when the datagram had the padding.
    ChannelData { padded: bool },
}

/// Where the RTP or RTCP of a datagram is, or `None` when it carries none.
pub fn split(d: &[u8]) -> Option<(Wrap, Range<usize>)> {
    let first = *d.first()?;
    match first >> 6 {
        2 => is_media(d).then_some((Wrap::Raw, 0..d.len())),
        0 => turn_data(d),
        1 => {
            if d.len() < 4 {
                return None;
            }
            let len = be16(d, 2) as usize;
            if 4 + len > d.len() || d.len() > 4 + ((len + 3) & !3) {
                return None;
            }
            let r = 4..4 + len;
            is_media(&d[r.clone()]).then_some((
                Wrap::ChannelData {
                    padded: d.len() > 4 + len,
                },
                r,
            ))
        }
        _ => None,
    }
}

/// The DATA of a TURN message that carries media.
fn turn_data(d: &[u8]) -> Option<(Wrap, Range<usize>)> {
    if d.len() < 20 || 20 + be16(d, 2) as usize != d.len() {
        return None;
    }
    let modern = be32(d, 4) == STUN_MAGIC;
    let attrs = attr_ranges(d, !modern)?;
    let aol = !modern
        && attrs.first().is_some_and(|(t, r)| {
            *t == AOL_TURN_COOKIE_ATTR && r.len() == 4 && be32(d, r.start) == AOL_TURN_COOKIE
        });
    if !aol && !modern {
        // Classic STUN of RFC 3489 carries no media.
        return None;
    }
    let pos = attrs.iter().position(|(t, _)| *t == ATTR_DATA)?;
    let r = attrs[pos].1.clone();
    if !is_media(&d[r.clone()]) {
        return None;
    }
    let guarded = attrs[pos..]
        .iter()
        .any(|(t, _)| *t == ATTR_MESSAGE_INTEGRITY || *t == ATTR_FINGERPRINT);
    Some((
        Wrap::Turn {
            padded: modern,
            guarded,
        },
        r,
    ))
}

/// The attributes of a STUN message as (type, value range in `d`).
fn attr_ranges(d: &[u8], exact: bool) -> Option<Vec<(u16, Range<usize>)>> {
    let mut out = Vec::new();
    let mut at = 20;
    while d.len() - at >= 4 {
        let t = be16(d, at);
        let l = be16(d, at + 2) as usize;
        if at + 4 + l > d.len() {
            return None;
        }
        out.push((t, at + 4..at + 4 + l));
        let step = if exact { 4 + l } else { 4 + ((l + 3) & !3) };
        if at + step > d.len() {
            return None;
        }
        at += step;
    }
    (at == d.len()).then_some(out)
}

/// `d` with the media at `range` replaced by `inner`, every length fixed.
pub fn rewrap(d: &[u8], wrap: Wrap, range: Range<usize>, inner: &[u8]) -> Vec<u8> {
    match wrap {
        Wrap::Raw => inner.to_vec(),
        Wrap::ChannelData { padded } => {
            let mut out = Vec::with_capacity(inner.len() + 8);
            out.extend_from_slice(&d[..2]);
            out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            out.extend_from_slice(inner);
            if padded {
                while out.len() % 4 != 0 {
                    out.push(0);
                }
            }
            out
        }
        Wrap::Turn { padded, .. } => {
            let attr_start = range.start - 4;
            let old_end = if padded {
                (range.start + ((range.len() + 3) & !3)).min(d.len())
            } else {
                range.end
            };
            let mut out = Vec::with_capacity(d.len() + inner.len());
            out.extend_from_slice(&d[..attr_start]);
            out.extend_from_slice(&ATTR_DATA.to_be_bytes());
            out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            out.extend_from_slice(inner);
            if padded {
                while (out.len() - 20) % 4 != 0 {
                    out.push(0);
                }
            }
            out.extend_from_slice(&d[old_end..]);
            let body = (out.len() - 20) as u16;
            out[2..4].copy_from_slice(&body.to_be_bytes());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(uin: &'static str, device: u32, k: u8, e: u8) -> Party<'static> {
        Party {
            uin,
            device,
            device_key: [k; 32],
            eph: [e; 32],
        }
    }

    /// The two sides of one call over the same secret.
    fn pair() -> (Media, Media) {
        let (a, b) = (party("100001", 1, 1, 3), party("100002", 2, 2, 4));
        let k1 = derive(&[9; 32], &[7; 32], &a, &b);
        let k2 = derive(&[9; 32], &[7; 32], &a, &b);
        (Media::new(k1, true), Media::new(k2, false))
    }

    fn rtp(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, 103];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&160u32.wrapping_mul(seq as u32).to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn rtcp_rr(ssrc: u32) -> Vec<u8> {
        let mut p = vec![0x81, 201, 0, 7];
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[0x11; 24]);
        p
    }

    #[test]
    fn the_kdf_binds_every_input_and_separates_directions() {
        let (a, b) = (party("100001", 1, 1, 3), party("100002", 2, 2, 4));
        let base = derive(&[9; 32], &[7; 32], &a, &b);
        let tag = confirm_tag(&base, &[5; 16]);
        assert_eq!(
            tag,
            confirm_tag(&derive(&[9; 32], &[7; 32], &a, &b), &[5; 16])
        );
        // Any input changed: other keys.
        let others = [
            derive(&[8; 32], &[7; 32], &a, &b),
            derive(&[9; 32], &[6; 32], &a, &b),
            derive(&[9; 32], &[7; 32], &party("100003", 1, 1, 3), &b),
            derive(&[9; 32], &[7; 32], &a, &party("100002", 3, 2, 4)),
            derive(&[9; 32], &[7; 32], &a, &party("100002", 2, 8, 4)),
            derive(&[9; 32], &[7; 32], &party("100001", 1, 1, 5), &b),
            derive(&[9; 32], &[7; 32], &b, &a),
        ];
        for k in &others {
            assert!(!same_tag(&tag, &confirm_tag(k, &[5; 16])));
        }
        // The two directions use different keys: a packet the caller sends
        // does not open as one the callee sent.
        let (mut caller, mut callee) = pair();
        let p = rtp(1, 0x1234, b"hello audio");
        let e = caller.protect_rtp(&p).unwrap();
        assert_eq!(callee.unprotect_rtp(&e).unwrap(), p);
        let (mut caller2, _) = pair();
        assert_eq!(caller2.unprotect_rtp(&e), Err(Fail::Auth));
    }

    #[test]
    fn rtp_round_trip_keeps_the_header_and_hides_the_payload() {
        let (mut a, mut b) = pair();
        let payload = b"the quick brown fox speaks in iSAC";
        let p = rtp(4242, 0xDEADBEEF, payload);
        let e = a.protect_rtp(&p).unwrap();
        assert_eq!(e.len(), p.len() + OVERHEAD);
        assert_eq!(&e[..12], &p[..12], "the header stays clear");
        assert!(!e.windows(9).any(|w| w == b"quick bro"));
        assert_eq!(&e[e.len() - 4..], &[0, 0, 0, 0], "ROC 0");
        assert_eq!(b.unprotect_rtp(&e).unwrap(), p);
        // A changed header, payload, tag or ROC: dropped.
        for at in [1, 5, 13, e.len() - 5, e.len() - 1] {
            let mut x = e.clone();
            x[at] ^= 1;
            let mut fresh = pair().1;
            assert!(fresh.unprotect_rtp(&x).is_err(), "byte {at}");
        }
    }

    #[test]
    fn rtp_with_csrc_extension_and_padding() {
        let (mut a, mut b) = pair();
        let mut p = vec![0x80 | 0x20 | 0x10 | 1, 97, 0, 9, 0, 0, 0, 1, 0, 0, 0, 2];
        p.extend_from_slice(&[0, 0, 0, 3]); // CSRC
        p.extend_from_slice(&[0xBE, 0xDE, 0, 1, 1, 2, 3, 4]); // extension
        p.extend_from_slice(&[0x55; 30]);
        p.extend_from_slice(&[0, 0, 3]); // padding
        let e = a.protect_rtp(&p).unwrap();
        assert_eq!(&e[..24], &p[..24], "header, CSRC and extension clear");
        assert_eq!(b.unprotect_rtp(&e).unwrap(), p);
    }

    #[test]
    fn replay_window_drops_repeats_and_old_packets_and_takes_reordering() {
        let (mut a, mut b) = pair();
        let packets: Vec<Vec<u8>> = (0..300u16)
            .map(|s| a.protect_rtp(&rtp(s, 7, &[s as u8; 20])).unwrap())
            .collect();
        // Out of order inside the window: all taken.
        for i in [5, 3, 4, 0, 1, 2, 10, 6, 9, 7, 8] {
            assert!(b.unprotect_rtp(&packets[i]).is_ok(), "{i}");
        }
        // A repeat: dropped.
        assert_eq!(b.unprotect_rtp(&packets[4]), Err(Fail::Replay));
        // Loss: jump ahead.
        assert!(b.unprotect_rtp(&packets[200]).is_ok());
        // 72 behind the top: inside the window, unseen, taken.
        assert!(b.unprotect_rtp(&packets[128]).is_ok());
        // More than 128 behind the top: too old.
        assert_eq!(b.unprotect_rtp(&packets[60]), Err(Fail::Replay));
        assert_eq!(b.stats.rtp_in, 13);

        let mut w = Replay::default();
        w.mark(1000);
        assert!(!w.fresh(1000) && w.fresh(1001) && w.fresh(873) && !w.fresh(872));
        w.mark(990);
        assert!(!w.fresh(990) && w.fresh(991));
        w.mark(5000);
        assert!(!w.fresh(1000) && w.fresh(4999) && !w.fresh(5000));
    }

    #[test]
    fn the_index_rolls_over_past_65536_packets_and_never_repeats() {
        let (mut a, mut b) = pair();
        let mut seq: u16 = 65_000;
        for _ in 0..70_000u32 {
            let e = a.protect_rtp(&rtp(seq, 1, b"x")).unwrap();
            assert!(b.unprotect_rtp(&e).is_ok(), "seq {seq}");
            seq = seq.wrapping_add(1);
        }
        assert_eq!(a.sent_rtp[&1] >> 16, 2, "two rollovers");
        // A sender that restarts its sequence numbers: a fresh index, still
        // accepted, never a repeated nonce.
        let before = a.sent_rtp[&1];
        let e = a.protect_rtp(&rtp(10, 1, b"y")).unwrap();
        assert!(a.sent_rtp[&1] > before);
        assert!(b.unprotect_rtp(&e).is_ok());
        // The same packet sent twice: two different ciphertexts, both new.
        let p = rtp(11, 1, b"z");
        let (e1, e2) = (a.protect_rtp(&p).unwrap(), a.protect_rtp(&p).unwrap());
        assert_ne!(e1, e2);
        assert!(b.unprotect_rtp(&e1).is_ok() && b.unprotect_rtp(&e2).is_ok());
    }

    #[test]
    fn rtcp_round_trip_index_and_replay() {
        let (mut a, mut b) = pair();
        let p = rtcp_rr(0xCAFE);
        let e1 = a.protect_rtcp(&p).unwrap();
        let e2 = a.protect_rtcp(&p).unwrap();
        assert_eq!(&e1[..8], &p[..8], "header and SSRC clear");
        assert_eq!(&e1[e1.len() - 4..], &[0x80, 0, 0, 0], "E set, index 0");
        assert_eq!(&e2[e2.len() - 4..], &[0x80, 0, 0, 1], "index 1");
        assert!(is_rtcp(&e1), "still RTCP to anything on the path");
        assert_eq!(b.unprotect_rtcp(&e2).unwrap(), p);
        assert_eq!(b.unprotect_rtcp(&e1).unwrap(), p, "reordered");
        assert_eq!(b.unprotect_rtcp(&e1), Err(Fail::Replay));
        // E cleared: an unencrypted SRTCP packet, refused.
        let mut x = a.protect_rtcp(&p).unwrap();
        let n = x.len();
        x[n - 4] &= 0x7F;
        assert_eq!(b.unprotect_rtcp(&x), Err(Fail::Plain));
        // Plain RTCP in an encrypted call: refused.
        assert_eq!(b.unprotect_rtcp(&p), Err(Fail::Plain));
    }

    #[test]
    fn plain_rtp_in_an_encrypted_call_is_dropped() {
        let (_, mut b) = pair();
        assert_eq!(b.unprotect_rtp(&rtp(1, 2, b"short")), Err(Fail::Plain));
        assert_eq!(
            b.unprotect_rtp(&rtp(1, 2, &[0x44; 160])),
            Err(Fail::Auth),
            "a long plain packet fails its tag"
        );
        assert_eq!(
            b.inbound(&rtp(1, 2, b"short")),
            Verdict::Drop(Fail::Plain.as_str())
        );
        assert_eq!(b.stats.plain_dropped, 1);
    }

    fn stun(msg_type: u16, id: [u8; 16], attrs: &[(u16, &[u8])], padded: bool) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            if padded {
                while body.len() % 4 != 0 {
                    body.push(0);
                }
            }
        }
        let mut m = msg_type.to_be_bytes().to_vec();
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&id);
        m.extend_from_slice(&body);
        m
    }

    const COOKIE: [u8; 4] = [0x72, 0xC6, 0x4B, 0xC6];

    #[test]
    fn turn_send_and_data_indication_are_rewrapped_with_lengths_fixed() {
        let (mut a, mut b) = pair();
        let inner = rtp(77, 0xABCD, &[0x33; 61]); // odd size: unpadded matters
        let dest = [0u8, 1, 0x40, 0x00, 192, 0, 2, 1];
        let send = stun(
            0x0004,
            [2; 16],
            &[(0x000F, &COOKIE), (0x0011, &dest), (0x0013, &inner)],
            false,
        );
        let out = match a.outbound(&send) {
            Verdict::Replace(v) => v,
            v => panic!("{v:?}"),
        };
        assert_eq!(out.len(), send.len() + OVERHEAD);
        assert_eq!(be16(&out, 2) as usize, out.len() - 20, "message length");
        let p = crate::calls::classify(&out);
        assert_eq!(p.class(), "turn-send/rtp", "still a Send carrying RTP");
        // The relay turns it into a Data Indication with the same DATA.
        let (_, r) = split(&out).unwrap();
        let data = out[r].to_vec();
        let ind = stun(
            0x0115,
            [3; 16],
            &[
                (0x000F, &COOKIE),
                (0x0012, &[0, 1, 0, 9, 1, 2, 3, 4]),
                (0x0013, &data),
            ],
            false,
        );
        let back = match b.inbound(&ind) {
            Verdict::Replace(v) => v,
            v => panic!("{v:?}"),
        };
        let want = stun(
            0x0115,
            [3; 16],
            &[
                (0x000F, &COOKIE),
                (0x0012, &[0, 1, 0, 9, 1, 2, 3, 4]),
                (0x0013, &inner),
            ],
            false,
        );
        assert_eq!(back, want, "the client gets the indication it would have");
    }

    #[test]
    fn rfc5766_send_indication_and_channel_data_are_rewrapped() {
        let (mut a, mut b) = pair();
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&STUN_MAGIC.to_be_bytes());
        let inner = rtp(5, 9, &[1; 33]);
        let peer = [0u8, 1, 0, 9, 1, 2, 3, 4];
        let m = stun(0x0016, id, &[(0x0012, &peer), (0x0013, &inner)], true);
        let out = match a.outbound(&m) {
            Verdict::Replace(v) => v,
            v => panic!("{v:?}"),
        };
        assert_eq!(out.len() % 4, 0);
        let (w, r) = split(&out).unwrap();
        assert_eq!(
            w,
            Wrap::Turn {
                padded: true,
                guarded: false
            }
        );
        assert_eq!(b.unprotect_rtp(&out[r]).unwrap(), inner);

        let mut cd = vec![0x40, 0x01];
        cd.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        cd.extend_from_slice(&inner);
        while cd.len() % 4 != 0 {
            cd.push(0);
        }
        let out = match a.outbound(&cd) {
            Verdict::Replace(v) => v,
            v => panic!("{v:?}"),
        };
        assert_eq!(out.len() % 4, 0);
        match b.inbound(&out) {
            Verdict::Replace(v) => assert_eq!(v, cd),
            v => panic!("{v:?}"),
        }
        // Integrity after DATA: cannot be rewritten, never sent plain.
        let guarded = stun(0x0016, id, &[(0x0013, &inner), (0x0008, &[0; 20])], true);
        assert!(matches!(a.outbound(&guarded), Verdict::Drop(_)));
    }

    #[test]
    fn stun_and_turn_control_pass_untouched() {
        let (mut a, mut b) = pair();
        let binding = stun(0x0001, [7; 16], &[(0x0003, &[0, 0, 0, 0])], false);
        let allocate = stun(0x0003, [1; 16], &[(0x000F, &COOKIE)], false);
        let sad = stun(
            0x0006,
            [1; 16],
            &[(0x000F, &COOKIE), (0x0011, &[0, 1, 0x40, 0, 1, 2, 3, 4])],
            false,
        );
        // A connectivity check carried in a Send: STUN inside, not media.
        let check = stun(
            0x0004,
            [2; 16],
            &[(0x000F, &COOKIE), (0x0013, &binding)],
            false,
        );
        for m in [&binding, &allocate, &sad, &check, &vec![0xFF, 1, 2]] {
            assert_eq!(a.outbound(m), Verdict::Pass);
            assert_eq!(b.inbound(m), Verdict::Pass);
        }
        assert_eq!(a.stats, Stats::default());
    }

    #[test]
    fn mtu_overflow_is_counted_not_fragmented() {
        let (mut a, _) = pair();
        let p = rtp(1, 1, &[0; MAX_UDP_PAYLOAD - 12 - 10]);
        match a.outbound(&p) {
            Verdict::Replace(v) => assert_eq!(v.len(), p.len() + OVERHEAD),
            v => panic!("{v:?}"),
        }
        assert_eq!(a.stats.over_mtu, 1);
        assert_eq!(a.stats.max_out, MAX_UDP_PAYLOAD - 10 + OVERHEAD);
    }
}
