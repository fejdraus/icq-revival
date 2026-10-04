//! File transfers as the wire shows them (stage F0 of
//! `docs/e2e/FILES-RESEARCH.md`): the rendezvous ICBMs that set a transfer
//! up, the rendezvous proxy's (ARS) frames, and the OFT2 headers of the data
//! connection. Plain parsing, no Windows.
//!
//! Both clients send a file over OFT2 on a peer TCP connection, set up by an
//! ICBM on channel 2 with the file transfer capability and an 8-byte cookie.
//! The same cookie names the transfer in the ARS frames and in every OFT2
//! header, so it is what ties a socket to a transfer.
//!
//! With `files_log = on` the add-on logs what each transfer does - which
//! stage carried it, which way, the OFT2 header types and sizes, the totals -
//! and never a file name, an address or a byte of content: an address is
//! logged as its class (`private`, `public`, ...), a cookie as the first four
//! bytes of its SHA-256.

use std::net::Ipv4Addr;

use crate::icbm::{self, Direction};
use crate::snac::{self, Reader};

/// `CapFileTransfer`, `09461343-4C7F-11D1-8222-444553540000`.
pub const CAP_FILE_TRANSFER: [u8; 16] = [
    0x09, 0x46, 0x13, 0x43, 0x4C, 0x7F, 0x11, 0xD1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
];

/// The rendezvous message types (the first u16 of the channel-2 data).
pub const RDV_PROPOSE: u16 = 0;
pub const RDV_CANCEL: u16 = 1;
pub const RDV_ACCEPT: u16 = 2;

/// Rendezvous TLVs.
pub const RDV_TLV_RDV_IP: u16 = 0x0002;
pub const RDV_TLV_REQUESTER_IP: u16 = 0x0003;
pub const RDV_TLV_VERIFIED_IP: u16 = 0x0004;
pub const RDV_TLV_PORT: u16 = 0x0005;
pub const RDV_TLV_SEQ: u16 = 0x000A;
pub const RDV_TLV_CANCEL_REASON: u16 = 0x000B;
pub const RDV_TLV_USE_ARS: u16 = 0x0010;

/// The ARS frame marker: `u16 length | 0x044A | u16 command | ...`.
pub const ARS_VERSION: u16 = 0x044A;
pub const ARS_ERROR: u16 = 0x0001;
pub const ARS_INIT_SEND: u16 = 0x0002;
pub const ARS_ACK: u16 = 0x0003;
pub const ARS_INIT_RECV: u16 = 0x0004;
pub const ARS_READY: u16 = 0x0005;
/// `length` counts what follows it: version, command, 4 unknown bytes, flags.
const ARS_HEAD_AFTER_LEN: usize = 10;

/// The OFT2 header magic.
pub const OFT_MAGIC: &[u8; 4] = b"OFT2";
/// The smallest OFT2 header the parser takes (up to the received-bytes field).
const OFT_MIN: usize = 64;
/// The largest it takes; real ones are 256 bytes, longer only for a long name.
const OFT_MAX: usize = 8192;

pub const OFT_PROMPT: u16 = 0x0101;
pub const OFT_ACK: u16 = 0x0202;
pub const OFT_DONE: u16 = 0x0204;
pub const OFT_RESUME: u16 = 0x0205;
pub const OFT_RESUME_ACCEPT: u16 = 0x0106;
pub const OFT_RESUME_ACK: u16 = 0x0207;

/// What a log line names a transfer by: the first four bytes of the cookie's
/// SHA-256, so two lines of one transfer match and the cookie itself (which
/// the server and the network also see) is not written down.
pub fn cookie_tag(cookie: &[u8; 8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, cookie);
    d.as_ref()[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// The class of an address, for the log in place of the address.
pub fn addr_class(ip: Ipv4Addr) -> &'static str {
    if ip.is_loopback() {
        "loopback"
    } else if ip.is_private() {
        "private"
    } else if ip.is_link_local() {
        "link-local"
    } else if ip.is_unspecified() {
        "unspecified"
    } else if (ip.octets()[0] == 100) && (ip.octets()[1] & 0xC0 == 64) {
        "cgnat"
    } else {
        "public"
    }
}

// --- the rendezvous ICBM ------------------------------------------------------------

/// A channel-2 ICBM with the file transfer capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendezvous {
    /// The contact, as the ICBM names them.
    pub peer: String,
    pub dir: Direction,
    /// [`RDV_PROPOSE`], [`RDV_CANCEL`] or [`RDV_ACCEPT`].
    pub kind: u16,
    pub cookie: [u8; 8],
    /// `0x000A`: 1 for the first proposal, 2 for a counter-proposal (reverse),
    /// 3 for the proxy stage.
    pub seq: Option<u16>,
    /// The addresses the proposal names (`0x0002`, `0x0003`, `0x0004`), in
    /// that order, each once.
    pub ips: Vec<Ipv4Addr>,
    /// `0x0005`: the port to connect to (or, through a proxy, its port token).
    pub port: Option<u16>,
    /// `0x0010`: through the rendezvous proxy.
    pub use_ars: bool,
    /// From the service data `0x2711`: number of files and their total size.
    pub files: Option<(u16, u32)>,
    /// `0x000B` of a cancel.
    pub reason: Option<u16>,
    /// The tags of the TLVs, in order.
    pub tlvs: Vec<u16>,
    /// The canonical digest of the rendezvous message ([`rdv_digest`]):
    /// what a key offer or a proposal announcement binds (seventh audit of
    /// 2026-10).
    pub digest: [u8; 16],
}

/// The canonical digest of a rendezvous message: SHA-256, cut to 16 bytes,
/// over its type, cookie, capability and every TLV of its data but the two
/// the server legitimately rewrites (`foodgroup/icbm.go`, `addExternalIP`):
/// the requester's address `0x0003`, replaced by the address the server
/// sees, and the verified address `0x0004`, which only the server adds. The
/// TLVs are taken sorted by tag (stable for repeats), each as tag, length,
/// value. So the proposed address and port, the proxy flag, the sequence
/// (stage), the file count, size and name, and the invitation text are all
/// bound; what the server must change is not.
pub fn rdv_digest(
    kind: u16,
    cookie: &[u8; 8],
    capability: &[u8],
    tlvs: &[snac::Tlv<'_>],
) -> [u8; 16] {
    let mut kept: Vec<&snac::Tlv<'_>> = tlvs
        .iter()
        .filter(|t| !matches!(t.tag, RDV_TLV_REQUESTER_IP | RDV_TLV_VERIFIED_IP))
        .collect();
    kept.sort_by_key(|t| t.tag);
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"icq-e2e rendezvous v1");
    ctx.update(&kind.to_be_bytes());
    ctx.update(cookie);
    ctx.update(capability);
    for t in kept {
        ctx.update(&t.tag.to_be_bytes());
        ctx.update(&(t.value.len() as u32).to_be_bytes());
        ctx.update(t.value);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&ctx.finish().as_ref()[..16]);
    out
}

impl Rendezvous {
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            RDV_PROPOSE => "propose",
            RDV_CANCEL => "cancel",
            RDV_ACCEPT => "accept",
            _ => "other",
        }
    }

    /// The stage a proposal opens: direct, reverse or proxy.
    pub fn stage(&self) -> &'static str {
        if self.use_ars {
            "proxy"
        } else if self.seq.unwrap_or(1) <= 1 {
            "direct"
        } else {
            "reverse"
        }
    }

    /// One line for the log: no name, no address, no invitation text.
    pub fn log_line(&self) -> String {
        let mut s = format!(
            "file rendezvous {} peer={} {} transfer={}",
            self.dir.tag(),
            self.peer,
            self.kind_name(),
            cookie_tag(&self.cookie)
        );
        if self.kind == RDV_PROPOSE {
            s.push_str(&format!(
                " seq={} stage={} port={} addresses=[{}] ars={}",
                self.seq.map_or("-".to_string(), |v| v.to_string()),
                self.stage(),
                self.port.map_or("-".to_string(), |v| v.to_string()),
                self.ips
                    .iter()
                    .map(|ip| addr_class(*ip))
                    .collect::<Vec<_>>()
                    .join(","),
                if self.use_ars { "yes" } else { "no" }
            ));
            if let Some((n, size)) = self.files {
                s.push_str(&format!(" files={n} size={size}"));
            }
        }
        if let Some(r) = self.reason {
            s.push_str(&format!(" reason={r:#06x}"));
        }
        s.push_str(&format!(
            " tlvs={}",
            self.tlvs
                .iter()
                .map(|t| format!("{t:#06x}"))
                .collect::<Vec<_>>()
                .join(",")
        ));
        s
    }
}

/// The file rendezvous of a SNAC payload travelling in `dir` (an outbound
/// `ICBMChannelMsgToHost`, an inbound `ICBMChannelMsgToClient`), or `None`
/// for anything else.
pub fn rendezvous(dir: Direction, payload: &[u8]) -> Option<Rendezvous> {
    let s = snac::parse(payload)?;
    if s.food_group != snac::FOOD_ICBM {
        return None;
    }
    let inbound = match (dir, s.sub_group) {
        (Direction::Outbound, snac::ICBM_MSG_TO_HOST) => false,
        (Direction::Inbound, snac::ICBM_MSG_TO_CLIENT) => true,
        _ => return None,
    };
    let mut r = Reader::new(s.body);
    r.skip(8)?;
    if r.u16()? != icbm::CHANNEL_RENDEZVOUS {
        return None;
    }
    let peer = String::from_utf8_lossy(r.len8()?).into_owned();
    if inbound {
        r.u16()?;
        let n = r.u16()?;
        for _ in 0..n {
            r.u16()?;
            let len = r.u16()? as usize;
            r.skip(len)?;
        }
    }
    let tlvs = snac::read_tlvs(&s.body[s.body.len() - r.remaining()..]);
    let data = snac::find_tlv(&tlvs, icbm::TLV_RENDEZVOUS_DATA)?;
    parse_data(dir, peer, data)
}

/// A cancel of the file proposal `cookie` to `peer`, as the client would
/// send it (`ICBMChannelMsgToHost`, channel 2, reason 1 "declined"), as a
/// SNAC payload with request id 0: what the add-on sends the sender of a
/// proposal it did not let through (sixth audit of 2026-10, finding 3), so
/// the sender's client stops waiting.
pub fn cancel_to_host(peer: &str, cookie: &[u8; 8]) -> Vec<u8> {
    let mut data = RDV_CANCEL.to_be_bytes().to_vec();
    data.extend_from_slice(cookie);
    data.extend_from_slice(&CAP_FILE_TRANSFER);
    snac::put_tlv(&mut data, RDV_TLV_CANCEL_REASON, &1u16.to_be_bytes());
    let name = &peer.as_bytes()[..peer.len().min(255)];
    let mut p = snac::FOOD_ICBM.to_be_bytes().to_vec();
    p.extend_from_slice(&snac::ICBM_MSG_TO_HOST.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    p.extend_from_slice(cookie);
    p.extend_from_slice(&icbm::CHANNEL_RENDEZVOUS.to_be_bytes());
    p.push(name.len() as u8);
    p.extend_from_slice(name);
    snac::put_tlv(&mut p, icbm::TLV_RENDEZVOUS_DATA, &data);
    p
}

/// The channel-2 data: `type | cookie | capability | TLVs`.
fn parse_data(dir: Direction, peer: String, data: &[u8]) -> Option<Rendezvous> {
    let mut r = Reader::new(data);
    let kind = r.u16()?;
    let mut cookie = [0u8; 8];
    cookie.copy_from_slice(r.bytes(8)?);
    if r.bytes(16)? != CAP_FILE_TRANSFER {
        return None;
    }
    let tlvs = snac::read_tlvs(r.bytes(r.remaining())?);
    let digest = rdv_digest(kind, &cookie, &CAP_FILE_TRANSFER, &tlvs);
    let u16_of = |tag| {
        snac::find_tlv(&tlvs, tag)
            .filter(|v| v.len() >= 2)
            .map(|v| u16::from_be_bytes([v[0], v[1]]))
    };
    let mut ips = Vec::new();
    for tag in [RDV_TLV_RDV_IP, RDV_TLV_REQUESTER_IP, RDV_TLV_VERIFIED_IP] {
        if let Some(v) = snac::find_tlv(&tlvs, tag).filter(|v| v.len() == 4) {
            let ip = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    let files = snac::find_tlv(&tlvs, icbm::RDV_TLV_SVC_DATA)
        .filter(|v| v.len() >= 8)
        .map(|v| {
            (
                u16::from_be_bytes([v[2], v[3]]),
                u32::from_be_bytes([v[4], v[5], v[6], v[7]]),
            )
        });
    Some(Rendezvous {
        peer,
        dir,
        kind,
        cookie,
        seq: u16_of(RDV_TLV_SEQ),
        ips,
        port: u16_of(RDV_TLV_PORT),
        use_ars: tlvs.iter().any(|t| t.tag == RDV_TLV_USE_ARS),
        files,
        reason: u16_of(RDV_TLV_CANCEL_REASON),
        tlvs: tlvs.iter().map(|t| t.tag).collect(),
        digest,
    })
}

// --- the rendezvous proxy -------------------------------------------------------------

/// One ARS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ars {
    pub command: u16,
    /// The whole frame's length on the wire.
    pub len: usize,
    /// The transfer's cookie, in `INIT_SEND` and `INIT_RECV`.
    pub cookie: Option<[u8; 8]>,
}

/// What the start of `b` is as an ARS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArsRead {
    /// A whole frame.
    Frame(Ars),
    /// Not enough bytes to tell, or the rest of the frame is still to come.
    NeedMore,
    /// Not an ARS frame.
    Not,
}

/// The rendezvous proxy's ARS frames as the preamble of an encrypted file
/// stream ([`crate::filestream::Preamble`]): they pass untouched, and the
/// hellos start after `READY`.
pub fn ars_preamble(b: &[u8]) -> crate::filestream::Preamble {
    use crate::filestream::Preamble;
    match ars_frame(b) {
        ArsRead::Frame(f) => Preamble::Frame {
            len: f.len,
            name: ars_name(f.command),
            last: f.command == ARS_READY,
        },
        ArsRead::NeedMore => Preamble::NeedMore,
        ArsRead::Not => Preamble::Not,
    }
}

/// Reads the ARS frame at the start of `b`.
pub fn ars_frame(b: &[u8]) -> ArsRead {
    if b.len() < 4 {
        return ArsRead::NeedMore;
    }
    if u16::from_be_bytes([b[2], b[3]]) != ARS_VERSION {
        return ArsRead::Not;
    }
    let after = u16::from_be_bytes([b[0], b[1]]) as usize;
    if after < ARS_HEAD_AFTER_LEN {
        return ArsRead::Not;
    }
    let len = 2 + after;
    if b.len() < len {
        return ArsRead::NeedMore;
    }
    let command = u16::from_be_bytes([b[4], b[5]]);
    let body = &b[2 + ARS_HEAD_AFTER_LEN..len];
    let cookie = match command {
        ARS_INIT_SEND => ars_cookie(body, false),
        ARS_INIT_RECV => ars_cookie(body, true),
        _ => None,
    };
    ArsRead::Frame(Ars {
        command,
        len,
        cookie,
    })
}

/// The cookie of an `INIT_SEND` (`screen name | cookie | TLVs`) or an
/// `INIT_RECV` (`screen name | port | cookie | TLVs`).
fn ars_cookie(body: &[u8], with_port: bool) -> Option<[u8; 8]> {
    let mut r = Reader::new(body);
    r.len8()?;
    if with_port {
        r.u16()?;
    }
    let mut c = [0u8; 8];
    c.copy_from_slice(r.bytes(8)?);
    Some(c)
}

pub fn ars_name(command: u16) -> &'static str {
    match command {
        ARS_ERROR => "ERROR",
        ARS_INIT_SEND => "INIT_SEND",
        ARS_ACK => "ACK",
        ARS_INIT_RECV => "INIT_RECV",
        ARS_READY => "READY",
        _ => "other",
    }
}

/// Builds an ARS frame (the tests, and the test host's proxy).
pub fn ars_build(command: u16, body: &[u8]) -> Vec<u8> {
    let mut f = ((ARS_HEAD_AFTER_LEN + body.len()) as u16)
        .to_be_bytes()
        .to_vec();
    f.extend_from_slice(&ARS_VERSION.to_be_bytes());
    f.extend_from_slice(&command.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    f.extend_from_slice(body);
    f
}

// --- OFT2 -------------------------------------------------------------------------

/// What the add-on reads of an OFT2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oft {
    /// The header's length on the wire.
    pub len: usize,
    pub kind: u16,
    pub cookie: [u8; 8],
    pub files_total: u16,
    pub files_left: u16,
    /// The size of the file the header is about.
    pub size: u32,
    /// The bytes the receiver already has (resume).
    pub received: u32,
}

/// What the start of `b` is as an OFT2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OftRead {
    Header(Oft),
    NeedMore,
    Not,
}

/// Reads the OFT2 header at the start of `b`.
pub fn oft_header(b: &[u8]) -> OftRead {
    let n = b.len().min(4);
    if b[..n] != OFT_MAGIC[..n] {
        return OftRead::Not;
    }
    if b.len() < 6 {
        return OftRead::NeedMore;
    }
    let len = u16::from_be_bytes([b[4], b[5]]) as usize;
    if !(OFT_MIN..=OFT_MAX).contains(&len) {
        return OftRead::Not;
    }
    if b.len() < len {
        return OftRead::NeedMore;
    }
    let u16_at = |o: usize| u16::from_be_bytes([b[o], b[o + 1]]);
    let u32_at = |o: usize| u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let mut cookie = [0u8; 8];
    cookie.copy_from_slice(&b[8..16]);
    OftRead::Header(Oft {
        len,
        kind: u16_at(6),
        cookie,
        files_total: u16_at(20),
        files_left: u16_at(22),
        size: u32_at(32),
        received: u32_at(60),
    })
}

pub fn oft_name(kind: u16) -> &'static str {
    match kind {
        OFT_PROMPT => "prompt",
        OFT_ACK => "ack",
        OFT_DONE => "done",
        OFT_RESUME => "resume",
        OFT_RESUME_ACCEPT => "resume accept",
        OFT_RESUME_ACK => "resume ack",
        _ => "other",
    }
}

/// A 256-byte OFT2 header (the tests and the test host).
pub fn oft_build(kind: u16, cookie: &[u8; 8], size: u32, received: u32, name: &str) -> Vec<u8> {
    let mut h = vec![0u8; 256];
    h[..4].copy_from_slice(OFT_MAGIC);
    h[4..6].copy_from_slice(&256u16.to_be_bytes());
    h[6..8].copy_from_slice(&kind.to_be_bytes());
    h[8..16].copy_from_slice(cookie);
    h[20..22].copy_from_slice(&1u16.to_be_bytes());
    h[22..24].copy_from_slice(&1u16.to_be_bytes());
    h[28..32].copy_from_slice(&size.to_be_bytes());
    h[32..36].copy_from_slice(&size.to_be_bytes());
    h[60..64].copy_from_slice(&received.to_be_bytes());
    h[68..81].copy_from_slice(b"Cool FileXfer");
    let n = name.len().min(63);
    h[192..192 + n].copy_from_slice(&name.as_bytes()[..n]);
    h
}

// --- watching a data connection (F0) -------------------------------------------------

/// What one direction of a watched connection is in the middle of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The first bytes of the connection: what they are decides the rest.
    Start,
    /// Before READY on a proxied connection: ARS frames.
    Ars,
    /// An OFT2 header, at a frame boundary.
    Header,
    /// File data, this many bytes still to come.
    Data(u64),
    /// Lost track (a header that did not read): only bytes are counted.
    Lost,
}

#[derive(Debug, Clone, Copy, Default)]
struct DirCount {
    bytes: u64,
    data: u64,
    headers: u32,
}

/// Watches the plaintext of one peer connection for the log: which
/// transfer it is (by the cookie in its first ARS frame or OFT2 header),
/// each header and ARS frame, and the totals. Never changes a byte.
#[derive(Debug)]
pub struct Watch {
    pub cookie: Option<[u8; 8]>,
    expect: [Expect; 2],
    buf: [Vec<u8>; 2],
    count: [DirCount; 2],
    files_done: u32,
    /// The last prompt's size: what the other side's data is measured by.
    size: u64,
    first: Option<&'static str>,
    started_ms: u64,
    /// Whether this connection turned out to be anything the watch knows.
    pub known: bool,
}

fn idx(dir: Direction) -> usize {
    match dir {
        Direction::Outbound => 0,
        Direction::Inbound => 1,
    }
}

impl Watch {
    pub fn new(now_ms: u64) -> Watch {
        Watch {
            cookie: None,
            expect: [Expect::Start, Expect::Start],
            buf: [Vec::new(), Vec::new()],
            count: [DirCount::default(); 2],
            files_done: 0,
            size: 0,
            first: None,
            started_ms: now_ms,
            known: false,
        }
    }

    /// Whether `b`, the first bytes of a connection in either direction,
    /// look like a file transfer: an OFT2 header, an ARS frame or the add-on's
    /// own key hello.
    pub fn looks_like_transfer(b: &[u8]) -> bool {
        b.starts_with(OFT_MAGIC)
            || b.starts_with(crate::filestream::HELLO_MAGIC)
            || matches!(ars_frame(b), ArsRead::Frame(_))
            || (b.len() < 4 && !b.is_empty() && OFT_MAGIC.starts_with(b))
    }

    /// The plaintext of one call, in `dir`; returns lines for the log.
    pub fn feed(&mut self, dir: Direction, bytes: &[u8]) -> Vec<String> {
        let i = idx(dir);
        let mut lines = Vec::new();
        self.count[i].bytes += bytes.len() as u64;
        self.buf[i].extend_from_slice(bytes);
        loop {
            let b = &self.buf[i];
            if b.is_empty() {
                break;
            }
            match self.expect[i] {
                Expect::Start => {
                    if b.starts_with(OFT_MAGIC) {
                        self.expect[i] = Expect::Header;
                        self.note_first(dir, "OFT2", &mut lines);
                    } else {
                        match ars_frame(b) {
                            ArsRead::Frame(_) => {
                                self.expect[i] = Expect::Ars;
                                self.note_first(dir, "ARS", &mut lines);
                            }
                            ArsRead::NeedMore => break,
                            ArsRead::Not if b.len() < 4 && OFT_MAGIC.starts_with(b) => break,
                            ArsRead::Not => {
                                self.expect[i] = Expect::Lost;
                                self.note_first(dir, "other", &mut lines);
                            }
                        }
                    }
                }
                Expect::Ars => match ars_frame(b) {
                    ArsRead::Frame(f) => {
                        if self.cookie.is_none() {
                            self.cookie = f.cookie;
                        }
                        lines.push(format!(
                            "{} ARS {} ({} B)",
                            dir.tag(),
                            ars_name(f.command),
                            f.len
                        ));
                        self.buf[i].drain(..f.len);
                        if f.command == ARS_READY {
                            // Both directions now carry OFT2.
                            self.expect = [Expect::Header, Expect::Header];
                        }
                    }
                    ArsRead::NeedMore => break,
                    ArsRead::Not => {
                        // The client's own bytes after INIT, before READY was
                        // seen this side: OFT2 from here on.
                        self.expect[i] = Expect::Header;
                    }
                },
                Expect::Header => match oft_header(b) {
                    OftRead::Header(h) => {
                        self.on_header(dir, &h, &mut lines);
                        self.buf[i].drain(..h.len);
                    }
                    OftRead::NeedMore => break,
                    OftRead::Not => {
                        lines.push(format!(
                            "{} not an OFT2 header where one was due: counting bytes only",
                            dir.tag()
                        ));
                        self.expect[i] = Expect::Lost;
                    }
                },
                Expect::Data(n) => {
                    let k = (b.len() as u64).min(n) as usize;
                    self.count[i].data += k as u64;
                    self.buf[i].drain(..k);
                    self.expect[i] = if n - k as u64 == 0 {
                        Expect::Header
                    } else {
                        Expect::Data(n - k as u64)
                    };
                }
                Expect::Lost => {
                    self.buf[i].clear();
                    break;
                }
            }
        }
        lines
    }

    fn note_first(&mut self, dir: Direction, what: &'static str, lines: &mut Vec<String>) {
        if self.first.is_none() {
            self.first = Some(what);
            self.known = what != "other";
            lines.push(format!("first bytes {} {what}", dir.tag()));
        }
    }

    fn on_header(&mut self, dir: Direction, h: &Oft, lines: &mut Vec<String>) {
        let i = idx(dir);
        self.count[i].headers += 1;
        if self.cookie.is_none() && h.cookie != [0; 8] {
            self.cookie = Some(h.cookie);
        }
        lines.push(format!(
            "{} OFT2 {} ({:#06x}, {} B) file {} of {}, size {}{}",
            dir.tag(),
            oft_name(h.kind),
            h.kind,
            h.len,
            h.files_total.saturating_sub(h.files_left) + 1,
            h.files_total,
            h.size,
            if h.received > 0 {
                format!(", {} B already there", h.received)
            } else {
                String::new()
            }
        ));
        let other = 1 - i;
        match h.kind {
            OFT_PROMPT => self.size = h.size as u64,
            // The receiver is ready: the sender's data follows, the whole
            // file or what resume left.
            OFT_ACK | OFT_RESUME_ACK => {
                let n = (h.size as u64).saturating_sub(h.received as u64);
                if n > 0 && self.expect[other] == Expect::Header {
                    self.expect[other] = Expect::Data(n);
                }
            }
            OFT_DONE => self.files_done += 1,
            _ => {}
        }
    }

    /// The totals, for the line logged when the socket closes.
    pub fn totals(&self, now_ms: u64) -> String {
        let d = |c: &DirCount| {
            format!(
                "{} B ({} OFT2 headers, {} B file data)",
                c.bytes, c.headers, c.data
            )
        };
        format!(
            "after {:.1} s: OUT {}, IN {}; files done {}",
            now_ms.saturating_sub(self.started_ms) as f64 / 1000.0,
            d(&self.count[0]),
            d(&self.count[1]),
            self.files_done
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An ICBM channel-2 body with the file capability, as the client sends
    /// it (outbound) or the server relays it (inbound).
    pub(crate) fn rdv_payload(
        dir: Direction,
        peer: &str,
        kind: u16,
        cookie: [u8; 8],
        tlvs: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut data = kind.to_be_bytes().to_vec();
        data.extend_from_slice(&cookie);
        data.extend_from_slice(&CAP_FILE_TRANSFER);
        for (t, v) in tlvs {
            snac::put_tlv(&mut data, *t, v);
        }
        let mut body = cookie.to_vec();
        body.extend_from_slice(&icbm::CHANNEL_RENDEZVOUS.to_be_bytes());
        body.push(peer.len() as u8);
        body.extend_from_slice(peer.as_bytes());
        let sub = match dir {
            Direction::Outbound => snac::ICBM_MSG_TO_HOST,
            Direction::Inbound => {
                body.extend_from_slice(&[0, 0, 0, 1]);
                snac::put_tlv(&mut body, 0x0001, &[0, 0x50]);
                snac::ICBM_MSG_TO_CLIENT
            }
        };
        snac::put_tlv(&mut body, icbm::TLV_RENDEZVOUS_DATA, &data);
        let mut p = snac::FOOD_ICBM.to_be_bytes().to_vec();
        p.extend_from_slice(&sub.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 7]);
        p.extend_from_slice(&body);
        p
    }

    /// A proposal: seq, addresses, port, maybe through the proxy, one file.
    pub(crate) fn proposal(
        dir: Direction,
        peer: &str,
        cookie: [u8; 8],
        seq: u16,
        ip: Ipv4Addr,
        port: u16,
        ars: bool,
    ) -> Vec<u8> {
        let mut svc = vec![0, 1, 0, 1];
        svc.extend_from_slice(&5_242_880u32.to_be_bytes());
        svc.extend_from_slice(b"secret plans.pdf\0");
        let mut t = vec![
            (RDV_TLV_SEQ, seq.to_be_bytes().to_vec()),
            (RDV_TLV_RDV_IP, ip.octets().to_vec()),
            (RDV_TLV_REQUESTER_IP, ip.octets().to_vec()),
            (RDV_TLV_PORT, port.to_be_bytes().to_vec()),
            (icbm::RDV_TLV_SVC_DATA, svc),
        ];
        if ars {
            t.push((RDV_TLV_USE_ARS, Vec::new()));
        }
        rdv_payload(dir, peer, RDV_PROPOSE, cookie, &t)
    }

    #[test]
    fn a_file_proposal_is_read_and_logged_without_name_or_address() {
        let c = [1, 2, 3, 4, 5, 6, 7, 8];
        let p = proposal(
            Direction::Inbound,
            "100001",
            c,
            1,
            Ipv4Addr::new(192, 168, 1, 20),
            5190,
            false,
        );
        let r = rendezvous(Direction::Inbound, &p).unwrap();
        assert_eq!(r.kind, RDV_PROPOSE);
        assert_eq!(r.cookie, c);
        assert_eq!(r.seq, Some(1));
        assert_eq!(r.port, Some(5190));
        assert_eq!(r.ips, vec![Ipv4Addr::new(192, 168, 1, 20)]);
        assert_eq!(r.files, Some((1, 5_242_880)));
        assert_eq!(r.stage(), "direct");
        let l = r.log_line();
        assert!(
            l.contains("propose") && l.contains("addresses=[private]"),
            "{l}"
        );
        assert!(l.contains(&cookie_tag(&c)), "{l}");
        assert!(!l.contains("secret") && !l.contains("192.168"), "{l}");
        // The outbound form, and the proxy stage.
        let p = proposal(
            Direction::Outbound,
            "100002",
            c,
            3,
            Ipv4Addr::new(203, 0, 113, 5),
            1234,
            true,
        );
        let r = rendezvous(Direction::Outbound, &p).unwrap();
        assert_eq!((r.stage(), r.peer.as_str()), ("proxy", "100002"));
        // Never a message: nothing of it is encrypted, held or logged as text.
        assert_eq!(icbm::parse_to_host(snac::parse(&p).unwrap().body), None);
        // Not a file transfer: another capability, another direction.
        let mut other = p.clone();
        let at = other
            .windows(16)
            .position(|w| w == CAP_FILE_TRANSFER)
            .unwrap();
        other[at + 3] = 0x49;
        assert_eq!(rendezvous(Direction::Outbound, &other), None);
        assert_eq!(rendezvous(Direction::Inbound, &p), None);
    }

    #[test]
    fn ars_frames_and_their_cookies() {
        let c = [9u8; 8];
        let mut body = vec![6];
        body.extend_from_slice(b"100001");
        body.extend_from_slice(&c);
        snac::put_tlv(&mut body, 1, &CAP_FILE_TRANSFER);
        let f = ars_build(ARS_INIT_SEND, &body);
        assert_eq!(
            ars_frame(&f),
            ArsRead::Frame(Ars {
                command: ARS_INIT_SEND,
                len: f.len(),
                cookie: Some(c)
            })
        );
        assert_eq!(ars_frame(&f[..5]), ArsRead::NeedMore);
        let mut body = vec![6];
        body.extend_from_slice(b"100002");
        body.extend_from_slice(&77u16.to_be_bytes());
        body.extend_from_slice(&c);
        let f = ars_build(ARS_INIT_RECV, &body);
        assert!(matches!(ars_frame(&f), ArsRead::Frame(Ars { cookie: Some(x), .. }) if x == c));
        assert_eq!(ars_frame(b"OFT2\x01\x00"), ArsRead::Not);
        assert_eq!(ars_frame(&[0x2A, 1, 0, 1, 0, 4]), ArsRead::Not);
    }

    #[test]
    fn the_watch_follows_headers_and_data_both_ways() {
        let c = [3u8; 8];
        let mut w = Watch::new(0);
        let mut lines = Vec::new();
        // The sender's prompt, then (in) the receiver's ack, then the data.
        let prompt = oft_build(OFT_PROMPT, &c, 1000, 0, "a.txt");
        lines.extend(w.feed(Direction::Outbound, &prompt[..100]));
        lines.extend(w.feed(Direction::Outbound, &prompt[100..]));
        lines.extend(w.feed(
            Direction::Inbound,
            &oft_build(OFT_ACK, &c, 1000, 0, "a.txt"),
        ));
        lines.extend(w.feed(Direction::Outbound, &[0x55; 600]));
        lines.extend(w.feed(Direction::Outbound, &[0x55; 400]));
        lines.extend(w.feed(
            Direction::Inbound,
            &oft_build(OFT_DONE, &c, 1000, 1000, "a.txt"),
        ));
        assert_eq!(w.cookie, Some(c));
        assert!(w.known);
        let t = w.totals(1500);
        assert!(
            t.contains("OUT 1256 B (1 OFT2 headers, 1000 B file data)")
                && t.contains("files done 1"),
            "{t}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("OFT2 prompt (0x0101, 256 B)")),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.contains("a.txt")), "{lines:?}");
        // Resume: data is what is left.
        let mut w = Watch::new(0);
        w.feed(Direction::Inbound, &oft_build(OFT_PROMPT, &c, 1000, 0, "b"));
        w.feed(
            Direction::Outbound,
            &oft_build(OFT_RESUME, &c, 1000, 700, "b"),
        );
        w.feed(
            Direction::Inbound,
            &oft_build(OFT_RESUME_ACCEPT, &c, 1000, 700, "b"),
        );
        w.feed(
            Direction::Outbound,
            &oft_build(OFT_RESUME_ACK, &c, 1000, 700, "b"),
        );
        w.feed(Direction::Inbound, &[1; 300]);
        w.feed(
            Direction::Outbound,
            &oft_build(OFT_DONE, &c, 1000, 1000, "b"),
        );
        assert!(
            w.totals(0)
                .contains("IN 812 B (2 OFT2 headers, 300 B file data)"),
            "{}",
            w.totals(0)
        );
        // A proxied connection: ARS first, then OFT2.
        let mut w = Watch::new(0);
        let mut body = vec![1, b'x'];
        body.extend_from_slice(&c);
        let l = w.feed(Direction::Outbound, &ars_build(ARS_INIT_SEND, &body));
        assert!(l.iter().any(|l| l.contains("ARS INIT_SEND")), "{l:?}");
        w.feed(Direction::Inbound, &ars_build(ARS_ACK, &[0; 6]));
        w.feed(Direction::Inbound, &ars_build(ARS_READY, &[]));
        let l = w.feed(Direction::Outbound, &oft_build(OFT_PROMPT, &c, 5, 0, "c"));
        assert!(l.iter().any(|l| l.contains("OFT2 prompt")), "{l:?}");
        assert_eq!(w.cookie, Some(c));
        // Anything else is not a transfer.
        assert!(!Watch::looks_like_transfer(&[0x2A, 1, 0, 1]));
        assert!(Watch::looks_like_transfer(b"OF"));
    }
}
