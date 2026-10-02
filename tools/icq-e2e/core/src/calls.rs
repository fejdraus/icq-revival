//! Observation of voice and video calls (stage C0 of
//! `docs/e2e/CALLS-RESEARCH.md`): what kind each media datagram is, and what
//! the SIP of a call says about its media - never the content.
//!
//! Only with `calls_log = on` in `icq-e2e.ini` (or `ICQE2E_CALLS_LOG=on`).
//! Nothing here changes a byte: the hooks in `hook_calls.rs` call the original
//! Winsock function first and hand the bytes here only to be looked at.
//!
//! - [`classify`] names one UDP datagram: STUN (RFC 3489 or RFC 5389), the
//!   TURN of ICQ 6.5 (draft-rosenberg-midcom-turn-08 with AOL's MAGIC-COOKIE,
//!   see `server/stun/turn.go`), whose Send and Data Indication carry a
//!   datagram in a DATA attribute, RFC 5766 ChannelData, RTP, RTCP, or other.
//!   For RTP: version, payload type, SSRC, sequence number and sizes; for RTCP
//!   the packet types of the compound packet.
//! - [`Tracker`] keeps the log small: the first [`FIRST_PACKETS`] packets of
//!   each flow (socket, remote address, direction) are logged one by one, then
//!   a new stream (another class, payload type or SSRC) once, and every
//!   [`SUMMARY_MS`] a summary per flow with counts, rate and the largest size
//!   per class.
//! - [`sip_line`] reads the SIP of a call out of an ICBM on channel 6 (raw SIP
//!   in TLV 0x0005, `wire.ICBMChannelSIP`): method or status, CSeq, a hash of
//!   the Call-ID, the user parts of From and To, and from the SDP the media
//!   lines (media, port, profile, payload types and their rtpmap names),
//!   whether `a=crypto` is there, and the ICE candidates by type.
//!
//! Addresses are never logged as they are: an address is `server` (the
//! configured server, which is where the TURN relay lives), `private`,
//! `loopback` or `public`, with its port, which is all the analysis needs and
//! keeps the log safe to share.
//!
//! Plain Rust, no Winsock: unit-tested directly.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};

use crate::icbm::Direction;
use crate::snac::{self, Reader};

/// ICBM channel 6: the SIP of an ICQ 6 voice or video call.
pub const CHANNEL_SIP: u16 = 0x0006;
/// The TLV of a channel-6 ICBM that holds the raw SIP message.
pub const TLV_SIP: u16 = 0x0005;

/// How many packets of a flow are logged one by one.
pub const FIRST_PACKETS: u32 = 8;
/// How often a flow's counters are summed up in the log.
pub const SUMMARY_MS: u64 = 5_000;
/// How many distinct streams of one flow are announced at most.
const MAX_STREAMS: usize = 32;

/// The TURN of ICQ 6.5 begins every message with this MAGIC-COOKIE attribute.
const AOL_TURN_COOKIE_ATTR: u16 = 0x000F;
const AOL_TURN_COOKIE: u32 = 0x72C6_4BC6;
/// RFC 5389's magic cookie, in the place of the first four bytes of the
/// transaction ID.
const STUN_MAGIC: u32 = 0x2112_A442;
/// The DATA attribute: the datagram a TURN Send or Data Indication carries.
const ATTR_DATA: u16 = 0x0013;

/// Which STUN a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// RFC 3489: a 16-byte transaction ID, no magic cookie.
    Rfc3489,
    /// RFC 5389/5766: the magic cookie, padded attributes.
    Rfc5389,
    /// The TURN of ICQ 6.5: RFC 3489 framing, unpadded attributes, AOL's
    /// MAGIC-COOKIE attribute first.
    AolTurn,
}

/// What one datagram is. Holds no content: only header fields and sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// STUN or TURN. `inner` is the datagram a TURN Send / Data Indication
    /// carries in its DATA attribute.
    Stun {
        msg_type: u16,
        dialect: Dialect,
        inner: Option<Box<Packet>>,
        inner_len: usize,
    },
    /// RFC 5766 ChannelData (a TURN channel), with what it carries.
    ChannelData {
        channel: u16,
        inner: Box<Packet>,
        inner_len: usize,
    },
    /// RTP version 2.
    Rtp {
        pt: u8,
        marker: bool,
        seq: u16,
        ssrc: u32,
        /// The payload size: the datagram without header, CSRCs, extension
        /// and padding.
        payload: usize,
    },
    /// RTCP: the packet types of a compound packet, in order.
    Rtcp { types: Vec<u8> },
    /// Anything else, named by its first byte.
    Other { first: u8 },
}

impl Packet {
    /// The class for counting: `stun`, `turn-send/rtp`, `rtp`...
    pub fn class(&self) -> String {
        match self {
            Packet::Stun {
                msg_type,
                dialect,
                inner,
                ..
            } => {
                let base = match (dialect, msg_type) {
                    (Dialect::AolTurn, 0x0004) => "turn-send",
                    (Dialect::AolTurn, 0x0115) => "turn-data",
                    (Dialect::AolTurn, _) => "turn",
                    (Dialect::Rfc5389, 0x0016) => "turn-send",
                    (Dialect::Rfc5389, 0x0017) => "turn-data",
                    _ => "stun",
                };
                match inner {
                    Some(p) => format!("{base}/{}", p.class()),
                    None => base.to_string(),
                }
            }
            Packet::ChannelData { inner, .. } => format!("channeldata/{}", inner.class()),
            Packet::Rtp { .. } => "rtp".to_string(),
            Packet::Rtcp { .. } => "rtcp".to_string(),
            Packet::Other { .. } => "other".to_string(),
        }
    }

    /// The stream within a flow: the class, and for RTP its payload type and
    /// SSRC (a new codec or a new source shows as a new stream).
    pub fn stream(&self) -> String {
        match self.media() {
            Some(Packet::Rtp { pt, ssrc, .. }) => {
                format!("{} pt={pt} ssrc={ssrc:#010x}", self.class())
            }
            _ => self.class(),
        }
    }

    /// The RTP or RTCP packet this is or carries.
    fn media(&self) -> Option<&Packet> {
        match self {
            Packet::Rtp { .. } | Packet::Rtcp { .. } => Some(self),
            Packet::Stun { inner, .. } => inner.as_deref().and_then(Packet::media),
            Packet::ChannelData { inner, .. } => inner.media(),
            Packet::Other { .. } => None,
        }
    }

    /// One phrase for the log, without a byte of the content.
    pub fn describe(&self) -> String {
        match self {
            Packet::Stun {
                msg_type,
                dialect,
                inner,
                inner_len,
            } => {
                let d = match dialect {
                    Dialect::Rfc3489 => "STUN/3489",
                    Dialect::Rfc5389 => "STUN/5389",
                    Dialect::AolTurn => "TURN/aol",
                };
                let mut s = format!("{d} {} ({msg_type:#06x})", stun_name(*dialect, *msg_type));
                if let Some(p) = inner {
                    s.push_str(&format!(" carrying {inner_len} B: {}", p.describe()));
                }
                s
            }
            Packet::ChannelData {
                channel,
                inner,
                inner_len,
            } => format!(
                "ChannelData {channel:#06x} carrying {inner_len} B: {}",
                inner.describe()
            ),
            Packet::Rtp {
                pt,
                marker,
                seq,
                ssrc,
                payload,
            } => format!(
                "RTP v2 pt={pt} m={} seq={seq} ssrc={ssrc:#010x} payload={payload} B",
                u8::from(*marker)
            ),
            Packet::Rtcp { types } => format!(
                "RTCP [{}]",
                types
                    .iter()
                    .map(|t| rtcp_name(*t))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Packet::Other { first } => format!("other (first byte {first:#04x})"),
        }
    }
}

/// The name of a STUN/TURN message type in its dialect.
fn stun_name(dialect: Dialect, t: u16) -> String {
    let named = match (dialect, t) {
        (_, 0x0001) => "Binding Request",
        (_, 0x0101) => "Binding Response",
        (_, 0x0111) => "Binding Error",
        (_, 0x0002) => "Shared Secret Request",
        (_, 0x0102) => "Shared Secret Response",
        (_, 0x0112) => "Shared Secret Error",
        (_, 0x0003) => "Allocate Request",
        (_, 0x0103) => "Allocate Response",
        (_, 0x0113) => "Allocate Error",
        (Dialect::AolTurn, 0x0004) => "Send Request",
        (Dialect::AolTurn, 0x0104) => "Send Response",
        (Dialect::AolTurn, 0x0114) => "Send Error",
        (Dialect::AolTurn, 0x0115) => "Data Indication",
        (Dialect::AolTurn, 0x0006) => "Set Active Destination Request",
        (Dialect::AolTurn, 0x0106) => "Set Active Destination Response",
        (Dialect::AolTurn, 0x0116) => "Set Active Destination Error",
        (Dialect::AolTurn, 0x0009) => "Close Binding Request",
        (Dialect::AolTurn, 0x0109) => "Close Binding Response",
        (Dialect::AolTurn, 0x0119) => "Close Binding Error",
        (_, 0x0004) => "Refresh Request",
        (_, 0x0104) => "Refresh Response",
        (_, 0x0016) => "Send Indication",
        (_, 0x0017) => "Data Indication",
        (_, 0x0008) => "CreatePermission Request",
        (_, 0x0009) => "ChannelBind Request",
        _ => return format!("type {t:#06x}"),
    };
    named.to_string()
}

fn rtcp_name(t: u8) -> String {
    match t {
        200 => "SR".to_string(),
        201 => "RR".to_string(),
        202 => "SDES".to_string(),
        203 => "BYE".to_string(),
        204 => "APP".to_string(),
        205 => "RTPFB".to_string(),
        206 => "PSFB".to_string(),
        207 => "XR".to_string(),
        t => format!("pt {t}"),
    }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// What kind of datagram `d` is.
pub fn classify(d: &[u8]) -> Packet {
    classify_depth(d, 0)
}

fn classify_depth(d: &[u8], depth: u8) -> Packet {
    let Some(&first) = d.first() else {
        return Packet::Other { first: 0 };
    };
    match first >> 6 {
        0 => stun(d, depth).unwrap_or(Packet::Other { first }),
        1 => channel_data(d, depth).unwrap_or(Packet::Other { first }),
        2 => rtp_or_rtcp(d).unwrap_or(Packet::Other { first }),
        _ => Packet::Other { first },
    }
}

/// STUN and TURN: a 20-byte header whose length field covers the rest
/// exactly.
fn stun(d: &[u8], depth: u8) -> Option<Packet> {
    if d.len() < 20 || 20 + be16(d, 2) as usize != d.len() {
        return None;
    }
    let msg_type = be16(d, 0);
    let modern = be32(d, 4) == STUN_MAGIC;
    let attrs = walk_attrs(&d[20..], !modern)?;
    let aol = !modern
        && attrs.first().is_some_and(|(t, v)| {
            *t == AOL_TURN_COOKIE_ATTR && v.len() == 4 && be32(v, 0) == AOL_TURN_COOKIE
        });
    let dialect = match (modern, aol) {
        (true, _) => Dialect::Rfc5389,
        (false, true) => Dialect::AolTurn,
        (false, false) => Dialect::Rfc3489,
    };
    let carries = match dialect {
        Dialect::AolTurn => matches!(msg_type, 0x0004 | 0x0115),
        Dialect::Rfc5389 => matches!(msg_type, 0x0016 | 0x0017),
        Dialect::Rfc3489 => false,
    };
    let data = carries
        .then(|| attrs.iter().find(|(t, _)| *t == ATTR_DATA).map(|(_, v)| *v))
        .flatten();
    let (inner, inner_len) = match data {
        Some(v) if depth == 0 => (Some(Box::new(classify_depth(v, depth + 1))), v.len()),
        _ => (None, 0),
    };
    Some(Packet::Stun {
        msg_type,
        dialect,
        inner,
        inner_len,
    })
}

/// The attributes of a STUN body; unpadded (`exact`) as ICQ 6.5 writes them,
/// or padded to four bytes as RFC 5389 has it. `None` unless they fill the
/// body.
fn walk_attrs(mut body: &[u8], exact: bool) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while body.len() >= 4 {
        let t = be16(body, 0);
        let l = be16(body, 2) as usize;
        if 4 + l > body.len() {
            return None;
        }
        out.push((t, &body[4..4 + l]));
        let step = if exact { 4 + l } else { 4 + ((l + 3) & !3) };
        if step > body.len() {
            return None;
        }
        body = &body[step..];
    }
    body.is_empty().then_some(out)
}

/// RFC 5766 ChannelData: channel 0x4000-0x7FFF, a length, the data, and up to
/// three bytes of padding over UDP.
fn channel_data(d: &[u8], depth: u8) -> Option<Packet> {
    if d.len() < 4 || depth > 0 {
        return None;
    }
    let channel = be16(d, 0);
    let len = be16(d, 2) as usize;
    if 4 + len > d.len() || d.len() > 4 + ((len + 3) & !3) {
        return None;
    }
    let inner = &d[4..4 + len];
    Some(Packet::ChannelData {
        channel,
        inner: Box::new(classify_depth(inner, depth + 1)),
        inner_len: inner.len(),
    })
}

/// RTP or RTCP: version 2; RTCP by the packet types 192-223 (RFC 5761).
fn rtp_or_rtcp(d: &[u8]) -> Option<Packet> {
    if d.len() < 4 {
        return None;
    }
    if (192..=223).contains(&d[1]) {
        return rtcp(d);
    }
    if d.len() < 12 {
        return None;
    }
    let padding = d[0] & 0x20 != 0;
    let extension = d[0] & 0x10 != 0;
    let cc = (d[0] & 0x0F) as usize;
    let mut head = 12 + 4 * cc;
    if extension {
        if d.len() < head + 4 {
            return None;
        }
        head += 4 + 4 * be16(d, head + 2) as usize;
    }
    let pad = if padding { *d.last()? as usize } else { 0 };
    let payload = d.len().checked_sub(head)?.checked_sub(pad)?;
    Some(Packet::Rtp {
        pt: d[1] & 0x7F,
        marker: d[1] & 0x80 != 0,
        seq: be16(d, 2),
        ssrc: be32(d, 8),
        payload,
    })
}

/// The packet types of a compound RTCP packet; `None` unless the lengths add
/// up and every part is version 2.
fn rtcp(d: &[u8]) -> Option<Packet> {
    let mut types = Vec::new();
    let mut at = 0;
    while at < d.len() {
        if d.len() < at + 4 || d[at] >> 6 != 2 {
            return None;
        }
        types.push(d[at + 1]);
        at += 4 * (be16(d, at + 2) as usize + 1);
        if types.len() > 16 {
            break;
        }
    }
    (at == d.len() || types.len() > 16).then_some(Packet::Rtcp { types })
}

// --- addresses ----------------------------------------------------------------

/// The configured server's addresses, resolved by the hooks once; empty until
/// then and in tests.
fn server_slot() -> &'static OnceLock<Vec<Ipv4Addr>> {
    static S: OnceLock<Vec<Ipv4Addr>> = OnceLock::new();
    &S
}

/// Records the server's addresses, so they show as `server`.
pub fn set_server_addrs(addrs: Vec<Ipv4Addr>) {
    let _ = server_slot().set(addrs);
}

/// The server's addresses, if they were resolved.
pub fn server_addrs() -> &'static [Ipv4Addr] {
    server_slot().get().map_or(&[], Vec::as_slice)
}

/// What kind of address `ip` is, for the log: never the address itself.
pub fn addr_class(ip: Ipv4Addr, servers: &[Ipv4Addr]) -> &'static str {
    if servers.contains(&ip) {
        "server"
    } else if ip.is_loopback() {
        "loopback"
    } else if ip.is_private()
        || ip.is_link_local()
        || ip.octets()[0] == 100 && ip.octets()[1] & 0xC0 == 64
    {
        "private"
    } else if ip.is_unspecified() {
        "any"
    } else {
        "public"
    }
}

/// `class:port`, as the log shows an address.
pub fn addr_label(ip: Ipv4Addr, port: u16, servers: &[Ipv4Addr]) -> String {
    format!("{}:{port}", addr_class(ip, servers))
}

// --- flows ----------------------------------------------------------------------

/// One way of one socket to one remote address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub socket: usize,
    pub remote: String,
    pub outbound: bool,
}

#[derive(Default, Clone, Copy)]
struct Count {
    packets: u64,
    bytes: u64,
    max: usize,
}

impl Count {
    fn add(&mut self, len: usize) {
        self.packets += 1;
        self.bytes += len as u64;
        self.max = self.max.max(len);
    }
}

struct Flow {
    module: &'static str,
    local_port: u16,
    logged: u32,
    streams: HashSet<String>,
    window_start: u64,
    window: BTreeMap<String, Count>,
    total: BTreeMap<String, Count>,
}

/// Keeps the per-flow counters and decides what is logged.
#[derive(Default)]
pub struct Tracker {
    flows: HashMap<FlowKey, Flow>,
}

impl Tracker {
    /// Takes one datagram of `len` bytes; returns the lines to log (often
    /// none).
    pub fn packet(
        &mut self,
        module: &'static str,
        key: FlowKey,
        local_port: u16,
        packet: &Packet,
        len: usize,
        now_ms: u64,
    ) -> Vec<String> {
        let mut lines = Vec::new();
        let head = flow_head(module, &key, local_port);
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            module,
            local_port,
            logged: 0,
            streams: HashSet::new(),
            window_start: now_ms,
            window: BTreeMap::new(),
            total: BTreeMap::new(),
        });
        let stream = packet.stream();
        let new_stream = flow.streams.len() < MAX_STREAMS && flow.streams.insert(stream.clone());
        if flow.logged < FIRST_PACKETS {
            flow.logged += 1;
            lines.push(format!(
                "{head} #{} {len} B: {}",
                flow.logged,
                packet.describe()
            ));
        } else if new_stream {
            lines.push(format!(
                "{head} new stream {stream}: {len} B: {}",
                packet.describe()
            ));
        }
        let class = packet.class();
        flow.window.entry(class.clone()).or_default().add(len);
        flow.total.entry(class).or_default().add(len);
        if now_ms.saturating_sub(flow.window_start) >= SUMMARY_MS {
            lines.push(format!(
                "{head} {}",
                summary(&flow.window, now_ms - flow.window_start)
            ));
            flow.window.clear();
            flow.window_start = now_ms;
        }
        lines
    }

    /// Closes every flow of `socket`: one line each with its totals.
    pub fn close(&mut self, socket: usize) -> Vec<String> {
        let keys: Vec<FlowKey> = self
            .flows
            .keys()
            .filter(|k| k.socket == socket)
            .cloned()
            .collect();
        let mut lines = Vec::new();
        for k in keys {
            if let Some(f) = self.flows.remove(&k) {
                let head = flow_head(f.module, &k, f.local_port);
                lines.push(format!("{head} closed; total: {}", totals(&f.total)));
            }
        }
        lines
    }
}

fn flow_head(module: &str, key: &FlowKey, local_port: u16) -> String {
    format!(
        "call media: {module} sock={} L:{local_port} {} {}",
        key.socket,
        if key.outbound { "OUT ->" } else { "IN  <-" },
        key.remote
    )
}

fn summary(window: &BTreeMap<String, Count>, ms: u64) -> String {
    let secs = (ms as f64 / 1000.0).max(0.001);
    let parts: Vec<String> = window
        .iter()
        .map(|(class, c)| {
            format!(
                "{class} {} pkt ({:.1}/s, {:.1} kbit/s) max {} B",
                c.packets,
                c.packets as f64 / secs,
                c.bytes as f64 * 8.0 / secs / 1000.0,
                c.max
            )
        })
        .collect();
    format!("{:.1}s: {}", secs, parts.join("; "))
}

fn totals(total: &BTreeMap<String, Count>) -> String {
    if total.is_empty() {
        return "nothing".to_string();
    }
    total
        .iter()
        .map(|(class, c)| format!("{class} {} pkt {} B max {} B", c.packets, c.bytes, c.max))
        .collect::<Vec<_>>()
        .join("; ")
}

/// The tracker the hooks share.
pub fn tracker() -> &'static Mutex<Tracker> {
    static T: std::sync::LazyLock<Mutex<Tracker>> = std::sync::LazyLock::new(Default::default);
    &T
}

// --- signalling -------------------------------------------------------------------

/// The log line for a SNAC payload that is an ICBM on channel 6, or `None`
/// for anything else. Only the fields named in the module docs are read out.
pub fn sip_line(dir: Direction, payload: &[u8], servers: &[Ipv4Addr]) -> Option<String> {
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
    if r.u16()? != CHANNEL_SIP {
        return None;
    }
    let peer = String::from_utf8_lossy(r.len8()?).into_owned();
    if inbound {
        r.u16()?; // warning level
        let n = r.u16()?;
        for _ in 0..n {
            r.u16()?;
            let len = r.u16()? as usize;
            r.skip(len)?;
        }
    }
    let tlvs = snac::read_tlvs(&s.body[s.body.len() - r.remaining()..]);
    let tag = dir.tag();
    let Some(sip) = snac::find_tlv(&tlvs, TLV_SIP) else {
        return Some(format!(
            "call SIP {tag} peer={peer} channel 6 without TLV 0x0005 (TLVs {})",
            tlvs.iter()
                .map(|t| format!("{:#06x}", t.tag))
                .collect::<Vec<_>>()
                .join(",")
        ));
    };
    Some(format!(
        "call SIP {tag} peer={peer} {}",
        sip_summary(sip, servers)
    ))
}

/// What a SIP message says about the call, without its content.
pub fn sip_summary(sip: &[u8], servers: &[Ipv4Addr]) -> String {
    let text = String::from_utf8_lossy(sip);
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => (text.as_ref(), ""),
    };
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let start = if let Some(rest) = first.strip_prefix("SIP/2.0 ") {
        let code = rest.split_whitespace().next().unwrap_or("?");
        let reason: String = rest
            .split_once(' ')
            .map_or("", |(_, r)| r)
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
            .take(32)
            .collect();
        format!("{code} {reason}")
    } else if first.ends_with("SIP/2.0") && first.contains(' ') {
        // The method only: the request URI names the callee's address.
        let method = first.split(' ').next().unwrap_or("?");
        if method.chars().all(|c| c.is_ascii_uppercase()) && !method.is_empty() {
            method.to_string()
        } else {
            "request (unreadable method)".to_string()
        }
    } else {
        return format!(
            "not SIP text ({} B, first byte {:#04x})",
            sip.len(),
            sip.first().copied().unwrap_or(0)
        );
    };
    let mut call_id = None;
    let mut from = None;
    let mut to = None;
    let mut cseq = None;
    let mut ctype = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "call-id" | "i" => call_id = Some(short_hash(value)),
            "from" | "f" => from = Some(uri_user(value)),
            "to" | "t" => to = Some(uri_user(value)),
            "cseq" => {
                cseq = Some(
                    value
                        .split_whitespace()
                        .map(|w| {
                            w.chars()
                                .filter(|c| c.is_ascii_alphanumeric())
                                .take(16)
                                .collect::<String>()
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            }
            "content-type" | "c" => {
                ctype = Some(
                    value
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || "/-+.".contains(*c))
                        .take(40)
                        .collect::<String>(),
                )
            }
            _ => {}
        }
    }
    let mut out = format!(
        "{start} cseq={} call={} from={} to={} {} B",
        cseq.as_deref().unwrap_or("?"),
        call_id.as_deref().unwrap_or("?"),
        from.as_deref().unwrap_or("?"),
        to.as_deref().unwrap_or("?"),
        sip.len()
    );
    if !body.is_empty() {
        if ctype
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case("application/sdp"))
            || body.starts_with("v=0")
        {
            out.push_str(&format!(" sdp: {}", sdp_summary(body, servers)));
        } else {
            out.push_str(&format!(
                " body {} ({} B)",
                ctype.as_deref().unwrap_or("of no type"),
                body.len()
            ));
        }
    }
    out
}

/// The user part of a From/To value (`"x" <sip:100001@host>;tag=..`):
/// letters and digits only, at most 24.
fn uri_user(v: &str) -> String {
    let uri = v
        .split_once('<')
        .map_or(v, |(_, r)| r.split('>').next().unwrap_or(r));
    let uri = uri
        .trim()
        .trim_start_matches("sips:")
        .trim_start_matches("sip:");
    match uri.split_once('@') {
        Some((user, _)) => user
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
            .take(24)
            .collect(),
        None => "(no user)".to_string(),
    }
}

/// The first eight hex digits of SHA-256: tells calls apart, says nothing.
fn short_hash(v: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, v.as_bytes());
    d.as_ref()[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// One media section of an SDP as it is read.
#[derive(Default)]
struct Media {
    line: String,
    rtpmap: Vec<String>,
    crypto: usize,
    candidates: BTreeMap<String, usize>,
    conn: Option<String>,
    attrs: Vec<String>,
}

/// The media lines of an SDP, with what each says about codecs, keys and
/// candidates.
pub fn sdp_summary(sdp: &str, servers: &[Ipv4Addr]) -> String {
    let mut session_conn = None;
    let mut session_crypto = 0;
    let mut media: Vec<Media> = Vec::new();
    for line in sdp.lines() {
        let line = line.trim_end();
        let cur = media.last_mut();
        if let Some(m) = line.strip_prefix("m=") {
            let mut f = m.split_whitespace();
            let kind: String = f.next().unwrap_or("?").chars().take(12).collect();
            let port = f.next().unwrap_or("?");
            let proto: String = f.next().unwrap_or("?").chars().take(20).collect();
            let pts: Vec<&str> = f.take(24).collect();
            media.push(Media {
                line: format!("{kind} port={port} {proto} pt=[{}]", pts.join(",")),
                ..Media::default()
            });
        } else if let Some(c) = line.strip_prefix("c=") {
            let label = c
                .split_whitespace()
                .nth(2)
                .and_then(|a| a.split('/').next())
                .and_then(|a| a.parse::<Ipv4Addr>().ok())
                .map_or("?", |ip| addr_class(ip, servers))
                .to_string();
            match cur {
                Some(m) => m.conn = Some(label),
                None => session_conn = Some(label),
            }
        } else if let Some(a) = line.strip_prefix("a=") {
            let (name, value) = a.split_once(':').unwrap_or((a, ""));
            let Some(m) = cur else {
                if name == "crypto" {
                    session_crypto += 1;
                }
                continue;
            };
            match name {
                "rtpmap" => m.rtpmap.push(
                    value
                        .split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join("=")
                        .chars()
                        .take(32)
                        .collect(),
                ),
                "crypto" => m.crypto += 1,
                "candidate" => {
                    let mut f = value.split_whitespace();
                    let typ = loop {
                        match f.next() {
                            Some("typ") => break f.next().unwrap_or("?"),
                            Some(_) => continue,
                            None => break "?",
                        }
                    };
                    *m.candidates
                        .entry(typ.chars().take(8).collect())
                        .or_default() += 1;
                }
                _ => {
                    let n: String = name
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                        .take(24)
                        .collect();
                    if !m.attrs.contains(&n) && m.attrs.len() < 16 {
                        m.attrs.push(n);
                    }
                }
            }
        }
    }
    if media.is_empty() {
        return format!("no m= line ({} B)", sdp.len());
    }
    let parts: Vec<String> = media
        .iter()
        .map(|m| {
            let cands = if m.candidates.is_empty() {
                "0".to_string()
            } else {
                format!(
                    "{} ({})",
                    m.candidates.values().sum::<usize>(),
                    m.candidates
                        .iter()
                        .map(|(t, n)| format!("{t} {n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            format!(
                "{} rtpmap=[{}] c={} crypto={} candidates={} attrs=[{}]",
                m.line,
                m.rtpmap.join(","),
                m.conn.as_deref().or(session_conn.as_deref()).unwrap_or("?"),
                m.crypto + session_crypto,
                cands,
                m.attrs.join(",")
            )
        })
        .collect();
    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun_msg(msg_type: u16, id: [u8; 16], attrs: &[(u16, &[u8])], padded: bool) -> Vec<u8> {
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

    fn rtp(pt: u8, seq: u16, ssrc: u32, payload: usize) -> Vec<u8> {
        let mut p = vec![0x80, pt];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&1234u32.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend(std::iter::repeat_n(0xAB, payload));
        p
    }

    const COOKIE: [u8; 4] = [0x72, 0xC6, 0x4B, 0xC6];

    #[test]
    fn classic_stun_binding() {
        let m = stun_msg(0x0001, [7; 16], &[(0x0003, &[0, 0, 0, 0])], false);
        let p = classify(&m);
        assert_eq!(p.class(), "stun");
        assert_eq!(p.describe(), "STUN/3489 Binding Request (0x0001)");
    }

    #[test]
    fn modern_stun_binding_response() {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&STUN_MAGIC.to_be_bytes());
        let m = stun_msg(0x0101, id, &[(0x0020, &[0, 1, 2, 3, 4, 5, 6, 7])], true);
        assert!(classify(&m)
            .describe()
            .starts_with("STUN/5389 Binding Response"));
    }

    #[test]
    fn aol_turn_allocate_and_set_active_destination() {
        let m = stun_msg(0x0003, [1; 16], &[(0x000F, &COOKIE)], false);
        let p = classify(&m);
        assert_eq!(p.class(), "turn");
        assert!(p.describe().contains("TURN/aol Allocate Request"));
        let m = stun_msg(
            0x0006,
            [1; 16],
            &[(0x000F, &COOKIE), (0x0011, &[0, 1, 0x40, 0, 1, 2, 3, 4])],
            false,
        );
        assert!(classify(&m)
            .describe()
            .contains("Set Active Destination Request"));
    }

    #[test]
    fn aol_turn_send_carries_rtp_unpadded() {
        // An odd-sized RTP packet: the DATA attribute is not padded in this
        // dialect, and the classifier must still see the whole message.
        let inner = rtp(103, 77, 0xDEADBEEF, 61);
        let dest = [0u8, 1, 0x40, 0x00, 192, 0, 2, 1];
        let m = stun_msg(
            0x0004,
            [2; 16],
            &[(0x000F, &COOKIE), (0x0011, &dest), (0x0013, &inner)],
            false,
        );
        let p = classify(&m);
        assert_eq!(p.class(), "turn-send/rtp");
        assert_eq!(p.stream(), "turn-send/rtp pt=103 ssrc=0xdeadbeef");
        let d = p.describe();
        assert!(d.contains("Send Request"), "{d}");
        assert!(d.contains(&format!("carrying {} B", inner.len())), "{d}");
        assert!(d.contains("payload=61 B"), "{d}");
    }

    #[test]
    fn aol_turn_data_indication_carries_rtcp() {
        let mut rr = vec![0x81, 201, 0, 7];
        rr.extend_from_slice(&[0; 28]);
        let m = stun_msg(
            0x0115,
            [3; 16],
            &[
                (0x000F, &COOKIE),
                (0x0012, &[0, 1, 0, 9, 1, 2, 3, 4]),
                (0x0013, &rr),
            ],
            false,
        );
        let p = classify(&m);
        assert_eq!(p.class(), "turn-data/rtcp");
        assert!(p.describe().contains("RTCP [RR]"));
    }

    #[test]
    fn rfc5766_send_indication_and_channel_data() {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&STUN_MAGIC.to_be_bytes());
        let inner = rtp(0, 1, 5, 160);
        let m = stun_msg(0x0016, id, &[(0x0013, &inner)], true);
        assert_eq!(classify(&m).class(), "turn-send/rtp");

        let inner = rtp(8, 2, 6, 161);
        let mut cd = vec![0x40, 0x01];
        cd.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        cd.extend_from_slice(&inner);
        while cd.len() % 4 != 0 {
            cd.push(0);
        }
        let p = classify(&cd);
        assert_eq!(p.class(), "channeldata/rtp");
        assert!(p.describe().starts_with("ChannelData 0x4001"));
    }

    #[test]
    fn rtp_fields_and_payload_size() {
        let mut p = rtp(97, 4242, 0x01020304, 100);
        p[1] |= 0x80; // marker
        match classify(&p) {
            Packet::Rtp {
                pt,
                marker,
                seq,
                ssrc,
                payload,
            } => {
                assert_eq!(
                    (pt, marker, seq, ssrc, payload),
                    (97, true, 4242, 0x01020304, 100)
                );
            }
            other => panic!("{other:?}"),
        }
        // A CSRC, an extension and padding are not payload.
        let mut q = vec![0x80 | 0x20 | 0x10 | 1, 0];
        q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 9]);
        q.extend_from_slice(&[0, 0, 0, 1]); // CSRC
        q.extend_from_slice(&[0xBE, 0xDE, 0, 1, 0, 0, 0, 0]); // extension, 1 word
        q.extend_from_slice(&[1; 20]);
        q.extend_from_slice(&[0, 0, 3]); // padding, 3 bytes
        match classify(&q) {
            Packet::Rtp { payload, .. } => assert_eq!(payload, 20),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn compound_rtcp() {
        let mut sr = vec![0x80, 200, 0, 6];
        sr.extend_from_slice(&[0; 24]);
        let mut sdes = vec![0x81, 202, 0, 2];
        sdes.extend_from_slice(&[0; 8]);
        let p = classify(&[sr, sdes].concat());
        assert_eq!(
            p,
            Packet::Rtcp {
                types: vec![200, 202]
            }
        );
        assert_eq!(p.describe(), "RTCP [SR, SDES]");
        // A length that does not add up is not RTCP.
        assert_eq!(classify(&[0x80, 200, 0, 6, 0, 0]).class(), "other");
    }

    #[test]
    fn other_and_short() {
        assert_eq!(classify(&[]).class(), "other");
        assert_eq!(classify(&[0xFF, 1, 2]).class(), "other");
        assert_eq!(classify(b"\x00\x01\x00\x00").class(), "other");
        // A STUN header whose length does not cover the datagram.
        let mut m = stun_msg(0x0001, [0; 16], &[], false);
        m.push(0);
        assert_eq!(classify(&m).class(), "other");
    }

    #[test]
    fn tracker_logs_first_packets_then_summaries() {
        let mut t = Tracker::default();
        let key = FlowKey {
            socket: 9,
            remote: "server:3478".into(),
            outbound: true,
        };
        let mut lines = Vec::new();
        for i in 0..200u64 {
            let p = classify(&rtp(103, i as u16, 7, 60 + (i % 3) as usize));
            lines.extend(t.packet("sipXtapi.dll", key.clone(), 16384, &p, 72, i * 30));
        }
        let singles = lines.iter().filter(|l| l.contains(" #")).count();
        assert_eq!(singles, FIRST_PACKETS as usize);
        let sums: Vec<_> = lines.iter().filter(|l| l.contains("pkt (")).collect();
        assert!(!sums.is_empty() && sums.len() <= 2, "{lines:#?}");
        assert!(
            sums[0].contains("rtp ") && sums[0].contains("max 72 B"),
            "{}",
            sums[0]
        );
        // A new payload type later on the same flow is said once.
        let p = classify(&rtp(0, 1, 7, 160));
        let l = t.packet("sipXtapi.dll", key.clone(), 16384, &p, 172, 6_100);
        assert!(l.iter().any(|l| l.contains("new stream rtp pt=0")), "{l:?}");
        let l = t.packet("sipXtapi.dll", key, 16384, &p, 172, 6_120);
        assert!(l.is_empty(), "{l:?}");
        let closed = t.close(9);
        assert_eq!(closed.len(), 1);
        assert!(closed[0].contains("total: rtp 202 pkt"), "{}", closed[0]);
        assert!(t.close(9).is_empty());
    }

    #[test]
    fn addresses_are_classes() {
        let srv = [Ipv4Addr::new(203, 0, 113, 5)];
        assert_eq!(
            addr_label(Ipv4Addr::new(203, 0, 113, 5), 3478, &srv),
            "server:3478"
        );
        assert_eq!(addr_class(Ipv4Addr::new(192, 168, 1, 2), &srv), "private");
        assert_eq!(addr_class(Ipv4Addr::new(10, 0, 0, 1), &srv), "private");
        assert_eq!(addr_class(Ipv4Addr::new(100, 64, 0, 1), &srv), "private");
        assert_eq!(addr_class(Ipv4Addr::new(127, 0, 0, 1), &srv), "loopback");
        assert_eq!(addr_class(Ipv4Addr::new(198, 51, 100, 7), &srv), "public");
    }

    /// An INVITE as sipXtapi writes it (shape of sipX 3.x), with an SDP offer
    /// for audio and video, ICE candidates and no `a=crypto`.
    const INVITE: &str = "INVITE sip:100002@198.51.100.7:5061 SIP/2.0\r\n\
        From: \"100001\"<sip:100001@192.168.1.20:5061>;tag=1c5a2b\r\n\
        To: <sip:100002@198.51.100.7:5061>\r\n\
        Call-Id: 4f3a2b1c-9d8e7f6a@192.168.1.20\r\n\
        Cseq: 1 INVITE\r\n\
        Contact: <sip:100001@192.168.1.20:5061>\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 400\r\n\
        User-Agent: sipX/3.0\r\n\
        \r\n\
        v=0\r\n\
        o=sipX 5 5 IN IP4 192.168.1.20\r\n\
        s=call\r\n\
        c=IN IP4 192.168.1.20\r\n\
        t=0 0\r\n\
        m=audio 16384 RTP/AVP 103 0 8 101\r\n\
        a=rtpmap:103 ISAC/16000\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        a=rtpmap:8 PCMA/8000\r\n\
        a=rtpmap:101 telephone-event/8000\r\n\
        a=fmtp:101 0-15\r\n\
        a=candidate:1 1 UDP 0.9 192.168.1.20 16384 typ host\r\n\
        a=candidate:2 1 UDP 0.8 198.51.100.20 16384 typ srflx\r\n\
        a=candidate:3 1 UDP 0.5 203.0.113.5 49170 typ relay\r\n\
        a=sendrecv\r\n\
        m=video 16386 RTP/AVP 98 34\r\n\
        c=IN IP4 203.0.113.5\r\n\
        a=rtpmap:98 VP71/90000\r\n\
        a=rtpmap:34 H263/90000\r\n";

    fn ch6_to_host(target: &str, sip: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&snac::FOOD_ICBM.to_be_bytes());
        p.extend_from_slice(&snac::ICBM_MSG_TO_HOST.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        p.extend_from_slice(&CHANNEL_SIP.to_be_bytes());
        p.push(target.len() as u8);
        p.extend_from_slice(target.as_bytes());
        snac::put_tlv(&mut p, TLV_SIP, sip);
        p
    }

    fn ch6_to_client(sender: &str, sip: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&snac::FOOD_ICBM.to_be_bytes());
        p.extend_from_slice(&snac::ICBM_MSG_TO_CLIENT.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 2]);
        p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        p.extend_from_slice(&CHANNEL_SIP.to_be_bytes());
        p.push(sender.len() as u8);
        p.extend_from_slice(sender.as_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]); // warning, one user-info TLV
        snac::put_tlv(&mut p, 0x0006, &[0, 0, 0, 0]);
        snac::put_tlv(&mut p, TLV_SIP, sip);
        p
    }

    #[test]
    fn invite_fields_and_nothing_else() {
        let srv = [Ipv4Addr::new(203, 0, 113, 5)];
        let l = sip_line(
            Direction::Outbound,
            &ch6_to_host("100002", INVITE.as_bytes()),
            &srv,
        )
        .unwrap();
        assert!(
            l.starts_with("call SIP OUT peer=100002 INVITE cseq=1 INVITE call="),
            "{l}"
        );
        assert!(l.contains("from=100001 to=100002"), "{l}");
        assert!(
            l.contains("audio port=16384 RTP/AVP pt=[103,0,8,101] rtpmap=[103=ISAC/16000,0=PCMU/8000,8=PCMA/8000,101=telephone-event/8000] c=private crypto=0 candidates=3 (host 1, relay 1, srflx 1) attrs=[fmtp,sendrecv]"),
            "{l}"
        );
        assert!(
            l.contains("video port=16386 RTP/AVP pt=[98,34] rtpmap=[98=VP71/90000,34=H263/90000] c=server crypto=0 candidates=0"),
            "{l}"
        );
        // No address, no Call-ID, no request URI in the line.
        for secret in ["192.168", "198.51", "203.0", "4f3a2b1c", "sip:", "sipX/3.0"] {
            assert!(!l.contains(secret), "{secret} leaked: {l}");
        }
        assert_eq!(l.matches("call=").count(), 1);
        let hash = short_hash("4f3a2b1c-9d8e7f6a@192.168.1.20");
        assert!(l.contains(&format!("call={hash}")), "{l}");
    }

    #[test]
    fn response_and_inbound_ack_with_crypto() {
        let ok = "SIP/2.0 200 OK\r\nf: <sip:100001@h>;tag=1\r\nt: <sip:100002@h>;tag=2\r\n\
                  i: abc\r\nCSeq: 1 INVITE\r\nc: application/sdp\r\n\r\n\
                  v=0\r\nc=IN IP4 198.51.100.9\r\nm=audio 20000 RTP/SAVP 103\r\n\
                  a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SECRETKEYMATERIAL\r\n";
        let l = sip_line(
            Direction::Inbound,
            &ch6_to_client("100002", ok.as_bytes()),
            &[],
        )
        .unwrap();
        assert!(
            l.starts_with("call SIP IN  peer=100002 200 OK cseq=1 INVITE"),
            "{l}"
        );
        assert!(l.contains("audio port=20000 RTP/SAVP pt=[103]"), "{l}");
        assert!(l.contains("c=public crypto=1"), "{l}");
        assert!(!l.contains("SECRETKEY") && !l.contains("AES_CM"), "{l}");
        assert!(l.contains(&format!("call={}", short_hash("abc"))));

        let bye =
            "BYE sip:100001@h SIP/2.0\r\nCSeq: 2 BYE\r\nCall-ID: abc\r\nContent-Length: 0\r\n\r\n";
        let l = sip_line(
            Direction::Inbound,
            &ch6_to_client("100002", bye.as_bytes()),
            &[],
        )
        .unwrap();
        assert!(l.contains("BYE cseq=2 BYE"), "{l}");
        assert!(!l.contains("sdp:"), "{l}");
    }

    #[test]
    fn other_channels_and_snacs_are_not_sip() {
        let mut p = ch6_to_host("1", b"INVITE x SIP/2.0\r\n\r\n");
        p[18] = 0; // channel 6 -> 1 (after the SNAC header and the cookie)
        p[19] = 1;
        assert!(sip_line(Direction::Outbound, &p, &[]).is_none());
        // The same SNAC in the wrong direction is not taken.
        assert!(sip_line(Direction::Inbound, &ch6_to_host("1", b"x"), &[]).is_none());
        let l = sip_line(Direction::Outbound, &ch6_to_host("1", &[0, 1, 2]), &[]).unwrap();
        assert!(l.contains("not SIP text (3 B, first byte 0x00)"), "{l}");
    }
}
