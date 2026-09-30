//! Decoding of ICBM message bodies and ICQ offline-message replies into a
//! `Message` record for the log. Best-effort: anything that does not parse
//! yields `None`, and the raw bytes have already passed through the hook
//! untouched by the time we get here.

use crate::snac::{self, Reader};
use crate::text;

/// ICBM channels.
pub const CHANNEL_IM: u16 = 0x0001;
pub const CHANNEL_RENDEZVOUS: u16 = 0x0002;

/// TLVs inside an ICBM body (see wire/snacs.go).
const TLV_AOL_IM_DATA: u16 = 0x0002; // channel-1 fragment list
const TLV_RENDEZVOUS_DATA: u16 = 0x0005; // channel-2 fragment

/// The rendezvous service-data TLV, big-endian inside the ch2 fragment.
const RDV_TLV_SVC_DATA: u16 = 0x2711;

/// Which way the message was travelling on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client -> server (hooked `send`).
    Outbound,
    /// Server -> client (hooked `recv`).
    Inbound,
}

impl Direction {
    pub fn tag(self) -> &'static str {
        match self {
            Direction::Outbound => "OUT",
            Direction::Inbound => "IN ",
        }
    }
}

/// A decoded message worth logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub direction: Direction,
    /// The other party: the target (outbound) or sender (inbound) screen name /
    /// UIN as the ICBM names it.
    pub peer: String,
    /// A short description of the channel and form, e.g. "ch1/html",
    /// "ch2/type2", "offline".
    pub form: String,
    /// The decoded, display-ready text.
    pub text: String,
}

impl Message {
    /// One log line.
    pub fn log_line(&self) -> String {
        format!(
            "{} peer={} {} text=\"{}\"",
            self.direction.tag(),
            if self.peer.is_empty() {
                "?"
            } else {
                &self.peer
            },
            self.form,
            text::for_log(&self.text, 512)
        )
    }
}

/// Parses an outbound `ICBMChannelMsgToHost` body.
/// Layout: cookie[8], channel:u16, target(len8), TLVs.
pub fn parse_to_host(body: &[u8]) -> Option<Message> {
    let mut r = Reader::new(body);
    r.skip(8)?; // cookie
    let channel = r.u16()?;
    let peer = String::from_utf8_lossy(r.len8()?).into_owned();
    let tlvs = snac::read_tlvs(&body[body.len() - r.remaining()..]);
    decode_channel(Direction::Outbound, channel, peer, &tlvs)
}

/// Parses an inbound `ICBMChannelMsgToClient` body.
/// Layout: cookie[8], channel:u16, sender(len8), warning:u16, tlvCount:u16,
/// [tlvCount user-info TLVs], message TLVs.
pub fn parse_to_client(body: &[u8]) -> Option<Message> {
    let mut r = Reader::new(body);
    r.skip(8)?; // cookie
    let channel = r.u16()?;
    let peer = String::from_utf8_lossy(r.len8()?).into_owned();
    let _warning = r.u16()?;
    let tlv_count = r.u16()? as usize;
    // Skip the user-info TLV block.
    for _ in 0..tlv_count {
        let _tag = r.u16()?;
        let len = r.u16()? as usize;
        r.skip(len)?;
    }
    let tlvs = snac::read_tlvs(&body[body.len() - r.remaining()..]);
    decode_channel(Direction::Inbound, channel, peer, &tlvs)
}

fn decode_channel(
    dir: Direction,
    channel: u16,
    peer: String,
    tlvs: &[snac::Tlv<'_>],
) -> Option<Message> {
    match channel {
        CHANNEL_IM => {
            let data = snac::find_tlv(tlvs, TLV_AOL_IM_DATA)?;
            let (text, is_html) = decode_ch1_fragments(data)?;
            Some(Message {
                direction: dir,
                peer,
                form: format!("ch1/{}", if is_html { "html" } else { "text" }),
                text,
            })
        }
        CHANNEL_RENDEZVOUS => {
            let data = snac::find_tlv(tlvs, TLV_RENDEZVOUS_DATA)?;
            let text = decode_ch2_text(data)?;
            Some(Message {
                direction: dir,
                peer,
                form: "ch2/type2".to_string(),
                text,
            })
        }
        _ => None,
    }
}

/// Decodes a channel-1 fragment list, returning the message text and whether it
/// looks like HTML. Fragment: id:u8, version:u8, len:u16, payload[len]. The
/// message fragment is id==1: charset:u16, lang:u16, text[].
fn decode_ch1_fragments(data: &[u8]) -> Option<(String, bool)> {
    let mut r = Reader::new(data);
    while r.remaining() >= 4 {
        let id = r.u8()?;
        let _version = r.u8()?;
        let len = r.u16()? as usize;
        let payload = r.bytes(len)?;
        if id == 1 {
            let mut m = Reader::new(payload);
            let charset = m.u16()?;
            let _lang = m.u16()?;
            let text_bytes = m.bytes(m.remaining())?;
            let decoded = text::decode(charset, text_bytes);
            let is_html = looks_like_html(&decoded);
            return Some((decoded, is_html));
        }
    }
    None
}

/// Reports whether the text carries HTML markup: a `<` that begins a tag
/// (`</...` or `<` followed by a letter). ICQ 6/7 wrap smileys and formatting
/// in HTML (`<font sml="...">`), so this tells a formatted message apart from a
/// plain one for the log.
fn looks_like_html(s: &str) -> bool {
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'<' {
            match b.get(i + 1) {
                Some(&c) if c == b'/' || c.is_ascii_alphabetic() => return true,
                _ => {}
            }
        }
    }
    false
}

/// Best-effort text extraction from a channel-2 (rendezvous) fragment.
/// Fragment: type:u16, cookie[8], capability[16], then a big-endian TLV block.
/// The extended-message text rides in the service-data TLV 0x2711 as a
/// plugin blob: `hdrLen:u16 | ... GUID ... | restLen:u32 | docLen:u32 | doc`.
/// We extract the document; failing that, the longest printable run.
fn decode_ch2_text(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);
    let _type = r.u16()?;
    r.skip(8)?; // cookie
    r.skip(16)?; // capability
    let rest = r.bytes(r.remaining())?;
    let tlvs = snac::read_tlvs(rest);
    let svc = snac::find_tlv(&tlvs, RDV_TLV_SVC_DATA)?;
    if let Some(doc) = plugin_document(svc) {
        return Some(String::from_utf8_lossy(doc).into_owned());
    }
    longest_printable(svc)
}

/// Extracts the document from a plugin service-data blob, mirroring the layout
/// the server writes (foodgroup/icbm_tzer.go): a u16 header length precedes the
/// blob, and after the plugin header come a u32 rest length and a u32 document
/// length, then the document bytes.
fn plugin_document(svc: &[u8]) -> Option<&[u8]> {
    if svc.len() < 2 {
        return None;
    }
    let hdr_len = u16::from_le_bytes([svc[0], svc[1]]) as usize;
    let pos = 2usize.checked_add(hdr_len)?;
    // After the first header: capabilities/unknown, then rest-len u32 and
    // doc-len u32. Search forward a little for the doc-len that fits.
    let mut at = pos;
    while at + 8 <= svc.len() {
        let doc_len =
            u32::from_le_bytes([svc[at + 4], svc[at + 5], svc[at + 6], svc[at + 7]]) as usize;
        let start = at + 8;
        if doc_len > 0 && start + doc_len <= svc.len() {
            return Some(&svc[start..start + doc_len]);
        }
        at += 1;
    }
    None
}

fn longest_printable(bytes: &[u8]) -> Option<String> {
    let mut best: (usize, usize) = (0, 0);
    let mut start = 0usize;
    let mut i = 0usize;
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b >= 0x80;
    while i <= bytes.len() {
        let run_end = i == bytes.len() || !printable(bytes[i]);
        if run_end {
            if i - start > best.1 - best.0 {
                best = (start, i);
            }
            start = i + 1;
        }
        i += 1;
    }
    if best.1 - best.0 >= 3 {
        Some(String::from_utf8_lossy(&bytes[best.0..best.1]).into_owned())
    } else {
        None
    }
}

// --- ICQ offline messages (food group 0x0015) -------------------------------

const ICQ_TLV_DATA: u16 = 0x0001;
const ICQ_REQ_OFFLINE_REPLY: u16 = 0x0041;

/// Parses an ICQ meta body (subgroup 0x0002) and, when it carries an offline
/// message reply (0x0041), returns the decoded message. Everything is
/// little-endian inside the 0x0001 TLV.
pub fn parse_icq_offline(body: &[u8]) -> Option<Message> {
    let tlvs = snac::read_tlvs(body);
    let env = snac::find_tlv(&tlvs, ICQ_TLV_DATA)?;
    // The value starts with a u16 length prefix of the message block.
    if env.len() < 2 {
        return None;
    }
    let inner = &env[2..];
    let mut r = LeReader::new(inner);
    let _uin = r.u32()?;
    let req_type = r.u16()?;
    let _seq = r.u16()?;
    if req_type != ICQ_REQ_OFFLINE_REPLY {
        return None;
    }
    let sender = r.u32()?;
    r.skip(2 + 1 + 1 + 1 + 1)?; // year(u16), month, day, hour, minute
    let _msg_type = r.u8()?;
    let _flags = r.u8()?;
    let mlen = r.u16()? as usize;
    let raw = r.bytes(mlen)?;
    // Trim a trailing NUL and decode as UTF-8, falling back to Latin-1.
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    let text = match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => raw.iter().map(|&b| b as char).collect(),
    };
    Some(Message {
        direction: Direction::Inbound,
        peer: sender.to_string(),
        form: "offline".to_string(),
        text,
    })
}

/// A little-endian cursor for the ICQ envelope.
struct LeReader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> LeReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        LeReader { data, pos: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        let lo = *self.data.get(self.pos)?;
        let hi = *self.data.get(self.pos + 1)?;
        self.pos += 2;
        Some(u16::from_le_bytes([lo, hi]))
    }
    fn u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.pos + n > self.data.len() {
            return None;
        }
        self.pos += n;
        Some(())
    }
}
