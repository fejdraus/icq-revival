//! SNAC-level rewriting of message text (Phase 1).
//!
//! Given one SNAC seen on the BOS connection, [`process`] decides whether it is
//! a message this phase handles, logs it, and - in harness mode - returns the
//! SNAC rebuilt with the text transformed by [`crate::harness`] and every length
//! on the way down fixed: the TLV, the channel-1 fragment, the little-endian
//! lengths of a channel-2 type-2 message or of an ICQ offline reply. The SNAC
//! header, every other TLV and any trailing bytes are copied as they were, so
//! the only difference on the wire is the text and the lengths around it.
//!
//! Handled: outbound ICBM `0x0004/0x0006` and inbound `0x0004/0x0007`, channel
//! 1 (fragment 1 of TLV 0x0002) and channel 2 server relay (plain type-2 text in
//! TLV 0x2711 of TLV 0x0005), and inbound ICQ `0x0015/0x0003` offline messages.
//! Besides messages, the client's capability list (`0x0002/0x0004`) gets the
//! add-on's capability appended, and contacts announcing it are reported
//! ([`crate::caps`]). Anything else is not touched.

use crate::caps::{self, Announce};
use crate::config::{Mode, Policy};
use crate::harness;
use crate::icbm::{self, Direction, Message, TextAt};
use crate::snac::{self, Reader};
use crate::text;

/// The most message text, in bytes, a rewrite may produce. A message that would
/// grow past it is sent unchanged: the client's own limits are close above
/// (Phase 2 splits long messages; this phase does not).
pub const MAX_TEXT: usize = 7000;

/// What became of one SNAC.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Processed {
    /// The rewritten SNAC (header and body), or `None` to pass the original.
    pub payload: Option<Vec<u8>>,
    /// Lines for the log.
    pub lines: Vec<String>,
    /// Contacts whose user info said whether they announce the add-on.
    pub e2e_contacts: Vec<(String, bool)>,
}

/// The kinds of SNAC that carry message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    ToHost,
    ToClient,
    Offline,
}

fn kind_of(dir: Direction, food_group: u16, sub_group: u16) -> Option<Kind> {
    match (dir, food_group, sub_group) {
        (Direction::Outbound, snac::FOOD_ICBM, snac::ICBM_MSG_TO_HOST) => Some(Kind::ToHost),
        (Direction::Inbound, snac::FOOD_ICBM, snac::ICBM_MSG_TO_CLIENT) => Some(Kind::ToClient),
        (Direction::Inbound, snac::FOOD_ICQ, snac::ICQ_DB_REPLY) => Some(Kind::Offline),
        _ => None,
    }
}

fn decode(kind: Kind, body: &[u8]) -> Option<Message> {
    match kind {
        Kind::ToHost => icbm::parse_to_host(body),
        Kind::ToClient => icbm::parse_to_client(body),
        Kind::Offline => icbm::parse_icq_offline(body),
    }
}

/// A text transform: charset id and text in, new text out, `None` to leave it.
type Transform = fn(u16, &[u8]) -> Option<Vec<u8>>;

/// Why a message could not be rewritten.
type Refusal = &'static str;

/// Looks at one SNAC payload travelling in `dir` and returns what to send in
/// its place and what to log.
pub fn process(dir: Direction, payload: &[u8], policy: &Policy) -> Processed {
    let mut p = Processed::default();
    let Some(s) = snac::parse(payload) else {
        return p;
    };
    match (dir, s.food_group, s.sub_group) {
        (Direction::Inbound, snac::FOOD_BUDDY, snac::BUDDY_ARRIVED) => {
            p.e2e_contacts = caps::contacts(s.body);
            return p;
        }
        (Direction::Outbound, snac::FOOD_LOCATE, snac::LOCATE_SET_INFO)
            if policy.mode == Mode::Harness =>
        {
            match caps::announce(s.body) {
                Announce::Added(body) => {
                    let header_len = payload.len() - s.body.len();
                    p.payload = Some([&payload[..header_len], &body[..]].concat());
                    p.lines
                        .push("OUT capabilities: E2E add-on announced (+16 bytes)".to_string());
                }
                Announce::Malformed => p.lines.push(
                    "OUT capabilities: list is not whole GUIDs; E2E add-on not announced"
                        .to_string(),
                ),
                Announce::AlreadyThere | Announce::NoList => {}
            }
            return p;
        }
        _ => {}
    }
    let Some(kind) = kind_of(dir, s.food_group, s.sub_group) else {
        return p;
    };
    let Some(msg) = decode(kind, s.body) else {
        return p;
    };
    if policy.mode == Mode::Observe {
        p.lines.push(msg.log_line());
        return p;
    }
    let (transform, verb): (Transform, &str) = match dir {
        Direction::Outbound => (harness::apply_charset, "rewritten"),
        Direction::Inbound => (harness::undo_charset, "restored"),
    };
    if dir == Direction::Outbound && !policy.rewrites_to(&msg.peer) {
        p.lines.push(format!(
            "{} (not rewritten: contact not in ICQE2E_PEERS)",
            msg.log_line()
        ));
        return p;
    }
    let header_len = payload.len() - s.body.len();
    match rewrite_body(kind, s.body, transform) {
        Ok(Some(body)) => {
            let mut out = Vec::with_capacity(header_len + body.len());
            out.extend_from_slice(&payload[..header_len]);
            out.extend_from_slice(&body);
            let delta = out.len() as isize - payload.len() as isize;
            let new = decode(kind, &body);
            let (shown, wire) = match dir {
                Direction::Outbound => (Some(&msg), new.as_ref()),
                Direction::Inbound => (new.as_ref(), Some(&msg)),
            };
            p.lines.push(format!(
                "{} {verb} {delta:+} bytes wire=\"{}\"",
                shown
                    .map(Message::log_line)
                    .unwrap_or_else(|| msg.log_line()),
                wire.map(|m| text::for_log(&m.text, 512))
                    .unwrap_or_default()
            ));
            p.payload = Some(out);
        }
        Ok(None) => p.lines.push(msg.log_line()),
        Err(why) => p
            .lines
            .push(format!("{} (left unchanged: {why})", msg.log_line())),
    }
    p
}

/// Rebuilds a message SNAC body with transformed text; `Ok(None)` when there is
/// nothing to change (inbound text without the marker, a message type this
/// phase does not handle).
fn rewrite_body(kind: Kind, body: &[u8], f: Transform) -> Result<Option<Vec<u8>>, Refusal> {
    if kind == Kind::Offline {
        return rewrite_tlv_block(body, |tag, value| {
            if tag == icbm::ICQ_TLV_DATA {
                rewrite_offline(value, f)
            } else {
                Ok(None)
            }
        });
    }
    let Some(head) = icbm_head_len(kind, body) else {
        return Ok(None);
    };
    let channel = u16::from_be_bytes([body[8], body[9]]);
    let rest = rewrite_tlv_block(&body[head..], |tag, value| match (channel, tag) {
        (icbm::CHANNEL_IM, icbm::TLV_AOL_IM_DATA) => rewrite_ch1(value, f),
        (icbm::CHANNEL_RENDEZVOUS, icbm::TLV_RENDEZVOUS_DATA) => rewrite_ch2(value, f),
        _ => Ok(None),
    })?;
    Ok(rest.map(|r| [&body[..head], &r[..]].concat()))
}

/// The length of an ICBM body before its message TLVs: cookie, channel, screen
/// name, and for inbound messages the warning level and the user-info block.
fn icbm_head_len(kind: Kind, body: &[u8]) -> Option<usize> {
    let mut r = Reader::new(body);
    r.skip(8)?; // cookie
    r.u16()?; // channel
    r.len8()?; // screen name
    if kind == Kind::ToClient {
        r.u16()?; // warning level
        let count = r.u16()?;
        for _ in 0..count {
            r.u16()?;
            let len = r.u16()? as usize;
            r.skip(len)?;
        }
    }
    Some(body.len() - r.remaining())
}

/// Rebuilds a TLV block with the first entry `edit` changes, keeping every
/// other entry and any trailing bytes as they were; `Ok(None)` when `edit`
/// changes none.
fn rewrite_tlv_block(
    data: &[u8],
    edit: impl Fn(u16, &[u8]) -> Result<Option<Vec<u8>>, Refusal>,
) -> Result<Option<Vec<u8>>, Refusal> {
    let (tlvs, tail) = snac::split_tlvs(data);
    let mut out = Vec::with_capacity(data.len() + 64);
    let mut changed = false;
    for t in &tlvs {
        let new = if changed { None } else { edit(t.tag, t.value)? };
        match new {
            Some(v) => {
                if v.len() > u16::MAX as usize {
                    return Err("TLV would exceed 64 KiB");
                }
                snac::put_tlv(&mut out, t.tag, &v);
                changed = true;
            }
            None => snac::put_tlv(&mut out, t.tag, t.value),
        }
    }
    if !changed {
        return Ok(None);
    }
    out.extend_from_slice(tail);
    Ok(Some(out))
}

/// Transforms message text, refusing growth past [`MAX_TEXT`].
fn transform_text(charset: u16, text: &[u8], f: Transform) -> Result<Option<Vec<u8>>, Refusal> {
    match f(charset, text) {
        None => Ok(None),
        Some(new) if new.len() > MAX_TEXT && new.len() > text.len() => {
            Err("message too long for the harness marker")
        }
        Some(new) => Ok(Some(new)),
    }
}

/// Like [`transform_text`] for 8-bit NUL-terminated text: the NUL stays last.
fn transform_nul_text(text: &[u8], f: Transform) -> Result<Option<Vec<u8>>, Refusal> {
    let (body, nul) = match text.strip_suffix(&[0]) {
        Some(b) => (b, true),
        None => (text, false),
    };
    Ok(transform_text(text::CHARSET_ASCII, body, f)?.map(|mut v| {
        if nul {
            v.push(0);
        }
        v
    }))
}

/// Channel 1: a list of fragments `id:u8 version:u8 len:u16 payload`; the
/// message is fragment 1, `charset:u16 language:u16 text`.
fn rewrite_ch1(frags: &[u8], f: Transform) -> Result<Option<Vec<u8>>, Refusal> {
    let mut out = Vec::with_capacity(frags.len() + 64);
    let mut r = Reader::new(frags);
    let mut changed = false;
    while r.remaining() >= 4 {
        let start = frags.len() - r.remaining();
        let (Some(id), Some(version), Some(len)) = (r.u8(), r.u8(), r.u16()) else {
            break;
        };
        let Some(payload) = r.bytes(len as usize) else {
            // A fragment running past the end: keep the rest as it is.
            out.extend_from_slice(&frags[start..]);
            return Ok(changed.then_some(out));
        };
        let mut new_payload = None;
        if id == 1 && !changed && payload.len() >= 4 {
            let charset = u16::from_be_bytes([payload[0], payload[1]]);
            if let Some(t) = transform_text(charset, &payload[4..], f)? {
                new_payload = Some([&payload[..4], &t[..]].concat());
            }
        }
        match new_payload {
            Some(p) => {
                let len = u16::try_from(p.len()).map_err(|_| "fragment would exceed 64 KiB")?;
                out.extend_from_slice(&[id, version]);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&p);
                changed = true;
            }
            None => out.extend_from_slice(&frags[start..start + 4 + len as usize]),
        }
    }
    out.extend_from_slice(&frags[frags.len() - r.remaining()..]);
    Ok(changed.then_some(out))
}

/// Channel 2: `type:u16 cookie[8] capability[16]` and a TLV block; a type-2
/// message under the ICQ server-relay capability has its text in TLV 0x2711.
fn rewrite_ch2(frag: &[u8], f: Transform) -> Result<Option<Vec<u8>>, Refusal> {
    const HEAD: usize = 2 + 8 + 16;
    if frag.len() < HEAD || frag[10..HEAD] != icbm::CAP_ICQ_SERVER_RELAY {
        return Ok(None);
    }
    let tlvs = rewrite_tlv_block(&frag[HEAD..], |tag, svc| {
        if tag != icbm::RDV_TLV_SVC_DATA {
            return Ok(None);
        }
        let Some(at) = icbm::type2_plain_text(svc) else {
            return Ok(None);
        };
        replace_at(svc, &at, f, |t| at.replace(svc, t))
    })?;
    Ok(tlvs.map(|t| [&frag[..HEAD], &t[..]].concat()))
}

/// ICQ offline reply: the text sits in the little-endian ICQ block of TLV
/// 0x0001, whose own length is fixed too.
fn rewrite_offline(env: &[u8], f: Transform) -> Result<Option<Vec<u8>>, Refusal> {
    let Some((at, _)) = icbm::offline_text(env) else {
        return Ok(None);
    };
    replace_at(env, &at, f, |t| icbm::replace_offline_text(env, &at, t))
}

/// Transforms the NUL-terminated text at `at` and rebuilds with `rebuild`.
fn replace_at(
    data: &[u8],
    at: &TextAt,
    f: Transform,
    rebuild: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, Refusal> {
    let old = &data[at.start..at.start + at.len];
    match transform_nul_text(old, f)? {
        None => Ok(None),
        Some(new) => rebuild(&new).map(Some).ok_or("message would exceed 64 KiB"),
    }
}
