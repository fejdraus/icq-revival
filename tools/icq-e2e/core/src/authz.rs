//! Text in a contact's name that is not a message (sixth audit of 2026-10,
//! finding 2): authorization events, and the profile, away message and
//! status text the server hands out about a contact.
//!
//! Authorization events carry text the contact wrote and the client shows as
//! theirs, relayed by the server:
//!
//! - Feedbag `0x0013/0x0019` `RequestAuthorizeToClient` {screen name,
//!   reason} and `0x0013/0x001B` `RespondAuthorizeToClient` {screen name,
//!   accepted, reason} (`wire/snacs.go`, `foodgroup/feedbag.go`);
//! - the legacy ICQ forms, an ICBM on channel 4 or an ICQ offline message of
//!   type `0x06` (request: `nick FE first FE last FE email FE auth FE
//!   reason`), `0x07` (denied: the reason) and `0x08` (granted).
//!
//! None of them can be authenticated end to end - the add-on cannot send
//! them, the server makes them - so for a protected contact the reason is
//! replaced by a local text ([`crate::policy::auth_local_text`]) and the
//! event kept, so the client's request and reply flow still works; for any
//! other contact a reason that starts like a note of the add-on's is shown
//! with "(from <contact>)" in front ([`crate::policy::unmark`]).
//!
//! Profiles (Locate `0x0002/0x0006`, TLVs `0x0002` and `0x0004`: the profile
//! and the away message) and the status text (the BART item of type `0x0002`
//! in a contact's user info, TLV `0x001D`, in "buddy arrived" and in the
//! Locate reply) are what a contact set for everyone, not words to the user:
//! they are left as they are, except that one starting like a note of the
//! add-on's is unmarked the same way.

use crate::snac::{self, Reader};

/// The Feedbag food group.
pub const FOOD_FEEDBAG: u16 = 0x0013;
/// `FeedbagRequestAuthorizeToClient`.
pub const FEEDBAG_REQUEST_AUTHORIZE_TO_CLIENT: u16 = 0x0019;
/// `FeedbagRespondAuthorizeToClient`.
pub const FEEDBAG_RESPOND_AUTHORIZE_TO_CLIENT: u16 = 0x001B;

/// The ICQ message types of authorization events (`ICBMMsgTypeAuthReq`,
/// `AuthDeny`, `AuthOK`).
pub const MSG_TYPE_AUTH_REQ: u8 = 0x06;
pub const AUTH_TYPES: &[u8] = &[MSG_TYPE_AUTH_REQ, 0x07, 0x08];

/// The Locate user info reply.
pub const LOCATE_USER_INFO_REPLY: u16 = 0x0006;
/// Its profile and away message texts, and their MIME types.
const LOCATE_PROFILE_MIME: u16 = 0x0001;
const LOCATE_PROFILE: u16 = 0x0002;
const LOCATE_AWAY_MIME: u16 = 0x0003;
const LOCATE_AWAY: u16 = 0x0004;
/// `0x0004/0x000B`: what a contact's client answers a request with - on
/// channel 2, an ICQ away message - relayed by the server.
pub const ICBM_AUTO_RESPONSE: u16 = 0x000B;
/// The ICQ away message types (away, occupied, N/A, DND, free for chat).
pub const AUTO_TYPES: &[u8] = &[0xE8, 0xE9, 0xEA, 0xEB, 0xEC];
/// The BART TLV of a user info block, and a status text item in it.
const USER_INFO_BART: u16 = 0x001D;
const BART_STATUS_STR: u16 = 0x0002;
const BART_FLAG_DATA: u8 = 0x04;

/// An authorization event in a Feedbag SNAC: who it is from, whether it is a
/// request, and where its reason is in the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbagAuth {
    pub peer: String,
    pub request: bool,
    /// The offset of the reason's u16 length in the body.
    len_at: usize,
    reason_len: usize,
}

impl FeedbagAuth {
    /// The reason as it came.
    pub fn reason<'a>(&self, body: &'a [u8]) -> &'a [u8] {
        &body[self.len_at + 2..self.len_at + 2 + self.reason_len]
    }

    /// `body` with `reason` in place of the old one, its length fixed.
    pub fn with_reason(&self, body: &[u8], reason: &[u8]) -> Option<Vec<u8>> {
        let len = u16::try_from(reason.len()).ok()?;
        let mut out = body[..self.len_at].to_vec();
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(reason);
        out.extend_from_slice(&body[self.len_at + 2 + self.reason_len..]);
        Some(out)
    }
}

/// The authorization event of an inbound Feedbag SNAC body (the extended
/// info block already skipped by [`snac::parse`]), or `None`.
pub fn feedbag_auth(sub_group: u16, body: &[u8]) -> Option<FeedbagAuth> {
    let request = match sub_group {
        FEEDBAG_REQUEST_AUTHORIZE_TO_CLIENT => true,
        FEEDBAG_RESPOND_AUTHORIZE_TO_CLIENT => false,
        _ => return None,
    };
    let mut r = Reader::new(body);
    let peer = String::from_utf8_lossy(r.len8()?).into_owned();
    if !request {
        r.u8()?; // accepted
    }
    let len_at = body.len() - r.remaining();
    let reason_len = r.u16()? as usize;
    r.bytes(reason_len)?;
    (!peer.is_empty()).then_some(FeedbagAuth {
        peer,
        request,
        len_at,
        reason_len,
    })
}

/// Splits the text of a legacy authorization message into what comes before
/// the reason and the reason: a request's reason is its sixth `0xFE`
/// separated field (the first five are the server's copy of the requester's
/// directory entry); any other text is all reason.
pub fn split_reason(text: &[u8]) -> (&[u8], &[u8]) {
    let mut seen = 0;
    for (i, b) in text.iter().enumerate() {
        if *b == 0xFE {
            seen += 1;
            if seen == 5 {
                return text.split_at(i + 1);
            }
        }
    }
    (&[], text)
}

/// The text of a legacy authorization message (a `request`, or a reply)
/// with its reason replaced by `reason`, or, when `reason` is `None`,
/// unmarked for `peer` - `None` when that changes nothing. Only a request
/// keeps the fields before its reason; a reply is all reason.
pub fn legacy_text(
    peer: &str,
    text: &[u8],
    request: bool,
    reason: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let (head, old) = if request {
        split_reason(text)
    } else {
        (&[][..], text)
    };
    let new = match reason {
        Some(r) => r.to_vec(),
        None => crate::policy::unmark(peer, crate::text::CHARSET_ASCII, old)?,
    };
    Some([head, &new[..]].concat())
}

/// An inbound SNAC payload with every profile, away message and status
/// text in a contact's name that starts like a note of the add-on's
/// unmarked, and what it was for the log; `None` when nothing was changed.
pub fn unmark_user_texts(payload: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    let s = snac::parse(payload)?;
    let header = &payload[..payload.len() - s.body.len()];
    let (body, what) = match (s.food_group, s.sub_group) {
        (snac::FOOD_LOCATE, LOCATE_USER_INFO_REPLY) => {
            let (peer, end, block) = user_info_block(s.body, 0)?;
            let mut changed = block.is_some();
            let mut out = block.unwrap_or_else(|| s.body[..end].to_vec());
            let rest = &s.body[end..];
            let (tlvs, tail) = snac::split_tlvs(rest);
            let mime = |tag| {
                tlvs.iter()
                    .find(|t| t.tag == tag)
                    .map(|t| t.value)
                    .unwrap_or_default()
            };
            for t in &tlvs {
                let new = match t.tag {
                    LOCATE_PROFILE => unmark_mime(&peer, mime(LOCATE_PROFILE_MIME), t.value),
                    LOCATE_AWAY => unmark_mime(&peer, mime(LOCATE_AWAY_MIME), t.value),
                    _ => None,
                };
                changed |= new.is_some();
                snac::put_tlv(&mut out, t.tag, new.as_deref().unwrap_or(t.value));
            }
            out.extend_from_slice(tail);
            if !changed {
                return None;
            }
            (out, "profile or away message")
        }
        (snac::FOOD_BUDDY, snac::BUDDY_ARRIVED) => {
            let mut at = 0;
            let mut out = Vec::with_capacity(s.body.len());
            let mut changed = false;
            while at < s.body.len() {
                let (_, end, block) = user_info_block(s.body, at)?;
                match block {
                    Some(b) => {
                        out.extend_from_slice(&b);
                        changed = true;
                    }
                    None => out.extend_from_slice(&s.body[at..end]),
                }
                at = end;
            }
            if !changed {
                return None;
            }
            (out, "status text")
        }
        (snac::FOOD_ICBM, ICBM_AUTO_RESPONSE) => (auto_response(s.body)?, "away message reply"),
        _ => return None,
    };
    Some(([header, &body[..]].concat(), what))
}

/// An ICQ away message the contact's client sent back when asked
/// (`0x0004/0x000B` on channel 2, `cookie channel name reason` and then the
/// layout of type-2 service data with one of [`AUTO_TYPES`]), unmarked.
fn auto_response(body: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(body);
    r.skip(8)?;
    if r.u16()? != crate::icbm::CHANNEL_RENDEZVOUS {
        return None;
    }
    let peer = String::from_utf8_lossy(r.len8()?).into_owned();
    r.u16()?; // reason
    let at = body.len() - r.remaining();
    let data = &body[at..];
    let t = crate::icbm::type2_text(data, AUTO_TYPES)?;
    let text = &data[t.start..t.start + t.len];
    let (text, nul) = match text.strip_suffix(&[0]) {
        Some(x) => (x, true),
        None => (text, false),
    };
    let mut new = crate::policy::unmark(&peer, crate::text::CHARSET_ASCII, text)?;
    if nul {
        new.push(0);
    }
    Some([&body[..at], &t.replace(data, &new)?[..]].concat())
}

/// A profile or away message text in the charset its MIME type names.
fn unmark_mime(peer: &str, mime: &[u8], text: &[u8]) -> Option<Vec<u8>> {
    let mime = String::from_utf8_lossy(mime).to_ascii_lowercase();
    let charset = if mime.contains("unicode-2-0") || mime.contains("utf-16") {
        crate::text::CHARSET_UNICODE
    } else {
        crate::text::CHARSET_ASCII
    };
    crate::policy::unmark(peer, charset, text)
}

/// One user info block at `at` (screen name, warning level, TLV count,
/// TLVs): the contact, where it ends, and the block rebuilt when its status
/// text was unmarked.
fn user_info_block(body: &[u8], at: usize) -> Option<(String, usize, Option<Vec<u8>>)> {
    let mut r = Reader::new(body.get(at..)?);
    let peer = String::from_utf8_lossy(r.len8()?).into_owned();
    r.u16()?; // warning level
    let count = r.u16()?;
    let head_end = at + (body.len() - at - r.remaining());
    let mut tlvs = Vec::new();
    for _ in 0..count {
        let tag = r.u16()?;
        let len = r.u16()? as usize;
        tlvs.push((tag, r.bytes(len)?));
    }
    let end = body.len() - r.remaining();
    let mut changed = false;
    let mut out = body[at..head_end].to_vec();
    for (tag, value) in tlvs {
        let new = (tag == USER_INFO_BART)
            .then(|| unmark_bart_status(&peer, value))
            .flatten();
        changed |= new.is_some();
        snac::put_tlv(&mut out, tag, new.as_deref().unwrap_or(value));
    }
    Some((peer, end, changed.then_some(out)))
}

/// A BART list (`type:u16 flags:u8 len:u8 data`...) with the status text
/// item (`len:u16 text`, then the rest of the item) unmarked; `None` when
/// nothing changed or it would not fit the item's one-byte length.
fn unmark_bart_status(peer: &str, list: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(list);
    let mut out = Vec::with_capacity(list.len() + 16);
    let mut changed = false;
    while r.remaining() >= 4 {
        let kind = r.u16()?;
        let flags = r.u8()?;
        let data = r.len8()?;
        let mut new = None;
        if kind == BART_STATUS_STR && flags & BART_FLAG_DATA != 0 && data.len() >= 2 {
            let n = u16::from_be_bytes([data[0], data[1]]) as usize;
            if let Some(text) = data.get(2..2 + n) {
                if let Some(t) = crate::policy::unmark(peer, crate::text::CHARSET_ASCII, text) {
                    let mut d = (t.len() as u16).to_be_bytes().to_vec();
                    d.extend_from_slice(&t);
                    d.extend_from_slice(&data[2 + n..]);
                    if d.len() <= u8::MAX as usize {
                        new = Some(d);
                    }
                }
            }
        }
        out.extend_from_slice(&kind.to_be_bytes());
        out.push(flags);
        let d = new.as_deref().unwrap_or(data);
        changed |= new.is_some();
        out.push(d.len() as u8);
        out.extend_from_slice(d);
    }
    out.extend_from_slice(&list[list.len() - r.remaining()..]);
    changed.then_some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A Feedbag authorization SNAC payload as the server sends it: flags
    /// `0x8000` and the extended info block, then the event.
    pub fn feedbag(sub: u16, peer: &str, reason: &[u8]) -> Vec<u8> {
        let mut p = FOOD_FEEDBAG.to_be_bytes().to_vec();
        p.extend_from_slice(&sub.to_be_bytes());
        p.extend_from_slice(&0x8000u16.to_be_bytes());
        p.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02]);
        p.push(peer.len() as u8);
        p.extend_from_slice(peer.as_bytes());
        if sub == FEEDBAG_RESPOND_AUTHORIZE_TO_CLIENT {
            p.push(0);
        }
        p.extend_from_slice(&(reason.len() as u16).to_be_bytes());
        p.extend_from_slice(reason);
        p.extend_from_slice(&[0, 0]);
        p
    }

    #[test]
    fn a_feedbag_event_is_read_and_its_reason_replaced() {
        for sub in [
            FEEDBAG_REQUEST_AUTHORIZE_TO_CLIENT,
            FEEDBAG_RESPOND_AUTHORIZE_TO_CLIENT,
        ] {
            let p = feedbag(sub, "100002", b"let me in");
            let s = snac::parse(&p).unwrap();
            let a = feedbag_auth(sub, s.body).unwrap();
            assert_eq!(a.peer, "100002");
            assert_eq!(a.request, sub == FEEDBAG_REQUEST_AUTHORIZE_TO_CLIENT);
            assert_eq!(a.reason(s.body), b"let me in");
            let b = a.with_reason(s.body, b"local").unwrap();
            let again = feedbag_auth(sub, &b).unwrap();
            assert_eq!(again.reason(&b), b"local");
            assert!(b.ends_with(&[0, 0]), "what follows the reason stays");
        }
        assert_eq!(feedbag_auth(0x001C, b"\x06100002"), None);
    }

    #[test]
    fn a_legacy_requests_reason_is_its_sixth_field() {
        let t = b"nick\xFEfirst\xFElast\xFEmail\xFE1\xFEplease";
        assert_eq!(split_reason(t).1, b"please");
        assert_eq!(
            legacy_text("100002", t, true, Some(b"X")).unwrap(),
            b"nick\xFEfirst\xFElast\xFEmail\xFE1\xFEX"
        );
        assert_eq!(split_reason(b"go away").1, b"go away");
        assert_eq!(
            legacy_text("100002", t, true, None),
            None,
            "nothing to unmark"
        );
        assert_eq!(
            legacy_text("100002", b"[ICQ E2E] verified", false, None).unwrap(),
            b"(from 100002) [ICQ E2E] verified"
        );
    }
}
