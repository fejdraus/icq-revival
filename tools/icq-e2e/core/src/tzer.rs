//! tZers in a protected contact's name (fifth and sixth audits of 2026-10).
//!
//! A tZer is a short public animation, not a secret: its document names one
//! of the movies the server hands out and a caption. The add-on therefore
//! never encrypts one (sixth audit, finding 4): the server must be able to
//! read it to turn one client's form into the other's (`foodgroup/icbm_tzer.go`,
//! `tzerForRecipient`) - ICQ 6.5 sends a channel-2 plugin message, ICQ 7.2 a
//! channel-1 IM with the tZer mark. Encrypted, ICQ 7.2's tZer reached ICQ 6.5
//! as a plugin message whose document was the armoured container.
//!
//! What makes a tZer the contact's is authentication instead: just before
//! the tZer goes, the sender's add-on sends an Olm control message,
//! [`Notice`] (`IQT1 | 1 | hash`), with the hash of the document
//! ([`doc_hash`]), which the server copies unchanged through either
//! translation. The receiver's add-on shows a tZer in a protected contact's
//! name only when a notice from that contact with the same hash arrived
//! (held up to a few seconds for it, then dropped with a warning); each
//! notice vouches for one tZer. An automatic contact's tZers pass as before.
//!
//! On the way out only a document of the known list on the configured
//! server ([`served_doc`]) is left unencrypted; any other channel-1 "tZer" is
//! text and encrypted as before. On the way in, a protected contact's tZer
//! must be such a document as well as announced.
//!
//! The server's channel-1 form, for reference:
//!
//! ```text
//! 05 01 00 01 01               features: text
//! 10 01 00 10 <CapICQTZers>    the tZer mark
//! 01 01 <len> 00 02 00 2D ...  the document in UCS-2BE
//! ```
//!
//! with the document as the clients' `tzer.xml` lists them:
//!
//! ```text
//! <tzerRoot id="cantH" url="https://<server>[:port]/icq/tzers/canthearu.swf"
//!     thumb="https://<server>[:port]/icq/tzers/canthearu.png" name="..." freeData=""/>
//! ```
//!
//! [`served_doc`] takes exactly that: the attributes in that order, an id of
//! the known list with its own movie and picture, both on the configured
//! server's `/icq/tzers/` path, an empty `freeData`, a short name of letters,
//! digits, spaces and a little punctuation (the caption in the sender's
//! language), at most [`MAX_DOC`] characters, and nothing before or after.

use crate::snac;

/// `CapICQTZers` (`B2EC8F16-7C6F-451B-BD79-DC58497888B9`, `wire/snacs.go`).
pub const CAP_ICQ_TZERS: [u8; 16] = [
    0xB2, 0xEC, 0x8F, 0x16, 0x7C, 0x6F, 0x45, 0x1B, 0xBD, 0x79, 0xDC, 0x58, 0x49, 0x78, 0x88, 0xB9,
];

/// The language field the server writes in the text fragment of a tZer.
const TZER_LANGUAGE: u16 = 0x002D;

/// The longest document taken, in characters.
pub const MAX_DOC: usize = 400;

/// The longest name taken, in characters.
pub const MAX_NAME: usize = 40;

/// The tZers the clients' `tzer.xml` lists and the server has: id, and the
/// file name of its movie and picture under `/icq/tzers/`. ICQ writes
/// `sorry` with a trailing space in its list.
const KNOWN: [(&str, &str); 13] = [
    ("gangSh", "gangsta"),
    ("cantH", "canthearu"),
    ("scratch", "skratch"),
    ("boo", "boo"),
    ("kisses", "kisses"),
    ("rasta", "chillout"),
    ("arakiri", "akitaka"),
    ("laugh", "laugh"),
    ("da", "duh"),
    ("beback", "beback"),
    ("ilikeu", "likeu"),
    ("sorry", "sorry"),
    ("sorry ", "sorry"),
];

/// The path the server serves tZers under.
const PATH: &str = "/icq/tzers/";

/// Whether `frags`, the TLV `0x0002` of a channel-1 message, is a tZer
/// exactly as the server writes it, with its files on `server`.
pub fn is_served_tzer(frags: &[u8], server: &str) -> bool {
    let mut at = 0;
    let mut next = |want_id: u8| -> Option<&[u8]> {
        let h = frags.get(at..at + 4)?;
        if h[0] != want_id || h[1] != 0x01 {
            return None;
        }
        let len = u16::from_be_bytes([h[2], h[3]]) as usize;
        let p = frags.get(at + 4..at + 4 + len)?;
        at += 4 + len;
        Some(p)
    };
    let (Some(features), Some(mark), Some(msg)) = (next(0x05), next(0x10), next(0x01)) else {
        return false;
    };
    if at != frags.len() || features != [0x01] || mark != CAP_ICQ_TZERS {
        return false;
    }
    if msg.len() < 4
        || u16::from_be_bytes([msg[0], msg[1]]) != crate::text::CHARSET_UNICODE
        || u16::from_be_bytes([msg[2], msg[3]]) != TZER_LANGUAGE
        || (msg.len() - 4) % 2 != 0
    {
        return false;
    }
    let units: Vec<u16> = msg[4..]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let Ok(doc) = String::from_utf16(&units) else {
        return false;
    };
    served_doc(&doc, server)
}

/// Whether `doc` is a tZer document of the known list on `server`.
pub fn served_doc(doc: &str, server: &str) -> bool {
    if doc.chars().count() > MAX_DOC || server.is_empty() {
        return false;
    }
    let doc = doc.strip_suffix("\r\n").unwrap_or(doc);
    let Some(rest) = doc.strip_prefix("<tzerRoot id=\"") else {
        return false;
    };
    let Some((id, rest)) = rest.split_once("\" url=\"") else {
        return false;
    };
    let Some((url, rest)) = rest.split_once("\" thumb=\"") else {
        return false;
    };
    let Some((thumb, rest)) = rest.split_once("\" name=\"") else {
        return false;
    };
    let Some(name) = rest.strip_suffix("\" freeData=\"\"/>") else {
        return false;
    };
    let Some(&(_, file)) = KNOWN.iter().find(|(k, _)| *k == id) else {
        return false;
    };
    on_server(url, server, &format!("{file}.swf"))
        && on_server(thumb, server, &format!("{file}.png"))
        && plain_name(name)
}

/// Whether `url` is `http(s)://<server>[:port]/icq/tzers/<file>`, exactly.
fn on_server(url: &str, server: &str, file: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let (authority, path) = rest.split_at(slash);
    let host = match authority.split_once(':') {
        Some((h, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            h
        }
        None => authority,
    };
    host.eq_ignore_ascii_case(server) && path.strip_prefix(PATH) == Some(file)
}

/// Whether a tZer's name is a short caption: letters, digits, spaces and
/// `' ! ? . , -`, nothing that makes a link or markup.
fn plain_name(name: &str) -> bool {
    name.chars().count() <= MAX_NAME
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '\'' | '!' | '?' | '.' | ',' | '-'))
        && !name.contains("..")
}

/// What an `IQT1` payload starts with, inside the control envelope.
pub const MAGIC: &[u8; 4] = b"IQT1";
const T_NOTICE: u8 = 1;

/// How long a notice waits for its tZer, in seconds.
pub const NOTICE_TTL: u64 = 120;
/// Notices kept at most; the oldest goes first.
pub const MAX_NOTICES: usize = 32;

/// A tZer's announcement: `IQT1 | 1 | hash[16]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notice {
    pub hash: [u8; 16],
}

impl Notice {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(T_NOTICE);
        v.extend_from_slice(&self.hash);
        v
    }

    /// `None` for anything that is not exactly a notice.
    pub fn decode(b: &[u8]) -> Option<Notice> {
        let rest = b.strip_prefix(MAGIC)?;
        let (&kind, hash) = rest.split_first()?;
        if kind != T_NOTICE || hash.len() != 16 {
            return None;
        }
        let mut h = [0u8; 16];
        h.copy_from_slice(hash);
        Some(Notice { hash: h })
    }
}

/// The hash a notice names: SHA-256 of the document in UTF-8, without a
/// trailing CRLF or NUL, cut to 16 bytes. The same whichever form the tZer
/// travels in: the server copies the document unchanged.
pub fn doc_hash(doc: &str) -> [u8; 16] {
    let d = ring::digest::digest(
        &ring::digest::SHA256,
        doc.trim_end_matches(['\r', '\n', '\0']).as_bytes(),
    );
    let mut h = [0u8; 16];
    h.copy_from_slice(&d.as_ref()[..16]);
    h
}

/// The tZer plugin's GUID in the service data,
/// `{4FA6F34C-09B7-FD48-9208-7E857AE07330}` (`tzerPluginGUID`).
const PLUGIN_GUID: [u8; 16] = [
    0x4F, 0xA6, 0xF3, 0x4C, 0x09, 0xB7, 0xFD, 0x48, 0x92, 0x08, 0x7E, 0x85, 0x7A, 0xE0, 0x73, 0x30,
];
/// The plugin function that sends a tZer.
const PLUGIN_FUNCTION: &[u8] = b"Send Tzer";

/// The document of a channel-1 tZer: fragment list `frags` (TLV `0x0002`)
/// with the tZer mark (fragment `0x10`, `CapICQTZers`); the text of fragment
/// 1, decoded. `None` for a message without the mark.
pub fn ch1_doc(frags: &[u8]) -> Option<String> {
    let mut r = snac::Reader::new(frags);
    let mut marked = false;
    let mut doc = None;
    while r.remaining() >= 4 {
        let (id, _version, len) = (r.u8()?, r.u8()?, r.u16()?);
        let p = r.bytes(len as usize)?;
        match id {
            0x10 => marked |= p == CAP_ICQ_TZERS,
            0x01 if p.len() >= 4 && doc.is_none() => {
                let charset = u16::from_be_bytes([p[0], p[1]]);
                doc = Some(crate::text::decode(charset, &p[4..]));
            }
            _ => {}
        }
    }
    if marked {
        doc
    } else {
        None
    }
}

/// The document of a channel-2 tZer: the rendezvous data (TLV `0x0005`) of a
/// proposal under the ICQ server relay capability whose service data names
/// the tZer plugin and its "Send Tzer" function, read the way the server
/// reads it (`parseTzerPlugin`). `None` for anything else.
pub fn plugin_doc(data: &[u8]) -> Option<String> {
    let mut r = snac::Reader::new(data);
    if r.u16()? != 0 {
        return None;
    }
    r.skip(8)?;
    if r.bytes(16)? != crate::icbm::CAP_ICQ_SERVER_RELAY {
        return None;
    }
    let tlvs = snac::read_tlvs(r.bytes(r.remaining())?);
    let svc = snac::find_tlv(&tlvs, crate::icbm::RDV_TLV_SVC_DATA)?;
    let at = svc.windows(16).position(|w| w == PLUGIN_GUID)?;
    if at < 2
        || !svc[at..]
            .windows(PLUGIN_FUNCTION.len())
            .any(|w| w == PLUGIN_FUNCTION)
    {
        return None;
    }
    let pos = at + u16::from_le_bytes([svc[at - 2], svc[at - 1]]) as usize;
    let len = u32::from_le_bytes(svc.get(pos + 4..pos + 8)?.try_into().ok()?) as usize;
    let doc = svc.get(pos + 8..(pos + 8).checked_add(len)?)?;
    Some(String::from_utf8_lossy(doc).into_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The fragments the server writes for `doc` (`tzerIMFragments`).
    pub fn fragments(doc: &str) -> Vec<u8> {
        let mut msg = vec![0x00, 0x02, 0x00, 0x2D];
        msg.extend(doc.encode_utf16().flat_map(|u| u.to_be_bytes()));
        let mut f = vec![0x05, 0x01, 0x00, 0x01, 0x01, 0x10, 0x01, 0x00, 0x10];
        f.extend_from_slice(&CAP_ICQ_TZERS);
        f.extend_from_slice(&[0x01, 0x01]);
        f.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        f.extend_from_slice(&msg);
        f
    }

    pub const DOC: &str = "<tzerRoot id=\"cantH\" url=\"https://icq.example.org:8102/icq/tzers/canthearu.swf\" thumb=\"https://icq.example.org:8102/icq/tzers/canthearu.png\" name=\" \u{0412}\u{0430}\u{0441} \u{043d}\u{0435} \u{0447}\u{0443}\u{0442}\u{0438}\" freeData=\"\"/>\r\n";

    #[test]
    fn the_servers_form_is_recognised_and_nothing_else() {
        let srv = "icq.example.org";
        assert!(is_served_tzer(&fragments(DOC), srv));
        assert!(is_served_tzer(
            &fragments(DOC.trim_end()),
            "ICQ.EXAMPLE.ORG"
        ));
        let sorry = "<tzerRoot id=\"sorry \" url=\"http://icq.example.org/icq/tzers/sorry.swf\" thumb=\"http://icq.example.org/icq/tzers/sorry.png\" name=\"\" freeData=\"\"/>";
        assert!(is_served_tzer(&fragments(sorry), srv));
        for bad in [
            format!("{DOC}send me your password"),
            format!("hello {DOC}"),
            DOC.replace("icq.example.org:8102/icq", "evil.example.com/icq"),
            DOC.replace(
                "icq.example.org:8102/icq/tzers/canthearu.swf",
                "icq.example.org:8102/x/canthearu.swf",
            ),
            DOC.replace("canthearu.swf", "boo.swf"),
            DOC.replace("cantH", "unknown"),
            DOC.replace("freeData=\"\"", "freeData=\"x\""),
            DOC.replace(" \u{0412}\u{0430}\u{0441}", "see http://evil.example.com"),
            DOC.replace(" \u{0412}\u{0430}\u{0441}", "<b>x</b>"),
            DOC.replace(" \u{0412}\u{0430}\u{0441}", &"a".repeat(41)),
            DOC.replace("8102", "81a2"),
            DOC.replace("\" thumb", "\" x=\"1\" thumb"),
        ] {
            assert!(!is_served_tzer(&fragments(&bad), srv), "{bad:?}");
        }
        // Not the server's fragments.
        let mut f = fragments(DOC);
        f.extend_from_slice(&[0x01, 0x01, 0x00, 0x04, 0, 0, 0, 0]);
        assert!(!is_served_tzer(&f, srv), "a second text fragment");
        let mut f = fragments(DOC);
        f[13] ^= 1;
        assert!(!is_served_tzer(&f, srv), "another capability");
        assert!(!is_served_tzer(&fragments(DOC), ""), "no server configured");
        assert!(!is_served_tzer(&fragments(DOC), "example.org"));
    }
}
