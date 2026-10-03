//! The one unencrypted channel-1 form that may be shown in a protected
//! contact's name: a tZer exactly as our server writes it for ICQ 7.2.
//!
//! ICQ 6.5 sends a tZer as a channel-2 plugin message, which the add-on does
//! not encrypt (it carries no text the add-on handles); the server turns it
//! into the channel-1 form ICQ 7.2 plays (`foodgroup/icbm_tzer.go`,
//! `tzerForRecipient`, `tzerIMFragments`):
//!
//! ```text
//! 05 01 00 01 01               features: text
//! 10 01 00 10 <CapICQTZers>    the tZer mark
//! 01 01 <len> 00 02 00 2D ...  the document in UCS-2BE
//! ```
//!
//! with the document ICQ 6.5 wrote, as the clients' `tzer.xml` lists them:
//!
//! ```text
//! <tzerRoot id="cantH" url="https://<server>[:port]/icq/tzers/canthearu.swf"
//!     thumb="https://<server>[:port]/icq/tzers/canthearu.png" name="..." freeData=""/>
//! ```
//!
//! Plaintext, so on its own it would be dropped for a protected contact
//! (fifth audit of 2026-10, finding 1) - which broke tZers between a 6.5 and
//! a 7.2 that are verified to each other. [`is_served_tzer`] recognises
//! exactly that form and nothing else: the three fragments in that order, the
//! attributes in that order, an id of the known list with its own movie and
//! picture, both on the configured server's `/icq/tzers/` path, an empty
//! `freeData`, a short name of letters, digits, spaces and a little
//! punctuation (the tZer's caption in the sender's language), at most
//! [`MAX_DOC`] characters, and nothing before or after. Anything that
//! deviates is text, and is dropped as text.

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
fn served_doc(doc: &str, server: &str) -> bool {
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
