//! The Phase 1 transform: a trivial, reversible rewrite of message text that
//! stands in for encryption while the transport is proven.
//!
//! Outbound text `T` becomes `MARKER + rot13(T)`; inbound text that carries the
//! marker gets it removed and ROT13 applied again. ROT13 touches only ASCII
//! letters outside HTML markup (`<...>` tags and `&...;` entities), and the
//! marker goes at the first text position, after any leading tags, so an HTML
//! message stays well-formed and a peer without the add-on still sees its
//! smileys and formatting, with `[e2e-harness] Uryyb` as the text.
//!
//! The transform works on code units - bytes for ASCII, UTF-8, Latin-1 and code
//! pages, big-endian `u16` for UCS-2 - never on decoded text. ROT13 on ASCII
//! letters is its own inverse on either, and it never turns a letter into markup
//! or back, so markup is found in the same places on both sides and the round
//! trip is exact whatever the charset.

/// What the add-on puts in front of rewritten text.
pub const MARKER: &str = "[e2e-harness] ";

/// A code unit of message text.
pub trait Unit: Copy + Eq {
    /// The ASCII byte this unit is, if it is one.
    fn ascii(self) -> Option<u8>;
    /// The unit for an ASCII byte.
    fn from_ascii(b: u8) -> Self;
}

impl Unit for u8 {
    fn ascii(self) -> Option<u8> {
        (self < 0x80).then_some(self)
    }
    fn from_ascii(b: u8) -> Self {
        b
    }
}

impl Unit for u16 {
    fn ascii(self) -> Option<u8> {
        (self < 0x80).then_some(self as u8)
    }
    fn from_ascii(b: u8) -> Self {
        b as u16
    }
}

/// Rewrites outbound text: the marker at the first text position, the text
/// after it ROT13'd outside markup.
pub fn apply<U: Unit>(text: &[U]) -> Vec<U> {
    let at = text_start(text);
    let mut out = Vec::with_capacity(text.len() + MARKER.len());
    out.extend_from_slice(&text[..at]);
    out.extend(MARKER.bytes().map(U::from_ascii));
    out.extend_from_slice(&rot13_outside_markup(&text[at..]));
    out
}

/// Restores inbound text rewritten by [`apply`], or `None` when the text does
/// not carry the marker (a peer without the add-on) and must be left as it is.
pub fn undo<U: Unit>(text: &[U]) -> Option<Vec<U>> {
    let at = text_start(text);
    let marker: Vec<U> = MARKER.bytes().map(U::from_ascii).collect();
    if !text[at..].starts_with(&marker) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() - marker.len());
    out.extend_from_slice(&text[..at]);
    out.extend_from_slice(&rot13_outside_markup(&text[at + marker.len()..]));
    Some(out)
}

/// Rewrites text given as bytes in an ICBM charset: UCS-2 (0x0002) as
/// big-endian `u16` units, everything else as bytes. `None` for UCS-2 text of
/// odd length, which cannot be split into units and is left alone.
pub fn apply_charset(charset: u16, bytes: &[u8]) -> Option<Vec<u8>> {
    map_charset(charset, bytes, |u| Some(apply(u)), |b| Some(apply(b)))
}

/// Restores text given as bytes in an ICBM charset; see [`apply_charset`].
pub fn undo_charset(charset: u16, bytes: &[u8]) -> Option<Vec<u8>> {
    map_charset(charset, bytes, undo, undo)
}

fn map_charset(
    charset: u16,
    bytes: &[u8],
    wide: impl Fn(&[u16]) -> Option<Vec<u16>>,
    narrow: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    if charset != crate::text::CHARSET_UNICODE {
        return narrow(bytes);
    }
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let out = wide(&units)?;
    Some(out.iter().flat_map(|u| u.to_be_bytes()).collect())
}

/// Where the text starts: past any tags at the very beginning.
fn text_start<U: Unit>(text: &[U]) -> usize {
    let mut i = 0;
    while i < text.len() && text[i].ascii() == Some(b'<') {
        match text[i..].iter().position(|u| u.ascii() == Some(b'>')) {
            Some(end) => i += end + 1,
            None => break,
        }
    }
    i
}

/// ROT13 on ASCII letters, skipping tags (`<` to `>`) and entities (`&`, a run
/// of letters, digits or `#`, then `;`).
fn rot13_outside_markup<U: Unit>(text: &[U]) -> Vec<U> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let skip = match text[i].ascii() {
            Some(b'<') => text[i..]
                .iter()
                .position(|u| u.ascii() == Some(b'>'))
                .map(|end| end + 1),
            Some(b'&') => entity_len(&text[i..]),
            _ => None,
        };
        match skip {
            Some(n) => {
                out.extend_from_slice(&text[i..i + n]);
                i += n;
            }
            None => {
                out.push(rot13(text[i]));
                i += 1;
            }
        }
    }
    out
}

/// The length of an entity starting at `text[0] == '&'`, or `None` if the `&`
/// does not start one.
fn entity_len<U: Unit>(text: &[U]) -> Option<usize> {
    const MAX: usize = 12;
    for (i, u) in text.iter().enumerate().skip(1).take(MAX) {
        match u.ascii() {
            Some(b';') if i > 1 => return Some(i + 1),
            Some(c) if c.is_ascii_alphanumeric() || c == b'#' => {}
            _ => return None,
        }
    }
    None
}

fn rot13<U: Unit>(u: U) -> U {
    match u.ascii() {
        Some(c @ b'a'..=b'z') => U::from_ascii((c - b'a' + 13) % 26 + b'a'),
        Some(c @ b'A'..=b'Z') => U::from_ascii((c - b'A' + 13) % 26 + b'A'),
        _ => u,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_s(s: &str) -> String {
        String::from_utf8(apply(s.as_bytes())).unwrap()
    }

    fn undo_s(s: &str) -> Option<String> {
        undo(s.as_bytes()).map(|v| String::from_utf8(v).unwrap())
    }

    #[test]
    fn plain_text() {
        assert_eq!(apply_s("Hello, world"), "[e2e-harness] Uryyb, jbeyq");
        assert_eq!(
            undo_s("[e2e-harness] Uryyb, jbeyq").as_deref(),
            Some("Hello, world")
        );
    }

    #[test]
    fn html_keeps_tags_smileys_and_entities() {
        let html =
            "<HTML><BODY><FONT sml=\"default\">Hi &amp; bye <b>there</b></FONT></BODY></HTML>";
        let wire = apply_s(html);
        assert_eq!(
            wire,
            "<HTML><BODY><FONT sml=\"default\">[e2e-harness] Uv &amp; olr <b>gurer</b></FONT></BODY></HTML>"
        );
        assert_eq!(undo_s(&wire).as_deref(), Some(html));
    }

    #[test]
    fn unmarked_text_is_left_alone() {
        assert_eq!(undo_s("Hello"), None);
        assert_eq!(undo_s("<b>Hello</b>"), None);
        // The marker only counts at the text start.
        assert_eq!(undo_s("x [e2e-harness] y"), None);
    }

    #[test]
    fn marker_typed_by_the_user_survives() {
        let typed = "[e2e-harness] literally";
        assert_eq!(undo_s(&apply_s(typed)).as_deref(), Some(typed));
    }

    #[test]
    fn empty_and_tag_only() {
        assert_eq!(undo_s(&apply_s("")).as_deref(), Some(""));
        assert_eq!(undo_s(&apply_s("<br>")).as_deref(), Some("<br>"));
        // An unclosed tag at the start is text.
        assert_eq!(undo_s(&apply_s("<oops")).as_deref(), Some("<oops"));
    }

    #[test]
    fn utf8_and_cyrillic_bytes_untouched() {
        let s = "Привет, Bob! 😀";
        let wire = apply_s(s);
        assert_eq!(wire, "[e2e-harness] Привет, Obo! 😀");
        assert_eq!(undo_s(&wire).as_deref(), Some(s));
    }

    #[test]
    fn ucs2_round_trip() {
        let s = "<b>Привет, Bob</b>";
        let bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        let wire = apply_charset(0x0002, &bytes).unwrap();
        let shown: Vec<u16> = wire
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(
            String::from_utf16(&shown).unwrap(),
            "<b>[e2e-harness] Привет, Obo</b>"
        );
        assert_eq!(undo_charset(0x0002, &wire).unwrap(), bytes);
        assert_eq!(apply_charset(0x0002, &[0x00]), None);
    }

    #[test]
    fn code_page_bytes_round_trip() {
        // Windows-1251 "Привет" followed by ASCII; any byte >= 0x80 is kept.
        let cp1251 = [0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2, b' ', b'A', b'b'];
        let wire = apply_charset(0x0000, &cp1251).unwrap();
        assert_eq!(undo_charset(0x0003, &wire).unwrap(), cp1251);
    }

    #[test]
    fn every_ascii_byte_round_trips() {
        let all: Vec<u8> = (0u8..=0xFF).collect();
        assert_eq!(undo(&apply(&all)).unwrap(), all);
    }
}
