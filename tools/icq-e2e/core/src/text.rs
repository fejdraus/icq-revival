//! Decoding of ICBM message text from the charset ids ICQ 6/7 use.
//!
//! Channel-1 messages name a charset in the fragment: 0x0000 ASCII (in
//! practice often UTF-8 for these clients), 0x0002 UCS-2 big-endian, 0x0003
//! Latin-1. We decode to a Rust `String` for the log; decoding never fails
//! (invalid bytes become U+FFFD), so a bad message can only produce an odd log
//! line, never a panic.

/// ICBM charset ids (`ICBMMessageEncoding*` in wire/snacs.go).
pub const CHARSET_ASCII: u16 = 0x0000;
pub const CHARSET_UNICODE: u16 = 0x0002; // UCS-2, big-endian
pub const CHARSET_LATIN1: u16 = 0x0003;

/// Decodes message text for the given charset id into a display string.
pub fn decode(charset: u16, bytes: &[u8]) -> String {
    match charset {
        CHARSET_UNICODE => decode_ucs2be(bytes),
        CHARSET_LATIN1 => bytes.iter().map(|&b| b as char).collect(),
        // 0x0000 is nominally ASCII, but ICQ 6/7 frequently put UTF-8 here; try
        // UTF-8 first and fall back to Latin-1 so no byte is lost.
        _ => match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => bytes.iter().map(|&b| b as char).collect(),
        },
    }
}

/// Decodes big-endian UCS-2 (UTF-16BE) text.
pub fn decode_ucs2be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Collapses a decoded message to one log line: control characters (except the
/// `\n` that HTML `<br>` decodes to) become spaces, and a long message is cut so
/// the log stays readable. The message content is preserved, only trimmed.
pub fn for_log(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max) + 3);
    for ch in s.chars() {
        if out.chars().count() >= max {
            out.push_str("...");
            break;
        }
        if ch == '\n' {
            out.push_str("\\n");
        } else if ch == '\r' {
            // drop
        } else if (ch as u32) < 0x20 {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_and_utf8() {
        assert_eq!(decode(CHARSET_ASCII, b"hello"), "hello");
        // UTF-8 smiley carried under the ASCII id.
        assert_eq!(decode(CHARSET_ASCII, "caf\u{e9}".as_bytes()), "caf\u{e9}");
    }

    #[test]
    fn ucs2be() {
        // "Hi" in UTF-16BE.
        assert_eq!(decode(CHARSET_UNICODE, &[0x00, 0x48, 0x00, 0x69]), "Hi");
        // A Cyrillic letter, U+0410.
        assert_eq!(decode(CHARSET_UNICODE, &[0x04, 0x10]), "\u{0410}");
    }

    #[test]
    fn latin1() {
        // 0xE9 is é in Latin-1.
        assert_eq!(
            decode(CHARSET_LATIN1, &[0x63, 0x61, 0x66, 0xE9]),
            "caf\u{e9}"
        );
    }

    #[test]
    fn log_trims_and_keeps_html() {
        assert_eq!(for_log("a\r\nb", 50), "a\\nb");
        assert_eq!(for_log("<b>hi</b>", 50), "<b>hi</b>");
        assert_eq!(for_log("abcdef", 3), "abc...");
    }
}
