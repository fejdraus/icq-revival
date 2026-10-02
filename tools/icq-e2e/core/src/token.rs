//! The key directory token (docs/e2e/KEY-DIRECTORY-API.md 3.1-3.2).
//!
//! The server hands it out in TLV `0x0E2E` of the MOTD on the BOS connection.
//! It is opaque to the add-on except for what it needs to know: whose token it
//! is (the add-on learns its own screen name from it) and when it expires. The
//! layout is `HMACCookieBaker`'s: `u16 len | data | u16 len | signature`, where
//! data is `u32 expiry | u16 len | payload` and the payload is
//! `FF FF FF 'E' '2' 'E' | len8 screen name | u64 sign-on | u8 instance`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// The magic a token's payload opens with.
const MAGIC: [u8; 6] = [0xFF, 0xFF, 0xFF, b'E', b'2', b'E'];

/// A token as the add-on keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The token for the `Authorization` header: base64url without padding.
    pub bearer: String,
    /// The account it belongs to, in ident form.
    pub screen_name: String,
    /// When it expires, Unix seconds.
    pub expires_at: u64,
}

impl Token {
    /// Reads a token's raw bytes; `None` if they are not a key directory token.
    pub fn parse(raw: &[u8]) -> Option<Token> {
        let be16 = |at: usize| -> Option<usize> {
            Some(u16::from_be_bytes([*raw.get(at)?, *raw.get(at + 1)?]) as usize)
        };
        let data_len = be16(0)?;
        let data = raw.get(2..2 + data_len)?;
        if data.len() < 6 {
            return None;
        }
        let expires_at = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let payload = data.get(6..6 + payload_len)?;
        if payload.get(..6)? != MAGIC {
            return None;
        }
        let sn_len = *payload.get(6)? as usize;
        let sn = payload.get(7..7 + sn_len)?;
        Some(Token {
            bearer: URL_SAFE_NO_PAD.encode(raw),
            screen_name: String::from_utf8_lossy(sn).into_owned(),
            expires_at,
        })
    }

    /// Reads a token handed out by `POST /e2e/v1/token` (base64url).
    pub fn from_bearer(bearer: &str) -> Option<Token> {
        Token::parse(&URL_SAFE_NO_PAD.decode(bearer.trim_end_matches('=')).ok()?)
    }
}

/// Builds an unsigned token in the server's layout, for fake directories in
/// tests and the test host; the real server's signature is only checked there.
pub fn unsigned(screen_name: &str, expires_at: u32) -> Vec<u8> {
    let mut payload = MAGIC.to_vec();
    payload.push(screen_name.len() as u8);
    payload.extend_from_slice(screen_name.as_bytes());
    payload.extend_from_slice(&1_790_000_000_000_000_000u64.to_be_bytes());
    payload.push(1);
    let mut data = expires_at.to_be_bytes().to_vec();
    data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    data.extend_from_slice(&payload);
    let mut raw = (data.len() as u16).to_be_bytes().to_vec();
    raw.extend_from_slice(&data);
    raw.extend_from_slice(&32u16.to_be_bytes());
    raw.extend_from_slice(&[0xAB; 32]);
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_owner_and_expiry() {
        let raw = unsigned("100001", 1_790_000_000);
        let t = Token::parse(&raw).unwrap();
        assert_eq!(t.screen_name, "100001");
        assert_eq!(t.expires_at, 1_790_000_000);
        assert!(!t.bearer.contains('='));
        assert_eq!(Token::from_bearer(&t.bearer), Some(t));
    }

    #[test]
    fn a_login_cookie_is_not_a_token() {
        let mut raw = unsigned("100001", 1);
        raw[8] = 0x00; // first magic byte
        assert_eq!(Token::parse(&raw), None);
        assert_eq!(Token::parse(&[0, 1]), None);
    }
}
