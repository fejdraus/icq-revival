//! The `IQE1` container and the envelope inside it (DESIGN.md section 7, as
//! adjusted in docs/e2e/STAGE-3-CLIENT-CRYPTO.md).
//!
//! Container, big-endian:
//!
//! ```text
//! version u8 = 1 | scheme u8 = 1 (Olm) | flags u8 (bit 0: control message)
//! sender_device u32 | n_wraps u8 | n x { device u32, olm_type u8, len u16, olm_message }
//! ciphertext: len u16 + ChaCha20-Poly1305(envelope)
//! ```
//!
//! The first two bytes are read before anything else and decide how the rest
//! is read ([`parse`]): a version or scheme this build does not know is
//! reported as [`Parsed::Unsupported`] - the user is told the message cannot
//! be read here - and never parsed with the scheme-1 layout. Scheme 2 is
//! reserved for the post-quantum handshake (CHECKLIST 9.1, 9.8).
//!
//! Each wrap is the one-off payload key, encrypted with the Olm session between
//! the sending device and that recipient device. Everything before the
//! ciphertext is the AEAD's associated data, so the header cannot be changed
//! without the payload failing to open. The key is fresh for every message, so
//! the nonce is zero.
//!
//! Envelope (the AEAD's plaintext):
//!
//! ```text
//! version u8 = 1 | kind u8 (0 control, 1 message)
//! from len8 | to len8 | time u64 (Unix seconds)
//! form u8 (1 = channel-1 fragment: charset u16, language u16; 2 = 8-bit text)
//! text len u16 + bytes | padding len u16 + bytes
//! ```
//!
//! On the wire the container is ASCII: [`HINT`], then [`ARMOR_TAG`] and the
//! container in base64 ([`armor`], [`find_armor`]).

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::snac::Reader;

pub const VERSION: u8 = 1;
/// Olm (vodozemac): an X3DH-like handshake and the Double Ratchet.
pub const SCHEME_OLM: u8 = 1;
/// Reserved, not read by this build: Signal's PQXDH (X25519 + ML-KEM-768)
/// in front of the same Double Ratchet (CHECKLIST 9.1). A container of this
/// scheme is [`Parsed::Unsupported`] here, so a build without it says the
/// message cannot be read instead of misreading it. The plan for it: the
/// scheme-1 layout, and the key exchange (with the ML-KEM ciphertext) in a
/// control container of its own, a wrap type of its own per recipient
/// device, sent just before the message (CHECKLIST 9.1).
pub const SCHEME_PQXDH: u8 = 2;
/// Flag: a control message, with no content for the user.
pub const FLAG_CONTROL: u8 = 0x01;

/// What a client without the add-on shows in front of the container.
pub const HINT: &str = "[ICQ E2E] Encrypted message - install the ICQ E2E add-on to read it. ";
/// Where the base64 container starts.
pub const ARMOR_TAG: &str = "IQE1:";

/// Olm message types, as vodozemac numbers them.
pub const OLM_PRE_KEY: u8 = 0;
pub const OLM_NORMAL: u8 = 1;

/// The payload key, wrapped for one recipient device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrap {
    pub device: u32,
    pub olm_type: u8,
    pub message: Vec<u8>,
}

/// A parsed container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub flags: u8,
    pub sender_device: u32,
    pub wraps: Vec<Wrap>,
    pub ciphertext: Vec<u8>,
}

impl Container {
    /// Everything before the ciphertext: the associated data.
    pub fn header(&self) -> Vec<u8> {
        let mut out = vec![VERSION, SCHEME_OLM, self.flags];
        out.extend_from_slice(&self.sender_device.to_be_bytes());
        out.push(self.wraps.len() as u8);
        for w in &self.wraps {
            out.extend_from_slice(&w.device.to_be_bytes());
            out.push(w.olm_type);
            out.extend_from_slice(&(w.message.len() as u16).to_be_bytes());
            out.extend_from_slice(&w.message);
        }
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header();
        out.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses a container this build can read; `None` for anything
    /// malformed or of another version or scheme. [`parse`] tells the two
    /// apart.
    pub fn from_bytes(b: &[u8]) -> Option<Container> {
        match parse(b)? {
            Parsed::Container(c) => Some(c),
            Parsed::Unsupported { .. } => None,
        }
    }

    /// The scheme-1 body, after the version and scheme bytes.
    fn scheme_olm(mut r: Reader) -> Option<Container> {
        let flags = r.u8()?;
        let sender_device = r.u32()?;
        let n = r.u8()?;
        let mut wraps = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let device = r.u32()?;
            let olm_type = r.u8()?;
            let len = r.u16()? as usize;
            wraps.push(Wrap {
                device,
                olm_type,
                message: r.bytes(len)?.to_vec(),
            });
        }
        let len = r.u16()? as usize;
        let ciphertext = r.bytes(len)?.to_vec();
        if r.remaining() != 0 {
            return None;
        }
        Some(Container {
            flags,
            sender_device,
            wraps,
            ciphertext,
        })
    }

    pub fn is_control(&self) -> bool {
        self.flags & FLAG_CONTROL != 0
    }

    /// The wrap for a device, if the sender made one.
    pub fn wrap_for(&self, device: u32) -> Option<&Wrap> {
        self.wraps.iter().find(|w| w.device == device)
    }
}

/// What the bytes after the armour tag turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// A container this build reads.
    Container(Container),
    /// A container of a version or scheme this build does not know - made by
    /// a newer add-on. Its body is not looked at.
    Unsupported { version: u8, scheme: u8 },
}

/// Reads the version and scheme, and the rest only if both are known.
/// `None` for bytes too short to name them, or a known scheme whose body is
/// malformed.
pub fn parse(b: &[u8]) -> Option<Parsed> {
    let mut r = Reader::new(b);
    let version = r.u8()?;
    let scheme = r.u8()?;
    match (version, scheme) {
        (VERSION, SCHEME_OLM) => Container::scheme_olm(r).map(Parsed::Container),
        _ => Some(Parsed::Unsupported { version, scheme }),
    }
}

/// Encrypts an envelope under a one-off key, bound to the container header.
pub fn seal(key: &[u8; 32], header: &[u8], envelope: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &[0u8; 12].into(),
            Payload {
                msg: envelope,
                aad: header,
            },
        )
        .expect("ChaCha20-Poly1305 encryption of an in-memory buffer")
}

/// Opens what [`seal`] made; `None` if anything was changed.
pub fn open(key: &[u8; 32], header: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &[0u8; 12].into(),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .ok()
}

/// How the text was carried when it was sent, so it can be put back the same
/// way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// Channel-1 fragment 1, with its charset and language.
    Fragment { charset: u16, language: u16 },
    /// 8-bit text of a channel-2 type-2 message or an offline message.
    EightBit,
}

/// What the envelope says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Control,
    Message,
}

/// The encrypted part of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub from: String,
    pub to: String,
    /// Send time, Unix seconds.
    pub time: u64,
    pub form: Form,
    pub text: Vec<u8>,
}

/// Text plus padding is at least this long (CHECKLIST 3.3)...
pub const PAD_MIN: usize = 64;
/// ...and then up to this much random padding more.
pub const PAD_RANDOM_MAX: usize = 200;

impl Envelope {
    /// Serialises the envelope with `padding` appended.
    pub fn to_bytes(&self, padding: &[u8]) -> Vec<u8> {
        let mut out = vec![
            VERSION,
            match self.kind {
                Kind::Control => 0,
                Kind::Message => 1,
            },
        ];
        for s in [&self.from, &self.to] {
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&self.time.to_be_bytes());
        match self.form {
            Form::Fragment { charset, language } => {
                out.push(1);
                out.extend_from_slice(&charset.to_be_bytes());
                out.extend_from_slice(&language.to_be_bytes());
            }
            Form::EightBit => out.push(2),
        }
        out.extend_from_slice(&(self.text.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.text);
        out.extend_from_slice(&(padding.len() as u16).to_be_bytes());
        out.extend_from_slice(padding);
        out
    }

    /// Parses an envelope. Padding of any length is accepted and dropped.
    pub fn from_bytes(b: &[u8]) -> Option<Envelope> {
        let mut r = Reader::new(b);
        if r.u8()? != VERSION {
            return None;
        }
        let kind = match r.u8()? {
            0 => Kind::Control,
            1 => Kind::Message,
            _ => return None,
        };
        let from = String::from_utf8(r.len8()?.to_vec()).ok()?;
        let to = String::from_utf8(r.len8()?.to_vec()).ok()?;
        let hi = r.u32()? as u64;
        let time = hi << 32 | r.u32()? as u64;
        let form = match r.u8()? {
            1 => Form::Fragment {
                charset: r.u16()?,
                language: r.u16()?,
            },
            2 => Form::EightBit,
            _ => return None,
        };
        let len = r.u16()? as usize;
        let text = r.bytes(len)?.to_vec();
        let pad = r.u16()? as usize;
        r.skip(pad)?;
        if r.remaining() != 0 {
            return None;
        }
        Some(Envelope {
            kind,
            from,
            to,
            time,
            form,
            text,
        })
    }
}

/// How much padding a text of `len` bytes gets, given a random `roll`.
pub fn padding_len(len: usize, roll: u32) -> usize {
    PAD_MIN.saturating_sub(len) + (roll as usize % (PAD_RANDOM_MAX + 1))
}

/// The wire text for a container: the hint line, the tag, base64.
pub fn armor(container: &[u8]) -> String {
    format!("{HINT}{ARMOR_TAG}{}", STANDARD.encode(container))
}

/// Finds an armoured container in received text, however the text was
/// wrapped: the tag, then the longest run of base64 characters.
pub fn find_armor(text: &str) -> Option<Vec<u8>> {
    let at = text.find(ARMOR_TAG)? + ARMOR_TAG.len();
    let run: String = text[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        .collect();
    STANDARD_NO_PAD.decode(run.trim_end_matches('=')).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope {
            kind: Kind::Message,
            from: "100001".into(),
            to: "100002".into(),
            time: 1_790_000_000,
            form: Form::Fragment {
                charset: 2,
                language: 0,
            },
            text: vec![0, b'H', 0x04, 0x10],
        }
    }

    #[test]
    fn envelope_round_trips_with_any_padding() {
        let e = envelope();
        for pad in [&[][..], &[7u8; 3][..], &[9u8; 500][..]] {
            assert_eq!(Envelope::from_bytes(&e.to_bytes(pad)), Some(e.clone()));
        }
        let mut b = e.to_bytes(&[]);
        b.push(0);
        assert_eq!(Envelope::from_bytes(&b), None, "bytes after the padding");
    }

    #[test]
    fn container_round_trips_and_binds_its_header() {
        let key = [5u8; 32];
        let mut c = Container {
            flags: 0,
            sender_device: 77,
            wraps: vec![Wrap {
                device: 9,
                olm_type: OLM_PRE_KEY,
                message: vec![1, 2, 3],
            }],
            ciphertext: Vec::new(),
        };
        let env = envelope().to_bytes(&[0; 10]);
        c.ciphertext = seal(&key, &c.header(), &env);
        let parsed = Container::from_bytes(&c.to_bytes()).unwrap();
        assert_eq!(parsed, c);
        assert_eq!(open(&key, &parsed.header(), &parsed.ciphertext), Some(env));
        let mut tampered = parsed.clone();
        tampered.sender_device = 78;
        assert_eq!(open(&key, &tampered.header(), &tampered.ciphertext), None);
    }

    #[test]
    fn an_unknown_version_or_scheme_is_never_read_as_scheme_one() {
        let c = Container {
            flags: 0,
            sender_device: 77,
            wraps: vec![Wrap {
                device: 9,
                olm_type: OLM_PRE_KEY,
                message: vec![1, 2, 3],
            }],
            ciphertext: vec![4; 20],
        };
        let good = c.to_bytes();
        assert_eq!(parse(&good), Some(Parsed::Container(c)));
        // The same body under the reserved post-quantum scheme, another
        // scheme, or another version: reported, not parsed.
        for (version, scheme) in [(VERSION, SCHEME_PQXDH), (VERSION, 9), (2, SCHEME_OLM)] {
            let mut b = good.clone();
            b[0] = version;
            b[1] = scheme;
            assert_eq!(parse(&b), Some(Parsed::Unsupported { version, scheme }));
            assert_eq!(Container::from_bytes(&b), None);
        }
        // Even with a body that scheme 1 could not read at all.
        assert_eq!(
            parse(&[VERSION, SCHEME_PQXDH]),
            Some(Parsed::Unsupported {
                version: VERSION,
                scheme: SCHEME_PQXDH
            })
        );
        // Too short to name a scheme, or a scheme-1 body that is cut short.
        assert_eq!(parse(&[VERSION]), None);
        assert_eq!(parse(&good[..good.len() - 1]), None);
    }

    #[test]
    fn armour_is_found_inside_html() {
        let bytes = vec![1u8, 1, 0, 0, 0, 0, 5, 0, 0, 0, 0xFF];
        let text = armor(&bytes);
        assert!(text.is_ascii());
        assert_eq!(find_armor(&text), Some(bytes.clone()));
        let html = format!("<HTML><BODY dir=\"ltr\"><FONT>{text}</FONT></BODY></HTML>");
        assert_eq!(find_armor(&html), Some(bytes));
        assert_eq!(find_armor("no container here"), None);
    }

    #[test]
    fn padding_reaches_the_minimum() {
        assert_eq!(padding_len(10, 0), 54);
        assert_eq!(padding_len(1000, 0), 0);
        assert_eq!(padding_len(1000, 201), 0);
        assert_eq!(padding_len(1000, 200), 200);
    }
}
