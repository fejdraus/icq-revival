//! The add-on's capability: announced for our client, noticed for contacts.
//!
//! OSCAR clients announce what they support as a list of 16-byte GUIDs in TLV
//! 0x0005 of `LocateSetInfo` (`0x0002/0x0004`); the server keeps the list per
//! session and hands it to contacts in the user info (TLV 0x000D) of "buddy
//! arrived" (`0x0003/0x000B`). The add-on appends [`CAP_E2E`] to the list the
//! client sends, in place, so a contact's add-on can tell who has one; and it
//! reads the same capability out of contacts' user info. The client sends its
//! list again whenever it changes (a mood is a capability too), and each time the
//! capability is appended again, so it is never dropped.
//!
//! The server compares capabilities one by one and passes unknown ones along, so
//! an extra GUID changes nothing for it; whether the stock clients ignore it is
//! part of the owner test (DESIGN.md section 12, risk 2).

use crate::snac::{self, Reader};

/// `CapE2EEncrypt`, `0946E2E1-4C7F-11D1-8222-444553540000`, in the ICQ
/// `0946xxxx` family (DESIGN.md section 7).
pub const CAP_E2E: [u8; 16] = [
    0x09, 0x46, 0xE2, 0xE1, 0x4C, 0x7F, 0x11, 0xD1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
];

/// Capability list TLV of `LocateSetInfo`.
const TLV_SET_INFO_CAPS: u16 = 0x0005;
/// Capability list TLV of a user info block.
const TLV_USER_INFO_CAPS: u16 = 0x000D;

/// What adding the capability to a `LocateSetInfo` body came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Announce {
    /// The body with the capability appended to the list.
    Added(Vec<u8>),
    /// The list already names it.
    AlreadyThere,
    /// The body carries no capability list (the client changes something
    /// else, such as its profile or away message).
    NoList,
    /// The list is not a whole number of GUIDs; left alone.
    Malformed,
}

/// Appends [`CAP_E2E`] to the capability list of a `LocateSetInfo` body,
/// keeping every other TLV and any trailing bytes as they were.
pub fn announce(body: &[u8]) -> Announce {
    let (tlvs, tail) = snac::split_tlvs(body);
    let Some(caps) = tlvs.iter().find(|t| t.tag == TLV_SET_INFO_CAPS) else {
        return Announce::NoList;
    };
    if caps.value.len() % 16 != 0 {
        return Announce::Malformed;
    }
    if names_e2e(caps.value) {
        return Announce::AlreadyThere;
    }
    if caps.value.len() + 16 > u16::MAX as usize {
        return Announce::Malformed;
    }
    let mut out = Vec::with_capacity(body.len() + 16);
    let mut done = false;
    for t in &tlvs {
        if t.tag == TLV_SET_INFO_CAPS && !done {
            snac::put_tlv(&mut out, t.tag, &[t.value, &CAP_E2E[..]].concat());
            done = true;
        } else {
            snac::put_tlv(&mut out, t.tag, t.value);
        }
    }
    out.extend_from_slice(tail);
    Announce::Added(out)
}

/// Reads a "buddy arrived" body - one or more user info blocks, each a screen
/// name (len8), a warning level (u16) and a counted TLV block - and returns each
/// contact with whether its capabilities name [`CAP_E2E`]. Blocks without a
/// capability list are left out: they say nothing either way.
pub fn contacts(body: &[u8]) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut r = Reader::new(body);
    while r.remaining() > 0 {
        let Some(sn) = r.len8() else { break };
        let (Some(_warning), Some(count)) = (r.u16(), r.u16()) else {
            break;
        };
        let mut has = None;
        for _ in 0..count {
            let (Some(tag), Some(len)) = (r.u16(), r.u16()) else {
                return out;
            };
            let Some(value) = r.bytes(len as usize) else {
                return out;
            };
            if tag == TLV_USER_INFO_CAPS {
                has = Some(names_e2e(value));
            }
        }
        if let Some(has) = has {
            out.push((String::from_utf8_lossy(sn).into_owned(), has));
        }
    }
    out
}

fn names_e2e(list: &[u8]) -> bool {
    list.chunks_exact(16).any(|c| c == CAP_E2E)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut v = tag.to_be_bytes().to_vec();
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    const OTHER: [u8; 16] = [0x11; 16];

    #[test]
    fn appended_to_the_list_in_place() {
        let body = [
            tlv(0x0001, b"text/x-aolrtf"),
            tlv(0x0005, &OTHER),
            tlv(0x0004, b""),
        ]
        .concat();
        let want = [
            tlv(0x0001, b"text/x-aolrtf"),
            tlv(0x0005, &[OTHER, CAP_E2E].concat()),
            tlv(0x0004, b""),
        ]
        .concat();
        assert_eq!(announce(&body), Announce::Added(want.clone()));
        assert_eq!(announce(&want), Announce::AlreadyThere);
    }

    #[test]
    fn left_alone_without_a_valid_list() {
        assert_eq!(announce(&tlv(0x0004, b"away")), Announce::NoList);
        assert_eq!(announce(&tlv(0x0005, &[1, 2, 3])), Announce::Malformed);
    }

    #[test]
    fn contacts_in_buddy_arrived() {
        let info = |sn: &str, tlvs: &[Vec<u8>]| {
            let mut v = vec![sn.len() as u8];
            v.extend_from_slice(sn.as_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&(tlvs.len() as u16).to_be_bytes());
            for t in tlvs {
                v.extend_from_slice(t);
            }
            v
        };
        let body = [
            info(
                "100001",
                &[
                    tlv(0x0001, &[0, 0x50]),
                    tlv(0x000D, &[OTHER, CAP_E2E].concat()),
                ],
            ),
            info("100002", &[tlv(0x000D, &OTHER)]),
            info("100003", &[tlv(0x0006, &[0, 0, 0, 0])]),
        ]
        .concat();
        assert_eq!(
            contacts(&body),
            vec![("100001".to_string(), true), ("100002".to_string(), false)]
        );
    }
}
