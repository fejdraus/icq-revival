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

/// TLV of `LocateSetInfo` carrying our account key, raw, so the key directory
/// will accept a first publish or a reset on this connection
/// (KEY-DIRECTORY-API.md 3.3). The server ignores a value that is not 32 bytes.
pub const TLV_ACCOUNT_KEY: u16 = 0x0E2E;
/// TLV of the MOTD (`0x0001/0x0013`) carrying the key directory's token.
pub const TLV_TOKEN: u16 = 0x0E2E;
/// The account key the server will accept as an announcement.
pub const ACCOUNT_KEY_LEN: usize = 32;
/// The `uint16` message type at the head of an MOTD body, before its TLVs.
const MOTD_MESSAGE_TYPE_LEN: usize = 2;
/// What appending the account key to a `LocateSetInfo` body came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAnnounce {
    /// The body with TLV 0x0E2E added or replaced.
    Added(Vec<u8>),
    /// The body already carries this key.
    AlreadyThere,
    /// The body has no key to announce: no account key has been made yet.
    NoKey,
    /// The key was not 32 bytes; left alone.
    Malformed,
}

/// Adds or replaces TLV `0x0E2E` in a `LocateSetInfo` body with the 32 raw bytes
/// of `account_key`, keeping every other TLV and any trailing bytes.
pub fn announce_key(body: &[u8], account_key: &[u8]) -> KeyAnnounce {
    if account_key.len() != ACCOUNT_KEY_LEN {
        return KeyAnnounce::Malformed;
    }
    let (tlvs, tail) = snac::split_tlvs(body);
    if tlvs
        .iter()
        .any(|t| t.tag == TLV_ACCOUNT_KEY && t.value == account_key)
    {
        return KeyAnnounce::AlreadyThere;
    }
    // A stale announcement from an earlier key would be replaced rather than
    // left beside the new one: the server keeps the last one it saw.
    let mut out = Vec::with_capacity(body.len() + 40);
    let mut added = false;
    for t in &tlvs {
        if t.tag == TLV_ACCOUNT_KEY {
            if !added {
                snac::put_tlv(&mut out, TLV_ACCOUNT_KEY, account_key);
                added = true;
            }
        } else {
            snac::put_tlv(&mut out, t.tag, t.value);
        }
    }
    if !added {
        snac::put_tlv(&mut out, TLV_ACCOUNT_KEY, account_key);
    }
    out.extend_from_slice(tail);
    KeyAnnounce::Added(out)
}

/// The key directory's token out of an MOTD body, read without changing a byte
/// (KEY-DIRECTORY-API.md 3.1). `None` when this MOTD carries none, which is
/// what any server not running the directory sends.
///
/// An MOTD body is a `uint16` message type and then its TLVs, so the TLVs
/// start two bytes in. Reading them from the start picks the message type up
/// as a tag and the first TLV's length as its value, which is why an MOTD that
/// does carry a token was read as carrying a single empty `0x0004`.
pub fn motd_token(body: &[u8]) -> Option<&[u8]> {
    let (tlvs, _) = snac::split_tlvs(motd_tlvs(body));
    tlvs.iter().find(|t| t.tag == TLV_TOKEN).map(|t| t.value)
}

/// The TLV tags a MOTD carries, in the order they came, as `0xNNNN`. For the
/// log: a MOTD that ought to carry [`TLV_TOKEN`] and does not says so by
/// listing every tag it does carry.
pub fn motd_tags(body: &[u8]) -> Vec<String> {
    let (tlvs, _) = snac::split_tlvs(motd_tlvs(body));
    tlvs.iter().map(|t| format!("{:#06X}", t.tag)).collect()
}

/// The TLVs of an MOTD body, past its `uint16` message type.
fn motd_tlvs(body: &[u8]) -> &[u8] {
    body.get(MOTD_MESSAGE_TYPE_LEN..).unwrap_or(&[])
}

/// The screen name of a sign-on body, when it is a UIN.
///
/// Both clients are launched from a shortcut that carries no UIN, so this is
/// how the add-on learns which account it is running as. `None` when the body
/// has no screen name or names something that is not a number: a guessed
/// account would publish a key nobody could tie to this connection.
pub fn sign_on_uin(body: &[u8]) -> Option<String> {
    let (tlvs, _) = snac::split_tlvs(body);
    let name = snac::find_tlv(&tlvs, snac::LOGIN_TLV_SCREEN_NAME)?;
    let text = std::str::from_utf8(name).ok()?.trim();
    text.parse::<u64>().ok().map(|n| n.to_string())
}

/// Our own UIN, out of an `OServiceUserInfoUpdate` body, when it is one.
///
/// This is the reliable source, for both clients. The clients do sign in over
/// the web API, so the BOS sign-on carries only a cookie and no screen name,
/// and ICQ 6.5 sends its UIN on the authorization connection instead - neither
/// of which the BOS stream ever sees. The server's own user info on the BOS
/// connection opens with the screen name, and that is the one place both
/// clients learn which account they are.
///
/// The body is not a TLV block: `TLVUserInfo` is a screen name with a `uint8`
/// length, then a `uint16` warning level, and only then the TLVs
/// (`wire.TLVUserInfo`).
pub fn own_uin_in_user_info(body: &[u8]) -> Option<String> {
    let len = *body.first()? as usize;
    let name = body.get(1..1 + len)?;
    // len8 counts the byte that carries it, so the name is one shorter.
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    let text = std::str::from_utf8(name).ok()?.trim();
    text.parse::<u64>().ok().map(|n| n.to_string())
}

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
/// contact with whether its capabilities name [`CAP_E2E`].
///
/// A block without a capability list counts as not announcing it: the server
/// puts the list in every user info whose client set one, and a client with
/// the add-on always sets one (with [`CAP_E2E`] in it). A client that sends
/// none at all - ICQ 99b, through the server's legacy bridge - is exactly a
/// client without end-to-end encryption (the owner's decision on the current
/// client, CHECKLIST 10.6).
pub fn contacts(body: &[u8]) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut r = Reader::new(body);
    while r.remaining() > 0 {
        match user_info(&mut r) {
            Some(c) => out.push(c),
            None => break,
        }
    }
    out
}

/// The contact of a `LocateUserInfoReply` (`0x0002/0x0006`) body and whether
/// its capabilities name [`CAP_E2E`], as for [`contacts`]. Only the first
/// block is a user info block: the profile and away message TLVs follow it.
pub fn user_info_reply(body: &[u8]) -> Option<(String, bool)> {
    user_info(&mut Reader::new(body))
}

/// The contacts of a "buddy departed" (`0x0003/0x000C`) body: user info
/// blocks like an arrival's, of which only the names count.
pub fn departed(body: &[u8]) -> Vec<String> {
    contacts(body).into_iter().map(|(name, _)| name).collect()
}

/// One user info block off `r`: the screen name and whether its capability
/// list names [`CAP_E2E`] (no list: not).
fn user_info(r: &mut Reader) -> Option<(String, bool)> {
    let sn = r.len8()?;
    r.u16()?; // warning level
    let count = r.u16()?;
    let mut has = false;
    for _ in 0..count {
        let tag = r.u16()?;
        let len = r.u16()?;
        let value = r.bytes(len as usize)?;
        if tag == TLV_USER_INFO_CAPS {
            has = names_e2e(value);
        }
    }
    Some((String::from_utf8_lossy(sn).into_owned(), has))
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
            vec![
                ("100001".to_string(), true),
                ("100002".to_string(), false),
                // No capability list at all (ICQ 99b): no add-on.
                ("100003".to_string(), false),
            ]
        );
        assert_eq!(departed(&body), vec!["100001", "100002", "100003"]);
        // A user info reply: the first block, then the profile's TLVs.
        let reply = [
            info("100001", &[tlv(0x000D, &[CAP_E2E, OTHER].concat())]),
            tlv(0x0002, b"profile"),
        ]
        .concat();
        assert_eq!(user_info_reply(&reply), Some(("100001".to_string(), true)));
        assert_eq!(
            user_info_reply(&info("100009", &[])),
            Some(("100009".to_string(), false))
        );
    }
}

#[cfg(test)]
mod userinfo_tests {
    use super::own_uin_in_user_info;

    /// The exact bytes `wire.MarshalBE` produces for
    /// `TLVUserInfo{ScreenName: "100001", WarningLevel: 7, ...}`, taken from
    /// the Go encoder rather than guessed. The screen name has a `uint8`
    /// length that counts the name only, and the warning level follows it.
    const FROM_SERVER: [u8; 22] = [
        0x06, 0x31, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00, 0x07, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x10, 0x00, 0x03, 0x00, 0x04, 0x6A,
    ];

    #[test]
    fn the_account_comes_off_the_servers_own_user_info() {
        assert_eq!(
            own_uin_in_user_info(&FROM_SERVER[..]).as_deref(),
            Some("100001")
        );
    }

    #[test]
    fn a_truncated_user_info_gives_no_account() {
        assert_eq!(own_uin_in_user_info(&FROM_SERVER[..2]), None);
        assert_eq!(own_uin_in_user_info(&[]), None);
    }

    #[test]
    fn a_screen_name_that_is_not_a_number_gives_no_account() {
        // len8 "somename", then a warning level.
        let mut body = vec![9u8];
        body.extend_from_slice(b"somename");
        body.extend_from_slice(&[0, 0]);
        assert_eq!(own_uin_in_user_info(&body), None);
    }
}
