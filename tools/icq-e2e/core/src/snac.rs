//! SNAC header parsing and small big-endian / TLV readers.
//!
//! A FLAP data-channel payload is a SNAC: `foodGroup:u16 | subGroup:u16 |
//! flags:u16 | requestID:u32` (all big-endian), then the SNAC body. When the
//! 0x8000 flag is set the body starts with an extra unnamed TLV block whose
//! length is a u16; we skip it so the real body lines up.

/// OSCAR food groups and subgroups we care about (see wire/snacs.go).
pub const FOOD_ICBM: u16 = 0x0004;
pub const FOOD_LOCATE: u16 = 0x0002;
pub const FOOD_BUDDY: u16 = 0x0003;
pub const FOOD_ICQ: u16 = 0x0015;
/// OService (`0x0001`): sign-on, versions and the MOTD.
pub const FOOD_OSERVICE: u16 = 0x0001;
/// `OServiceMOTD` (`0x0001/0x0013`), whose TLV block carries TLV 0x0E2E: the
/// key directory's token (KEY-DIRECTORY-API.md 3.1).
pub const OSERVICE_MOTD: u16 = 0x0013;

/// `OServiceSignOn` (`0x0001/0x0001`). Its TLV `0x0001` is the screen name,
/// which for these clients is the UIN: the one place the add-on can learn
/// which account is signing on without the command line having to say so.
pub const OSERVICE_SIGN_ON: u16 = 0x0001;
/// TLV `0x0001` of a sign-on: the screen name (`wire.LoginTLVTagsScreenName`).
pub const LOGIN_TLV_SCREEN_NAME: u16 = 0x0001;
/// `OServiceUserInfoUpdate` (`0x0001/0x000F`), the server telling the client
/// about itself right after sign-on.
pub const OSERVICE_USER_INFO: u16 = 0x000F;

pub const LOCATE_SET_INFO: u16 = 0x0004; // outbound: profile, away message, capabilities
pub const BUDDY_ARRIVED: u16 = 0x000B; // inbound: a contact's user info

pub const ICBM_MSG_TO_HOST: u16 = 0x0006; // outbound (client -> server)
pub const ICBM_MSG_TO_CLIENT: u16 = 0x0007; // inbound (server -> client)
pub const ICBM_HOST_ACK: u16 = 0x000C; // inbound: the server's ack of a message that asked for one

pub const ICQ_DB_QUERY: u16 = 0x0002; // ICQ meta request (client -> server)
pub const ICQ_DB_REPLY: u16 = 0x0003; // ICQ meta reply (server -> client), offline messages ride here

/// A parsed SNAC header plus the body that follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snac<'a> {
    pub food_group: u16,
    pub sub_group: u16,
    pub flags: u16,
    pub request_id: u32,
    pub body: &'a [u8],
}

/// Parses a SNAC header from a FLAP data payload. Returns `None` if the payload
/// is too short or an announced sub-TLV block runs past the end.
pub fn parse<'a>(payload: &'a [u8]) -> Option<Snac<'a>> {
    if payload.len() < 10 {
        return None;
    }
    let food_group = u16::from_be_bytes([payload[0], payload[1]]);
    let sub_group = u16::from_be_bytes([payload[2], payload[3]]);
    let flags = u16::from_be_bytes([payload[4], payload[5]]);
    let request_id = u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]]);
    let mut off = 10;
    if flags & 0x8000 != 0 {
        if payload.len() < off + 2 {
            return None;
        }
        let extra = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
        off += 2 + extra;
        if off > payload.len() {
            return None;
        }
    }
    Some(Snac {
        food_group,
        sub_group,
        flags,
        request_id,
        body: &payload[off..],
    })
}

/// The byte cursor, kept here under its old path for the OSCAR parsers. It
/// lives in [`crate::bytes`] because the IQE1 container reads with it too.
pub use crate::bytes::Reader;

/// One TLV: tag, and the value slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u16,
    pub value: &'a [u8],
}

/// Reads a TLV block (each entry `tag:u16 | len:u16 | value`) to the end of the
/// slice. A malformed tail simply stops the walk.
pub fn read_tlvs(data: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    while r.remaining() >= 4 {
        let tag = match r.u16() {
            Some(v) => v,
            None => break,
        };
        let len = match r.u16() {
            Some(v) => v as usize,
            None => break,
        };
        match r.bytes(len) {
            Some(value) => out.push(Tlv { tag, value }),
            None => break,
        }
    }
    out
}

/// Splits a TLV block into its entries and whatever trailing bytes do not form a
/// whole TLV, so a block can be rebuilt byte for byte around a changed entry.
pub fn split_tlvs(data: &[u8]) -> (Vec<Tlv<'_>>, &[u8]) {
    let tlvs = read_tlvs(data);
    let used: usize = tlvs.iter().map(|t| 4 + t.value.len()).sum();
    (tlvs, &data[used..])
}

/// Appends one TLV. The caller makes sure the value fits a u16 length.
pub fn put_tlv(out: &mut Vec<u8>, tag: u16, value: &[u8]) {
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Finds the first TLV with the given tag.
pub fn find_tlv<'a>(tlvs: &[Tlv<'a>], tag: u16) -> Option<&'a [u8]> {
    tlvs.iter().find(|t| t.tag == tag).map(|t| t.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header() {
        let mut p = Vec::new();
        p.extend_from_slice(&FOOD_ICBM.to_be_bytes());
        p.extend_from_slice(&ICBM_MSG_TO_HOST.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0x1234u32.to_be_bytes());
        p.extend_from_slice(b"body");
        let s = parse(&p).unwrap();
        assert_eq!(s.food_group, FOOD_ICBM);
        assert_eq!(s.sub_group, ICBM_MSG_TO_HOST);
        assert_eq!(s.request_id, 0x1234);
        assert_eq!(s.body, b"body");
    }

    #[test]
    fn skips_extra_tlv_block_when_flag_set() {
        let mut p = Vec::new();
        p.extend_from_slice(&FOOD_ICBM.to_be_bytes());
        p.extend_from_slice(&ICBM_MSG_TO_CLIENT.to_be_bytes());
        p.extend_from_slice(&0x8000u16.to_be_bytes()); // flag set
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&3u16.to_be_bytes()); // extra block len
        p.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // extra block
        p.extend_from_slice(b"real");
        let s = parse(&p).unwrap();
        assert_eq!(s.body, b"real");
    }

    #[test]
    fn tlv_walk() {
        let mut d = Vec::new();
        d.extend_from_slice(&2u16.to_be_bytes());
        d.extend_from_slice(&3u16.to_be_bytes());
        d.extend_from_slice(b"abc");
        d.extend_from_slice(&5u16.to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(b"x");
        let tlvs = read_tlvs(&d);
        assert_eq!(tlvs.len(), 2);
        assert_eq!(find_tlv(&tlvs, 2), Some(&b"abc"[..]));
        assert_eq!(find_tlv(&tlvs, 5), Some(&b"x"[..]));
        assert_eq!(find_tlv(&tlvs, 9), None);
    }

    #[test]
    fn short_payload_is_none() {
        assert!(parse(&[0, 4, 0, 6]).is_none());
    }
}
