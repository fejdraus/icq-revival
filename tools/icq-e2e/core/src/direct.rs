//! Peer-to-peer instant messages are kept off while the add-on encrypts
//! (audit 2026-10, second part, finding 5).
//!
//! The add-on encrypts what goes over the BOS connection: ICBM channel 1 and
//! the channel-2 server relay. Two older ways of carrying text go from client
//! to client instead, over a TCP connection of their own, and would carry the
//! text past the container in clear:
//!
//! - **Direct IM** (AIM's "Direct IM", ODC): a channel-2 rendezvous with
//!   `CapDirectICBM`, `09461345-4C7F-11D1-8222-444553540000`
//!   (`wire.CapDirectICBM`), after which the two clients exchange `ODC2`
//!   frames on a peer connection. A client offers it by naming the capability
//!   in its `LocateSetInfo`.
//! - **ICQ direct connections** (the ICQ v7-v9 peer protocol of ICQ 99 -
//!   2003b): each client publishes its address and port in the DC info
//!   (TLV `0x000C`) of `OServiceSetUserInfoFields` (`0x0001/0x001E`); the
//!   server hands it to contacts in the user info of "buddy arrived"; a peer
//!   that finds an address there may connect and send messages straight to it.
//!
//! In encrypt mode the add-on therefore
//!
//! - takes `CapDirectICBM` out of the capability list the client announces,
//!   so a contact's client is not told it may propose direct IM;
//! - drops every direct-IM proposal and acceptance, both ways, and hands the
//!   client a cancel from the contact for one it proposed, so it does not
//!   wait (with `ICQE2E_NO_INJECT` the frame stays but turns into a cancel);
//! - zeroes the address, port and connection type of the DC info both in the
//!   client's own `SetUserInfoFields` and in the contacts' user info, so
//!   neither side has an address to open an ICQ direct connection to. The
//!   lengths stay the same; the server's own default for the TLV is zeros.
//!
//! File transfer (`CapFileTransfer`, its own rendezvous) and calls (channel 6)
//! are not touched. Whether ICQ 6.5 and 7.2 use either kind of direct
//! messaging at all is for the live test in `tools/icq-e2e/README.md`.

use crate::files::{RDV_ACCEPT, RDV_CANCEL, RDV_PROPOSE, RDV_TLV_CANCEL_REASON};
use crate::icbm::{self, Direction};
use crate::snac::{self, Reader};

/// `CapDirectICBM`, `09461345-4C7F-11D1-8222-444553540000`.
pub const CAP_DIRECT_ICBM: [u8; 16] = [
    0x09, 0x46, 0x13, 0x45, 0x4C, 0x7F, 0x11, 0xD1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
];

/// `OServiceSetUserInfoFields` (`0x0001/0x001E`).
pub const OSERVICE_SET_USER_INFO_FIELDS: u16 = 0x001E;
/// The DC info TLV (`wire.OServiceUserInfoICQDC`), in `SetUserInfoFields`
/// and in a user info block.
pub const TLV_DC_INFO: u16 = 0x000C;
/// Address (4), port (4) and connection type (1): what is zeroed.
const DC_ADDRESS_LEN: usize = 9;

/// Capability list TLV of `LocateSetInfo`.
const TLV_SET_INFO_CAPS: u16 = 0x0005;

/// The reason a cancel the add-on makes gives (`0x000B`): 1, cancelled.
const CANCEL_REASON: u16 = 0x0001;

/// `LocateSetInfo` body without [`CAP_DIRECT_ICBM`] in its capability list,
/// or `None` when it does not name it (or the list is not whole GUIDs).
/// Every other TLV and any trailing bytes stay as they were.
pub fn strip_cap(body: &[u8]) -> Option<Vec<u8>> {
    let (tlvs, tail) = snac::split_tlvs(body);
    let caps = tlvs.iter().find(|t| t.tag == TLV_SET_INFO_CAPS)?;
    if caps.value.len() % 16 != 0 || !caps.value.chunks_exact(16).any(|c| c == CAP_DIRECT_ICBM) {
        return None;
    }
    let mut out = Vec::with_capacity(body.len());
    for t in &tlvs {
        if t.tag == TLV_SET_INFO_CAPS {
            let kept: Vec<u8> = t
                .value
                .chunks_exact(16)
                .filter(|c| *c != CAP_DIRECT_ICBM)
                .flatten()
                .copied()
                .collect();
            snac::put_tlv(&mut out, t.tag, &kept);
        } else {
            snac::put_tlv(&mut out, t.tag, t.value);
        }
    }
    out.extend_from_slice(tail);
    Some(out)
}

/// A direct-IM rendezvous ICBM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectRdv {
    pub peer: String,
    /// [`RDV_PROPOSE`], [`RDV_CANCEL`] or [`RDV_ACCEPT`].
    pub kind: u16,
    pub cookie: [u8; 8],
    /// Where the rendezvous type sits in the SNAC payload, to turn the frame
    /// into a cancel in place.
    kind_at: usize,
}

impl DirectRdv {
    /// Whether the frame has to go: a proposal or an acceptance. A cancel
    /// opens nothing and passes.
    pub fn opens(&self) -> bool {
        self.kind == RDV_PROPOSE || self.kind == RDV_ACCEPT
    }
}

/// The direct-IM rendezvous of a SNAC payload travelling in `dir` (an
/// outbound `ICBMChannelMsgToHost`, an inbound `ICBMChannelMsgToClient`), or
/// `None` for anything else.
pub fn rendezvous(dir: Direction, payload: &[u8]) -> Option<DirectRdv> {
    let s = snac::parse(payload)?;
    if s.food_group != snac::FOOD_ICBM {
        return None;
    }
    let inbound = match (dir, s.sub_group) {
        (Direction::Outbound, snac::ICBM_MSG_TO_HOST) => false,
        (Direction::Inbound, snac::ICBM_MSG_TO_CLIENT) => true,
        _ => return None,
    };
    let body_at = payload.len() - s.body.len();
    let mut r = Reader::new(s.body);
    r.skip(8)?;
    if r.u16()? != icbm::CHANNEL_RENDEZVOUS {
        return None;
    }
    let peer = String::from_utf8_lossy(r.len8()?).into_owned();
    if inbound {
        r.u16()?;
        let n = r.u16()?;
        for _ in 0..n {
            r.u16()?;
            let len = r.u16()? as usize;
            r.skip(len)?;
        }
    }
    // The TLVs one by one, to know where the rendezvous data starts.
    let mut at = s.body.len() - r.remaining();
    loop {
        let tag = u16::from_be_bytes(s.body.get(at..at + 2)?.try_into().ok()?);
        let len = u16::from_be_bytes(s.body.get(at + 2..at + 4)?.try_into().ok()?) as usize;
        let value = s.body.get(at + 4..at + 4 + len)?;
        if tag == icbm::TLV_RENDEZVOUS_DATA {
            if value.get(10..26)? != CAP_DIRECT_ICBM {
                return None;
            }
            let kind = u16::from_be_bytes([value[0], value[1]]);
            let mut cookie = [0u8; 8];
            cookie.copy_from_slice(&value[2..10]);
            return Some(DirectRdv {
                peer,
                kind,
                cookie,
                kind_at: body_at + at + 4,
            });
        }
        at += 4 + len;
    }
}

/// The same SNAC payload as a cancel: the rendezvous type set to
/// [`RDV_CANCEL`], nothing else changed, so no length moves. For a stream
/// that may not take a frame out (`ICQE2E_NO_INJECT`): the other side gets a
/// cancel for a cookie it never saw proposed, which it ignores.
pub fn as_cancel(rdv: &DirectRdv, payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    out[rdv.kind_at..rdv.kind_at + 2].copy_from_slice(&RDV_CANCEL.to_be_bytes());
    out
}

/// A cancel of the direct-IM proposal `cookie`, as the server would relay
/// it from `peer` to the client (`ICBMChannelMsgToClient`, channel 2): what
/// the client is given for a proposal the add-on kept from the server, so it
/// stops waiting for an answer.
pub fn cancel_to_client(peer: &str, cookie: &[u8; 8]) -> Vec<u8> {
    let mut data = RDV_CANCEL.to_be_bytes().to_vec();
    data.extend_from_slice(cookie);
    data.extend_from_slice(&CAP_DIRECT_ICBM);
    snac::put_tlv(
        &mut data,
        RDV_TLV_CANCEL_REASON,
        &CANCEL_REASON.to_be_bytes(),
    );
    let name = &peer.as_bytes()[..peer.len().min(255)];
    let mut p = snac::FOOD_ICBM.to_be_bytes().to_vec();
    p.extend_from_slice(&snac::ICBM_MSG_TO_CLIENT.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    p.extend_from_slice(cookie);
    p.extend_from_slice(&icbm::CHANNEL_RENDEZVOUS.to_be_bytes());
    p.push(name.len() as u8);
    p.extend_from_slice(name);
    p.extend_from_slice(&[0, 0, 0, 0]); // warning level, no user info TLVs
    snac::put_tlv(&mut p, icbm::TLV_RENDEZVOUS_DATA, &data);
    p
}

/// Zeroes address, port and connection type of a DC info value in place.
/// Whether anything was not zero before.
fn zero_dc(value: &mut [u8]) -> bool {
    let n = value.len().min(DC_ADDRESS_LEN);
    let had = value[..n].iter().any(|b| *b != 0);
    value[..n].fill(0);
    had
}

/// The client's own `OServiceSetUserInfoFields` body (a TLV block) with the
/// DC info's address, port and type zeroed, or `None` when it carries no DC
/// info with any of them set. Same length.
pub fn strip_own_dc(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = body.to_vec();
    let mut at = 0;
    let mut changed = false;
    while at + 4 <= out.len() {
        let tag = u16::from_be_bytes([out[at], out[at + 1]]);
        let len = u16::from_be_bytes([out[at + 2], out[at + 3]]) as usize;
        let end = (at + 4 + len).min(out.len());
        if tag == TLV_DC_INFO {
            changed |= zero_dc(&mut out[at + 4..end]);
        }
        at += 4 + len;
    }
    changed.then_some(out)
}

/// A "buddy arrived" body (one or more user info blocks) with each
/// contact's DC info address, port and type zeroed, or `None` when there was
/// nothing to zero. Same length.
pub fn strip_contacts_dc(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = body.to_vec();
    let mut changed = false;
    // A block that does not read stops the walk; what was zeroed stays.
    let _ = zero_contacts_dc(&mut out, &mut changed);
    changed.then_some(out)
}

fn zero_contacts_dc(out: &mut [u8], changed: &mut bool) -> Option<()> {
    let be16 = |b: &[u8], at: usize| -> Option<usize> {
        Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?) as usize)
    };
    let mut at = 0;
    while at < out.len() {
        let sn = *out.get(at)? as usize;
        at += 1 + sn + 2; // screen name, warning level
        let count = be16(out, at)?;
        at += 2;
        for _ in 0..count {
            let tag = be16(out, at)? as u16;
            let len = be16(out, at + 2)?;
            let end = at + 4 + len;
            if end > out.len() {
                return None;
            }
            if tag == TLV_DC_INFO {
                *changed |= zero_dc(&mut out[at + 4..end]);
            }
            at = end;
        }
    }
    Some(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::files::CAP_FILE_TRANSFER;

    pub(crate) fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut v = tag.to_be_bytes().to_vec();
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    /// A channel-2 ICBM with `cap`, as the client sends it (outbound) or the
    /// server relays it (inbound).
    pub(crate) fn rdv(
        dir: Direction,
        peer: &str,
        kind: u16,
        cookie: [u8; 8],
        cap: [u8; 16],
    ) -> Vec<u8> {
        let mut data = kind.to_be_bytes().to_vec();
        data.extend_from_slice(&cookie);
        data.extend_from_slice(&cap);
        data.extend(tlv(0x000A, &[0, 1]));
        data.extend(tlv(0x0003, &[192, 168, 1, 20]));
        data.extend(tlv(0x0005, &[0x14, 0x46]));
        let mut body = cookie.to_vec();
        body.extend_from_slice(&icbm::CHANNEL_RENDEZVOUS.to_be_bytes());
        body.push(peer.len() as u8);
        body.extend_from_slice(peer.as_bytes());
        let sub = match dir {
            Direction::Outbound => snac::ICBM_MSG_TO_HOST,
            Direction::Inbound => {
                body.extend_from_slice(&[0, 0, 0, 1]);
                body.extend(tlv(0x0001, &[0, 0x50]));
                snac::ICBM_MSG_TO_CLIENT
            }
        };
        body.extend(tlv(icbm::TLV_RENDEZVOUS_DATA, &data));
        if dir == Direction::Outbound {
            body.extend(tlv(icbm::TLV_REQUEST_HOST_ACK, &[]));
        }
        let mut p = snac::FOOD_ICBM.to_be_bytes().to_vec();
        p.extend_from_slice(&sub.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 7]);
        p.extend_from_slice(&body);
        p
    }

    #[test]
    fn the_direct_im_capability_is_taken_out_of_the_list() {
        let other = [0x11u8; 16];
        let body = [
            tlv(0x0001, b"text/x-aolrtf"),
            tlv(
                0x0005,
                &[other, CAP_DIRECT_ICBM, CAP_FILE_TRANSFER].concat(),
            ),
            tlv(0x0004, b""),
        ]
        .concat();
        let want = [
            tlv(0x0001, b"text/x-aolrtf"),
            tlv(0x0005, &[other, CAP_FILE_TRANSFER].concat()),
            tlv(0x0004, b""),
        ]
        .concat();
        assert_eq!(strip_cap(&body), Some(want.clone()));
        assert_eq!(strip_cap(&want), None);
        assert_eq!(strip_cap(&tlv(0x0005, &[1, 2, 3])), None);
    }

    #[test]
    fn a_direct_im_rendezvous_is_told_from_a_file_transfer() {
        let c = [5u8; 8];
        for dir in [Direction::Outbound, Direction::Inbound] {
            let p = rdv(dir, "100002", RDV_PROPOSE, c, CAP_DIRECT_ICBM);
            let r = rendezvous(dir, &p).unwrap();
            assert_eq!((r.peer.as_str(), r.kind, r.cookie), ("100002", 0, c));
            assert!(r.opens());
            let cancel = as_cancel(&r, &p);
            assert_eq!(cancel.len(), p.len());
            let rc = rendezvous(dir, &cancel).unwrap();
            assert_eq!(rc.kind, RDV_CANCEL);
            assert!(!rc.opens());
            let f = rdv(dir, "100002", RDV_PROPOSE, c, CAP_FILE_TRANSFER);
            assert_eq!(rendezvous(dir, &f), None);
        }
        // The cancel for the client reads back as one, from the contact.
        let p = cancel_to_client("100002", &c);
        let r = rendezvous(Direction::Inbound, &p).unwrap();
        assert_eq!(
            (r.peer.as_str(), r.kind, r.cookie),
            ("100002", RDV_CANCEL, c)
        );
    }

    #[test]
    fn dc_info_loses_address_and_port_and_keeps_its_length() {
        let mut dc = vec![192, 168, 1, 20, 0, 0, 0x14, 0x46, 4, 0, 9];
        dc.extend_from_slice(&[0xAB; 26]);
        let body = [tlv(0x0006, &[0, 0, 0, 0]), tlv(TLV_DC_INFO, &dc)].concat();
        let got = strip_own_dc(&body).unwrap();
        assert_eq!(got.len(), body.len());
        let mut want_dc = vec![0; 9];
        want_dc.extend_from_slice(&dc[9..]);
        assert_eq!(
            got,
            [tlv(0x0006, &[0, 0, 0, 0]), tlv(TLV_DC_INFO, &want_dc)].concat()
        );
        assert_eq!(strip_own_dc(&got), None);

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
        let arrived = [
            info("100001", &[tlv(0x0001, &[0, 0x50]), tlv(TLV_DC_INFO, &dc)]),
            info("100002", &[tlv(TLV_DC_INFO, &dc)]),
        ]
        .concat();
        let want = [
            info(
                "100001",
                &[tlv(0x0001, &[0, 0x50]), tlv(TLV_DC_INFO, &want_dc)],
            ),
            info("100002", &[tlv(TLV_DC_INFO, &want_dc)]),
        ]
        .concat();
        assert_eq!(strip_contacts_dc(&arrived), Some(want.clone()));
        assert_eq!(strip_contacts_dc(&want), None);
    }
}
