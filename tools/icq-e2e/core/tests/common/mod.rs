//! Builders for synthetic FLAP/SNAC/ICBM frames shared by the integration tests.
#![allow(dead_code)]

/// Keeps these tests out of the live client's log.
///
/// `ICQE2E_LOG` is set for the whole user, and an integration test links the
/// library as an ordinary dependency where `cfg!(test)` is false, so this
/// binary has to say so itself before anything writes a line.
#[ctor::ctor(unsafe)]
fn own_log() {
    icqe2e_core::log::own_file();
}

pub const FLAP_MARKER: u8 = 0x2A;
pub const FLAP_SNAC: u8 = 0x02;

pub fn flap(channel: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![FLAP_MARKER, channel];
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A SNAC data frame.
pub fn data(seq: u16, payload: &[u8]) -> Vec<u8> {
    flap(FLAP_SNAC, seq, payload)
}

/// The channel-1 frame both sides open an OSCAR connection with.
pub fn hello(seq: u16) -> Vec<u8> {
    flap(0x01, seq, &[0, 0, 0, 1])
}

pub fn snac(fg: u16, sg: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&fg.to_be_bytes());
    v.extend_from_slice(&sg.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes()); // flags
    v.extend_from_slice(&1u32.to_be_bytes()); // request id
    v.extend_from_slice(body);
    v
}

pub fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&(value.len() as u16).to_be_bytes());
    v.extend_from_slice(value);
    v
}

/// A channel-1 message fragment list: a caps fragment (id 5) then the message
/// fragment (id 1) with charset, language and text.
pub fn ch1_fragments(charset: u16, text: &[u8]) -> Vec<u8> {
    let mut frags = Vec::new();
    frags.extend_from_slice(&[0x05, 0x01, 0x00, 0x02, 0x01, 0x01]);
    let mut msg = Vec::new();
    msg.extend_from_slice(&charset.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // language
    msg.extend_from_slice(text);
    frags.push(0x01);
    frags.push(0x01);
    frags.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    frags.extend_from_slice(&msg);
    frags
}

pub fn ucs2be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

pub fn to_host_body(target: &str, channel: u16, msg_tlvs: &[u8]) -> Vec<u8> {
    let mut b = vec![1, 2, 3, 4, 5, 6, 7, 8]; // cookie
    b.extend_from_slice(&channel.to_be_bytes());
    b.push(target.len() as u8);
    b.extend_from_slice(target.as_bytes());
    b.extend_from_slice(msg_tlvs);
    b
}

pub fn to_client_body(sender: &str, channel: u16, msg_tlvs: &[u8]) -> Vec<u8> {
    let mut b = vec![8, 7, 6, 5, 4, 3, 2, 1]; // cookie
    b.extend_from_slice(&channel.to_be_bytes());
    b.push(sender.len() as u8);
    b.extend_from_slice(sender.as_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // warning level
    b.extend_from_slice(&2u16.to_be_bytes()); // user-info TLV count
    b.extend_from_slice(&tlv(0x0001, &[0x00, 0x50])); // user class
    b.extend_from_slice(&tlv(0x0006, &[0, 0, 0, 0])); // status
    b.extend_from_slice(msg_tlvs);
    b
}

/// Outbound channel-1 message as the client sends it: message TLV, then a
/// request-ack and store-offline TLV that must pass untouched.
pub fn out_ch1(seq: u16, target: &str, charset: u16, text: &[u8]) -> Vec<u8> {
    let mut tlvs = tlv(0x0002, &ch1_fragments(charset, text));
    tlvs.extend(tlv(0x0003, &[]));
    tlvs.extend(tlv(0x0006, &[]));
    data(seq, &snac(0x0004, 0x0006, &to_host_body(target, 1, &tlvs)))
}

/// The same message as the server relays it to the recipient.
pub fn in_ch1(seq: u16, sender: &str, charset: u16, text: &[u8]) -> Vec<u8> {
    let mut tlvs = tlv(0x0002, &ch1_fragments(charset, text));
    tlvs.extend(tlv(0x000B, &[]));
    data(
        seq,
        &snac(0x0004, 0x0007, &to_client_body(sender, 1, &tlvs)),
    )
}

/// TLV 0x2711 of a plain type-2 message: header 1, header 2, msgType 0x01,
/// flags, status, priority, text (NUL-terminated), colours and the UTF-8 cap.
pub fn type2_svc(text: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x1Bu16.to_le_bytes());
    v.extend_from_slice(&[0x09, 0x00]); // protocol version
    v.extend_from_slice(&[0u8; 16]); // plugin: none
    v.extend_from_slice(&[0, 0, 3, 0, 0, 0, 0, 0xFF, 0xFF]);
    v.extend_from_slice(&0x0Eu16.to_le_bytes());
    v.extend_from_slice(&[0xFF, 0xFF]);
    v.extend_from_slice(&[0u8; 12]);
    v.extend_from_slice(&[0x01, 0x00]); // msgType plain, flags
    v.extend_from_slice(&[0, 0, 0x21, 0]); // status, priority
    let mut t = text.to_vec();
    t.push(0);
    v.extend_from_slice(&(t.len() as u16).to_le_bytes());
    v.extend_from_slice(&t);
    v.extend_from_slice(&[0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x00]); // colours
    let cap = b"{0946134E-4C7F-11D1-8222-444553540000}";
    v.extend_from_slice(&(cap.len() as u32).to_le_bytes());
    v.extend_from_slice(cap);
    v
}

pub const CAP_SERVER_RELAY: [u8; 16] = [
    0x09, 0x46, 0x13, 0x49, 0x4C, 0x7F, 0x11, 0xD1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
];

/// A channel-2 fragment (TLV 0x0005 value) around `svc`.
pub fn ch2_fragment(cap: [u8; 16], svc: &[u8]) -> Vec<u8> {
    let mut frag = Vec::new();
    frag.extend_from_slice(&0u16.to_be_bytes()); // type: propose
    frag.extend_from_slice(&[9u8; 8]); // cookie
    frag.extend_from_slice(&cap);
    frag.extend_from_slice(&tlv(0x000A, &[0, 1])); // sequence number
    frag.extend_from_slice(&tlv(0x000F, &[]));
    frag.extend_from_slice(&tlv(0x2711, svc));
    frag
}

pub fn out_ch2(seq: u16, target: &str, text: &[u8]) -> Vec<u8> {
    let mut tlvs = tlv(0x0005, &ch2_fragment(CAP_SERVER_RELAY, &type2_svc(text)));
    tlvs.extend(tlv(0x0003, &[]));
    data(seq, &snac(0x0004, 0x0006, &to_host_body(target, 2, &tlvs)))
}

pub fn in_ch2(seq: u16, sender: &str, text: &[u8]) -> Vec<u8> {
    let tlvs = tlv(0x0005, &ch2_fragment(CAP_SERVER_RELAY, &type2_svc(text)));
    data(
        seq,
        &snac(0x0004, 0x0007, &to_client_body(sender, 2, &tlvs)),
    )
}

/// An ICQ DB reply (0x0015/0x0003) carrying one offline message.
pub fn offline_reply(seq: u16, sender: u32, text: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&100003u32.to_le_bytes()); // our UIN
    inner.extend_from_slice(&0x0041u16.to_le_bytes()); // offline message
    inner.extend_from_slice(&7u16.to_le_bytes()); // seq
    inner.extend_from_slice(&sender.to_le_bytes());
    inner.extend_from_slice(&2026u16.to_le_bytes());
    inner.extend_from_slice(&[9, 30, 12, 0]); // month, day, hour, minute
    inner.push(0x01); // plain
    inner.push(0x00); // flags
    let mut t = text.to_vec();
    t.push(0);
    inner.extend_from_slice(&(t.len() as u16).to_le_bytes());
    inner.extend_from_slice(&t);
    let mut env = Vec::new();
    env.extend_from_slice(&(inner.len() as u16).to_le_bytes());
    env.extend_from_slice(&inner);
    data(seq, &snac(0x0015, 0x0003, &tlv(0x0001, &env)))
}

/// `LocateSetInfo` with a MIME type, the capability list and an away message.
pub fn set_info(seq: u16, caps: &[[u8; 16]]) -> Vec<u8> {
    let mut body = tlv(0x0001, b"text/aolrtf; charset=\"us-ascii\"");
    body.extend(tlv(0x0005, &caps.concat()));
    body.extend(tlv(0x0004, b""));
    data(seq, &snac(0x0002, 0x0004, &body))
}

/// "Buddy arrived" for one contact with a capability list.
pub fn buddy_arrived(seq: u16, sn: &str, caps: &[[u8; 16]]) -> Vec<u8> {
    let mut b = vec![sn.len() as u8];
    b.extend_from_slice(sn.as_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&2u16.to_be_bytes());
    b.extend(tlv(0x0006, &[0, 0, 0, 0]));
    b.extend(tlv(0x000D, &caps.concat()));
    data(seq, &snac(0x0003, 0x000B, &b))
}

/// The channel-1 message as it sits on the wire: the declared charset and the
/// text's raw bytes, before anything decodes them.
///
/// `icbm::parse_*` hands back a decoded `String`, which is what the log wants
/// but not what a test of the message path wants: there the bytes must survive
/// the round trip exactly, HTML and all.
pub struct RawText {
    /// The charset declared in the fragment, not what the text really is.
    pub charsets: Vec<u16>,
    /// The text as sent.
    pub text: Vec<u8>,
}

/// Finds the message fragment of a channel-1 SNAC payload and returns its
/// charset and raw text. `None` if this is not a channel-1 message.
pub fn snac_text(payload: &[u8]) -> Option<RawText> {
    // SNAC header: food group, subgroup, flags, request id - 10 bytes. Then
    // cookie[8] channel:u16 and a len8 screen name.
    let channel = u16::from_be_bytes([*payload.get(18)?, *payload.get(19)?]);
    if channel != 1 {
        return None;
    }
    let name_len = *payload.get(20)? as usize;
    // `tlvs` starts here and `r` indexes into it, not into the whole payload.
    let tlvs = &payload[21 + name_len..];
    let mut charsets = Vec::new();
    // A `ToClient` body carries a warning level and a count of user-info TLVs
    // between the screen name and the message TLVs; a `ToHost` body does not.
    let sub_group = u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]);
    let mut r = 0usize;
    if sub_group == 0x0007 {
        // warning level:u16 then a count of user-info TLVs, each walked by its
        // own length - they are not all four bytes.
        let count = u16::from_be_bytes([*tlvs.get(2)?, *tlvs.get(3)?]) as usize;
        r = 4;
        for _ in 0..count {
            let len = u16::from_be_bytes([*tlvs.get(r + 2)?, *tlvs.get(r + 3)?]) as usize;
            r += 4 + len;
        }
    }
    while r + 4 <= tlvs.len() {
        let tag = u16::from_be_bytes([tlvs[r], tlvs[r + 1]]);
        let len = u16::from_be_bytes([tlvs[r + 2], tlvs[r + 3]]) as usize;
        let Some(value) = tlvs.get(r + 4..r + 4 + len) else {
            break;
        };
        if tag == 0x0002 {
            // The fragment list: id:u8 version:u8 len:u16 payload.
            let mut f = 0usize;
            while f + 4 <= value.len() {
                let id = value[f];
                let flen = u16::from_be_bytes([value[f + 2], value[f + 3]]) as usize;
                let Some(payload) = value.get(f + 4..f + 4 + flen) else {
                    break;
                };
                if id == 1 && payload.len() >= 4 {
                    charsets.push(u16::from_be_bytes([payload[0], payload[1]]));
                    return Some(RawText {
                        charsets,
                        text: payload[4..].to_vec(),
                    });
                }
                f += 4 + flen;
            }
        }
        r += 4 + len;
    }
    None
}

/// The declared charset of the message in a SNAC payload.
pub fn snac_charset(payload: &[u8]) -> Option<u16> {
    snac_text(payload).and_then(|t| t.charsets.first().copied())
}

/// The offline message the client *sends*: `0x0015/0x0002`, the same block as
/// the reply with the recipient where the reply has the sender.
pub fn offline_send(seq: u16, recipient: u32, text: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&100003u32.to_le_bytes()); // our UIN
    inner.extend_from_slice(&0x0006u16.to_le_bytes()); // offline message, sent
    inner.extend_from_slice(&7u16.to_le_bytes()); // seq
    inner.extend_from_slice(&recipient.to_le_bytes());
    inner.extend_from_slice(&2026u16.to_le_bytes());
    inner.extend_from_slice(&[9, 30, 12, 0]); // month, day, hour, minute
    inner.push(0x01); // plain
    inner.push(0x00); // flags
                      // NUL-terminated, with its length in front, little-endian like the block.
    let mut t = text.to_vec();
    t.push(0);
    inner.extend_from_slice(&(t.len() as u16).to_le_bytes());
    inner.extend_from_slice(&t);
    let mut env = Vec::new();
    env.extend_from_slice(&(inner.len() as u16).to_le_bytes());
    env.extend_from_slice(&inner);
    data(seq, &snac(0x0015, 0x0002, &tlv(0x0001, &env)))
}

/// The text of the offline message in an `0x0015` SNAC on the wire.
///
/// The block starts with a u16 little-endian length, then the message, and the
/// text is the last thing in it.
pub fn offline_text_on_wire(frame: &[u8]) -> Option<String> {
    // FLAP header, SNAC header, then the TLV block of tag 0x0001.
    let body = 6 + 10;
    let tag = u16::from_be_bytes([*frame.get(body)?, *frame.get(body + 1)?]);
    let len = u16::from_be_bytes([*frame.get(body + 2)?, *frame.get(body + 3)?]) as usize;
    if tag != 0x0001 {
        return None;
    }
    let env = frame.get(body + 4..body + 4 + len)?;
    let block_len = u16::from_le_bytes([*env.get(0)?, *env.get(1)?]) as usize;
    let block = env.get(2..2 + block_len)?;
    // Everything before the text length is fixed for a plain message: the
    // recipient, the request type, the sequence, the other party, the
    // timestamp, the message type and the flags.
    let len_at = 4 + 2 + 2 + 4 + 2 + 1 + 1 + 1 + 1 + 1 + 1;
    let text_len = u16::from_le_bytes([*block.get(len_at)?, *block.get(len_at + 1)?]) as usize;
    let start = len_at + 2;
    let raw = block.get(start..start + text_len)?;
    Some(
        String::from_utf8_lossy(raw)
            .trim_end_matches('\0')
            .to_string(),
    )
}
