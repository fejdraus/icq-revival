//! Builders for synthetic FLAP/SNAC/ICBM frames shared by the integration tests.
#![allow(dead_code)]

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
