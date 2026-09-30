//! End-to-end tests that build synthetic FLAP/SNAC/ICBM frames and drive the
//! engine, asserting the log lines it produces. These exercise reassembly,
//! SNAC routing, ICBM channel-1/channel-2 decoding and ICQ offline parsing
//! without any Windows or Winsock dependency.

use icqe2e_core::engine::Engine;

const FLAP_MARKER: u8 = 0x2A;
const FLAP_SNAC: u8 = 0x02;

fn flap(seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![FLAP_MARKER, FLAP_SNAC];
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn snac(fg: u16, sg: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&fg.to_be_bytes());
    v.extend_from_slice(&sg.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes()); // flags
    v.extend_from_slice(&1u32.to_be_bytes()); // request id
    v.extend_from_slice(body);
    v
}

fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&(value.len() as u16).to_be_bytes());
    v.extend_from_slice(value);
    v
}

/// A channel-1 message fragment list: a caps fragment (id 5) then the message
/// fragment (id 1) with charset, language and text.
fn ch1_fragments(charset: u16, text: &[u8]) -> Vec<u8> {
    let mut frags = Vec::new();
    // id 5 caps fragment {1,1,2}
    frags.extend_from_slice(&[0x05, 0x01, 0x00, 0x02, 0x01, 0x01]);
    // id 1 message fragment
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

fn to_host_body(target: &str, channel: u16, msg_tlv: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8]; // cookie
    b.extend_from_slice(&channel.to_be_bytes());
    b.push(target.len() as u8);
    b.extend_from_slice(target.as_bytes());
    b.extend_from_slice(msg_tlv);
    b
}

fn to_client_body(sender: &str, channel: u16, msg_tlv: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8]; // cookie
    b.extend_from_slice(&channel.to_be_bytes());
    b.push(sender.len() as u8);
    b.extend_from_slice(sender.as_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // warning level
    b.extend_from_slice(&0u16.to_be_bytes()); // user-info TLV count = 0
    b.extend_from_slice(msg_tlv);
    b
}

#[test]
fn outbound_channel1_ascii() {
    let mut e = Engine::new();
    let frags = ch1_fragments(0x0000, b"hello world");
    let body = to_host_body("100002", 1, &tlv(0x0002, &frags));
    let frame = flap(10, &snac(0x0004, 0x0006, &body));
    let lines = e.on_send(1, &frame);
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("OUT"));
    assert!(lines[0].contains("peer=100002"));
    assert!(lines[0].contains("ch1/text"));
    assert!(lines[0].contains("text=\"hello world\""));
}

#[test]
fn inbound_channel1_html_ucs2be() {
    let mut e = Engine::new();
    // "<b>hi</b>" as UTF-16BE.
    let mut ucs2 = Vec::new();
    for ch in "<b>hi</b>".chars() {
        ucs2.extend_from_slice(&(ch as u16).to_be_bytes());
    }
    let frags = ch1_fragments(0x0002, &ucs2);
    let body = to_client_body("54321", 1, &tlv(0x0002, &frags));
    let frame = flap(3, &snac(0x0004, 0x0007, &body));
    let lines = e.on_recv(2, &frame);
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("IN"));
    assert!(lines[0].contains("peer=54321"));
    assert!(lines[0].contains("ch1/html"));
    assert!(lines[0].contains("text=\"<b>hi</b>\""));
}

#[test]
fn channel1_split_across_recv_calls() {
    let mut e = Engine::new();
    let frags = ch1_fragments(0x0000, b"partial frame test");
    let body = to_client_body("777", 1, &tlv(0x0002, &frags));
    let frame = flap(4, &snac(0x0004, 0x0007, &body));
    let (a, b) = frame.split_at(9);
    assert!(e.on_recv(5, a).is_empty());
    let lines = e.on_recv(5, b);
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("text=\"partial frame test\""));
}

#[test]
fn channel2_type2_plugin_document() {
    let mut e = Engine::new();
    // Build a service-data blob: hdrLen(u16 LE) header, then restLen(u32 LE),
    // docLen(u32 LE), doc.
    let doc = b"greeting text";
    let mut svc = Vec::new();
    let header = [0u8; 4];
    svc.extend_from_slice(&(header.len() as u16).to_le_bytes());
    svc.extend_from_slice(&header);
    svc.extend_from_slice(&(0u32).to_le_bytes()); // rest len (ignored)
    svc.extend_from_slice(&(doc.len() as u32).to_le_bytes());
    svc.extend_from_slice(doc);

    // ch2 fragment: type(u16 BE), cookie[8], capability[16], TLV block.
    let mut frag = Vec::new();
    frag.extend_from_slice(&0u16.to_be_bytes()); // type
    frag.extend_from_slice(&[0u8; 8]); // cookie
    frag.extend_from_slice(&[0u8; 16]); // capability
    frag.extend_from_slice(&tlv(0x2711, &svc));

    let body = to_host_body("223344", 2, &tlv(0x0005, &frag));
    let frame = flap(11, &snac(0x0004, 0x0006, &body));
    let lines = e.on_send(7, &frame);
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("ch2/type2"));
    assert!(lines[0].contains("greeting text"));
}

#[test]
fn inbound_icq_offline_reply() {
    let mut e = Engine::new();
    // ICQ envelope (little-endian) inside TLV 0x0001, itself u16-length-prefixed.
    let mut inner = Vec::new();
    inner.extend_from_slice(&100003u32.to_le_bytes()); // our UIN
    inner.extend_from_slice(&0x0041u16.to_le_bytes()); // req type: offline reply
    inner.extend_from_slice(&1u16.to_le_bytes()); // seq
    inner.extend_from_slice(&600123u32.to_le_bytes()); // sender UIN
    inner.extend_from_slice(&2026u16.to_le_bytes()); // year
    inner.extend_from_slice(&[9, 30, 12, 0]); // month, day, hour, minute
    inner.push(0x01); // msg type
    inner.push(0x00); // flags
    let text = b"offline hi\x00";
    inner.extend_from_slice(&(text.len() as u16).to_le_bytes());
    inner.extend_from_slice(text);

    let mut env = Vec::new();
    env.extend_from_slice(&(inner.len() as u16).to_le_bytes());
    env.extend_from_slice(&inner);

    let body = tlv(0x0001, &env);
    let frame = flap(20, &snac(0x0015, 0x0002, &body));
    let lines = e.on_recv(9, &frame);
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("offline"));
    assert!(lines[0].contains("peer=600123"));
    assert!(lines[0].contains("text=\"offline hi\""));
}

#[test]
fn non_message_snacs_are_ignored() {
    let mut e = Engine::new();
    // A typing notification (ICBMClientEvent, 0x0004/0x0014) must not log.
    let body = vec![0u8; 12];
    let frame = flap(1, &snac(0x0004, 0x0014, &body));
    assert!(e.on_send(1, &frame).is_empty());
    // Presence (buddy arrived) likewise.
    let frame2 = flap(2, &snac(0x0003, 0x000B, &vec![0u8; 8]));
    assert!(e.on_recv(1, &frame2).is_empty());
}

#[test]
fn peer_context_from_connect() {
    let mut e = Engine::new();
    e.on_connect(1, Some("203.0.113.5:5190".to_string()));
    let frags = ch1_fragments(0x0000, b"hey");
    let body = to_host_body("100002", 1, &tlv(0x0002, &frags));
    let frame = flap(10, &snac(0x0004, 0x0006, &body));
    let lines = e.on_send(1, &frame);
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains("via=203.0.113.5:5190"),
        "got {}",
        lines[0]
    );
}
