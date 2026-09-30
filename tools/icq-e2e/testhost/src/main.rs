//! A tiny in-process harness for the observation engine. It feeds a handful of
//! synthetic FLAP/SNAC/ICBM frames (an outbound plain IM, an inbound HTML IM
//! split across two reads, and an ICQ offline reply) and prints the decoded log
//! lines. It links the same engine the loaders use, so it proves the parsing
//! path end to end without touching a real client. Run it after building:
//!
//!   cargo run --release -p icqe2e_testhost

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
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&1u32.to_be_bytes());
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

fn ch1(charset: u16, text: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&charset.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(text);
    let mut frags = vec![0x05u8, 0x01, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01];
    frags.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    frags.extend_from_slice(&msg);
    frags
}

fn to_host(target: &str, tlvs: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1u16.to_be_bytes());
    b.push(target.len() as u8);
    b.extend_from_slice(target.as_bytes());
    b.extend_from_slice(tlvs);
    b
}

fn to_client(sender: &str, tlvs: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1u16.to_be_bytes());
    b.push(sender.len() as u8);
    b.extend_from_slice(sender.as_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(tlvs);
    b
}

fn main() {
    let mut e = Engine::new();
    let mut all = Vec::new();

    e.on_connect(1, Some("203.0.113.5:5190".to_string()));

    // Outbound plain IM.
    let out = flap(
        1,
        &snac(
            0x0004,
            0x0006,
            &to_host("100002", &tlv(0x0002, &ch1(0x0000, b"hi there"))),
        ),
    );
    all.extend(e.on_send(1, &out));

    // Inbound HTML IM (UTF-16BE), delivered in two reads.
    let mut ucs2 = Vec::new();
    for ch in "<font sml=\"1\">yo</font>".chars() {
        ucs2.extend_from_slice(&(ch as u16).to_be_bytes());
    }
    let inb = flap(
        2,
        &snac(
            0x0004,
            0x0007,
            &to_client("100002", &tlv(0x0002, &ch1(0x0002, &ucs2))),
        ),
    );
    let (p1, p2) = inb.split_at(12);
    all.extend(e.on_recv(1, p1));
    all.extend(e.on_recv(1, p2));

    if all.is_empty() {
        eprintln!("FAIL: no messages decoded");
        std::process::exit(1);
    }
    println!("decoded {} message(s):", all.len());
    for line in &all {
        println!("  {line}");
    }
}
