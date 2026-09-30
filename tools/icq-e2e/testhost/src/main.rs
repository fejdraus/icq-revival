//! A tiny in-process harness for the engine. It plays two clients, A and B,
//! each with the add-on in harness mode: A sends a plain message and an HTML
//! one with a smiley and Cyrillic, the "server" relays what came off A's wire
//! to B, and B's add-on restores it. It prints the log lines and checks that B
//! gets exactly what A typed. It links the same engine the loaders use, so it
//! proves the rewrite path end to end without touching a real client:
//!
//!   cargo run --release -p icqe2e_testhost

use icqe2e_core::config::Policy;
use icqe2e_core::engine::Engine;

fn flap(channel: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x2A, channel];
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn hello() -> Vec<u8> {
    flap(1, 1, &[0, 0, 0, 1])
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

fn to_host(target: &str, charset: u16, text: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1u16.to_be_bytes());
    b.push(target.len() as u8);
    b.extend_from_slice(target.as_bytes());
    b.extend_from_slice(&tlv(0x0002, &ch1(charset, text)));
    snac(0x0004, 0x0006, &b)
}

fn to_client(sender: &str, charset: u16, text: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1u16.to_be_bytes());
    b.push(sender.len() as u8);
    b.extend_from_slice(sender.as_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&tlv(0x0002, &ch1(charset, text)));
    snac(0x0004, 0x0007, &b)
}

/// The message text of a to-host SNAC built by [`to_host`].
fn text_of_to_host(frame: &[u8], target: &str) -> Vec<u8> {
    let snac_start = 6;
    let body = snac_start + 10;
    let tlvs = body + 8 + 2 + 1 + target.len();
    let frags = tlvs + 4;
    // The caps fragment (4 + 2), the message fragment header (4), charset and
    // language (4).
    let msg = frags + 6 + 4 + 4;
    frame[msg..].to_vec()
}

fn main() {
    let mut a = Engine::with_policy(Policy::harness());
    let mut b = Engine::with_policy(Policy::harness());
    a.on_connect(1, Some("203.0.113.5:5190".to_string()));
    b.on_connect(1, Some("203.0.113.5:5190".to_string()));
    let mut sink = Vec::new();
    a.send(1, &hello(), &mut sink);
    b.recv(1, &hello(), &mut sink);

    let ucs2: Vec<u8> = "<font sml=\"default\">Привет, B :-)</font>"
        .encode_utf16()
        .flat_map(|u| u.to_be_bytes())
        .collect();
    let messages: [(u16, &[u8]); 2] = [(0x0000, b"hi there"), (0x0002, &ucs2)];

    let mut ok = true;
    for (i, (charset, text)) in messages.iter().enumerate() {
        let seq = 2 + i as u16;
        let mut wire = Vec::new();
        for line in a.send(1, &flap(2, seq, &to_host("B", *charset, text)), &mut wire) {
            println!("A  {line}");
        }
        // The server relays the text it received to B.
        let relayed = flap(
            2,
            seq,
            &to_client("A", *charset, &text_of_to_host(&wire, "B")),
        );
        let mut shown = Vec::new();
        for line in b.recv(1, &relayed, &mut shown) {
            println!("B  {line}");
        }
        let expected = flap(2, seq, &to_client("A", *charset, text));
        if shown != expected {
            eprintln!("FAIL: message {i} did not come back as sent");
            ok = false;
        }
    }
    if !ok {
        std::process::exit(1);
    }
    println!("ok: every message went out rewritten and came back as typed");
}
