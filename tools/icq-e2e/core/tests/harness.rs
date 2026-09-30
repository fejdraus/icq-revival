//! Harness mode (Phase 1): messages are rewritten in place on the way out and
//! restored on the way in. Every check compares whole byte streams with frames
//! built independently, so a wrong length anywhere - FLAP, TLV, fragment,
//! little-endian ICQ field - or a changed sequence number fails the test.

mod common;

use common::*;
use icqe2e_core::config::Policy;
use icqe2e_core::engine::Engine;
use icqe2e_core::harness::{apply_charset, MARKER};

fn harness() -> Engine {
    Engine::with_policy(Policy::harness())
}

/// Sends `frames` after the opening frame; returns the wire bytes (without the
/// opening frame) and the log.
fn send_all(e: &mut Engine, frames: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut out = Vec::new();
    e.send(1, &hello(1), &mut out);
    assert_eq!(out, hello(1));
    out.clear();
    let lines = e.send(1, frames, &mut out);
    (out, lines)
}

/// Receives `frames` after the opening frame; returns what the client gets
/// (without the opening frame) and the log.
fn recv_all(e: &mut Engine, frames: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut out = Vec::new();
    e.recv(1, &hello(1), &mut out);
    out.clear();
    let lines = e.recv(1, frames, &mut out);
    (out, lines)
}

/// The three charsets the clients use, with text that exercises each.
fn samples() -> Vec<(u16, Vec<u8>)> {
    vec![
        (0x0000, b"Hello, world".to_vec()),
        (
            0x0000,
            "<HTML><BODY dir=\"ltr\"><FONT face=\"Arial\" sml=\"default\">Привет :-) &amp; bye</FONT></BODY></HTML>"
                .as_bytes()
                .to_vec(),
        ),
        (
            0x0002,
            ucs2be("<div><font sml=\"icq\">Здравствуй, Alice</font><br></div>"),
        ),
        (0x0003, vec![b'c', b'a', b'f', 0xE9, b'!']),
    ]
}

#[test]
fn channel1_round_trip_in_every_charset() {
    for (charset, text) in samples() {
        let wire_text = apply_charset(charset, &text).unwrap();

        let mut a = harness();
        let (wire, lines) = send_all(&mut a, &out_ch1(10, "100002", charset, &text));
        assert_eq!(
            wire,
            out_ch1(10, "100002", charset, &wire_text),
            "charset {charset}"
        );
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("rewritten +"), "{}", lines[0]);

        let mut b = harness();
        let (shown, lines) = recv_all(&mut b, &in_ch1(20, "100001", charset, &wire_text));
        assert_eq!(
            shown,
            in_ch1(20, "100001", charset, &text),
            "charset {charset}"
        );
        assert!(lines[0].contains("restored -"), "{}", lines[0]);
    }
}

#[test]
fn the_wire_text_carries_marker_and_rot13() {
    let mut a = harness();
    let (_, lines) = send_all(&mut a, &out_ch1(10, "100002", 0, b"<b>Hello</b>"));
    assert!(
        lines[0].contains(&format!(
            "text=\"<b>Hello</b>\" rewritten +{} bytes",
            MARKER.len()
        )),
        "{}",
        lines[0]
    );
    assert!(
        lines[0].contains("wire=\"<b>[e2e-harness] Uryyb</b>\""),
        "{}",
        lines[0]
    );
}

#[test]
fn channel2_type2_round_trip() {
    let text = "Hi from 6.5, Вася".as_bytes();
    let wire_text = apply_charset(0, text).unwrap();

    let mut a = harness();
    let (wire, _) = send_all(&mut a, &out_ch2(5, "100002", text));
    assert_eq!(wire, out_ch2(5, "100002", &wire_text));

    let mut b = harness();
    let (shown, _) = recv_all(&mut b, &in_ch2(6, "100001", &wire_text));
    assert_eq!(shown, in_ch2(6, "100001", text));
}

#[test]
fn channel2_other_capabilities_pass() {
    let svc = type2_svc(b"not a relay message");
    let frag = ch2_fragment([0x11; 16], &svc);
    let frame = data(
        5,
        &snac(0x0004, 0x0006, &to_host_body("1", 2, &tlv(0x0005, &frag))),
    );
    let (wire, _) = send_all(&mut harness(), &frame);
    assert_eq!(wire, frame);
}

#[test]
fn offline_message_is_restored() {
    let text = "left while you were away".as_bytes();
    let wire_text = apply_charset(0, text).unwrap();
    let (shown, lines) = recv_all(&mut harness(), &offline_reply(3, 600123, &wire_text));
    assert_eq!(shown, offline_reply(3, 600123, text));
    assert!(lines[0].contains("offline"), "{}", lines[0]);
    assert!(lines[0].contains("restored"), "{}", lines[0]);
}

#[test]
fn messages_from_peers_without_the_add_on_pass() {
    let frame = in_ch1(4, "100009", 0, b"plain old message");
    let (shown, lines) = recv_all(&mut harness(), &frame);
    assert_eq!(shown, frame);
    assert_eq!(lines.len(), 1);
    assert!(!lines[0].contains("restored"));
    let off = offline_reply(3, 1, b"plain offline");
    assert_eq!(recv_all(&mut harness(), &off).0, off);
}

#[test]
fn everything_else_passes_byte_for_byte() {
    let mut s = Vec::new();
    s.extend(data(
        2,
        &snac(
            0x0004,
            0x0014,
            &[1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 1, b'9', 0, 2],
        ),
    ));
    s.extend(data(3, &snac(0x0001, 0x0002, &[0, 1, 0, 3])));
    s.extend(flap(5, 4, &[]));
    s.extend(data(5, &[1, 2, 3])); // too short to be a SNAC
    let (wire, lines) = send_all(&mut harness(), &s);
    assert_eq!(wire, s);
    assert!(lines.is_empty());
}

#[test]
fn contacts_outside_the_peer_list_are_not_rewritten() {
    let mut e = Engine::with_policy(Policy::from_values(None, Some("100005")));
    let frame = out_ch1(10, "100002", 0, b"not for the harness");
    let (wire, lines) = send_all(&mut e, &frame);
    assert_eq!(wire, frame);
    assert!(lines[0].contains("not rewritten"), "{}", lines[0]);
    let mut out = Vec::new();
    e.send(1, &out_ch1(11, "100005", 0, b"for it"), &mut out);
    assert_eq!(
        out,
        out_ch1(11, "100005", 0, &apply_charset(0, b"for it").unwrap())
    );
}

#[test]
fn a_message_too_long_to_grow_is_sent_unchanged() {
    let text = vec![b'a'; icqe2e_core::rewrite::MAX_TEXT];
    let frame = out_ch1(10, "100002", 0, &text);
    let (wire, lines) = send_all(&mut harness(), &frame);
    assert_eq!(wire, frame);
    assert!(lines[0].contains("left unchanged"), "{}", lines[0]);
}

#[test]
fn observe_mode_changes_nothing() {
    let mut e = Engine::new();
    let frame = out_ch1(10, "100002", 0, b"just watching");
    let (wire, lines) = send_all(&mut e, &frame);
    assert_eq!(wire, frame);
    assert_eq!(lines.len(), 1);
}

/// However the stream is cut into reads, the output is the same.
#[test]
fn every_split_point_gives_the_same_stream() {
    let mut s = hello(1);
    s.extend(out_ch1(2, "100002", 0x0002, &ucs2be("<b>one</b>")));
    s.extend(data(3, &snac(0x0004, 0x0014, &[0u8; 14])));
    s.extend(out_ch2(4, "100002", b"two"));
    s.extend(out_ch1(5, "100003", 0, b"three"));

    let mut whole = Vec::new();
    harness().send(1, &s, &mut whole);
    assert_ne!(whole, s);

    for cut in 0..=s.len() {
        let mut e = harness();
        let mut out = Vec::new();
        e.send(1, &s[..cut], &mut out);
        e.send(1, &s[cut..], &mut out);
        assert_eq!(out, whole, "cut at {cut}");
    }
    // And byte by byte.
    let mut e = harness();
    let mut out = Vec::new();
    for b in &s {
        e.send(1, std::slice::from_ref(b), &mut out);
    }
    assert_eq!(out, whole);
}

/// A full trip: A's add-on rewrites, the "server" relays the text into an
/// inbound SNAC, B's add-on restores it, over many messages in one stream.
#[test]
fn a_conversation_survives_the_trip() {
    let msgs: Vec<(u16, Vec<u8>)> = samples();
    let mut a = harness();
    let mut b = harness();
    let mut to_b = hello(1);
    let mut expected = hello(1);
    let mut out = Vec::new();
    a.send(1, &hello(1), &mut out);
    for (i, (charset, text)) in msgs.iter().enumerate() {
        let seq = 10 + i as u16;
        out.clear();
        a.send(1, &out_ch1(seq, "B", *charset, text), &mut out);
        // What the server received has the wire text; it relays it as-is.
        let wire_text = apply_charset(*charset, text).unwrap();
        assert_eq!(out, out_ch1(seq, "B", *charset, &wire_text));
        to_b.extend(in_ch1(seq, "A", *charset, &wire_text));
        expected.extend(in_ch1(seq, "A", *charset, text));
    }
    let mut shown = Vec::new();
    b.recv(1, &to_b, &mut shown);
    assert_eq!(shown, expected);
}

const MOOD: [u8; 16] = [0x22; 16];

#[test]
fn the_capability_is_announced_in_place() {
    use icqe2e_core::caps::CAP_E2E;
    let frame = [
        set_info(7, &[CAP_SERVER_RELAY, MOOD]),
        set_info(8, &[CAP_SERVER_RELAY]),
    ]
    .concat();
    let (wire, lines) = send_all(&mut harness(), &frame);
    assert_eq!(
        wire,
        [
            set_info(7, &[CAP_SERVER_RELAY, MOOD, CAP_E2E]),
            set_info(8, &[CAP_SERVER_RELAY, CAP_E2E]),
        ]
        .concat()
    );
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("E2E add-on announced"), "{}", lines[0]);

    // Not in observe mode.
    let (wire, _) = send_all(&mut Engine::new(), &set_info(7, &[MOOD]));
    assert_eq!(wire, set_info(7, &[MOOD]));
}

#[test]
fn contacts_with_the_add_on_are_logged_on_change() {
    use icqe2e_core::caps::CAP_E2E;
    let mut s = buddy_arrived(2, "100001", &[MOOD, CAP_E2E]);
    s.extend(buddy_arrived(3, "100001", &[CAP_E2E])); // a status change: no new line
    s.extend(buddy_arrived(4, "100002", &[MOOD])); // never had it: no line
    s.extend(buddy_arrived(5, "100001", &[MOOD]));
    let (shown, lines) = recv_all(&mut harness(), &s);
    assert_eq!(shown, s, "user info passes unchanged");
    assert_eq!(
        lines,
        vec![
            "contact 100001 announces the E2E add-on".to_string(),
            "contact 100001 no longer announces the E2E add-on".to_string(),
        ]
    );
}
