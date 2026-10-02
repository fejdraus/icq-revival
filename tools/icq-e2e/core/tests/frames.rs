//! Observe mode (Phase 0 behaviour): synthetic FLAP/SNAC/ICBM streams drive
//! the engine, and the log lines it produces are checked. These exercise
//! reassembly, SNAC routing, ICBM channel-1/channel-2 decoding and ICQ offline
//! parsing without any Windows or Winsock dependency.

mod common;

use common::*;
use icqe2e_core::config::Policy;
use icqe2e_core::engine::Engine;
use icqe2e_core::icbm::Direction;
use icqe2e_core::stream::StreamRewriter;

/// An engine with socket 1 already past its opening frame in both directions.
fn opened() -> Engine {
    let mut e = Engine::new();
    assert!(e.on_send(1, &hello(1)).is_empty());
    assert!(e.on_recv(1, &hello(1)).is_empty());
    e
}

#[test]
fn outbound_channel1_ascii() {
    let mut e = opened();
    let lines = e.on_send(1, &out_ch1(10, "100002", 0x0000, b"hello world"));
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("OUT"));
    assert!(lines[0].contains("peer=100002"));
    assert!(lines[0].contains("ch1/text"));
    assert!(lines[0].contains("text=\"hello world\""));
}

#[test]
fn inbound_channel1_html_ucs2be() {
    let mut e = opened();
    let lines = e.on_recv(1, &in_ch1(3, "54321", 0x0002, &ucs2be("<b>hi</b>")));
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("IN"));
    assert!(lines[0].contains("peer=54321"));
    assert!(lines[0].contains("ch1/html"));
    assert!(lines[0].contains("text=\"<b>hi</b>\""));
}

#[test]
fn channel1_split_across_recv_calls() {
    let mut e = opened();
    let frame = in_ch1(4, "777", 0x0000, b"partial frame test");
    let (a, b) = frame.split_at(9);
    assert!(e.on_recv(1, a).is_empty());
    let lines = e.on_recv(1, b);
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("text=\"partial frame test\""));
}

#[test]
fn opening_frame_and_message_in_one_read() {
    let mut e = Engine::new();
    let mut s = hello(1);
    s.extend(in_ch1(2, "777", 0x0000, b"right after sign-on"));
    let lines = e.on_recv(9, &s);
    assert_eq!(lines.len(), 1, "got {lines:?}");
}

#[test]
fn channel2_type2_plain_text() {
    let mut e = opened();
    let lines = e.on_send(1, &out_ch2(11, "223344", "greeting text".as_bytes()));
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("ch2/type2"));
    assert!(lines[0].contains("text=\"greeting text\""), "{}", lines[0]);
}

#[test]
fn channel2_type2_plugin_document() {
    let mut e = opened();
    // A plugin blob: hdrLen(u16 LE) header, then restLen(u32 LE), docLen(u32
    // LE), doc - the shape the server writes for tZers.
    let doc = b"greeting text";
    let mut svc = Vec::new();
    let header = [0u8; 4];
    svc.extend_from_slice(&(header.len() as u16).to_le_bytes());
    svc.extend_from_slice(&header);
    svc.extend_from_slice(&(0u32).to_le_bytes());
    svc.extend_from_slice(&(doc.len() as u32).to_le_bytes());
    svc.extend_from_slice(doc);
    let frag = ch2_fragment([0u8; 16], &svc);
    let body = to_host_body("223344", 2, &tlv(0x0005, &frag));
    let lines = e.on_send(1, &data(11, &snac(0x0004, 0x0006, &body)));
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("ch2/type2"));
    assert!(lines[0].contains("greeting text"));
}

#[test]
fn inbound_icq_offline_reply() {
    let mut e = opened();
    let lines = e.on_recv(1, &offline_reply(20, 600123, b"offline hi"));
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("offline"));
    assert!(lines[0].contains("peer=600123"));
    assert!(lines[0].contains("text=\"offline hi\""));
}

#[test]
fn non_message_snacs_are_ignored() {
    let mut e = opened();
    // A typing notification (ICBMClientEvent, 0x0004/0x0014) must not log.
    let frame = data(1, &snac(0x0004, 0x0014, &[0u8; 12]));
    assert!(e.on_send(1, &frame).is_empty());
    // Presence (buddy arrived) likewise.
    let frame2 = data(2, &snac(0x0003, 0x000B, &[0u8; 8]));
    assert!(e.on_recv(1, &frame2).is_empty());
    // The client's own ICQ DB query is not a reply.
    let q = data(
        3,
        &snac(
            0x0015,
            0x0002,
            &tlv(0x0001, &[8, 0, 0, 0, 0, 0, 0x3C, 0, 0, 0]),
        ),
    );
    assert!(e.on_send(1, &q).is_empty());
}

#[test]
fn peer_context_from_connect() {
    let mut e = Engine::new();
    e.on_connect(1, Some("203.0.113.5:5190".to_string()));
    e.on_send(1, &hello(1));
    let lines = e.on_send(1, &out_ch1(10, "100002", 0x0000, b"hey"));
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains("via=203.0.113.5:5190"),
        "got {}",
        lines[0]
    );
}

#[test]
fn a_stream_that_is_not_oscar_is_not_decoded() {
    let mut e = Engine::new();
    // A message frame with no opening frame before it: not taken for OSCAR.
    assert!(e
        .on_recv(1, &in_ch1(3, "1", 0x0000, b"mid-stream"))
        .is_empty());
}

/// The account is learned from the server's own user info wherever in the
/// stream it lands. A raw `recv` may start in the middle of the frame before
/// it, so the detection has to happen where frames are reassembled - this is
/// the regression for the add-on logging «no UIN yet» while the server log
/// showed `0x0001/0x000F` arriving.
#[test]
fn own_user_info_is_read_from_the_reassembled_stream() {
    let mut body = Vec::new();
    body.extend_from_slice(&[6, b'1', b'0', b'0', b'0', b'0', b'1']);
    body.extend_from_slice(&7u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10]);
    let frame = data(3, &snac(0x0001, 0x000F, &body));

    for split in 1..frame.len() {
        let mut rw = StreamRewriter::new(Direction::Inbound);
        let mut out = Vec::new();
        rw.push(&hello(1), &Policy::observe(), &mut out);
        rw.push(&frame[..split], &Policy::observe(), &mut out);
        assert_eq!(rw.take_sign_on_uin(), None, "half a frame names nothing");
        rw.push(&frame[split..], &Policy::observe(), &mut out);
        assert_eq!(
            rw.take_sign_on_uin().as_deref(),
            Some("100001"),
            "split at byte {split}"
        );
    }
}

/// Several frames in one read, the last of them the one that names the account:
/// nothing before it may swallow it.
#[test]
fn own_user_info_behind_other_frames_in_one_read() {
    let mut body = Vec::new();
    body.extend_from_slice(&[6, b'1', b'0', b'0', b'0', b'0', b'1']);
    body.extend_from_slice(&7u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10]);

    let mut chunk = hello(1);
    chunk.extend(data(2, &snac(0x0001, 0x0014, &[0, 1, 2, 3])));
    chunk.extend(data(3, &snac(0x0003, 0x0005, &[0, 4, 5])));
    chunk.extend(data(4, &snac(0x0001, 0x000F, &body)));

    let mut rw = StreamRewriter::new(Direction::Inbound);
    let mut out = Vec::new();
    rw.push(&chunk, &Policy::observe(), &mut out);
    assert_eq!(rw.take_sign_on_uin().as_deref(), Some("100001"));
}

/// A MOTD token split across two reads is still read: the key directory
/// depends on it, and a client never sends the MOTD in one piece.
#[test]
fn a_split_motd_still_yields_its_token() {
    let token = vec![0xA5u8; 24];
    // An MOTD body is the `uint16` message type `0x0004` and then its TLVs:
    // the message text in 0x000B, the key directory token in 0x0E2E.
    let mut body = 0x0004u16.to_be_bytes().to_vec();
    body.extend(tlv(0x000B, b"welcome"));
    body.extend(tlv(0x0E2E, &token));
    let frame = data(5, &snac(0x0001, 0x0013, &body));

    for split in [1, frame.len() / 3, frame.len() - 1] {
        let mut rw = StreamRewriter::new(Direction::Inbound);
        let mut out = Vec::new();
        rw.push(&hello(1), &Policy::observe(), &mut out);
        rw.push(&frame[..split], &Policy::observe(), &mut out);
        rw.push(&frame[split..], &Policy::observe(), &mut out);
        assert_eq!(
            rw.take_token(),
            Some(token.clone()),
            "split at byte {split}"
        );
    }
}
