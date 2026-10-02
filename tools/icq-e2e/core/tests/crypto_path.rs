//! The stage-3 message path: a message that leaves encrypted and comes back as
//! the sender wrote it, through [`rewrite::process_crypto`] and a real
//! [`Engine`] over the in-memory key directory.
//!
//! These stand in for the owner running two ICQ clients: everything below the
//! socket - frames in, frames out - is real.

mod common;

use common::*;
use icqe2e_core::caps;
use icqe2e_core::config::{Policy, Settings};
use icqe2e_core::container::{self, Form};
use icqe2e_core::crypto::{Crypto, Engine, Progress};
use icqe2e_core::directory::{DirectoryApi, MemoryDirectory};
use icqe2e_core::icbm::Direction;
use icqe2e_core::keys::{Outbound, OwnKeys};
use icqe2e_core::rewrite;
use icqe2e_core::stream::StreamRewriter;
use icqe2e_core::text;

use std::sync::Arc;

const NOW: u64 = 1_790_000_000;

/// An MOTD body as the server builds it: the `uint16` message type `0x0004`
/// and then the TLVs.
fn motd_body(tlvs: &[Vec<u8>]) -> Vec<u8> {
    let mut body = 0x0004u16.to_be_bytes().to_vec();
    for t in tlvs {
        body.extend_from_slice(t);
    }
    body
}

/// Two published accounts, so a message between them can really be encrypted.
fn two_published() -> (Arc<MemoryDirectory>, OwnKeys, OwnKeys) {
    let dir = Arc::new(MemoryDirectory::new());
    let mut a = OwnKeys::create("100001");
    let mut b = OwnKeys::create("100002");
    for k in [&mut a, &mut b] {
        let key = k.account_key_bytes();
        dir.announce(&k.screen_name, &key);
        let token = icqe2e_core::token::Token::parse(&dir.token(&k.screen_name))
            .unwrap()
            .bearer;
        let (ak, sig) = k.account_object();
        dir.put_account(&token, &ak, &sig).unwrap();
        let (curve, ed, dsig) = k.device_object().unwrap();
        dir.put_device(&token, k.device_id, &curve, &ed, &dsig)
            .unwrap();
        let pool = k.new_one_time_keys(0);
        dir.upload_one_time_keys(&token, k.device_id, &pool)
            .unwrap();
    }
    (dir, a, b)
}

/// An engine for `keys` that has its token and has published everything.
fn engine(dir: &Arc<MemoryDirectory>, keys: OwnKeys, who: &str) -> Engine {
    let mut e = Engine::new(dir.clone(), keys);
    e.set_token(&dir.token(who));
    assert!(matches!(e.publish(NOW), Progress::Done(_)));
    e
}

/// The SNAC payload of a frame the helpers above built.
fn payload(frame: &[u8]) -> &[u8] {
    &frame[6..]
}

/// Encrypts an outbound channel-1 message and returns what went on the wire.
fn send(e: &mut Engine, to: &str, text: &[u8]) -> Vec<u8> {
    let frame = out_ch1(1, to, 2, &ucs2be(&String::from_utf8_lossy(text)));
    let p = rewrite::process_crypto(Direction::Outbound, payload(&frame), e, NOW);
    assert!(!p.drop, "the message must not be dropped: {:?}", p.lines);
    p.payload.expect("the message is replaced, not dropped")
}

#[test]
fn a_message_leaves_encrypted_and_comes_back_exactly_as_written() {
    let (dir, a, b) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let mut eb = engine(&dir, b, "100002");

    let written = "hi <FONT COLOR=\"#FF0000\">there</FONT> :-) &amp; friends";
    let sent = send(&mut ea, "100002", written.as_bytes());

    // What went out is not the text: the plaintext is nowhere in it.
    assert!(
        !String::from_utf8_lossy(&sent).contains("there"),
        "the plaintext must not be on the wire"
    );
    assert!(
        String::from_utf8_lossy(&sent).contains("IQE1:"),
        "an armoured container: {sent:?}"
    );
    // The charset on the wire is ASCII, whatever the client used.
    let wire = snac_text(&sent).expect("a channel-1 message");
    assert_eq!(
        wire.charsets[0],
        text::CHARSET_ASCII,
        "an armoured container is ASCII on the wire"
    );

    // And it comes back byte for byte, charset and all.
    let back = in_ch1(9, "100001", wire.charsets[0], &wire.text);
    let p = rewrite::process_crypto(Direction::Inbound, payload(&back), &mut eb, NOW);
    let shown = p.payload.expect("the container is replaced with the text");
    let got = snac_text(&shown).expect("a channel-1 message");
    assert_eq!(
        got.charsets[0], 2,
        "the sender's charset is restored from the envelope"
    );
    assert_eq!(
        text::decode(got.charsets[0], &got.text),
        written,
        "the sender's own text comes back, HTML and all, with nothing added to it"
    );
}

#[test]
fn the_first_message_of_a_conversation_still_opens_at_the_far_end() {
    // The first message in a conversation is a pre-key message: it has to build
    // a session with no prior contact at all.
    let (dir, a, b) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let mut eb = engine(&dir, b, "100002");

    let sent = send(&mut ea, "100002", b"first");
    let wire = snac_text(&sent).unwrap();
    let back = in_ch1(1, "100001", wire.charsets[0], &wire.text);
    let p = rewrite::process_crypto(Direction::Inbound, payload(&back), &mut eb, NOW);

    let shown = p.payload.expect("the text is put back");
    assert_eq!(
        text::decode(2, &snac_text(&shown).unwrap().text),
        "first",
        "the text, exactly as it was sent"
    );
}

#[test]
fn a_contact_without_the_add_on_still_gets_their_text_and_a_note() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");

    // 100009 has published nothing, so the directory knows no devices.
    let out = out_ch1(3, "100009", 2, &ucs2be("hello"));
    let p = rewrite::process_crypto(Direction::Outbound, payload(&out), &mut ea, NOW);

    assert!(
        !p.drop,
        "a contact without the add-on still gets their message: {:?}",
        p.lines
    );
    assert!(
        p.payload.is_none(),
        "the frame is untouched, so the text goes out as the client wrote it"
    );
    let sent = payload(&out);
    assert_eq!(
        text::decode(2, &snac_text(sent).expect("a message").text),
        "hello",
        "clear text goes out unchanged"
    );
    assert!(
        p.lines.iter().any(|l| l.contains("unencrypted")),
        "the user is told: {:?}",
        p.lines
    );
}

#[test]
fn a_message_too_long_to_encrypt_is_refused_rather_than_cut() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");

    // Text that is legal on its own, but whose container is over the limit.
    let long = "x".repeat(rewrite::MAX_TEXT);
    let frame = out_ch1(5, "100002", 2, &ucs2be(&long));
    let p = rewrite::process_crypto(Direction::Outbound, payload(&frame), &mut ea, NOW);

    assert!(p.drop, "a message over the limit is not sent at all");
    assert!(
        p.payload.is_none(),
        "and nothing goes out in its place: {:?}",
        p.lines
    );
    assert!(
        p.lines.iter().any(|l| l.contains("[ICQ E2E]")),
        "the user is told why: {:?}",
        p.lines
    );
}

#[test]
fn a_tampered_container_shows_a_note_and_nothing_else() {
    let (dir, a, b) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let mut eb = engine(&dir, b, "100002");

    // A real container from a to b, then one byte of it spoiled in flight.
    let sent = send(&mut ea, "100002", b"secret");
    let wire = snac_text(&sent).unwrap();
    let mut spoiled = wire.text.clone();
    let at = spoiled.len() / 2;
    spoiled[at] = if spoiled[at] == b'A' { b'B' } else { b'A' };

    let back = in_ch1(9, "100001", wire.charsets[0], &spoiled);
    let p = rewrite::process_crypto(Direction::Inbound, payload(&back), &mut eb, NOW);

    assert!(p.payload.is_none(), "no garbage reaches the chat");
    assert!(
        p.lines.iter().any(|l| l.contains("[ICQ E2E]")),
        "the user is told it could not be read: {:?}",
        p.lines
    );
}

#[test]
fn a_container_of_a_newer_scheme_is_said_to_be_unreadable_not_misread() {
    let (dir, a, b) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let mut eb = engine(&dir, b, "100002");

    // A real container whose scheme byte names the reserved post-quantum
    // scheme, as a newer add-on would send it (CHECKLIST 9.8).
    let sent = send(&mut ea, "100002", b"secret");
    let wire = snac_text(&sent).unwrap();
    let mut bytes = container::find_armor(&String::from_utf8_lossy(&wire.text)).unwrap();
    bytes[1] = container::SCHEME_PQXDH;
    let newer = container::armor(&bytes);

    let back = in_ch1(9, "100001", wire.charsets[0], newer.as_bytes());
    let p = rewrite::process_crypto(Direction::Inbound, payload(&back), &mut eb, NOW);

    assert!(
        p.drop && p.payload.is_none(),
        "nothing of it reaches the chat"
    );
    let note = eb.take_note().expect("the user is told");
    assert!(note.text.contains("newer format"), "{}", note.text);
    assert!(eb.take_note().is_none(), "and told once");
}

#[test]
fn a_control_message_is_taken_out_of_the_stream() {
    let (dir, a, b) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let mut eb = engine(&dir, b, "100002");

    // b owes a a control message. It has to travel a to b and come back, so
    // that a has a session to advance: a sends first, then b answers with an
    // empty container, and a must recognise that as a control message and take
    // it out of the stream rather than show it.
    let first = send(&mut ea, "100002", b"hello");
    let w = snac_text(&first).unwrap();
    let back1 = in_ch1(2, "100001", w.charsets[0], &w.text);
    rewrite::process_crypto(Direction::Inbound, payload(&back1), &mut eb, NOW);

    let wire = match eb.outbound(
        "100001",
        Form::Fragment {
            charset: 0,
            language: 0,
        },
        b"",
        NOW,
    ) {
        Outbound::Encrypted(w) => w,
        other => panic!("{other:?}"),
    };
    let back = in_ch1(4, "100002", 0, wire.as_bytes());
    let p = rewrite::process_crypto(Direction::Inbound, payload(&back), &mut ea, NOW);

    assert!(
        p.drop || p.payload.is_none(),
        "a control message shows nothing: {:?}",
        p.lines
    );
    assert!(
        p.lines.iter().any(|l| l.contains("control")),
        "the log says so: {:?}",
        p.lines
    );
}

#[test]
fn the_motd_token_is_read_without_changing_a_byte() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let raw = dir.token("100001");

    let motd = snac(
        0x0001,
        0x0013,
        &motd_body(&[
            tlv(0x000B, b"Welcome to the ICQ network"),
            tlv(caps::TLV_TOKEN, &raw),
        ]),
    );

    let p = rewrite::process_crypto(Direction::Inbound, &motd, &mut ea, NOW);
    assert_eq!(
        p.token.as_deref(),
        Some(&raw[..]),
        "the token is read whole"
    );
    assert!(p.payload.is_none(), "the MOTD itself is never changed");
}

/// A MOTD is logged either way, so that "no line about a token at all" cannot
/// happen: the add-on either saw a MOTD and said what was in it, or never saw
/// one, which is the bug this reports.
#[test]
fn every_motd_is_logged_with_whether_it_carried_a_token() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let raw = dir.token("100001");

    let p = rewrite::process_crypto(
        Direction::Inbound,
        &snac(
            0x0001,
            0x0013,
            &motd_body(&[
                tlv(0x000B, b"Welcome to the ICQ network"),
                tlv(caps::TLV_TOKEN, &raw),
            ]),
        ),
        &mut ea,
        NOW,
    );
    assert!(
        p.lines.iter().any(|l| l.contains("token read")),
        "a MOTD with a token says so: {:?}",
        p.lines
    );

    // The service connection: no token, and the log has to admit it rather
    // than stay silent, so a BOS MOTD missing its token is visible.
    let p = rewrite::process_crypto(
        Direction::Inbound,
        &snac(0x0001, 0x0013, &motd_body(&[tlv(0x000B, b"Welcome")])),
        &mut ea,
        NOW,
    );
    assert!(
        p.lines.iter().any(|l| l.contains("token not present")),
        "a MOTD without one says so too: {:?}",
        p.lines
    );
}

#[test]
fn a_server_without_the_directory_sends_no_token_and_nothing_breaks() {
    let (dir, a, _) = two_published();
    let mut ea = Engine::new(dir.clone(), a);
    let motd = snac(0x0001, 0x0013, &tlv(0x000B, b"Welcome"));

    let p = rewrite::process_crypto(Direction::Inbound, &motd, &mut ea, NOW);
    assert!(p.token.is_none(), "no token is invented");
    assert!(p.payload.is_none(), "and the MOTD still passes through");
    assert!(
        !ea.ready(),
        "with no token there is nothing to encrypt with"
    );
}

#[test]
fn the_account_key_is_announced_in_the_clients_own_set_info() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");

    let frame = set_info(
        2,
        &[[0x09, 0x46, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]],
    );
    let p = rewrite::process_crypto(Direction::Outbound, payload(&frame), &mut ea, NOW);
    let sent = p.payload.expect("SetInfo is rewritten in place");

    let key = ea.keys().account_key_bytes();
    assert!(
        sent.windows(4 + key.len())
            .any(|w| w[..2] == [0x0E, 0x2E] && w[4..] == key[..]),
        "TLV 0x0E2E carries the 32 raw bytes"
    );
    assert_eq!(
        p.announce_key,
        Some(key),
        "and the engine knows it announced this key"
    );
    assert!(
        p.lines.iter().any(|l| l.contains("account key announced")),
        "the log says so: {:?}",
        p.lines
    );
}

#[test]
fn a_contacts_capabilities_are_read_without_touching_the_directory() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");

    let frame = buddy_arrived(1, "100002", &[caps::CAP_E2E]);
    let before = dir.requests().len();
    let p = rewrite::process_crypto(Direction::Inbound, payload(&frame), &mut ea, NOW);

    assert_eq!(p.e2e_contacts, vec![("100002".to_string(), true)]);
    assert_eq!(
        dir.requests().len(),
        before,
        "reading capabilities costs nothing"
    );
}

#[test]
fn a_snick_that_is_not_a_message_is_left_alone() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");

    // A user-info update on the BUDDY food group: no message in it at all.
    let mood = snac(0x0003, 0x0005, &tlv(0x0001, &[1, 2, 3, 4]));
    let p = rewrite::process_crypto(Direction::Outbound, &mood, &mut ea, NOW);
    assert!(p.payload.is_none() && !p.drop, "untouched: {:?}", p.lines);
}

#[test]
fn a_message_to_a_contact_the_directory_cannot_answer_for_still_goes_out() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    dir.set_offline(true);

    let frame = out_ch1(3, "100002", 2, &ucs2be("still here"));
    let p = rewrite::process_crypto(Direction::Outbound, payload(&frame), &mut ea, NOW);

    assert!(!p.drop, "an outage must not lose the message");
    assert!(
        p.payload.is_none(),
        "the frame is untouched, so nothing is lost during an outage"
    );
    let sent = payload(&frame);
    assert_eq!(
        text::decode(2, &snac_text(sent).expect("a message").text),
        "still here"
    );
}
#[test]
fn an_offline_message_is_stored_as_a_container_and_opened_on_delivery() {
    // The server stores whatever text it is given, so an offline message is
    // encrypted on the way out and opened on arrival, exactly like a live one
    // (DESIGN.md 5.3).
    let (dir, a, b) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let mut eb = engine(&dir, b, "100002");

    // A sends B an offline message.
    let frame = offline_send(4, 100002, b"sent while you were away");
    let p = rewrite::process_crypto(Direction::Outbound, payload(&frame), &mut ea, NOW);
    let stored = p
        .payload
        .expect("the offline message is encrypted, not dropped");
    assert!(!p.drop);

    // What the server will hold is a container, not the text.
    let held = offline_text_on_wire(
        &[0; 6][..]
            .iter()
            .copied()
            .chain(stored.iter().copied())
            .collect::<Vec<u8>>(),
    )
    .expect("an offline message on the wire");
    assert!(
        held.contains("IQE1:"),
        "the offline store gets an armoured container: {held:?}"
    );
    assert!(
        !held.contains("sent while"),
        "and never the plaintext: {held:?}"
    );

    // The server hands it back to B unchanged; B's add-on opens it.
    let reply = offline_reply(9, 100001, held.as_bytes());
    let q = rewrite::process_crypto(Direction::Inbound, payload(&reply), &mut eb, NOW);
    let shown = q.payload.expect("the container is opened for the chat");
    assert_eq!(
        offline_text_on_wire(
            &[0; 6][..]
                .iter()
                .copied()
                .chain(shown.iter().copied())
                .collect::<Vec<u8>>()
        )
        .as_deref(),
        Some("sent while you were away"),
        "the offline message reads exactly as it was sent"
    );
}

#[test]
fn an_offline_message_to_someone_without_the_add_on_goes_out_in_clear() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");

    let frame = offline_send(4, 100009, b"still readable");
    let p = rewrite::process_crypto(Direction::Outbound, payload(&frame), &mut ea, NOW);

    assert!(
        !p.drop,
        "a contact without the add-on still gets their offline message: {:?}",
        p.lines
    );
    assert!(
        p.payload.is_none(),
        "the frame goes out as the client wrote it"
    );
    assert!(
        p.lines.iter().any(|l| l.contains("unencrypted")),
        "and the user is told: {:?}",
        p.lines
    );
}

/// The account comes off the server's own user info (`0x0001/0x000F`), not the
/// sign-on, because both clients sign in over the web API and their BOS
/// sign-on carries only a cookie.
#[test]
fn the_own_user_info_names_the_account() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    // wire.MarshalBE of TLVUserInfo{ScreenName: "100001", WarningLevel: 7} -
    // the len8 counts the name only, the warning level follows it.
    let body = [
        0x06, 0x31, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00, 0x07, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x10, 0x00, 0x03, 0x00, 0x04, 0x6A,
    ];
    let frame = snac(0x0001, 0x000F, &body);

    let p = rewrite::process_crypto(Direction::Inbound, &frame, &mut ea, NOW);
    assert_eq!(
        p.sign_on_uin.as_deref(),
        Some("100001"),
        "the UIN comes off the server's own user info"
    );
    assert!(p.payload.is_none(), "and the frame itself is never changed");
}

/// An MOTD body is a `uint16` message type and then its TLVs. Reading the
/// TLVs from the start sees the message type as a tag and the first TLV's
/// length as its value, so a MOTD that does carry a token was reported as
/// carrying one empty `0x0004` and the add-on stayed without a directory.
/// These are the server's own bytes: message type `0x0004`, the message in
/// `0x000B`, the token in `0x0E2E`.
#[test]
fn the_motd_token_is_read_past_the_message_type() {
    let token = vec![0x5Au8; 64];
    let mut body = 0x0004u16.to_be_bytes().to_vec();
    body.extend(tlv(0x000B, b"Welcome to Open OSCAR Server"));
    body.extend(tlv(0x0E2E, &token));

    assert_eq!(
        caps::motd_token(&body),
        Some(token.as_slice()),
        "the token is the TLV after the message type"
    );
    assert_eq!(
        caps::motd_tags(&body),
        vec!["0x000B".to_string(), "0x0E2E".to_string()]
    );
}

/// The same MOTD on a service connection: the message and no token.
#[test]
fn a_motd_with_no_token_reads_as_none() {
    let mut body = 0x0004u16.to_be_bytes().to_vec();
    body.extend(tlv(0x000B, b"Welcome to Open OSCAR Server"));

    assert_eq!(caps::motd_token(&body), None);
    assert_eq!(caps::motd_tags(&body), vec!["0x000B".to_string()]);
}

/// An encrypt-mode client tells its contacts it has the add-on.
///
/// The capability went out in harness mode only, and harness is the mode the
/// owner tests the transport in - so a 7.2 client in encrypt mode sent no
/// capability at all, and every other client read that as "no add-on here".
/// ICQ 6.5 said so out loud: "Messages to 100001 are sent unencrypted: they
/// do not have the add-on", about a client that was publishing keys the whole
/// time.
#[test]
fn an_encrypting_client_announces_the_add_on_to_its_contacts() {
    let policy = icqe2e_core::config::Policy::from_settings(icqe2e_core::config::Settings {
        mode: Some("encrypt"),
        ..Default::default()
    });

    // What the client sends: its own capability list.
    let frame = set_info(7, &[[9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6]]);
    let p = rewrite::process(Direction::Outbound, payload(&frame), &policy);
    let sent = p
        .payload
        .expect("the capability list is rewritten in place");
    assert!(
        p.lines.iter().any(|l| l.contains("capabilities")),
        "and said so: {:?}",
        p.lines
    );

    // The server keeps that list per session and hands it to contacts in the
    // user info of "buddy arrived". Here is what 100002 is given.
    let frame = buddy_arrived(8, "100002", &caps_from(&sent));
    let p = rewrite::process(Direction::Inbound, payload(&frame), &policy);
    assert_eq!(
        p.e2e_contacts,
        vec![("100002".to_string(), true)],
        "the contact announces the add-on: {:?}",
        p.lines
    );
}

/// The capability GUIDs in a `LocateSetInfo` body this add-on sent out.
fn caps_from(sent: &[u8]) -> Vec<[u8; 16]> {
    let s = icqe2e_core::snac::parse(sent).expect("a whole SNAC");
    let tlvs = icqe2e_core::snac::split_tlvs(s.body).0;
    let caps = tlvs
        .iter()
        .find(|t| t.tag == 0x0005)
        .expect("the client always sends a capability list")
        .value;
    caps.chunks_exact(16)
        .map(|g| <[u8; 16]>::try_from(g).expect("whole GUIDs"))
        .collect()
}

// --- the user's control (CHECKLIST 10) ---------------------------------------

/// A policy that encrypts, with frames allowed in and out unless `no_inject`.
fn encrypting(no_inject: bool) -> Policy {
    Policy::from_settings(Settings {
        mode: Some("encrypt"),
        no_inject: no_inject.then_some("1"),
        ..Settings::default()
    })
}

/// The text of the channel-1 message in a SNAC payload, decoded.
fn shown_text(payload: &[u8]) -> String {
    let t = snac_text(payload).expect("a channel-1 message");
    text::decode(t.charsets[0], &t.text)
}

#[test]
fn a_command_typed_in_the_chat_is_consumed_and_answered() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");

    // ICQ sends what was typed as HTML, in UCS-2.
    let html =
        "<HTML><BODY dir=\"ltr\"><FONT face=\"Arial\" size=\"2\">/e2e status</FONT></BODY></HTML>";
    let frame = out_ch1(3, "100002", 2, &ucs2be(html));
    let p = rewrite::process_crypto(Direction::Outbound, payload(&frame), &mut ea, NOW);

    assert!(p.drop, "a command never reaches the contact: {:?}", p.lines);
    assert!(p.payload.is_none());
    // Where frames cannot be dropped, the text goes out withheld.
    let withheld = shown_text(&p.withheld.expect("a withheld copy"));
    assert_eq!(withheld, rewrite::WITHHELD);
    assert!(!withheld.contains("status"));

    let note = ea.take_note().expect("the command is answered");
    assert_eq!(note.peer.as_deref(), Some("100002"), "in that chat");
    assert!(note.text.contains("Encryption with 100002"), "{note:?}");
    assert!(ea.take_note().is_none());
}

#[test]
fn a_held_message_never_leaves_in_clear() {
    let (dir, a, b) = two_published();
    let b_device = b.device_id;
    let mut ea = engine(&dir, a, "100001");
    send(&mut ea, "100002", b"hello");
    while ea.take_note().is_some() {}

    // The server stops showing the keys of a contact that encrypted.
    dir.revoke("100002", b_device);
    let frame = out_ch1(4, "100002", 2, &ucs2be("secret plans"));
    let p = rewrite::process_crypto(Direction::Outbound, payload(&frame), &mut ea, NOW);
    assert!(p.drop && p.payload.is_none(), "{:?}", p.lines);
    assert!(!shown_text(&p.withheld.unwrap()).contains("secret"));
    let note = ea.take_note().expect("the chat says why");
    assert!(note.text.contains("NOT sent"), "{note:?}");

    // Even with no frame allowed out of the stream, the text stays home.
    let mut out_side = StreamRewriter::new(Direction::Outbound);
    let mut wire = Vec::new();
    let all = [hello(1), frame.clone()].concat();
    out_side.push_crypto(&all, &mut ea, NOW, &encrypting(true), &mut wire);
    assert!(
        !String::from_utf8_lossy(&wire).contains("secret")
            && !text::decode_ucs2be(&wire).contains("secret"),
        "the held text is not on the wire"
    );
    assert!(String::from_utf8_lossy(&wire).contains(rewrite::WITHHELD));
}

#[test]
fn a_note_goes_into_its_chat_without_waiting_for_the_server() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let policy = encrypting(false);

    // The inbound side of the connection is signed on and quiet.
    let mut inb = StreamRewriter::new(Direction::Inbound);
    let mut out = Vec::new();
    let opening = [hello(1), data(2, &snac(0x0001, 0x0003, &[]))].concat();
    inb.push_crypto(&opening, &mut ea, NOW, &policy, &mut out);
    out.clear();

    // The user writes to 100009, who has no add-on. That note used to reach
    // only the log: nothing came from the server to carry it into the chat.
    let frame = out_ch1(3, "100009", 2, &ucs2be("hi"));
    rewrite::process_crypto(Direction::Outbound, payload(&frame), &mut ea, NOW);
    let mut lines = Vec::new();
    assert!(inb.put_notes(&mut ea, &policy, &mut out, &mut lines));

    // One message from 100009 into the chat with 100009.
    let p = &out[6..];
    let name_len = p[20] as usize;
    assert_eq!(&p[21..21 + name_len], b"100009", "in the chat it is about");
    assert!(
        shown_text(p).contains("Messages to 100009 are sent unencrypted"),
        "{:?}",
        shown_text(p)
    );
    assert_eq!(
        u16::from_be_bytes([out[2], out[3]]),
        3,
        "numbered after the server's last frame"
    );
    out.clear();
    assert!(!inb.put_notes(&mut ea, &policy, &mut out, &mut lines));
    assert!(out.is_empty(), "and only once");
}

/// A socket's two rewriters past their sign-on, the inbound one having
/// carried one frame from the server, as on a quiet connection.
fn signed_on_pair(ea: &mut Engine, policy: &Policy) -> (StreamRewriter, StreamRewriter) {
    let (mut out_side, mut inb) = StreamRewriter::pair();
    let mut sink = Vec::new();
    out_side.push_crypto(&hello(1), ea, NOW, policy, &mut sink);
    let opening = [hello(1), data(2, &snac(0x0001, 0x0003, &[]))].concat();
    inb.push_crypto(&opening, ea, NOW, policy, &mut sink);
    (out_side, inb)
}

/// The FLAP frames of a byte stream, as `(sequence, payload)`.
fn frames(bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let seq = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
        let len = u16::from_be_bytes([bytes[at + 4], bytes[at + 5]]) as usize;
        out.push((seq, bytes[at + 6..at + 6 + len].to_vec()));
        at += 6 + len;
    }
    out
}

/// What `foodgroup/icbm.go` answers a message to `to` with request id `1`
/// that asked for an ack: `ICBMHostAck` with the message's cookie, channel
/// and screen name.
fn expected_ack(to: &str) -> Vec<u8> {
    let mut p = vec![0x00, 0x04, 0x00, 0x0C, 0x00, 0x00, 0, 0, 0, 1];
    p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    p.extend_from_slice(&1u16.to_be_bytes());
    p.push(to.len() as u8);
    p.extend_from_slice(to.as_bytes());
    p
}

#[test]
fn a_command_that_asked_for_an_ack_is_acknowledged_by_the_add_on() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let policy = encrypting(false);
    let (mut out_side, mut inb) = signed_on_pair(&mut ea, &policy);

    // ICQ 7.2 sends the command with TLV 0x0003 and waits for the ack; the
    // server never sees the command, so it would never come.
    let mut wire = Vec::new();
    let lines = out_side.push_crypto(
        &out_ch1(2, "100002", 2, &ucs2be("/e2e status")),
        &mut ea,
        NOW,
        &policy,
        &mut wire,
    );
    assert!(wire.is_empty(), "the command never leaves: {lines:?}");
    assert!(lines.iter().any(|l| l.contains("owed")), "{lines:?}");

    // The ack comes from the add-on, first, then the answer to the command.
    let mut got = Vec::new();
    let mut lines = Vec::new();
    assert!(inb.put_notes(&mut ea, &policy, &mut got, &mut lines));
    let f = frames(&got);
    assert_eq!(f.len(), 2, "the ack and the note: {lines:?}");
    assert_eq!(
        f[0].1,
        expected_ack("100002"),
        "the ack the server would send"
    );
    assert!(shown_text(&f[1].1).contains("Encryption with 100002"));
    // Numbered after the server's last frame, without a gap.
    assert_eq!((f[0].0, f[1].0), (3, 4));

    // Given once.
    got.clear();
    assert!(!inb.put_notes(&mut ea, &policy, &mut got, &mut lines));
    assert!(got.is_empty());
}

#[test]
fn an_owed_ack_rides_on_the_next_frame_from_the_server() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let policy = encrypting(false);
    let (mut out_side, mut inb) = signed_on_pair(&mut ea, &policy);
    let mut sink = Vec::new();
    out_side.push_crypto(
        &out_ch1(2, "100002", 2, &ucs2be("/e2e status")),
        &mut ea,
        NOW,
        &policy,
        &mut sink,
    );

    // The inbound side was busy, so the next frame it reads carries the ack.
    let mut got = Vec::new();
    inb.push_crypto(
        &data(3, &snac(0x0001, 0x0003, &[])),
        &mut ea,
        NOW,
        &policy,
        &mut got,
    );
    let f = frames(&got);
    assert!(f.len() >= 2, "{f:?}");
    assert_eq!(f[0].0, 3, "the server's frame keeps its place");
    assert_eq!(f[1], (4, expected_ack("100002")));
}

#[test]
fn a_command_that_asked_for_no_ack_gets_none() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let policy = encrypting(false);
    let (mut out_side, mut inb) = signed_on_pair(&mut ea, &policy);
    let tlvs = tlv(0x0002, &ch1_fragments(0, b"/e2e status"));
    let command = data(2, &snac(0x0004, 0x0006, &to_host_body("100002", 1, &tlvs)));
    let mut sink = Vec::new();
    out_side.push_crypto(&command, &mut ea, NOW, &policy, &mut sink);
    assert!(sink.is_empty());

    let mut got = Vec::new();
    let mut lines = Vec::new();
    assert!(inb.put_notes(&mut ea, &policy, &mut got, &mut lines));
    let f = frames(&got);
    assert_eq!(f.len(), 1, "only the note");
    assert!(shown_text(&f[0].1).contains("Encryption with 100002"));
}

#[test]
fn with_injection_off_the_server_acks_the_withheld_command_itself() {
    let (dir, a, _) = two_published();
    let mut ea = engine(&dir, a, "100001");
    let policy = encrypting(true);
    let (mut out_side, mut inb) = signed_on_pair(&mut ea, &policy);
    let mut wire = Vec::new();
    out_side.push_crypto(
        &out_ch1(2, "100002", 2, &ucs2be("/e2e status")),
        &mut ea,
        NOW,
        &policy,
        &mut wire,
    );
    // The withheld frame goes to the server with its TLV 0x0003, so the
    // server's own ack answers it and the add-on owes nothing.
    assert_eq!(frames(&wire).len(), 1);
    let mut got = Vec::new();
    inb.push_crypto(
        &data(3, &snac(0x0001, 0x0003, &[])),
        &mut ea,
        NOW,
        &policy,
        &mut got,
    );
    assert_eq!(frames(&got).len(), 1, "no ack of the add-on's own");
}
