//! An in-process run of two clients with the add-on in encrypt mode, over the
//! real stream, crypto and key-directory code the loaders use.
//!
//! A and B each have their own device. Both sign on, read their token out of
//! the MOTD, announce their account key in `SetInfo` and publish to a key
//! directory. A then types messages, and the "server" relays what came off A's
//! wire to B. Nothing about the plaintext may appear on the wire, and B must get
//! back exactly what A typed - HTML, smileys and Cyrillic included.
//!
//! It links the same engine the loaders use, so it proves the whole path
//! without touching a real client:
//!
//!   cargo run --release -p icqe2e_testhost
//!
//! Then the same path runs through the real Winsock hooks over TLS 1.3
//! (`over_tls.rs`): real loopback sockets, `WSAAsyncSelect` to a hidden window,
//! an in-process TLS server, sign-in, BOS, E2E messages, reconnects, slow
//! delivery, a server that closes, and the fail-closed cases.
//!
//! `--go <tls-port> <ca.pem> [name]` runs a sign-in through the hooks
//! against a local Open OSCAR Server instead (`over_tls::go_server`), and
//! `--make-cert <dir> [name]` writes a CA and a certificate for it.

mod over_tls;

use icqe2e_core::config::{Mode, Policy};
use icqe2e_core::directory::{DirectoryApi, MemoryDirectory};
use icqe2e_core::icbm::Direction;
use icqe2e_core::session::{self, Session};
use icqe2e_core::stream::StreamRewriter;
use icqe2e_core::text;
use std::sync::Arc;

/// A clock that does not move, so a run is reproducible.
pub(crate) const NOW: u64 = 1_790_000_000;

pub(crate) fn flap(channel: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x2A, channel];
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

pub(crate) fn hello() -> Vec<u8> {
    flap(1, 1, &[0, 0, 0, 1])
}

pub(crate) fn snac(fg: u16, sg: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&fg.to_be_bytes());
    v.extend_from_slice(&sg.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(body);
    v
}

pub(crate) fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&(value.len() as u16).to_be_bytes());
    v.extend_from_slice(value);
    v
}

/// A channel-1 message fragment list: the caps fragment, then the message.
pub(crate) fn ch1(charset: u16, text: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&charset.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(text);
    let mut frags = vec![0x05u8, 0x01, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01];
    frags.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    frags.extend_from_slice(&msg);
    frags
}

pub(crate) fn to_host(target: &str, charset: u16, text: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1u16.to_be_bytes());
    b.push(target.len() as u8);
    b.extend_from_slice(target.as_bytes());
    b.extend_from_slice(&tlv(0x0002, &ch1(charset, text)));
    b.extend(tlv(0x0006, &[])); // store offline
    snac(0x0004, 0x0006, &b)
}

pub(crate) fn to_client(sender: &str, charset: u16, text: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1u16.to_be_bytes());
    b.push(sender.len() as u8);
    b.extend_from_slice(sender.as_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&2u16.to_be_bytes());
    b.extend_from_slice(&tlv(0x0001, &[0x00, 0x50])); // user class
    b.extend_from_slice(&tlv(0x0006, &[0, 0, 0, 0])); // status
    b.extend_from_slice(&tlv(0x0002, &ch1(charset, text)));
    snac(0x0004, 0x0007, &b)
}

/// The payload of the first SNAC frame in `bytes`.
///
/// What the client's chat window shows is the payload; the FLAP sequence
/// around it is the add-on's to number, and a note after it is a frame of its
/// own.
pub(crate) fn message_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 6 || bytes[0] != 0x2A {
        return None;
    }
    let len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    bytes.get(6..6 + len).map(|p| p.to_vec())
}

/// The text of the channel-1 message in a `to-host` SNAC on the wire.
///
/// The server does not look inside a frame; it relays what came off the wire.
/// This is the testhost standing in for it, so the bytes handed to B are the
/// bytes that really travelled.
pub(crate) fn message_text(frame: &[u8], peer: &str) -> Option<String> {
    // FLAP header, SNAC header, cookie[8], channel:u16, len8, name.
    let mut at = 6 + 10 + 8 + 2 + 1 + peer.len();
    while at + 4 <= frame.len() {
        let tag = u16::from_be_bytes([frame[at], frame[at + 1]]);
        let len = u16::from_be_bytes([frame[at + 2], frame[at + 3]]) as usize;
        let value = frame.get(at + 4..at + 4 + len)?;
        if tag == 0x0002 {
            // The fragment list: id:u8 version:u8 len:u16 payload.
            let mut f = 0usize;
            while f + 4 <= value.len() {
                let id = value[f];
                let flen = u16::from_be_bytes([value[f + 2], value[f + 3]]) as usize;
                let payload = value.get(f + 4..f + 4 + flen)?;
                if id == 1 && payload.len() >= 4 {
                    return Some(String::from_utf8_lossy(&payload[4..]).into_owned());
                }
                f += 4 + flen;
            }
        }
        at += 4 + len;
    }
    None
}

/// The MOTD the server sends, carrying the key directory's token.
///
/// An MOTD body is the `uint16` message type and then its TLVs, exactly as
/// `foodgroup.OServiceService` builds it.
pub(crate) fn motd(token: &[u8]) -> Vec<u8> {
    let mut body = 0x0004u16.to_be_bytes().to_vec();
    body.extend(tlv(0x000B, b"Welcome to the ICQ network"));
    body.extend(tlv(0x0E2E, token));
    snac(0x0001, 0x0013, &body)
}

/// The `SetInfo` the client sends to claim its capability, which is also where
/// the add-on announces the account key.
pub(crate) fn set_info() -> Vec<u8> {
    let mut body = tlv(0x0001, b"text/aolrtf; charset=\"us-ascii\"");
    body.extend(tlv(
        0x0005,
        &[0x09, 0x46, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    ));
    body.extend(tlv(0x0004, b""));
    snac(0x0002, 0x0004, &body)
}

/// One client's side of the run.
pub(crate) struct Client {
    out: StreamRewriter,
    inb: StreamRewriter,
    session: Session,
    uin: String,
    label: &'static str,
    /// The clock this client reads: [`NOW`] in memory, the real one when it
    /// talks to the hooked client, whose containers carry the real time.
    now: u64,
}

impl Client {
    /// Feeds bytes the way the client would see them, and logs what the add-on
    /// says.
    fn feed_out(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        for line in session::pump(
            &mut self.out,
            Direction::Outbound,
            &mut self.session,
            bytes,
            self.now,
            &encrypting(),
            out,
        ) {
            println!("{}  {line}", self.label);
        }
    }

    fn feed_in(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        for line in session::pump(
            &mut self.inb,
            Direction::Inbound,
            &mut self.session,
            bytes,
            self.now,
            &encrypting(),
            out,
        ) {
            println!("{}  {line}", self.label);
        }
    }

    /// The account key, as the client would announce it.
    fn account_key(&mut self) -> [u8; 32] {
        use icqe2e_core::crypto::Crypto;
        self.session.engine().account_key().unwrap()
    }
}

pub(crate) fn encrypting() -> Policy {
    Policy::from_settings(icqe2e_core::config::Settings {
        mode: Some("encrypt"),
        ..Default::default()
    })
}

/// A state directory that cleans itself up.
pub(crate) struct Temp(std::path::PathBuf);

impl Temp {
    fn new(tag: &str) -> Temp {
        let p = std::env::temp_dir().join(format!("icqe2e-testhost-{tag}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Temp(p)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The two clients in memory, as before TLS: whether every check passed.
fn in_memory() -> bool {
    let home_a = Temp::new("a");
    let home_b = Temp::new("b");
    // Leaked so a session can borrow it for the life of the run, which is what
    // the loaders do with the real directory.
    let dir: Arc<MemoryDirectory> = Arc::new(MemoryDirectory::new());

    // Both accounts exist and have handed out a token, as they would after
    // signing on for the first time.
    let (a_out, a_inb) = StreamRewriter::pair();
    let mut a = Client {
        out: a_out,
        inb: a_inb,
        session: Session::open(dir.clone(), &home_a.0, "100001").unwrap(),
        uin: "100001".into(),
        label: "A",
        now: NOW,
    };
    let (b_out, b_inb) = StreamRewriter::pair();
    let mut b = Client {
        out: b_out,
        inb: b_inb,
        session: Session::open(dir.clone(), &home_b.0, "100002").unwrap(),
        uin: "100002".into(),
        label: "B",
        now: NOW,
    };

    // 1. Sign on. A stream is only taken for FLAP once it has seen the sign-on
    //    frame, and each direction has its own, so both sides see it coming the
    //    way they really do: A sends it, the server relays it to B.
    let mut wire = Vec::new();
    a.feed_out(&hello(), &mut wire);
    b.feed_in(&flap(1, 1, &[0, 0, 0, 1]), &mut wire);
    // A's own inbound direction opens on the server's answer to the sign-on.
    a.feed_in(&flap(1, 2, &[0, 0, 0, 1]), &mut wire);
    b.feed_out(&hello(), &mut wire);

    // 2. The server's MOTD carries each one's token.
    wire.clear();
    a.feed_in(&flap(2, 2, &motd(&dir.token("100001"))), &mut wire);
    b.feed_in(&flap(2, 2, &motd(&dir.token("100002"))), &mut wire);

    // 3. Each announces its account key in its own SetInfo, which is what the
    //    server checks before it accepts a first publish.
    for c in [&mut a, &mut b] {
        wire.clear();
        let key = c.account_key();
        dir.announce(&c.uin, &key);
        c.feed_out(&flap(2, 3, &set_info()), &mut wire);
    }

    let mut ok = true;

    // 4. A sends messages; the server relays what came off the wire to B.
    let ucs2: Vec<u8> = "<font sml=\"default\">Привет, B :-)</font>"
        .encode_utf16()
        .flat_map(|u| u.to_be_bytes())
        .collect();
    let messages: [(u16, &str, &[u8]); 3] = [
        (0x0000, "plain ASCII", b"hi there"),
        (0x0002, "UCS-2 with HTML, a smiley and Cyrillic", &ucs2),
        (
            0x0001,
            "Latin-1 with accents",
            "caf\u{e9} \u{fc}ber".as_bytes(),
        ),
    ];

    for (i, (charset, what, text)) in messages.iter().enumerate() {
        let seq = 10 + i as u16;
        let mut sent = Vec::new();
        a.feed_out(&flap(2, seq, &to_host("100002", *charset, text)), &mut sent);

        // Nothing readable may be on the wire.
        let visible = String::from_utf8_lossy(&sent);
        // What the server relays: the armoured text as it came off the wire.
        let sent_text = message_text(&sent, "100002").expect("the message on the wire");
        if visible.contains("hi there") || visible.contains("Привет") {
            eprintln!("FAIL [{what}]: the plaintext is on the wire");
            ok = false;
        }
        if !sent_text.contains("IQE1:") {
            eprintln!("FAIL [{what}]: no container on the wire");
            ok = false;
        }

        // The server relays the text it received, armoured container and all,
        // in whatever charset the fragment declared - which for a container is
        // ASCII, whatever the message really was.
        let relayed = flap(
            2,
            seq,
            &to_client("100001", text::CHARSET_ASCII, sent_text.as_bytes()),
        );
        let mut shown = Vec::new();
        b.feed_in(&relayed, &mut shown);

        // B must see exactly what A typed, in A's own charset, with nothing
        // added to it. The first frame B got is the message; anything after it
        // is a note the add-on had reason to show, and the FLAP sequence is the
        // add-on's to number.
        let expect = to_client("100001", *charset, text);
        let got = message_payload(&shown).unwrap_or_default();
        if got != expect {
            eprintln!(
                "FAIL [{what}]: B saw {:?}, expected {:?}",
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&expect)
            );
            ok = false;
        } else {
            let notes = shown.len().saturating_sub(got.len());
            let extra = if notes == 0 {
                String::new()
            } else {
                format!(" (plus {notes} bytes of note from the add-on)")
            };
            println!("ok  [{what}]: encrypted on the wire, {what} back{extra}");
        }
    }

    // 5. The keys must have reached the directory, or none of the above could
    //    have worked.
    for c in [&a, &b] {
        let uin = c.uin.clone();
        let label = c.label;
        let devices = dir
            .user_devices(&uin)
            .unwrap_or_else(|e| panic!("{label} has no devices: {e}"));
        println!(
            "ok  [{label}]: {} device(s) in the directory",
            devices.devices.len()
        );
    }

    if ok {
        println!("\nok: every message went out as a container and came back exactly as typed");
    }
    let _ = Mode::Encrypt;
    ok
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let special = match args.first().map(String::as_str) {
        Some("--go") => Some(over_tls::go_server(&args[1..])),
        Some("--make-cert") => Some(over_tls::make_cert(&args[1..])),
        _ => None,
    };
    if let Some(ok) = special {
        std::process::exit(if ok { 0 } else { 1 });
    }
    let mut ok = in_memory();
    println!("\n--- the same path through the Winsock hooks over TLS 1.3 ---\n");
    ok &= over_tls::run();
    if !ok {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    /// `cargo test` runs the TLS scenarios too.
    #[test]
    fn over_tls() {
        assert!(
            super::over_tls::run(),
            "a TLS scenario failed; see the output"
        );
    }
}
