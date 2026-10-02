//! SNAC-level rewriting of message text (Phase 1).
//!
//! Given one SNAC seen on the BOS connection, [`process`] decides whether it is
//! a message this phase handles, logs it, and - in harness mode - returns the
//! SNAC rebuilt with the text transformed by [`crate::harness`] and every length
//! on the way down fixed: the TLV, the channel-1 fragment, the little-endian
//! lengths of a channel-2 type-2 message or of an ICQ offline reply. The SNAC
//! header, every other TLV and any trailing bytes are copied as they were, so
//! the only difference on the wire is the text and the lengths around it.
//!
//! Handled: outbound ICBM `0x0004/0x0006` and inbound `0x0004/0x0007`, channel
//! 1 (fragment 1 of TLV 0x0002) and channel 2 server relay (plain type-2 text in
//! TLV 0x2711 of TLV 0x0005), and inbound ICQ `0x0015/0x0003` offline messages.
//! Besides messages, the client's capability list (`0x0002/0x0004`) gets the
//! add-on's capability appended, and contacts announcing it are reported
//! ([`crate::caps`]). Anything else is not touched.

use crate::caps::{self, Announce};
use crate::config::{Mode, Policy};
use crate::container;
use crate::container::Form;
use crate::crypto::Crypto;
use crate::harness;
use crate::icbm::TLV_REQUEST_HOST_ACK;
use crate::icbm::{self, Direction, Message, TextAt};
use crate::keys::{Inbound, Outbound};
use crate::snac::{self, Reader};
use crate::text;

/// The most message text, in bytes, a rewrite may produce. A message that would
/// grow past it is sent unchanged: the client's own limits are close above
/// (Phase 2 splits long messages; this phase does not).
pub const MAX_TEXT: usize = 7000;

/// What goes out in place of a message the add-on would have dropped, where
/// no frame may be dropped: never the text the user typed.
pub const WITHHELD: &str = "[ICQ E2E] (a message was withheld by the sender's add-on)";

/// The harness transform on outbound text: the text changes, the charset does
/// not.
fn apply_harness(charset: u16, text: &[u8]) -> Option<Replaced> {
    harness::apply_charset(charset, text).map(|t| (charset, t))
}

/// The harness transform on inbound text, when it carries the marker.
fn undo_harness(charset: u16, text: &[u8]) -> Option<Replaced> {
    harness::undo_charset(charset, text).map(|t| (charset, t))
}

/// What became of one SNAC.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Processed {
    /// The rewritten SNAC (header and body), or `None` to pass the original.
    pub payload: Option<Vec<u8>>,
    /// Lines for the log.
    pub lines: Vec<String>,
    /// Contacts whose user info said whether they announce the add-on.
    pub e2e_contacts: Vec<(String, bool)>,
    /// A message SNAC to drop instead of sending: a container that would be too
    /// long, one to a contact who must not get clear text but cannot be
    /// encrypted for (CHECKLIST 10.7, 10.8), or a `/e2e` command (10.2).
    /// Never both a payload and a drop.
    pub drop: bool,
    /// For an outbound drop: the SNAC to send instead when frames cannot be
    /// taken out of the stream (`ICQE2E_NO_INJECT`). The text is replaced by
    /// [`WITHHELD`], so the frame count stays the client's and still nothing
    /// the user typed leaves in clear.
    pub withheld: Option<Vec<u8>>,
    /// The key directory's token, read out of the MOTD without changing a byte.
    pub token: Option<Vec<u8>>,
    /// Our account key, to announce in `LocateSetInfo` TLV 0x0E2E.
    pub announce_key: Option<[u8; 32]>,
    /// Our own UIN, read off an outgoing sign-on. It arrives before the MOTD,
    /// so by the time the token does the state file already has a name.
    pub sign_on_uin: Option<String>,
    /// An incoming container was found and removed: the frame must not reach
    /// the client, and the ack the server sends for it must not either.
    pub ack_request: Option<u32>,
    /// For an outbound message the add-on consumed (a `/e2e` command) that
    /// asked the server for an ack with TLV `0x0003`: the `ICBMHostAck`
    /// (`0x0004/0x000C`) SNAC the server would have answered with. The message
    /// never reaches the server, so the add-on has to give the client this
    /// answer itself, or the client marks the message as failed to send.
    pub host_ack: Option<Vec<u8>>,
}

impl Processed {
    /// Nothing to do: pass the SNAC on as it was.
    fn plain() -> Processed {
        Processed::default()
    }
}

/// The kinds of SNAC that carry message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    ToHost,
    ToClient,
    Offline,
    /// An offline message the client sends. The server stores whatever text it
    /// is given, so this is encrypted on the way out exactly like a live
    /// message (DESIGN.md 5.3).
    OfflineOut,
}

fn kind_of(dir: Direction, food_group: u16, sub_group: u16) -> Option<Kind> {
    match (dir, food_group, sub_group) {
        (Direction::Outbound, snac::FOOD_ICBM, snac::ICBM_MSG_TO_HOST) => Some(Kind::ToHost),
        (Direction::Inbound, snac::FOOD_ICBM, snac::ICBM_MSG_TO_CLIENT) => Some(Kind::ToClient),
        (Direction::Inbound, snac::FOOD_ICQ, snac::ICQ_DB_REPLY) => Some(Kind::Offline),
        (Direction::Outbound, snac::FOOD_ICQ, snac::ICQ_DB_QUERY) => Some(Kind::OfflineOut),
        _ => None,
    }
}

fn decode(kind: Kind, body: &[u8]) -> Option<Message> {
    match kind {
        Kind::ToHost => icbm::parse_to_host(body),
        Kind::ToClient => icbm::parse_to_client(body),
        Kind::Offline => icbm::parse_icq_offline(body),
        Kind::OfflineOut => icbm::parse_icq_offline_out(body),
    }
}

/// What a transform returns for a message: the text to put there and the
/// charset to declare it in. The charset travels separately because an
/// encrypted message is ASCII on the wire while the envelope carries the real
/// one (CHECKLIST 3.2).
type Replaced = (u16, Vec<u8>);

/// A text transform: the charset id and text in, the charset and new text out,
/// `None` to leave the message as it was.
type Transform = fn(u16, &[u8]) -> Option<Replaced>;

/// Why a message could not be rewritten.
type Refusal = &'static str;

/// Reads the OService SNACs the add-on needs and says each one out loud, so a
/// sign-on step that reaches the client but is never recognised shows up in
/// the log rather than as silence.
///
/// Two carry something the add-on uses: the MOTD's key directory token
/// (`0x0013`), and the server's own user info with our UIN (`0x000F`), which
/// is the only place both clients say which account they are - they sign in
/// over the web API, so the BOS sign-on carries only a cookie. Every other
/// one is only logged, by subgroup, because that is how you see whether the
/// one you expected ever came.
fn detect_oservice(s: &snac::Snac, p: &mut Processed) {
    if s.food_group != snac::FOOD_OSERVICE {
        return;
    }
    match s.sub_group {
        snac::OSERVICE_MOTD => {
            p.token = caps::motd_token(s.body).map(|t| t.to_vec());
            // Either way: a service connection's MOTD has no token, and a BOS
            // MOTD that should have had one is the difference between
            // encrypting and not.
            p.lines.push(format!(
                "IN MOTD: key directory token {} ({} byte(s) in {})",
                if p.token.is_some() {
                    "read"
                } else {
                    "not present"
                },
                p.token.as_ref().map_or(0, Vec::len),
                caps::motd_tags(s.body).join(", ")
            ));
        }
        snac::OSERVICE_USER_INFO => {
            p.sign_on_uin = caps::own_uin_in_user_info(s.body);
            p.lines.push(match &p.sign_on_uin {
                Some(uin) => format!("IN own user info: account is {uin}"),
                None => "IN own user info: no UIN in it".to_string(),
            });
        }
        sub_group => p.lines.push(format!(
            "IN OService SNAC 0x0001/{sub_group:#06X} ({} bytes)",
            s.body.len()
        )),
    }
}

/// Looks at one SNAC payload travelling in `dir` and returns what to send in
/// its place and what to log.
pub fn process(dir: Direction, payload: &[u8], policy: &Policy) -> Processed {
    let mut p = Processed::default();
    let Some(s) = snac::parse(payload) else {
        return p;
    };
    // Inbound OSERVICE first, whatever the mode: the add-on needs the MOTD's
    // token and its own account even where it would otherwise not rewrite.
    if dir == Direction::Inbound {
        detect_oservice(&s, &mut p);
    }
    match (dir, s.food_group, s.sub_group) {
        (Direction::Inbound, snac::FOOD_BUDDY, snac::BUDDY_ARRIVED) => {
            p.e2e_contacts = caps::contacts(s.body);
            return p;
        }
        // The capability goes out in every mode, not only harness. It is how a
        // contact learns this add-on exists: ICQ 6.5 reads it out of the
        // capability list in the user info it is given, and a client that
        // never sends it looks to every other client exactly like one without
        // the add-on - which is what made 6.5 answer "they do not have the
        // add-on" about a 7.2 that was publishing keys the whole time.
        (Direction::Outbound, snac::FOOD_LOCATE, snac::LOCATE_SET_INFO)
            if matches!(policy.mode, Mode::Harness | Mode::Encrypt) =>
        {
            match caps::announce(s.body) {
                Announce::Added(body) => {
                    let header_len = payload.len() - s.body.len();
                    p.payload = Some([&payload[..header_len], &body[..]].concat());
                    p.lines
                        .push("OUT capabilities: E2E add-on announced (+16 bytes)".to_string());
                }
                Announce::Malformed => p.lines.push(
                    "OUT capabilities: list is not whole GUIDs; E2E add-on not announced"
                        .to_string(),
                ),
                Announce::AlreadyThere | Announce::NoList => {}
            }
        }
        _ => {}
    }
    let Some(kind) = kind_of(dir, s.food_group, s.sub_group) else {
        return p;
    };
    let Some(msg) = decode(kind, s.body) else {
        return p;
    };
    // Only the harness rewrites messages here. In encrypt mode this path is
    // reached only by a connection without a session (no directory set, or
    // the session could not open), and the test transform must never reach
    // a contact from it.
    if policy.mode != Mode::Harness {
        p.lines.push(msg.log_line());
        return p;
    }
    let (transform, verb): (Transform, &str) = match dir {
        Direction::Outbound => (apply_harness, "rewritten"),
        Direction::Inbound => (undo_harness, "restored"),
    };
    if dir == Direction::Outbound && !policy.rewrites_to(&msg.peer) {
        p.lines.push(format!(
            "{} (not rewritten: contact not in ICQE2E_PEERS)",
            msg.log_line()
        ));
        return p;
    }
    let header_len = payload.len() - s.body.len();
    match rewrite_body(kind, s.body, transform) {
        Ok(Some(body)) => {
            let mut out = Vec::with_capacity(header_len + body.len());
            out.extend_from_slice(&payload[..header_len]);
            out.extend_from_slice(&body);
            let delta = out.len() as isize - payload.len() as isize;
            let new = decode(kind, &body);
            let (shown, wire) = match dir {
                Direction::Outbound => (Some(&msg), new.as_ref()),
                Direction::Inbound => (new.as_ref(), Some(&msg)),
            };
            p.lines.push(format!(
                "{} {verb} {delta:+} bytes wire=\"{}\"",
                shown
                    .map(Message::log_line)
                    .unwrap_or_else(|| msg.log_line()),
                wire.map(|m| text::for_log(&m.text, 512))
                    .unwrap_or_default()
            ));
            p.payload = Some(out);
        }
        Ok(None) => p.lines.push(msg.log_line()),
        Err(why) => p
            .lines
            .push(format!("{} (left unchanged: {why})", msg.log_line())),
    }
    p
}

/// The stage-3 message path: encrypt the whole text fragment on the way out,
/// decrypt it on the way in (STAGE-3-CLIENT-CRYPTO.md "the message path").
///
/// The whole fragment is encrypted, HTML and `<FONT sml>` smileys included
/// (CHECKLIST 3.2): the recipient's client gets back exactly the bytes the
/// sender's client produced, so its own rendering is what shows. Only the
/// charset is touched, and only on the way out: an armoured container is plain
/// ASCII, so the charset goes to 0x0000 and the real one travels inside the
/// envelope, from where the inbound path restores it.
pub fn process_crypto(
    dir: Direction,
    payload: &[u8],
    crypto: &mut dyn Crypto,
    now: u64,
) -> Processed {
    let mut p = Processed::plain();
    let Some(s) = snac::parse(payload) else {
        return p;
    };
    // Inbound OSERVICE is read regardless of how a message would be handled:
    // the add-on needs the MOTD's token and its own account here.
    if dir == Direction::Inbound {
        detect_oservice(&s, &mut p);
    }
    match (dir, s.food_group, s.sub_group) {
        // The account key is announced in the same SNAC that gets the
        // capability, so no frame is added and the client sends nothing extra
        // (KEY-DIRECTORY-API.md 3.3).
        (Direction::Outbound, snac::FOOD_LOCATE, snac::LOCATE_SET_INFO) => {
            if let Some(key) = crypto.account_key() {
                match caps::announce_key(s.body, &key) {
                    caps::KeyAnnounce::Added(body) => {
                        let header_len = payload.len() - s.body.len();
                        let mut out = Vec::with_capacity(header_len + body.len());
                        out.extend_from_slice(&payload[..header_len]);
                        out.extend_from_slice(&body);
                        p.payload = Some(out);
                        p.announce_key = Some(key);
                        p.lines
                            .push("OUT account key announced in SetInfo (+36 bytes)".to_string());
                    }
                    caps::KeyAnnounce::AlreadyThere => p.announce_key = Some(key),
                    caps::KeyAnnounce::Malformed | caps::KeyAnnounce::NoKey => {
                        p.lines
                            .push("OUT SetInfo: no usable account key to announce".to_string());
                    }
                }
            }
            return p;
        }
        // The MOTD token is read by `detect_oservice` above, so this arm only
        // stops it from reaching the message path: the client's own copy goes
        // out byte for byte as the server sent it.
        (Direction::Inbound, snac::FOOD_OSERVICE, snac::OSERVICE_MOTD) => return p,
        // The user's own info is read the same way, above.
        (Direction::Inbound, snac::FOOD_OSERVICE, snac::OSERVICE_USER_INFO) => return p,
        (Direction::Inbound, snac::FOOD_BUDDY, snac::BUDDY_ARRIVED) => {
            p.e2e_contacts = caps::contacts(s.body);
            return p;
        }
        _ => {}
    }
    let Some(kind) = kind_of(dir, s.food_group, s.sub_group) else {
        return p;
    };
    let Some(msg) = decode(kind, s.body) else {
        return p;
    };
    p.lines.push(msg.log_line());

    let header_len = payload.len() - s.body.len();
    match dir {
        // A command typed in the chat is the user talking to the add-on: it is
        // answered with a note and never reaches the contact (CHECKLIST 10.2).
        Direction::Outbound if crypto.command(&msg.peer, &msg.text, now) => {
            withhold(kind, payload, header_len, s.body, &mut p);
            p.host_ack = host_ack(kind, s.request_id, s.body);
            p.lines
                .push(format!("{} /e2e command (not sent)", msg.log_line()));
        }
        // `e2e=off`: everything else is the client's own bytes, both ways.
        _ if !crypto.encrypts() => {}
        Direction::Outbound => {
            // The raw bytes, not the decoded string: the recipient's client is
            // what renders this, so it must get back exactly what the sender
            // produced, and it only understands its declared charset.
            let out = crypto.outbound(&msg.peer, form_of(&msg), &msg.raw, now);
            match out {
                Outbound::Encrypted(wire) => match replace_text(kind, s.body, &wire) {
                    Ok(Some(body)) => {
                        p.payload = Some([&payload[..header_len], &body[..]].concat());
                        p.lines
                            .push(format!("{} encrypted {} bytes", msg.log_line(), wire.len()));
                    }
                    Ok(None) => p.lines.push(format!(
                        "{} (left unchanged: no text this add-on handles)",
                        msg.log_line()
                    )),
                    Err(why) => {
                        withhold(kind, payload, header_len, s.body, &mut p);
                        p.lines.push(format!("{} not sent: {why}", msg.log_line()));
                    }
                },
                // A contact without the add-on: the text goes as it was.
                // A contact without the add-on, or a directory we could not
                // reach: the text goes out exactly as it arrived, so only the
                // log changes.
                Outbound::Clear { note, .. } => {
                    p.lines.push(format!("{} sent unencrypted", msg.log_line()));
                    p.lines.push(note);
                }
                Outbound::Refused(note) => {
                    withhold(kind, payload, header_len, s.body, &mut p);
                    p.lines.push(format!("{} not sent", msg.log_line()));
                    p.lines.push(note);
                }
            }
        }
        Direction::Inbound => {
            // An armoured container is a whole message in the armor's own text,
            // wherever it was carried; a peer without the add-on sends plain
            // text, which is left exactly as it arrived.
            let Some(bytes) = container::find_armor(&msg.text) else {
                return p;
            };
            // A version or scheme this build does not know is a message it
            // cannot read, said like any other; it is never read with the
            // scheme-1 layout (CHECKLIST 9.8).
            let got = match container::parse(&bytes) {
                Some(container::Parsed::Container(c)) => crypto.inbound(&msg.peer, &c, now),
                Some(container::Parsed::Unsupported { version, scheme }) => {
                    crypto.unsupported(&msg.peer, version, scheme)
                }
                None => {
                    p.lines
                        .push(format!("{} (armored but not a container)", msg.log_line()));
                    return p;
                }
            };
            p.ack_request = ack_request(kind, s.body);
            match got {
                Inbound::Text { text, form, .. } => {
                    // The sender's own bytes go back into the fragment, with the
                    // charset restored from the envelope: the reader sees the
                    // message exactly as it was written, nothing added to it.
                    match put_text(kind, s.body, &text, form) {
                        Ok(Some(body)) => {
                            p.payload = Some([&payload[..header_len], &body[..]].concat());
                            p.lines.push(format!(
                                "{} decrypted {} bytes",
                                msg.log_line(),
                                text.len()
                            ));
                        }
                        Ok(None) => {}
                        Err(why) => {
                            p.drop = true;
                            p.lines.push(format!("{} not shown: {why}", msg.log_line()));
                        }
                    }
                }
                // A control message advances the ratchet and shows nothing.
                Inbound::Control => {
                    p.drop = true;
                    p.lines
                        .push(format!("{} control message (removed)", msg.log_line()));
                }
                Inbound::Unreadable(note) => {
                    p.drop = true;
                    p.lines.push(note);
                }
            }
        }
    }
    p
}

/// Drops an outbound message SNAC, and keeps a copy with its text replaced
/// by [`WITHHELD`] for a stream that may not drop frames.
fn withhold(kind: Kind, payload: &[u8], header_len: usize, body: &[u8], p: &mut Processed) {
    p.drop = true;
    p.payload = None;
    if let Ok(Some(b)) = replace_text(kind, body, WITHHELD) {
        p.withheld = Some([&payload[..header_len], &b[..]].concat());
    }
}

/// The form an outbound message of this kind carries, for the envelope.
fn form_of(msg: &Message) -> Form {
    if msg.form.starts_with("offline") {
        Form::EightBit
    } else {
        Form::Fragment {
            charset: msg.charset,
            language: 0,
        }
    }
}

/// The ack request an inbound message asks for, if any: TLV `0x0003`, whose
/// answer is `ICBMHostAck` (`0x0004/0x000C`) naming the same id. A container we
/// remove from the stream must take the server's answer to it with it, or the
/// client sees an ack for a message it was never shown.
fn ack_request(kind: Kind, body: &[u8]) -> Option<u32> {
    if kind != Kind::ToClient {
        return None;
    }
    let head = icbm_head_len(kind, body)?;
    let (tlvs, _) = snac::split_tlvs(&body[head..]);
    let t = tlvs.iter().find(|t| t.tag == TLV_REQUEST_HOST_ACK)?;
    Some(u32::from_le_bytes(t.value.get(..4)?.try_into().ok()?))
}

/// The `ICBMHostAck` (`0x0004/0x000C`) the server sends for an outbound
/// message that asked for one with TLV `0x0003`, built the way
/// foodgroup/icbm.go builds it: the request id of the message, flags 0, and a
/// body of the message's own cookie, channel and screen name
/// (`SNAC_0x04_0x0C_ICBMHostAck` in wire/snacs.go). `None` for a message that
/// asked for no ack, which the server would not have answered either.
fn host_ack(kind: Kind, request_id: u32, body: &[u8]) -> Option<Vec<u8>> {
    if kind != Kind::ToHost {
        return None;
    }
    let head = icbm_head_len(kind, body)?;
    let (tlvs, _) = snac::split_tlvs(&body[head..]);
    tlvs.iter().find(|t| t.tag == TLV_REQUEST_HOST_ACK)?;
    let mut p = Vec::with_capacity(10 + head);
    p.extend_from_slice(&snac::FOOD_ICBM.to_be_bytes());
    p.extend_from_slice(&snac::ICBM_HOST_ACK.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // flags
    p.extend_from_slice(&request_id.to_be_bytes());
    // For a message to the host the head is exactly cookie, channel and the
    // length-prefixed screen name.
    p.extend_from_slice(&body[..head]);
    Some(p)
}

/// Puts `wire` where the text of this message was, as ASCII, fixing the length
/// of every structure around it.
fn replace_text(kind: Kind, body: &[u8], wire: &str) -> Result<Option<Vec<u8>>, &'static str> {
    let ascii = wire.as_bytes();
    if ascii.len() > MAX_TEXT {
        return Err("message too long to send encrypted");
    }
    rewrite_body(kind, body, move |_, _| {
        Some((text::CHARSET_ASCII, ascii.to_vec()))
    })
}

/// Puts the sender's own text back, with the charset the envelope carried.
fn put_text(
    kind: Kind,
    body: &[u8],
    text: &[u8],
    form: Form,
) -> Result<Option<Vec<u8>>, &'static str> {
    let charset = match form {
        Form::Fragment { charset, .. } => charset,
        Form::EightBit => text::CHARSET_LATIN1,
    };
    rewrite_body(kind, body, move |_, _| Some((charset, text.to_vec())))
}

/// Rebuilds a message SNAC body with transformed text; `Ok(None)` when there is
/// nothing to change (inbound text without the marker, a message type this
/// phase does not handle).
fn rewrite_body(
    kind: Kind,
    body: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
) -> Result<Option<Vec<u8>>, Refusal> {
    // Both directions of an offline message carry their text in the same TLV
    // of the same little-endian block, so the same rewrite serves each.
    if kind == Kind::Offline || kind == Kind::OfflineOut {
        return rewrite_tlv_block(body, |tag, value| {
            if tag == icbm::ICQ_TLV_DATA {
                rewrite_offline(value, f)
            } else {
                Ok(None)
            }
        });
    }
    let Some(head) = icbm_head_len(kind, body) else {
        return Ok(None);
    };
    let channel = u16::from_be_bytes([body[8], body[9]]);
    let rest = rewrite_tlv_block(&body[head..], |tag, value| match (channel, tag) {
        (icbm::CHANNEL_IM, icbm::TLV_AOL_IM_DATA) => rewrite_ch1(value, f),
        (icbm::CHANNEL_RENDEZVOUS, icbm::TLV_RENDEZVOUS_DATA) => rewrite_ch2(value, f),
        _ => Ok(None),
    })?;
    Ok(rest.map(|r| [&body[..head], &r[..]].concat()))
}

/// The length of an ICBM body before its message TLVs: cookie, channel, screen
/// name, and for inbound messages the warning level and the user-info block.
fn icbm_head_len(kind: Kind, body: &[u8]) -> Option<usize> {
    let mut r = Reader::new(body);
    r.skip(8)?; // cookie
    r.u16()?; // channel
    r.len8()?; // screen name
    if kind == Kind::ToClient {
        r.u16()?; // warning level
        let count = r.u16()?;
        for _ in 0..count {
            r.u16()?;
            let len = r.u16()? as usize;
            r.skip(len)?;
        }
    }
    Some(body.len() - r.remaining())
}

/// Rebuilds a TLV block with the first entry `edit` changes, keeping every
/// other entry and any trailing bytes as they were; `Ok(None)` when `edit`
/// changes none.
fn rewrite_tlv_block(
    data: &[u8],
    edit: impl Fn(u16, &[u8]) -> Result<Option<Vec<u8>>, Refusal>,
) -> Result<Option<Vec<u8>>, Refusal> {
    let (tlvs, tail) = snac::split_tlvs(data);
    let mut out = Vec::with_capacity(data.len() + 64);
    let mut changed = false;
    for t in &tlvs {
        let new = if changed { None } else { edit(t.tag, t.value)? };
        match new {
            Some(v) => {
                if v.len() > u16::MAX as usize {
                    return Err("TLV would exceed 64 KiB");
                }
                snac::put_tlv(&mut out, t.tag, &v);
                changed = true;
            }
            None => snac::put_tlv(&mut out, t.tag, t.value),
        }
    }
    if !changed {
        return Ok(None);
    }
    out.extend_from_slice(tail);
    Ok(Some(out))
}

/// Runs the transform and keeps the charset it asked for, refusing only a
/// rewrite that made the text longer than the limit and over the original.
fn transform_text(
    charset: u16,
    text: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced>,
) -> Result<Option<Replaced>, Refusal> {
    match f(charset, text) {
        None => Ok(None),
        Some(replaced) if replaced.1.len() > MAX_TEXT && replaced.1.len() > text.len() => {
            Err("message too long for the harness marker")
        }
        Some(replaced) => Ok(Some(replaced)),
    }
}

/// Like [`transform_text`] for 8-bit NUL-terminated text: the NUL stays last.
fn transform_nul_text(
    text: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced>,
) -> Result<Option<Vec<u8>>, Refusal> {
    let (body, nul) = match text.strip_suffix(&[0]) {
        Some(b) => (b, true),
        None => (text, false),
    };
    Ok(
        transform_text(text::CHARSET_ASCII, body, f)?.map(|(_, mut v)| {
            if nul {
                v.push(0);
            }
            v
        }),
    )
}

/// Channel 1: a list of fragments `id:u8 version:u8 len:u16 payload`; the
/// message is fragment 1, `charset:u16 language:u16 text`.
fn rewrite_ch1(
    frags: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
) -> Result<Option<Vec<u8>>, Refusal> {
    let mut out = Vec::with_capacity(frags.len() + 64);
    let mut r = Reader::new(frags);
    let mut changed = false;
    while r.remaining() >= 4 {
        let start = frags.len() - r.remaining();
        let (Some(id), Some(version), Some(len)) = (r.u8(), r.u8(), r.u16()) else {
            break;
        };
        let Some(payload) = r.bytes(len as usize) else {
            // A fragment running past the end: keep the rest as it is.
            out.extend_from_slice(&frags[start..]);
            return Ok(changed.then_some(out));
        };
        let mut new_payload = None;
        if id == 1 && !changed && payload.len() >= 4 {
            let charset = u16::from_be_bytes([payload[0], payload[1]]);
            if let Some((new_charset, t)) = transform_text(charset, &payload[4..], f)? {
                // The charset field goes with the text: an ASCII container must
                // declare ASCII, or the client reads the armor as UCS-2. The
                // real charset rides in the envelope and is restored on the way
                // back in. The language field is not ours to change and stays
                // exactly as it arrived.
                let mut head = Vec::with_capacity(4);
                head.extend_from_slice(&new_charset.to_be_bytes());
                head.extend_from_slice(&payload[2..4]);
                new_payload = Some([&head[..], &t[..]].concat());
            }
        }
        match new_payload {
            Some(p) => {
                let len = u16::try_from(p.len()).map_err(|_| "fragment would exceed 64 KiB")?;
                out.extend_from_slice(&[id, version]);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&p);
                changed = true;
            }
            None => out.extend_from_slice(&frags[start..start + 4 + len as usize]),
        }
    }
    out.extend_from_slice(&frags[frags.len() - r.remaining()..]);
    Ok(changed.then_some(out))
}

/// Channel 2: `type:u16 cookie[8] capability[16]` and a TLV block; a type-2
/// message under the ICQ server-relay capability has its text in TLV 0x2711.
fn rewrite_ch2(
    frag: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
) -> Result<Option<Vec<u8>>, Refusal> {
    const HEAD: usize = 2 + 8 + 16;
    if frag.len() < HEAD || frag[10..HEAD] != icbm::CAP_ICQ_SERVER_RELAY {
        return Ok(None);
    }
    let tlvs = rewrite_tlv_block(&frag[HEAD..], |tag, svc| {
        if tag != icbm::RDV_TLV_SVC_DATA {
            return Ok(None);
        }
        let Some(at) = icbm::type2_plain_text(svc) else {
            return Ok(None);
        };
        replace_at(svc, &at, f, |t| at.replace(svc, t))
    })?;
    Ok(tlvs.map(|t| [&frag[..HEAD], &t[..]].concat()))
}

/// ICQ offline reply: the text sits in the little-endian ICQ block of TLV
/// 0x0001, whose own length is fixed too.
fn rewrite_offline(
    env: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
) -> Result<Option<Vec<u8>>, Refusal> {
    let Some((at, _)) = icbm::offline_text(env) else {
        return Ok(None);
    };
    replace_at(env, &at, f, |t| icbm::replace_offline_text(env, &at, t))
}

/// Transforms the NUL-terminated text at `at` and rebuilds with `rebuild`.
fn replace_at(
    data: &[u8],
    at: &TextAt,
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
    rebuild: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, Refusal> {
    let old = &data[at.start..at.start + at.len];
    match transform_nul_text(old, f)? {
        None => Ok(None),
        Some(new) => rebuild(&new).map(Some).ok_or("message would exceed 64 KiB"),
    }
}
