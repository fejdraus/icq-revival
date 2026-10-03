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

use crate::authz;
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
    /// SNACs the client is owed for a frame the add-on kept from the server:
    /// the contact's cancel of a direct-IM proposal the client made
    /// ([`crate::direct`]), handed to the client by the inbound direction.
    pub owed: Vec<Vec<u8>>,
    /// An inbound frame that may only reach the client once `action` has
    /// been announced by the contact's add-on (a tZer's `IQT1`, sixth audit
    /// of 2026-10, finding 4): the stream holds it for a few seconds, then
    /// drops it. With `ICQE2E_NO_INJECT` it is dropped at once ([`Self::withheld`]).
    pub hold: Option<crate::crypto::Action>,
    /// Control containers to put on the wire to the contact before this
    /// outbound frame (a tZer's announcement).
    pub controls: Vec<Vec<u8>>,
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

/// Keeps peer-to-peer messaging off while the add-on encrypts
/// ([`crate::direct`], audit 2026-10 second part, finding 5): a direct-IM
/// proposal or acceptance is dropped either way - one the client made is
/// answered to it by a cancel from the contact - and the DC info's address
/// and port are zeroed in the client's own `SetUserInfoFields` and in the
/// contacts' user info. Whether it took the SNAC; the caller then returns.
/// "Buddy arrived" is left to the caller, which reads it as well.
fn keep_direct_off(dir: Direction, payload: &[u8], s: &snac::Snac, p: &mut Processed) -> bool {
    let header_len = payload.len() - s.body.len();
    if let Some(rdv) = crate::direct::rendezvous(dir, payload) {
        if !rdv.opens() {
            return true;
        }
        p.drop = true;
        p.payload = None;
        // A stream that may not lose a frame sends it on as a cancel.
        p.withheld = Some(crate::direct::as_cancel(&rdv, payload));
        if dir == Direction::Outbound {
            p.owed
                .push(crate::direct::cancel_to_client(&rdv.peer, &rdv.cookie));
            p.host_ack = host_ack(Kind::ToHost, s.request_id, s.body);
        }
        p.lines.push(format!(
            "direct IM {} peer={} {}: refused, text stays on the server path while encrypting",
            dir.tag(),
            rdv.peer,
            if rdv.kind == crate::files::RDV_PROPOSE {
                "proposal"
            } else {
                "acceptance"
            }
        ));
        return true;
    }
    if (dir, s.food_group, s.sub_group)
        == (
            Direction::Outbound,
            snac::FOOD_OSERVICE,
            crate::direct::OSERVICE_SET_USER_INFO_FIELDS,
        )
    {
        if let Some(body) = crate::direct::strip_own_dc(s.body) {
            p.payload = Some([&payload[..header_len], &body[..]].concat());
            p.lines
                .push("OUT user info: direct connection address left out".to_string());
        }
        return true;
    }
    false
}

/// Runs `inner` on an inbound SNAC with every peer address in its user info
/// zeroed while encrypting ([`crate::direct::strip_user_info_dc`]: the DC
/// info and external address of buddy arrived, a Locate user info reply, a
/// message's sender, chat users and the rest; third audit of 2026-10,
/// finding 4), and passes the zeroed SNAC on unless `inner` changed or
/// dropped it. Anything else goes to `inner` as it is.
fn addresses_off(
    dir: Direction,
    payload: &[u8],
    encrypting: bool,
    inner: impl FnOnce(&[u8]) -> Processed,
) -> Processed {
    if dir != Direction::Inbound || !encrypting {
        return inner(payload);
    }
    let Some((zeroed, what)) = crate::direct::strip_user_info_dc(payload) else {
        return inner(payload);
    };
    let mut p = inner(&zeroed);
    if p.payload.is_none() && !p.drop {
        p.payload = Some(zeroed);
    }
    p.lines
        .push(format!("IN {what}: direct connection address left out"));
    p
}

/// Looks at one SNAC payload travelling in `dir` and returns what to send in
/// its place and what to log.
pub fn process(dir: Direction, payload: &[u8], policy: &Policy) -> Processed {
    addresses_off(dir, payload, policy.mode == Mode::Encrypt, |payload| {
        process_snac(dir, payload, policy)
    })
}

fn process_snac(dir: Direction, payload: &[u8], policy: &Policy) -> Processed {
    let mut p = Processed::default();
    let Some(s) = snac::parse(payload) else {
        return p;
    };
    // Inbound OSERVICE first, whatever the mode: the add-on needs the MOTD's
    // token and its own account even where it would otherwise not rewrite.
    if dir == Direction::Inbound {
        detect_oservice(&s, &mut p);
    }
    let encrypting = policy.mode == Mode::Encrypt;
    if encrypting && keep_direct_off(dir, payload, &s, &mut p) {
        return p;
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
            let header_len = payload.len() - s.body.len();
            // Encrypting, the client does not offer direct IM.
            let stripped = encrypting
                .then(|| crate::direct::strip_cap(s.body))
                .flatten();
            if stripped.is_some() {
                p.lines
                    .push("OUT capabilities: direct IM left out while encrypting".to_string());
            }
            let base = stripped.as_deref().unwrap_or(s.body);
            match caps::announce(base) {
                Announce::Added(body) => {
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
            if p.payload.is_none() {
                if let Some(body) = stripped {
                    p.payload = Some([&payload[..header_len], &body[..]].concat());
                }
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
    process_crypto_for(dir, payload, crypto, now, None)
}

/// [`process_crypto`] knowing the server's domain (`server =` of the ini),
/// which is where the tZers the server hands out live
/// ([`crate::tzer::served_doc`]). Without it no tZer is recognised: one
/// of the client's is encrypted as text, and one from a protected contact
/// is not shown.
pub fn process_crypto_for(
    dir: Direction,
    payload: &[u8],
    crypto: &mut dyn Crypto,
    now: u64,
    server: Option<&str>,
) -> Processed {
    let encrypting = crypto.encrypts();
    addresses_off(dir, payload, encrypting, |payload| {
        process_crypto_snac(dir, payload, crypto, now, server)
    })
}

fn process_crypto_snac(
    dir: Direction,
    payload: &[u8],
    crypto: &mut dyn Crypto,
    now: u64,
    server: Option<&str>,
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
    let encrypting = crypto.encrypts();
    if encrypting && keep_direct_off(dir, payload, &s, &mut p) {
        return p;
    }
    match (dir, s.food_group, s.sub_group) {
        // The account key is announced in the same SNAC that gets the
        // capability, so no frame is added and the client sends nothing extra
        // (KEY-DIRECTORY-API.md 3.3).
        (Direction::Outbound, snac::FOOD_LOCATE, snac::LOCATE_SET_INFO) => {
            // Encrypting, the client does not offer direct IM.
            let stripped = encrypting
                .then(|| crate::direct::strip_cap(s.body))
                .flatten();
            if let Some(body) = &stripped {
                let header_len = payload.len() - s.body.len();
                p.payload = Some([&payload[..header_len], &body[..]].concat());
                p.lines
                    .push("OUT capabilities: direct IM left out while encrypting".to_string());
            }
            let base = stripped.as_deref().unwrap_or(s.body);
            if let Some(key) = crypto.account_key() {
                match caps::announce_key(base, &key) {
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
            unmark_user_texts(payload, &mut p);
            return p;
        }
        (Direction::Inbound, snac::FOOD_LOCATE, authz::LOCATE_USER_INFO_REPLY)
        | (Direction::Inbound, snac::FOOD_ICBM, authz::ICBM_AUTO_RESPONSE) => {
            unmark_user_texts(payload, &mut p);
            return p;
        }
        (Direction::Inbound, authz::FOOD_FEEDBAG, sub) => {
            if let Some(a) = authz::feedbag_auth(sub, s.body) {
                feedbag_auth_in(payload, s.body, &a, crypto, &mut p);
            }
            return p;
        }
        _ => {}
    }
    let Some(kind) = kind_of(dir, s.food_group, s.sub_group) else {
        return p;
    };
    let header_len = payload.len() - s.body.len();
    // A tZer of the client's goes as it is, announced to the contact's
    // add-on first (sixth audit of 2026-10, finding 4).
    if dir == Direction::Outbound && kind == Kind::ToHost {
        if let Some((peer, doc)) = tzer_of(kind, s.body) {
            if server.is_some_and(|srv| crate::tzer::served_doc(&doc, srv)) {
                let hash = crate::tzer::doc_hash(&doc);
                let notice = crypto.tzer_notice(&peer, hash, now);
                p.lines.push(format!(
                    "OUT peer={peer} tZer: sent as it is (not secret), {}",
                    if notice.is_some() {
                        "announced to the contact's add-on first"
                    } else {
                        "no session to announce it over"
                    }
                ));
                p.controls.extend(notice);
                return p;
            }
        }
    }
    let msg = decode(kind, s.body);
    if let Some(m) = &msg {
        p.lines.push(m.log_line());
    }
    // Inbound, anything that is not a whole armoured container and that the
    // client shows as the contact's words - on any channel, and offline -
    // is unauthenticated text: asked about once, in one place (fifth audit
    // of 2026-10, finding 1). "Whole" is the container parser's word, not
    // the armor tag's: text that only carries `IQE1:<base64>` somewhere
    // (sixth audit, finding 1) is text like any other. With `e2e=off`
    // nothing is decrypted, so a container is text too.
    if dir == Direction::Inbound {
        let parsed = msg
            .as_ref()
            .and_then(|m| container::find_armor(&m.text))
            .and_then(|bytes| container::parse(&bytes));
        return match (msg, parsed) {
            (Some(msg), Some(parsed)) if crypto.encrypts() => {
                container_in(kind, payload, header_len, &s, &msg, parsed, crypto, now, p)
            }
            (msg, parsed) => {
                if let (Some(m), None) = (&msg, &parsed) {
                    if container::find_armor(&m.text).is_some() {
                        p.lines.push(format!(
                            "{} (armored but not a container: taken as unencrypted text)",
                            m.log_line()
                        ));
                    }
                }
                plain_in(kind, payload, header_len, s.body, crypto, now, server, p)
            }
        };
    }
    let Some(msg) = msg else {
        return p;
    };

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
        // Inbound returned above.
        Direction::Inbound => {}
    }
    p
}

/// An inbound message whose text is a whole armoured container
/// ([`container::parse`] read it): decrypted, or the note for a version or
/// scheme this build does not know, said like any other and never read with
/// the scheme-1 layout (CHECKLIST 9.8). Whatever happens, the frame never
/// reaches the client as it came: the decrypted text in its place, or
/// nothing.
#[allow(clippy::too_many_arguments)]
fn container_in(
    kind: Kind,
    payload: &[u8],
    header_len: usize,
    s: &snac::Snac,
    msg: &Message,
    parsed: container::Parsed,
    crypto: &mut dyn Crypto,
    now: u64,
    mut p: Processed,
) -> Processed {
    let got = match parsed {
        container::Parsed::Container(c) => crypto.inbound(&msg.peer, &c, now),
        container::Parsed::Unsupported { version, scheme } => {
            crypto.unsupported(&msg.peer, version, scheme)
        }
    };
    p.ack_request = ack_request(kind, s.body);
    match got {
        Inbound::Text { text, form, .. } => {
            // The sender's own bytes go back into the fragment, with the
            // charset restored from the envelope: the reader sees the
            // message exactly as it was written, nothing added to it -
            // unless it starts like a note of the add-on's, which only
            // the add-on may write (fifth audit of 2026-10, finding 2).
            let text = match crate::policy::unmark(&msg.peer, charset_of(form), &text) {
                Some(t) => {
                    p.lines.push(format!(
                        "{} starts like a note of the add-on's: shown as the contact's",
                        msg.log_line()
                    ));
                    t
                }
                None => text,
            };
            match put_text(kind, s.body, &text, form) {
                Ok(Some(body)) => {
                    p.payload = Some([&payload[..header_len], &body[..]].concat());
                    p.lines
                        .push(format!("{} decrypted {} bytes", msg.log_line(), text.len()));
                }
                // No text where the container was found: the frame is
                // never handed on with the container in it.
                Ok(None) => {
                    p.drop = true;
                    p.lines.push(format!(
                        "{} not shown: no place for the decrypted text",
                        msg.log_line()
                    ));
                }
                Err(why) => {
                    p.drop = true;
                    p.lines.push(format!("{} not shown: {why}", msg.log_line()));
                }
            }
        }
        // A control message advances the ratchet and shows nothing.
        Inbound::Control(_) => {
            p.drop = true;
            p.lines
                .push(format!("{} control message (removed)", msg.log_line()));
        }
        Inbound::Unreadable(note) => {
            p.drop = true;
            p.lines.push(note);
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
    let charset = charset_of(form);
    rewrite_body(kind, body, move |_, _| Some((charset, text.to_vec())))
}

/// The charset a decrypted text is in.
fn charset_of(form: Form) -> u16 {
    match form {
        Form::Fragment { charset, .. } => charset,
        Form::EightBit => text::CHARSET_LATIN1,
    }
}

/// An inbound message that is not an armoured container (fifth audit of
/// 2026-10, findings 1 and 2). If the client would show its text as the
/// contact's words ([`shown_text`]): the engine says whether an
/// unauthenticated message may be shown in that contact's name
/// ([`Crypto::plain_inbound`]); refused, the frame is dropped - with
/// `ICQE2E_NO_INJECT` it stays with the add-on's words in place of the
/// text. Shown, text that starts like a note of the add-on's gets
/// "(from <contact>)" in front of it. Anything else passes as it is.
fn plain_in(
    kind: Kind,
    payload: &[u8],
    header_len: usize,
    body: &[u8],
    crypto: &mut dyn Crypto,
    now: u64,
    server: Option<&str>,
    mut p: Processed,
) -> Processed {
    // A tZer, in either form: shown in a protected contact's name only when
    // their add-on announced it (sixth audit of 2026-10, finding 4).
    if let Some((peer, doc, exact)) = tzer_form_of(kind, body) {
        return tzer_in(
            kind, payload, header_len, body, &peer, &doc, exact, crypto, now, server, p,
        );
    }
    // An authorization event carries the contact's text too (finding 2).
    if let Some((peer, msg_type)) = auth_peer(kind, body) {
        let request = msg_type == authz::MSG_TYPE_AUTH_REQ;
        auth_in(
            kind, payload, header_len, body, &peer, request, crypto, &mut p,
        );
        return p;
    }
    let Some((peer, form)) = shown_text(kind, body) else {
        return p;
    };
    if let Some(why) = crypto.plain_inbound(&peer, now) {
        p.drop = true;
        p.payload = None;
        p.ack_request = ack_request(kind, body);
        let instead = format!(
            "{}(an unencrypted message in {peer}'s name was not shown: {why})",
            crate::policy::PREFIX
        );
        if let Ok(Some(b)) = rewrite_shown(kind, body, |_, _| {
            Some((text::CHARSET_ASCII, instead.as_bytes().to_vec()))
        }) {
            p.withheld = Some([&payload[..header_len], &b[..]].concat());
        }
        p.lines.push(format!(
            "IN  peer={peer} {form}: not end-to-end encrypted and not shown: {why}"
        ));
        return p;
    }
    let unmark =
        |charset: u16, t: &[u8]| crate::policy::unmark(&peer, charset, t).map(|t| (charset, t));
    if let Ok(Some(b)) = rewrite_shown(kind, body, unmark) {
        p.payload = Some([&payload[..header_len], &b[..]].concat());
        p.lines.push(format!(
            "IN  peer={peer} {form}: starts like a note of the add-on's: shown as the contact's"
        ));
    }
    p
}

/// A profile, away message or status text that starts like a note of the
/// add-on's, unmarked (sixth audit of 2026-10, finding 2).
fn unmark_user_texts(payload: &[u8], p: &mut Processed) {
    if let Some((b, what)) = authz::unmark_user_texts(payload) {
        p.payload = Some(b);
        p.lines.push(format!(
            "IN  {what} starts like a note of the add-on's: shown as the contact's"
        ));
    }
}

/// A Feedbag authorization event (sixth audit of 2026-10, finding 2): for a
/// protected contact its reason is replaced by the add-on's words and the
/// event kept; for any other, a reason that starts like a note is unmarked.
fn feedbag_auth_in(
    payload: &[u8],
    body: &[u8],
    a: &authz::FeedbagAuth,
    crypto: &mut dyn Crypto,
    p: &mut Processed,
) {
    let header_len = payload.len() - body.len();
    let reason = a.reason(body);
    let new = match crypto.protected(&a.peer) {
        Some(why) if a.request || !reason.is_empty() => {
            p.lines.push(format!(
                "IN  peer={} authorization {}: its text is not shown, it is not end-to-end authenticated ({why})",
                a.peer,
                if a.request { "request" } else { "reply" }
            ));
            Some(crate::policy::auth_local_text(&a.peer, a.request).into_bytes())
        }
        Some(_) => None,
        None => crate::policy::unmark(&a.peer, text::CHARSET_ASCII, reason),
    };
    let Some(r) = new else {
        return;
    };
    match a.with_reason(body, &r) {
        Some(b) => p.payload = Some([&payload[..header_len], &b[..]].concat()),
        None => {
            p.drop = true;
            p.payload = None;
        }
    }
}

/// The contact and the message type of a legacy authorization event
/// (channel 4, or an ICQ offline message, of one of [`authz::AUTH_TYPES`]).
fn auth_peer(kind: Kind, body: &[u8]) -> Option<(String, u8)> {
    match kind {
        Kind::ToClient => {
            let head = icbm_head_len(kind, body)?;
            if u16::from_be_bytes([*body.get(8)?, *body.get(9)?]) != icbm::CHANNEL_ICQ {
                return None;
            }
            let tlvs = snac::read_tlvs(&body[head..]);
            let (t, _) = icbm::ch4_text(
                snac::find_tlv(&tlvs, icbm::TLV_ICQ_DATA)?,
                authz::AUTH_TYPES,
            )?;
            let n = *body.get(10)? as usize;
            let peer = String::from_utf8_lossy(body.get(11..11 + n)?).into_owned();
            (!peer.is_empty()).then_some((peer, t))
        }
        Kind::Offline => {
            let tlvs = snac::read_tlvs(body);
            let env = snac::find_tlv(&tlvs, icbm::ICQ_TLV_DATA)?;
            authz::AUTH_TYPES.iter().find_map(|t| {
                icbm::offline_reply_text(env, &[*t]).map(|(_, sender)| (sender.to_string(), *t))
            })
        }
        Kind::ToHost | Kind::OfflineOut => None,
    }
}

/// A legacy authorization event (sixth audit of 2026-10, finding 2), as
/// [`feedbag_auth_in`]: the event stays, the contact's text does not for a
/// protected contact; it is unmarked for any other.
#[allow(clippy::too_many_arguments)]
fn auth_in(
    kind: Kind,
    payload: &[u8],
    header_len: usize,
    body: &[u8],
    peer: &str,
    request: bool,
    crypto: &mut dyn Crypto,
    p: &mut Processed,
) {
    let protected = crypto.protected(peer);
    let rewritten = match &protected {
        Some(_) => rewrite_typed(
            kind,
            body,
            |_, t| {
                if t.is_empty() && !request {
                    return None;
                }
                let local = crate::policy::auth_local_text(peer, request);
                authz::legacy_text(peer, t, request, Some(local.as_bytes()))
                    .map(|t| (text::CHARSET_ASCII, t))
            },
            authz::AUTH_TYPES,
        ),
        None => rewrite_typed(
            kind,
            body,
            |_, t| authz::legacy_text(peer, t, request, None).map(|t| (text::CHARSET_ASCII, t)),
            authz::AUTH_TYPES,
        ),
    };
    match rewritten {
        Ok(Some(b)) => {
            p.payload = Some([&payload[..header_len], &b[..]].concat());
            p.lines.push(match protected {
                Some(why) => format!(
                    "IN  peer={peer} authorization event: its text is not shown, it is not end-to-end authenticated ({why})"
                ),
                None => format!(
                    "IN  peer={peer} authorization event starts like a note of the add-on's: shown as the contact's"
                ),
            });
        }
        Ok(None) => {}
        // A text that cannot be put back is never shown as it came.
        Err(why) => {
            p.drop = true;
            p.payload = None;
            p.lines.push(format!(
                "IN  peer={peer} authorization event dropped: {why}"
            ));
        }
    }
}

/// The contact and the document of a tZer in either form: a channel-1
/// message with the tZer mark, or a channel-2 tZer plugin message
/// ([`crate::tzer`]). Both directions.
fn tzer_of(kind: Kind, body: &[u8]) -> Option<(String, String)> {
    tzer_form_of(kind, body).map(|(peer, doc, _)| (peer, doc))
}

/// [`tzer_of`], and whether the tZer carries nothing but its document
/// ([`crate::tzer::ch1_exact`], [`crate::tzer::plugin_exact`]; seventh audit
/// of 2026-10).
fn tzer_form_of(kind: Kind, body: &[u8]) -> Option<(String, String, bool)> {
    if !matches!(kind, Kind::ToClient | Kind::ToHost) {
        return None;
    }
    let head = icbm_head_len(kind, body)?;
    let channel = u16::from_be_bytes([*body.get(8)?, *body.get(9)?]);
    let n = *body.get(10)? as usize;
    let peer = String::from_utf8_lossy(body.get(11..11 + n)?).into_owned();
    let tlvs = snac::read_tlvs(&body[head..]);
    let (doc, exact) = match channel {
        icbm::CHANNEL_IM => {
            let frags = snac::find_tlv(&tlvs, icbm::TLV_AOL_IM_DATA)?;
            (crate::tzer::ch1_doc(frags)?, crate::tzer::ch1_exact(frags))
        }
        icbm::CHANNEL_RENDEZVOUS => {
            let data = snac::find_tlv(&tlvs, icbm::TLV_RENDEZVOUS_DATA)?;
            (
                crate::tzer::plugin_doc(data)?,
                crate::tzer::plugin_exact(data),
            )
        }
        _ => return None,
    };
    (!peer.is_empty()).then_some((peer, doc, exact))
}

/// An inbound tZer (sixth audit of 2026-10, finding 4). From a contact who
/// is not protected: as it came. From a protected one: shown only when it
/// is a tZer of this server's ([`crate::tzer::served_doc`]) and the
/// contact's add-on announced it ([`crate::tzer::Notice`]); one of this
/// server's that is not announced yet is held for its announcement
/// ([`Processed::hold`]); anything else is dropped with a warning.
#[allow(clippy::too_many_arguments)]
fn tzer_in(
    kind: Kind,
    payload: &[u8],
    header_len: usize,
    body: &[u8],
    peer: &str,
    doc: &str,
    exact: bool,
    crypto: &mut dyn Crypto,
    now: u64,
    server: Option<&str>,
    mut p: Processed,
) -> Processed {
    let Some(why) = crypto.protected(peer) else {
        p.lines
            .push(format!("IN  peer={peer} tZer: shown as it came"));
        return p;
    };
    let action = crate::crypto::Action::Tzer {
        peer: peer.to_string(),
        hash: crate::tzer::doc_hash(doc),
    };
    // The notice vouches for the document only, so the tZer must carry
    // nothing else (seventh audit of 2026-10).
    let known = exact && server.is_some_and(|srv| crate::tzer::served_doc(doc, srv));
    if known && crypto.authenticated(&action, true, now) {
        p.lines.push(format!(
            "IN  peer={peer} tZer: announced by the contact's add-on, shown"
        ));
        return p;
    }
    p.drop = true;
    p.payload = None;
    p.withheld = tzer_stand_in(kind, payload, header_len, body);
    if known {
        p.lines.push(format!(
            "IN  peer={peer} tZer: held for the announcement of the contact's add-on"
        ));
        p.hold = Some(action);
    } else {
        let why = format!("{why}; it is not one of this server's tZers either");
        p.lines.push(format!(
            "IN  peer={peer} tZer: not end-to-end authenticated and not shown: {why}"
        ));
        crypto.unauthenticated(
            peer,
            "tZer",
            crate::policy::unauthenticated_action_note(peer, "tZer", &why),
            now,
        );
    }
    p
}

/// What a tZer that is not shown becomes where no frame may be dropped
/// (`ICQE2E_NO_INJECT`): on channel 1 the document gives way to the
/// add-on's words; on channel 2 the proposal becomes a cancel, which the
/// client ignores.
fn tzer_stand_in(kind: Kind, payload: &[u8], header_len: usize, body: &[u8]) -> Option<Vec<u8>> {
    let instead = format!(
        "{}(a tZer that was not authenticated was not shown)",
        crate::policy::PREFIX
    );
    let instead = instead.as_bytes();
    if let Ok(Some(b)) = rewrite_typed(
        kind,
        body,
        |_, _| Some((text::CHARSET_ASCII, instead.to_vec())),
        icbm::SHOWN_TYPES,
    ) {
        return Some([&payload[..header_len], &b[..]].concat());
    }
    let head = icbm_head_len(kind, body)?;
    let (tlvs, _) = snac::split_tlvs(&body[head..]);
    let t = tlvs.iter().find(|t| t.tag == icbm::TLV_RENDEZVOUS_DATA)?;
    let at = header_len + (t.value.as_ptr() as usize - body.as_ptr() as usize);
    let mut out = payload.to_vec();
    out.get_mut(at..at + 2)?
        .copy_from_slice(&crate::files::RDV_CANCEL.to_be_bytes());
    Some(out)
}

/// Who an inbound message is from and on which path, when the client shows
/// its text in the chat as the contact's words: channel 1, a channel-2
/// server-relay message or a channel-4 message of one of
/// [`icbm::SHOWN_TYPES`], or an offline message of one of them. `None` for
/// everything else (a rendezvous of another kind, a plugin message, an
/// authorization request, ...).
fn shown_text(kind: Kind, body: &[u8]) -> Option<(String, &'static str)> {
    match kind {
        Kind::ToClient => {
            let head = icbm_head_len(kind, body)?;
            let channel = u16::from_be_bytes([*body.get(8)?, *body.get(9)?]);
            let name_len = *body.get(10)? as usize;
            let peer = String::from_utf8_lossy(body.get(11..11 + name_len)?).into_owned();
            let tlvs = snac::read_tlvs(&body[head..]);
            let form = match channel {
                icbm::CHANNEL_IM => {
                    let frags = snac::find_tlv(&tlvs, icbm::TLV_AOL_IM_DATA)?;
                    ch1_has_text(frags).then_some("ch1")?
                }
                icbm::CHANNEL_RENDEZVOUS => {
                    let frag = snac::find_tlv(&tlvs, icbm::TLV_RENDEZVOUS_DATA)?;
                    const HEAD: usize = 2 + 8 + 16;
                    if frag.len() < HEAD || frag[10..HEAD] != icbm::CAP_ICQ_SERVER_RELAY {
                        return None;
                    }
                    let inner = snac::read_tlvs(&frag[HEAD..]);
                    let svc = snac::find_tlv(&inner, icbm::RDV_TLV_SVC_DATA)?;
                    icbm::type2_text(svc, icbm::SHOWN_TYPES)?;
                    "ch2/type2"
                }
                icbm::CHANNEL_ICQ => {
                    let data = snac::find_tlv(&tlvs, icbm::TLV_ICQ_DATA)?;
                    icbm::ch4_text(data, icbm::SHOWN_TYPES)?;
                    "ch4"
                }
                _ => return None,
            };
            (!peer.is_empty()).then_some((peer, form))
        }
        Kind::Offline => {
            let tlvs = snac::read_tlvs(body);
            let env = snac::find_tlv(&tlvs, icbm::ICQ_TLV_DATA)?;
            let (_, sender) = icbm::offline_reply_text(env, icbm::SHOWN_TYPES)?;
            Some((sender.to_string(), "offline"))
        }
        Kind::ToHost | Kind::OfflineOut => None,
    }
}

/// Whether a channel-1 fragment list has a message fragment (id 1).
fn ch1_has_text(frags: &[u8]) -> bool {
    let mut r = Reader::new(frags);
    while r.remaining() >= 4 {
        let (Some(id), Some(_version), Some(len)) = (r.u8(), r.u8(), r.u16()) else {
            return false;
        };
        let Some(payload) = r.bytes(len as usize) else {
            return false;
        };
        if id == 1 && payload.len() >= 4 {
            return true;
        }
    }
    false
}

/// [`rewrite_body`] for the text of an inbound message the client shows as
/// the contact's words ([`shown_text`]): every type of
/// [`icbm::SHOWN_TYPES`], channel 4 included.
fn rewrite_shown(
    kind: Kind,
    body: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
) -> Result<Option<Vec<u8>>, Refusal> {
    rewrite_typed(kind, body, f, icbm::SHOWN_TYPES)
}

/// Rebuilds a message SNAC body with transformed text; `Ok(None)` when there is
/// nothing to change (inbound text without the marker, a message type this
/// phase does not handle).
fn rewrite_body(
    kind: Kind,
    body: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
) -> Result<Option<Vec<u8>>, Refusal> {
    rewrite_typed(kind, body, f, icbm::PLAIN_ONLY)
}

/// [`rewrite_body`] for the ICQ message `types` of channel 2, channel 4 and
/// offline messages (channel 1 has no types).
fn rewrite_typed(
    kind: Kind,
    body: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
    types: &'static [u8],
) -> Result<Option<Vec<u8>>, Refusal> {
    // Both directions of an offline message carry their text in the same TLV
    // of the same little-endian block, so the same rewrite serves each.
    if kind == Kind::Offline || kind == Kind::OfflineOut {
        return rewrite_tlv_block(body, |tag, value| {
            if tag == icbm::ICQ_TLV_DATA {
                rewrite_offline(value, f, types)
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
        (icbm::CHANNEL_RENDEZVOUS, icbm::TLV_RENDEZVOUS_DATA) => rewrite_ch2(value, f, types),
        (icbm::CHANNEL_ICQ, icbm::TLV_ICQ_DATA) => rewrite_ch4(value, f, types),
        _ => Ok(None),
    })?;
    Ok(rest.map(|r| [&body[..head], &r[..]].concat()))
}

/// Channel 4: `uin:u32 type:u8 flags:u8 len:u16 text` little-endian.
fn rewrite_ch4(
    data: &[u8],
    f: impl Fn(u16, &[u8]) -> Option<Replaced> + Copy,
    types: &[u8],
) -> Result<Option<Vec<u8>>, Refusal> {
    let Some((_, at)) = icbm::ch4_text(data, types) else {
        return Ok(None);
    };
    replace_at(data, &at, f, |t| at.replace(data, t))
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
    types: &[u8],
) -> Result<Option<Vec<u8>>, Refusal> {
    const HEAD: usize = 2 + 8 + 16;
    if frag.len() < HEAD || frag[10..HEAD] != icbm::CAP_ICQ_SERVER_RELAY {
        return Ok(None);
    }
    let tlvs = rewrite_tlv_block(&frag[HEAD..], |tag, svc| {
        if tag != icbm::RDV_TLV_SVC_DATA {
            return Ok(None);
        }
        let Some(at) = icbm::type2_text(svc, types) else {
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
    types: &[u8],
) -> Result<Option<Vec<u8>>, Refusal> {
    let found = if types == icbm::PLAIN_ONLY {
        icbm::offline_text(env)
    } else {
        icbm::offline_reply_text(env, types)
    };
    let Some((at, _)) = found else {
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
