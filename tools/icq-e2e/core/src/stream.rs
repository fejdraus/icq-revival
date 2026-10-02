//! One direction of one socket as a stream transformer: bytes in, bytes out,
//! FLAP frames rewritten in place.
//!
//! A FLAP frame is `0x2A | channel:u8 | sequence:u16 BE | payload_len:u16 BE |
//! payload` (wire/frames.go). Complete frames are emitted in order, one out for
//! each one in: a SNAC frame [`crate::rewrite`] changes goes out with its new
//! payload and length and the sender's own sequence number, every other frame
//! byte for byte. A partial frame is held until the rest arrives. So in harness
//! mode the frame count and the sequence numbering on the connection never
//! change (DESIGN.md section 6).
//!
//! Stage 3 departs from that where it has to ([`Self::push_crypto`]): the
//! message path is [`crate::rewrite::process_crypto`], a message the add-on
//! removes leaves the stream, and control messages and notes are put in. From
//! the first such frame on, the direction renumbers: every frame it emits -
//! the ones it only passes too - takes the next number of the connection's own
//! counter, so the sequence the far end sees stays strictly increasing and
//! without a gap. A frame the add-on removed leaves its own number free, and
//! an inserted frame takes the number after the last one emitted; the peer's
//! own numbering is therefore never disturbed more than it has to be.
//!
//! A stream is taken for FLAP only if its first frame is a channel-1 frame
//! starting with FLAP version `00 00 00 01` - how both sides of an OSCAR
//! connection open - and every later header has the marker and a channel from 1
//! to 5. Anything else (direct connections, file transfer, a proxy) turns the
//! stream raw at once: bytes held so far are released unchanged, and from then
//! on everything passes straight through.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::config::Policy;
use crate::container;
use crate::crypto::{Crypto, Note};
use crate::icbm::{self, Direction};
use crate::rewrite;
use crate::snac;
use crate::text;

/// FLAP start-of-frame marker.
pub const FLAP_MARKER: u8 = 0x2A;
/// FLAP channel of the sign-on frame that opens a connection.
pub const FLAP_CHANNEL_SIGNON: u8 = 0x01;
/// FLAP channel carrying SNAC data.
pub const FLAP_CHANNEL_SNAC: u8 = 0x02;
/// The highest FLAP channel (keep-alive).
const FLAP_CHANNEL_MAX: u8 = 0x05;
/// FLAP version at the start of a sign-on frame.
const FLAP_VERSION: [u8; 4] = [0, 0, 0, 1];
const HEADER_LEN: usize = 6;

/// `ICBMHostAck` (`0x0004/0x000C`): the server's answer to a message that asked
/// for one, naming the request id it answers.
const ICBM_HOST_ACK: u16 = snac::ICBM_HOST_ACK;
/// `ICBMErr` (`0x0004/0x0001`): the server's refusal of a message, naming the
/// request id it answers the same way.
const ICBM_ERR: u16 = 0x0001;

/// Who a note for the user comes from when no message has been seen on this
/// connection yet, so the note still has somewhere to show.
const NOTE_SENDER: &str = "ICQ E2E";

/// Where the request ids of the frames the add-on puts on the wire itself come
/// from, and how many there are.
///
/// A client's own ids are nowhere near this range. Both clients keep the low
/// word of a request id at 15 bits (`packFNACHeader` masks it with `0x7FFF` in
/// Miranda's `icq_packet.cpp`, and `AllocateCookie` counts up to `0x7FFF` in
/// `cookies.cpp`) with a small type in the high word, so a client's id is
/// `0x00TTssss`. The server marks the frames it starts itself with
/// `0x8000_0000` (`ReqIDFromServer` in wire/frames.go). `0x4000_0000` sits
/// between the two, so an injected id cannot be mistaken for a server's own
/// either: a collision would need the client to wrap its 15-bit counter
/// inside the `0x0001_0000` ids of one window and land on the same number.
const INJECTED_ID_BASE: u32 = 0x4000_0000;
/// The request id of a SNAC the server starts itself (`ReqIDFromServer` in
/// wire/frames.go), which every message it relays to a client carries.
///
/// A note takes it too. With its high bit clear a request id says "the answer
/// to your request with this id", and ICQ 7.2 throws away an answer to a
/// request it never made: a note with an id from [`INJECTED_ID_BASE`] was
/// logged as shown and never appeared, while the ack for a command - which
/// names the client's own request - was taken.
const REQ_ID_FROM_SERVER: u32 = 0x8000_0000;
const INJECTED_ID_COUNT: u32 = 0x0001_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Nothing complete seen yet; the first frame decides.
    Opening,
    /// A FLAP stream.
    Flap,
    /// Not FLAP: everything passes through.
    Raw,
}

/// What the crypto path noticed while rewriting, for the layer that owns the
/// engine to act on. [`StreamRewriter`] only reads bytes, so it cannot publish
/// a token or note a contact itself.
#[derive(Debug, Default)]
pub struct Detected {
    /// Our own UIN, off an outgoing sign-on.
    pub sign_on_uin: Option<String>,
    /// The key directory's token, out of the MOTD.
    pub token: Option<Vec<u8>>,
    /// Our account key, after it has gone out in `LocateSetInfo`.
    pub announce_key: Option<[u8; 32]>,
    /// Contacts whose user info said whether they announce the add-on, in the
    /// order they were seen.
    pub contacts: Vec<(String, bool)>,
}

/// The server's answers to the client's requests that the add-on looks after,
/// shared by the two directions of one socket: a request goes out on one
/// direction and its answer comes back on the other, so the two rewriters
/// have to see each other's work (CHECKLIST 8.3).
///
/// Two kinds: request ids whose answers the client must not see (a frame the
/// add-on put in on the way out), and answers the client is owed but the
/// server will never send (an ack for a `/e2e` command the add-on kept from
/// the server), which the inbound direction puts in itself.
#[derive(Debug, Clone, Default)]
pub struct Answers {
    hidden: Arc<Mutex<Vec<u32>>>,
    owed: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Answers {
    /// How many ids are remembered. A session lasts days and the list only
    /// ever holds what the add-on itself sent, so this is generous.
    const MAX: usize = 256;

    pub fn new() -> Self {
        Self::default()
    }

    /// Remembers `id`, dropping the oldest if the list is full.
    pub fn hide(&self, id: u32) {
        let mut v = self.hidden.lock().expect("hidden ids");
        if v.contains(&id) {
            return;
        }
        if v.len() == Self::MAX {
            v.remove(0);
        }
        v.push(id);
    }

    /// Whether an answer naming `id` is one the client must not see.
    pub fn contains(&self, id: u32) -> bool {
        self.hidden.lock().expect("hidden ids").contains(&id)
    }

    /// Queues `snac`, a SNAC payload, for the inbound direction to hand to
    /// the client in the server's place. Bounded like the hidden ids: the
    /// oldest goes if nothing has taken them for that long.
    pub fn owe(&self, snac: Vec<u8>) {
        let mut v = self.owed.lock().expect("owed answers");
        if v.len() == Self::MAX {
            v.remove(0);
        }
        v.push(snac);
    }

    /// Takes every owed answer, oldest first.
    pub fn take_owed(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.owed.lock().expect("owed answers"))
    }

    /// Whether an answer is waiting to be handed to the client.
    pub fn owes(&self) -> bool {
        !self.owed.lock().expect("owed answers").is_empty()
    }
}

/// Which sequence number a frame is given on the way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seq {
    /// The sender's own number, which a frame the add-on only rewrites must
    /// keep as long as the direction is not renumbering.
    Own,
    /// The connection's own counter, for a frame the add-on puts in.
    Ours,
}

/// One direction of one socket.
pub struct StreamRewriter {
    dir: Direction,
    state: State,
    buf: Vec<u8>,
    /// Contacts last seen announcing the add-on or not, so the log reports
    /// changes only (a contact's user info comes with every status change).
    e2e_contacts: HashMap<String, bool>,
    /// The contact of the last message seen in this direction, which is where
    /// a note for the user goes.
    last_peer: Option<String>,
    /// What the crypto path noticed.
    detected: Detected,
    /// The account key whose announcement has gone out, taken by the caller.
    announced: Option<[u8; 32]>,
    /// The server's answers this socket's two directions look after.
    answers: Answers,
    /// Whether this direction has taken a frame in or out and so numbers the
    /// frames itself. Until then every frame keeps the sender's number.
    renumber: bool,
    /// The number the next frame of the connection's own gets.
    next_seq: u16,
    /// The number of the last frame emitted, if any.
    last_seq: Option<u16>,
    /// How many frames of our own this connection has numbered.
    injected: u32,
    /// Whether the MOTD of this connection carried the key directory token,
    /// which the server sends only on the connection the chats are on.
    saw_token: bool,
    /// Whether the layout of a real incoming message, and of a note, has been
    /// logged on this connection: once each, so a live run shows what the
    /// client accepts next to what the add-on makes.
    logged_real: bool,
    logged_note: bool,
}

impl StreamRewriter {
    pub fn new(dir: Direction) -> Self {
        Self::with_answers(dir, Answers::new())
    }

    /// The two directions of one socket, outbound and inbound, sharing the
    /// [`Answers`] they look after. A socket's rewriters must be made this way:
    /// made apart, an answer one of them arranges never reaches the other.
    pub fn pair() -> (Self, Self) {
        let answers = Answers::new();
        (
            Self::with_answers(Direction::Outbound, answers.clone()),
            Self::with_answers(Direction::Inbound, answers),
        )
    }

    /// A rewriter for one direction of a socket, sharing `answers` with the
    /// other direction's rewriter.
    pub fn with_answers(dir: Direction, answers: Answers) -> Self {
        StreamRewriter {
            dir,
            state: State::Opening,
            buf: Vec::new(),
            e2e_contacts: HashMap::new(),
            last_peer: None,
            announced: None,
            detected: Detected::default(),
            answers,
            renumber: false,
            next_seq: 1,
            last_seq: None,
            injected: 0,
            saw_token: false,
            logged_real: false,
            logged_note: false,
        }
    }

    /// The answers this rewriter looks after, to hand to the other
    /// direction's rewriter.
    pub fn answers(&self) -> Answers {
        self.answers.clone()
    }

    /// What the crypto path noticed and the caller has not taken yet.
    pub fn detected(&self) -> &Detected {
        &self.detected
    }

    /// Takes the contacts seen announcing the add-on since the last call, so
    /// the caller can tell the engine once per contact.
    pub fn take_contacts(&mut self) -> Vec<(String, bool)> {
        std::mem::take(&mut self.detected.contacts)
    }

    /// Takes the token, so it is handed to the engine once and not again on
    /// every later frame. The MOTD arrives once per sign-on, but the rewriter
    /// would otherwise keep reporting the token it saw.
    pub fn take_token(&mut self) -> Option<Vec<u8>> {
        self.detected.token.take()
    }

    /// Takes the UIN an outgoing sign-on named, once. It goes to the layer that
    /// opens the state file, and a later sign-on on the same connection says
    /// the same thing.
    pub fn take_sign_on_uin(&mut self) -> Option<String> {
        self.detected.sign_on_uin.take()
    }

    /// Takes the account key, once the SetInfo carrying it has gone out.
    ///
    /// Not taken on the first sight of it but on the first time the frame it
    /// rode in has left: the announcement only counts once it is on the wire.
    pub fn take_announce(&mut self) -> Option<[u8; 32]> {
        self.announced.take()
    }

    /// Whether the stream has been found not to be FLAP.
    pub fn is_raw(&self) -> bool {
        self.state == State::Raw
    }

    /// How many bytes are held waiting for the rest of a frame.
    pub fn held(&self) -> usize {
        self.buf.len()
    }

    /// Feeds bytes; appends what may go on to `out` and returns log lines.
    /// Never fails: anything it cannot make sense of passes through unchanged.
    ///
    /// This is the stage-2 path: the harness transform, no crypto, and the
    /// frame count and numbering on the connection unchanged.
    pub fn push(&mut self, bytes: &[u8], policy: &Policy, out: &mut Vec<u8>) -> Vec<String> {
        self.feed(bytes, policy, None, out)
    }

    /// Feeds bytes on the stage-3 path: messages go through
    /// [`crate::rewrite::process_crypto`], a message the add-on removes leaves
    /// the stream, notes for the user arrive as messages from the contact, and
    /// a control message is sent when one is due.
    ///
    /// `now` is the send time in Unix seconds. With `policy` not allowing
    /// frames to be added or removed (`ICQE2E_NO_INJECT`) the messages are
    /// still encrypted and decrypted, but nothing is taken out or put in: the
    /// frame count on the connection stays the client's own.
    pub fn push_crypto(
        &mut self,
        bytes: &[u8],
        crypto: &mut dyn Crypto,
        now: u64,
        policy: &Policy,
        out: &mut Vec<u8>,
    ) -> Vec<String> {
        self.feed(
            bytes,
            policy,
            Some(&mut Ctx {
                crypto,
                now,
                add_frames: policy.may_inject(),
            }),
            out,
        )
    }

    fn feed(
        &mut self,
        bytes: &[u8],
        policy: &Policy,
        mut ctx: Option<&mut Ctx<'_>>,
        out: &mut Vec<u8>,
    ) -> Vec<String> {
        let mut lines = Vec::new();
        if self.state == State::Raw {
            out.extend_from_slice(bytes);
            return lines;
        }
        let mut buf = std::mem::take(&mut self.buf);
        buf.extend_from_slice(bytes);
        let mut used = 0;
        loop {
            let rest = &buf[used..];
            match self.check_header(rest) {
                Header::NeedMore => break,
                Header::NotFlap => {
                    self.state = State::Raw;
                    out.extend_from_slice(rest);
                    used = buf.len();
                    break;
                }
                Header::Frame(total) => {
                    if rest.len() < total {
                        break;
                    }
                    self.state = State::Flap;
                    self.emit(&rest[..total], policy, ctx.as_deref_mut(), out, &mut lines);
                    used += total;
                }
            }
        }
        buf.drain(..used);
        self.buf = buf;
        lines
    }

    /// Releases held bytes unchanged, for the end of the stream.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.buf);
    }
}

/// What one call to [`StreamRewriter::push_crypto`] needs beyond the bytes.
struct Ctx<'a> {
    /// The engine, borrowed for the length of one call and no longer.
    crypto: &'a mut dyn Crypto,
    /// The send time in Unix seconds.
    now: u64,
    /// Whether a frame may be taken out of the stream or put into it.
    add_frames: bool,
}

impl StreamRewriter {
    fn check_header(&self, b: &[u8]) -> Header {
        if b.is_empty() {
            return Header::NeedMore;
        }
        if b[0] != FLAP_MARKER {
            return Header::NotFlap;
        }
        let Some(&channel) = b.get(1) else {
            return Header::NeedMore;
        };
        let opening = self.state == State::Opening;
        if !(1..=FLAP_CHANNEL_MAX).contains(&channel) || (opening && channel != FLAP_CHANNEL_SIGNON)
        {
            return Header::NotFlap;
        }
        if b.len() < HEADER_LEN {
            return Header::NeedMore;
        }
        let payload_len = u16::from_be_bytes([b[4], b[5]]) as usize;
        if opening {
            if payload_len < FLAP_VERSION.len() {
                return Header::NotFlap;
            }
            if b.len() < HEADER_LEN + FLAP_VERSION.len() {
                return Header::NeedMore;
            }
            if b[HEADER_LEN..HEADER_LEN + FLAP_VERSION.len()] != FLAP_VERSION {
                return Header::NotFlap;
            }
        }
        Header::Frame(HEADER_LEN + payload_len)
    }

    /// One SNAC frame in, whatever it became, out.
    fn emit(
        &mut self,
        frame: &[u8],
        policy: &Policy,
        mut ctx: Option<&mut Ctx<'_>>,
        out: &mut Vec<u8>,
        lines: &mut Vec<String>,
    ) {
        let may_add = ctx.as_ref().is_some_and(|c| c.add_frames);
        if frame[1] != FLAP_CHANNEL_SNAC {
            self.put_frame(frame, Seq::Own, out);
            return;
        }
        let payload = &frame[HEADER_LEN..];
        // The contact a message is about, so a note or a control message goes
        // into the conversation it belongs to.
        // Only on the crypto path, the one that puts notes in.
        if self.dir == Direction::Inbound && ctx.is_some() && !self.logged_real {
            if let Some(l) = icbm_layout(payload) {
                self.logged_real = true;
                lines.push(format!("layout of a server message: {l}"));
            }
        }
        let peer = message_peer(self.dir, payload);
        if let Some(p) = &peer {
            self.last_peer = Some(p.clone());
        }
        // An answer to a request the client never made: the server's words
        // about a message the add-on put on the wire itself.
        if self.answers_a_hidden_id(payload) {
            self.removed(seq_of(frame));
            lines.push("server answer to a message of the add-on's own: removed".to_string());
            return;
        }
        let processed = match ctx.as_mut() {
            Some(c) => rewrite::process_crypto(self.dir, payload, c.crypto, c.now),
            None => rewrite::process(self.dir, payload, policy),
        };
        lines.extend(processed.lines);
        for (contact, has) in processed.e2e_contacts {
            self.detected.contacts.push((contact.clone(), has));
            let before = self.e2e_contacts.insert(contact.clone(), has);
            match (before, has) {
                (None | Some(false), true) => {
                    lines.push(format!("contact {contact} announces the E2E add-on"))
                }
                (Some(true), false) => lines.push(format!(
                    "contact {contact} no longer announces the E2E add-on"
                )),
                _ => {}
            }
        }
        if processed.sign_on_uin.is_some() {
            self.detected.sign_on_uin = processed.sign_on_uin;
        }
        if processed.token.is_some() {
            self.saw_token = true;
            self.detected.token = processed.token;
        }
        if processed.announce_key.is_some() {
            self.detected.announce_key = processed.announce_key;
            self.announced = processed.announce_key;
        }
        if processed.drop && !may_add {
            // With `ICQE2E_NO_INJECT` the frame count on the connection must
            // not change, so the frame stays. An outbound one goes with its
            // text withheld - a held message or a command must never leave as
            // the user typed it; an inbound one goes to the client as it is.
            match processed.withheld {
                Some(p) if p.len() <= u16::MAX as usize => {
                    lines.push(
                        "frame kept with its text withheld: ICQE2E_NO_INJECT is set".to_string(),
                    );
                    self.put_frame(&with_payload(frame, &p), Seq::Own, out);
                }
                _ => {
                    lines.push("frame kept: ICQE2E_NO_INJECT is set".to_string());
                    self.put_frame(frame, Seq::Own, out);
                }
            }
        } else if processed.drop {
            // The container is gone, so the server's answer to it must go too:
            // an ack for a message the client was never shown would leave the
            // client's ack bookkeeping one message ahead of the chat.
            if let Some(id) = processed.ack_request {
                self.hide(id, lines);
            }
            // A command the server never sees is never acknowledged by it, and
            // a client that asked for an ack would mark the message as failed
            // to send. The ack is owed by the inbound direction instead.
            if let Some(ack) = processed.host_ack {
                self.answers.owe(ack);
                lines.push("the ack for the /e2e command is owed to the client".to_string());
            }
            self.removed(seq_of(frame));
        } else {
            match processed.payload {
                Some(p) if p.len() <= u16::MAX as usize => {
                    self.put_frame(&with_payload(frame, &p), Seq::Own, out);
                }
                Some(_) => {
                    lines.push("frame would exceed 64 KiB; sent unchanged".to_string());
                    self.put_frame(frame, Seq::Own, out);
                }
                None => self.put_frame(frame, Seq::Own, out),
            }
        }
        // The add-on's own frames, after the client's. An owed ack goes first,
        // on whichever connection the command went out on.
        if may_add {
            if self.dir == Direction::Inbound {
                self.put_owed(out, lines);
            }
            match self.dir {
                // A control message goes the way the client's messages go.
                Direction::Outbound => {
                    if let (Some(peer), Some(c)) = (peer.as_deref(), ctx.as_deref_mut()) {
                        self.inject_control(peer, c.crypto, out, lines);
                    }
                }
                // A note is shown as a message from the contact, so it goes
                // towards the client, in whichever direction that is.
                // Only on the connection the chats are on: a service
                // connection's client would not show a message.
                Direction::Inbound if !self.carries_messages() => {}
                Direction::Inbound => loop {
                    let note = match ctx.as_deref_mut() {
                        Some(c) => c.crypto.take_note(),
                        None => None,
                    };
                    match note {
                        Some(n) => self.put_note(&n, out, lines),
                        None => break,
                    }
                },
            }
        }
    }

    /// Hands the client every answer the server owes it but will never send
    /// (an ack for a `/e2e` command), as the server would have sent it, and
    /// says whether there was any.
    fn put_owed(&mut self, out: &mut Vec<u8>, lines: &mut Vec<String>) -> bool {
        let owed = self.answers.take_owed();
        for snac in &owed {
            self.put_frame(&flap(FLAP_CHANNEL_SNAC, snac), Seq::Ours, out);
            lines.push("ack for the /e2e command given to the client".to_string());
        }
        !owed.is_empty()
    }

    /// Puts every note the engine has waiting into the chat, between frames,
    /// and says whether it put any. For the moments no frame from the server
    /// is coming to carry them: the answer to a `/e2e` command, or a note about
    /// a message the user just sent. Only the inbound direction of a connection
    /// that is already past its sign-on takes them.
    ///
    /// An ack the client is owed for a `/e2e` command goes first, where the
    /// server's own ack would have come: right after the message was sent.
    pub fn put_notes(
        &mut self,
        crypto: &mut dyn Crypto,
        policy: &Policy,
        out: &mut Vec<u8>,
        lines: &mut Vec<String>,
    ) -> bool {
        if self.dir != Direction::Inbound
            || self.state != State::Flap
            || self.last_seq.is_none()
            || !policy.may_inject()
        {
            return false;
        }
        let mut put = self.put_owed(out, lines);
        while let Some(n) = crypto.take_note() {
            self.put_note(&n, out, lines);
            put = true;
        }
        put
    }

    /// Whether this direction has carried an instant message, which is what
    /// tells the connection the chats live on from the service connections.
    pub fn carries_messages(&self) -> bool {
        self.last_peer.is_some() || self.saw_token
    }

    /// Puts a note for the user into the chat it belongs in, as an incoming
    /// message from that contact, so it arrives where the user is looking and
    /// is marked as ours. A note about no contact in particular goes into the
    /// chat last used.
    fn put_note(&mut self, note: &Note, out: &mut Vec<u8>, lines: &mut Vec<String>) {
        let from = note
            .peer
            .clone()
            .or_else(|| self.last_peer.clone())
            .unwrap_or_else(|| NOTE_SENDER.to_string());
        let body = to_client_body(&from, &note_text(&note.text));
        let payload = snac_frame(
            snac::FOOD_ICBM,
            snac::ICBM_MSG_TO_CLIENT,
            REQ_ID_FROM_SERVER,
            &body,
        );
        if !self.logged_note {
            if let Some(l) = icbm_layout(&payload) {
                self.logged_note = true;
                lines.push(format!("layout of a note: {l}"));
            }
        }
        self.put_frame(&flap(FLAP_CHANNEL_SNAC, &payload), Seq::Ours, out);
        lines.push(format!("note shown in the chat with {from}"));
    }

    /// Puts one control message to `peer` on the wire, if one is due, and
    /// reports whether it did. The frame is the add-on's own, so it carries
    /// neither the ack request TLV `0x0003` nor the store-offline TLV
    /// `0x0006`: the server keeps no copy of it and answers nothing
    /// (CHECKLIST 2.2, 2.3, 3.8, 8.3).
    ///
    /// This is the outbound direction's own path, so a caller can also use it
    /// for a heartbeat where no client frame is due to attach the control
    /// message to.
    pub fn inject_control(
        &mut self,
        peer: &str,
        crypto: &mut dyn Crypto,
        out: &mut Vec<u8>,
        lines: &mut Vec<String>,
    ) -> bool {
        let Some(container) = crypto.take_control(peer) else {
            return false;
        };
        // A frame with no FLAP frame before it has no number of its own to
        // take, so there is nowhere to put it.
        if self.last_seq.is_none() {
            lines.push(format!(
                "control message to {peer} not sent: nothing on the wire yet"
            ));
            return false;
        }
        let id = self.next_injected_id();
        let body = to_host_body(peer, &container::armor(&container));
        // The server's answer to a frame of ours names a request id the client
        // never used, so it is hidden rather than shown.
        self.hide(id, lines);
        let f = flap(
            FLAP_CHANNEL_SNAC,
            &snac_frame(snac::FOOD_ICBM, snac::ICBM_MSG_TO_HOST, id, &body),
        );
        self.put_frame(&f, Seq::Ours, out);
        lines.push(format!("control message to {peer} added to the stream"));
        true
    }

    /// Puts one frame on the wire.
    ///
    /// `Seq::Own` keeps the sender's own sequence number, which is what a
    /// frame the add-on only rewrites must do. Once this direction has taken a
    /// frame in or out it renumbers, and from then on every frame - the
    /// sender's and ours alike - takes the next number of the connection's own
    /// counter, so what the far end sees stays strictly increasing and without
    /// a gap however many frames were added or removed (CHECKLIST 8.3).
    fn put_frame(&mut self, frame: &[u8], seq: Seq, out: &mut Vec<u8>) {
        let n = match seq {
            Seq::Own if !self.renumber => seq_of(frame),
            _ => {
                self.renumber = true;
                let n = self.next_seq;
                n
            }
        };
        self.last_seq = Some(n);
        self.next_seq = n.wrapping_add(1);
        out.extend_from_slice(&[FLAP_MARKER, frame[1]]);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&((frame.len() - HEADER_LEN) as u16).to_be_bytes());
        out.extend_from_slice(&frame[HEADER_LEN..]);
    }

    /// A frame the add-on took out. Nothing goes on the wire for it, so the
    /// numbering carries on from the last frame that did: with nothing
    /// emitted yet in this direction the number the removed frame had is
    /// taken, so the next frame takes the one after it and the far end sees no
    /// gap either way.
    fn removed(&mut self, seq: u16) {
        self.renumber = true;
        self.next_seq = match self.last_seq {
            Some(last) => last.wrapping_add(1),
            None => seq,
        };
    }

    /// Remembers a request id the client must not see an answer to. It goes
    /// into the list both directions share, because the answer to a message
    /// sent outbound comes back inbound.
    fn hide(&mut self, id: u32, lines: &mut Vec<String>) {
        if self.answers.contains(id) {
            return;
        }
        self.answers.hide(id);
        lines.push(format!("the server's answer to request {id} is hidden"));
    }

    /// Whether this SNAC is the server answering a request the client must
    /// not see: `ICBMHostAck` (`0x0004/0x000C`) and `ICBMErr` (`0x0004/0x0001`)
    /// both carry the id of the request they answer.
    fn answers_a_hidden_id(&self, payload: &[u8]) -> bool {
        let Some(s) = snac::parse(payload) else {
            return false;
        };
        s.food_group == snac::FOOD_ICBM
            && (s.sub_group == ICBM_HOST_ACK || s.sub_group == ICBM_ERR)
            && self.answers.contains(s.request_id)
    }

    /// The request id of the next frame the add-on puts on the wire itself.
    fn next_injected_id(&mut self) -> u32 {
        let id = INJECTED_ID_BASE + self.injected;
        self.injected = (self.injected + 1) % INJECTED_ID_COUNT;
        id
    }
}

enum Header {
    NeedMore,
    NotFlap,
    /// A plausible header; the frame is this many bytes long.
    Frame(usize),
}

/// The sequence number a FLAP frame carries.
fn seq_of(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[2], frame[3]])
}

/// `frame` with its payload replaced by `payload`, header and sequence kept.
fn with_payload(frame: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(HEADER_LEN + payload.len());
    f.extend_from_slice(&frame[..4]);
    f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A FLAP frame: marker, channel, sequence, length, payload.
fn flap(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![FLAP_MARKER, channel, 0, 0];
    f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A SNAC payload: header and body, with no version block.
fn snac_frame(food_group: u16, sub_group: u16, request_id: u32, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(10 + body.len());
    p.extend_from_slice(&food_group.to_be_bytes());
    p.extend_from_slice(&sub_group.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&request_id.to_be_bytes());
    p.extend_from_slice(body);
    p
}

/// The other party of a message SNAC travelling in `dir`, if this is one.
fn message_peer(dir: Direction, payload: &[u8]) -> Option<String> {
    let s = snac::parse(payload)?;
    let msg = match (dir, s.food_group, s.sub_group) {
        (Direction::Outbound, snac::FOOD_ICBM, snac::ICBM_MSG_TO_HOST) => {
            icbm::parse_to_host(s.body)
        }
        (Direction::Inbound, snac::FOOD_ICBM, snac::ICBM_MSG_TO_CLIENT) => {
            icbm::parse_to_client(s.body)
        }
        _ => None,
    }?;
    (!msg.peer.is_empty()).then_some(msg.peer)
}

/// An `ICBMChannelMsgToHost` body (channel 1) carrying `text` and nothing else:
/// TLV `0x0002`, the fragment list. No TLV `0x0003`, so the server is not
/// asked to acknowledge the message, and no TLV `0x0006`, so the server keeps
/// no offline copy of it.
fn to_host_body(peer: &str, text: &str) -> Vec<u8> {
    let mut b = fresh_cookie().to_vec();
    b.extend_from_slice(&icbm::CHANNEL_IM.to_be_bytes());
    b.push(peer.len() as u8);
    b.extend_from_slice(peer.as_bytes());
    let frags = ch1_fragments(text::CHARSET_ASCII, text.as_bytes());
    snac::put_tlv(&mut b, icbm::TLV_AOL_IM_DATA, &frags);
    b
}

/// An `ICBMChannelMsgToClient` body (channel 1) as the server relays one, with
/// the user-info TLVs the server always puts first (`userInfo` in
/// state/session.go): user class, sign-on time and status.
///
/// Every one gets a cookie of its own. A client takes the cookie for the
/// message's identity: ICQ 7 shows a message whose cookie it has already seen
/// as a duplicate - that is, not at all - so with one fixed cookie only the
/// first note of a session would ever have appeared.
fn to_client_body(sender: &str, text: &str) -> Vec<u8> {
    let mut b = fresh_cookie().to_vec();
    b.extend_from_slice(&icbm::CHANNEL_IM.to_be_bytes());
    b.push(sender.len() as u8);
    b.extend_from_slice(sender.as_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // warning level
    b.extend_from_slice(&3u16.to_be_bytes()); // user-info TLV count
    snac::put_tlv(&mut b, 0x0001, &[0x00, 0x50]); // user class: ICQ, free
    snac::put_tlv(
        &mut b,
        0x0003,
        &(crate::crypto::unix_now() as u32).to_be_bytes(),
    ); // sign-on time
    snac::put_tlv(&mut b, 0x0006, &[0, 0, 0, 0]); // status
    let frags = ch1_fragments(text::CHARSET_UNICODE, &ucs2be(&as_html(text)));
    snac::put_tlv(&mut b, icbm::TLV_AOL_IM_DATA, &frags);
    b
}

/// `text` the way ICQ 6.5 and 7.2 write a message themselves - the only two
/// clients the add-on runs in, both of which read HTML (`readsHTML` in
/// foodgroup/icbm.go): an HTML document, with the characters HTML gives a
/// meaning to escaped and line breaks as `<BR>`.
fn as_html(text: &str) -> String {
    let mut h = String::from("<HTML><BODY>");
    for c in text.chars() {
        match c {
            '&' => h.push_str("&amp;"),
            '<' => h.push_str("&lt;"),
            '>' => h.push_str("&gt;"),
            '"' => h.push_str("&quot;"),
            '\r' => {}
            '\n' => h.push_str("<BR>"),
            c => h.push(c),
        }
    }
    h.push_str("</BODY></HTML>");
    h
}

/// `s` in UCS-2 big-endian, the charset `0x0002` of a message fragment.
fn ucs2be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

/// The shape of an incoming channel-1 message, for the log: request id,
/// flags, the tags of the user-info and message TLVs, and the fragments of
/// TLV `0x0002` with the capability fragment in full and of the text only the
/// charset and length - never the text itself. `None` for any other SNAC.
fn icbm_layout(payload: &[u8]) -> Option<String> {
    let s = snac::parse(payload)?;
    if s.food_group != snac::FOOD_ICBM || s.sub_group != snac::ICBM_MSG_TO_CLIENT {
        return None;
    }
    let b = s.body;
    let channel = u16::from_be_bytes([*b.get(8)?, *b.get(9)?]);
    let mut at = 11 + *b.get(10)? as usize + 2; // cookie, channel, name, warning
    let count = u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]);
    at += 2;
    let mut info = Vec::new();
    for _ in 0..count {
        let tag = u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]);
        let len = u16::from_be_bytes([*b.get(at + 2)?, *b.get(at + 3)?]) as usize;
        info.push(format!("{tag:04X}/{len}"));
        at += 4 + len;
    }
    let mut tlvs = Vec::new();
    let mut frags = Vec::new();
    for t in snac::read_tlvs(b.get(at..)?) {
        tlvs.push(format!("{:04X}/{}", t.tag, t.value.len()));
        if t.tag != icbm::TLV_AOL_IM_DATA {
            continue;
        }
        let mut f = 0;
        while f + 4 <= t.value.len() {
            let (id, ver) = (t.value[f], t.value[f + 1]);
            let len = u16::from_be_bytes([t.value[f + 2], t.value[f + 3]]) as usize;
            let v = &t.value[f + 4..(f + 4 + len).min(t.value.len())];
            if id == 0x05 {
                let hex: Vec<String> = v.iter().map(|x| format!("{x:02X}")).collect();
                frags.push(format!("{id:02X}{ver:02X}[{}]", hex.join(" ")));
            } else if id == 0x01 && v.len() >= 4 {
                let cs = u16::from_be_bytes([v[0], v[1]]);
                let lang = u16::from_be_bytes([v[2], v[3]]);
                frags.push(format!(
                    "{id:02X}{ver:02X}[charset {cs:04X} lang {lang:04X} {} bytes]",
                    v.len() - 4
                ));
            } else {
                frags.push(format!("{id:02X}{ver:02X}/{len}"));
            }
            f += 4 + len;
        }
    }
    Some(format!(
        "req=0x{:08X} flags=0x{:04X} ch={channel} user-info=[{}] tlvs=[{}] fragments=[{}]",
        s.request_id,
        s.flags,
        info.join(" "),
        tlvs.join(" "),
        frags.join(" ")
    ))
}

/// A message cookie for a frame the add-on makes itself: 8 bytes from the OS
/// random source, so it never repeats - not between notes, not across
/// reconnections, where a counter would start over - and is no likelier to
/// meet a client's own cookie than two of the client's are to meet each other.
/// Should the random source fail, the clock and a counter stand in, which
/// still never repeat within a process.
fn fresh_cookie() -> [u8; 8] {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let mut c = [0u8; 8];
    if getrandom::fill(&mut c).is_ok() {
        return c;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    c[..4].copy_from_slice(&nanos.to_be_bytes());
    c[4..].copy_from_slice(&n.to_be_bytes());
    c
}

/// A channel-1 fragment list: a caps fragment (id 5) and the message fragment
/// (id 1) with charset, language and text, the layout `icbm` parses.
fn ch1_fragments(charset: u16, text: &[u8]) -> Vec<u8> {
    let mut f = vec![0x05, 0x01, 0x00, 0x02, 0x01, 0x01];
    let mut msg = Vec::with_capacity(4 + text.len());
    msg.extend_from_slice(&charset.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // language
    msg.extend_from_slice(text);
    f.push(0x01);
    f.push(0x01);
    f.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    f.extend_from_slice(&msg);
    f
}

/// The text of a note, with the marker in front of it once and only once: the
/// engine already prefixes its notes, so this only covers a caller that did
/// not.
fn note_text(note: &str) -> String {
    const PREFIX: &str = "[ICQ E2E] ";
    if note.starts_with(PREFIX) {
        note.to_string()
    } else {
        format!("{PREFIX}{note}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(channel: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![FLAP_MARKER, channel];
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn hello() -> Vec<u8> {
        frame(1, 100, &[0, 0, 0, 1])
    }

    fn run(r: &mut StreamRewriter, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        r.push(bytes, &Policy::harness(), &mut out);
        out
    }

    #[test]
    fn flap_frames_pass_whole() {
        let mut r = StreamRewriter::new(Direction::Outbound);
        let mut s = hello();
        s.extend(frame(2, 101, b"not a snac we touch"));
        s.extend(frame(5, 102, b""));
        assert_eq!(run(&mut r, &s), s);
        assert!(!r.is_raw());
    }

    #[test]
    fn partial_frame_is_held() {
        let mut r = StreamRewriter::new(Direction::Inbound);
        let s = [hello(), frame(2, 7, b"abcdef")].concat();
        let cut = s.len() - 3;
        assert_eq!(run(&mut r, &s[..cut]), hello());
        assert_eq!(r.held(), cut - hello().len());
        assert_eq!(run(&mut r, &s[cut..]), frame(2, 7, b"abcdef"));
        assert_eq!(r.held(), 0);
    }

    #[test]
    fn non_flap_goes_raw_at_once() {
        let mut r = StreamRewriter::new(Direction::Inbound);
        assert_eq!(run(&mut r, b"OFT2 file transfer"), b"OFT2 file transfer");
        assert!(r.is_raw());
        assert_eq!(run(&mut r, &hello()), hello());
    }

    #[test]
    fn a_star_that_is_not_a_signon_goes_raw() {
        // Starts like FLAP but channel 2 first: not an OSCAR connection opening.
        let mut r = StreamRewriter::new(Direction::Outbound);
        let s = frame(2, 1, b"xyz");
        assert_eq!(run(&mut r, &s[..3]), &s[..3]);
        assert!(r.is_raw());
        // Right channel, wrong version.
        let mut r = StreamRewriter::new(Direction::Outbound);
        let s = frame(1, 1, &[0, 0, 0, 9]);
        assert_eq!(run(&mut r, &s), s);
        assert!(r.is_raw());
    }

    #[test]
    fn desync_later_releases_held_bytes() {
        let mut r = StreamRewriter::new(Direction::Inbound);
        let s = [hello(), b"\x2A\x09garbage".to_vec()].concat();
        assert_eq!(run(&mut r, &s), s);
        assert!(r.is_raw());
    }

    #[test]
    fn finish_releases_a_partial_frame() {
        let mut r = StreamRewriter::new(Direction::Inbound);
        let partial = &frame(1, 1, &[0, 0, 0, 1, 9, 9])[..8];
        assert!(run(&mut r, partial).is_empty());
        let mut out = Vec::new();
        r.finish(&mut out);
        assert_eq!(out, partial);
    }

    // ---- the crypto path ----

    use crate::container::{self, Container, Form};
    use crate::keys::{Inbound, Outbound};

    /// A crypto engine that answers from a script, so a test can say what a
    /// message becomes without a key directory, a token or a clock.
    struct Fake {
        outbound: Vec<Outbound>,
        inbound: Vec<Inbound>,
        notes: Vec<String>,
        control: Option<Vec<u8>>,
        /// The peers whose messages were asked about, so a test can prove a
        /// message really was taken to the engine.
        seen: Vec<String>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                outbound: Vec::new(),
                inbound: Vec::new(),
                notes: Vec::new(),
                control: None,
                seen: Vec::new(),
            }
        }

        /// Answers every outbound message with `out`.
        fn sending(mut self, out: Outbound) -> Self {
            self.outbound.push(out);
            self
        }

        /// Answers every inbound container with `in`.
        fn receiving(mut self, in_: Inbound) -> Self {
            self.inbound.push(in_);
            self
        }

        fn with_notes(mut self, notes: &[&str]) -> Self {
            self.notes = notes.iter().map(|s| s.to_string()).collect();
            self
        }

        fn with_control(mut self, container: Vec<u8>) -> Self {
            self.control = Some(container);
            self
        }

        fn next_out(&mut self) -> Outbound {
            self.outbound.remove(0)
        }

        fn next_in(&mut self) -> Inbound {
            self.inbound.remove(0)
        }
    }

    impl Crypto for Fake {
        fn bearer(&self) -> Option<String> {
            None
        }

        fn ready(&self) -> bool {
            true
        }

        fn account_key(&self) -> Option<[u8; 32]> {
            None
        }

        fn outbound(&mut self, peer: &str, _: Form, _: &[u8], _: u64) -> Outbound {
            self.seen.push(peer.to_string());
            self.next_out()
        }

        fn inbound(&mut self, peer: &str, _: &Container, _: u64) -> Inbound {
            self.seen.push(peer.to_string());
            self.next_in()
        }

        fn unsupported(&mut self, peer: &str, _: u8, _: u8) -> Inbound {
            self.seen.push(peer.to_string());
            Inbound::Unreadable(format!("unsupported from {peer}"))
        }

        fn take_note(&mut self) -> Option<Note> {
            if self.notes.is_empty() {
                None
            } else {
                Some(Note {
                    peer: None,
                    text: self.notes.remove(0),
                })
            }
        }

        fn take_control(&mut self, _peer: &str) -> Option<Vec<u8>> {
            self.control.take()
        }

        fn since_control(&self, _peer: &str) -> u32 {
            0
        }
    }

    /// Encryption mode with adding and removing frames allowed, which is the
    /// default the client runs in.
    fn encrypt() -> Policy {
        Policy::from_settings(crate::config::Settings {
            mode: Some("encrypt"),
            directory: Some("https://example.invalid"),
            home: Some(" "),
            ..Default::default()
        })
    }

    /// A rewriter that has already seen the sign-on frame, and the bytes that
    /// frame put on the wire.
    fn opened(dir: Direction) -> (StreamRewriter, Vec<u8>) {
        let mut r = StreamRewriter::new(dir);
        let mut out = Vec::new();
        r.push_crypto(&hello(), &mut Fake::new(), 1, &encrypt(), &mut out);
        assert_eq!(out, hello(), "the sign-on goes out unchanged");
        (r, out)
    }

    /// The FLAP frames of a byte stream, as `(sequence, payload)`.
    fn frames_of(bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            assert_eq!(bytes[at], FLAP_MARKER, "frame marker at {at}");
            let seq = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
            let len = u16::from_be_bytes([bytes[at + 4], bytes[at + 5]]) as usize;
            out.push((seq, bytes[at + HEADER_LEN..at + HEADER_LEN + len].to_vec()));
            at += HEADER_LEN + len;
        }
        out
    }

    fn texts_of(frames: &[(u16, Vec<u8>)]) -> Vec<String> {
        frames
            .iter()
            .filter_map(|(_, p)| {
                let s = snac::parse(p)?;
                if s.food_group != snac::FOOD_ICBM || s.sub_group != snac::ICBM_MSG_TO_CLIENT {
                    return None;
                }
                Some(icbm::parse_to_client(s.body)?.text)
            })
            .collect()
    }

    /// An armoured container with no wrap and no readable ciphertext: enough
    /// for `container::find_armor` and `Container::from_bytes` to accept and
    /// for `rewrite` to take the message down the crypto path.
    fn any_container() -> Vec<u8> {
        Container {
            flags: container::FLAG_CONTROL,
            sender_device: 7,
            wraps: Vec::new(),
            ciphertext: vec![1, 2, 3],
        }
        .to_bytes()
    }

    /// An inbound channel-1 message as the server relays it, with TLV
    /// `0x0003` asking for an ack of `ack` - the little-endian id the server
    /// echoes back in `ICBMHostAck` (foodgroup/icbm.go).
    fn in_message(seq: u16, sender: &str, text: &str, ack: Option<u32>) -> Vec<u8> {
        let mut tlvs = Vec::new();
        let frags = ch1_fragments(text::CHARSET_ASCII, text.as_bytes());
        snac::put_tlv(&mut tlvs, icbm::TLV_AOL_IM_DATA, &frags);
        if let Some(id) = ack {
            snac::put_tlv(&mut tlvs, icbm::TLV_REQUEST_HOST_ACK, &id.to_le_bytes());
        }
        let mut body = vec![8, 7, 6, 5, 4, 3, 2, 1]; // cookie
        body.extend_from_slice(&icbm::CHANNEL_IM.to_be_bytes());
        body.push(sender.len() as u8);
        body.extend_from_slice(sender.as_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // warning level
        body.extend_from_slice(&2u16.to_be_bytes()); // user-info TLV count
        snac::put_tlv(&mut body, 0x0001, &[0x00, 0x50]); // user class
        snac::put_tlv(&mut body, 0x0006, &[0, 0, 0, 0]); // status
        body.extend_from_slice(&tlvs);
        frame(
            FLAP_CHANNEL_SNAC,
            seq,
            &snac_frame(snac::FOOD_ICBM, snac::ICBM_MSG_TO_CLIENT, 0, &body),
        )
    }

    /// The server's `ICBMHostAck` for request `id`: the frame it sends to the
    /// client after a message that asked to be acknowledged.
    fn host_ack(seq: u16, id: u32) -> Vec<u8> {
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8]; // cookie
        body.extend_from_slice(&icbm::CHANNEL_IM.to_be_bytes());
        body.push(4);
        body.extend_from_slice(b"peer");
        frame(
            FLAP_CHANNEL_SNAC,
            seq,
            &snac_frame(snac::FOOD_ICBM, ICBM_HOST_ACK, id, &body),
        )
    }

    /// An outbound channel-1 message as the client sends it.
    fn out_message(seq: u16, target: &str, text: &str) -> Vec<u8> {
        let frags = ch1_fragments(text::CHARSET_ASCII, text.as_bytes());
        let mut tlvs = Vec::new();
        snac::put_tlv(&mut tlvs, icbm::TLV_AOL_IM_DATA, &frags);
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8]; // cookie
        body.extend_from_slice(&icbm::CHANNEL_IM.to_be_bytes());
        body.push(target.len() as u8);
        body.extend_from_slice(target.as_bytes());
        body.extend_from_slice(&tlvs);
        frame(
            FLAP_CHANNEL_SNAC,
            seq,
            &snac_frame(snac::FOOD_ICBM, snac::ICBM_MSG_TO_HOST, 0x0000_0011, &body),
        )
    }

    #[test]
    fn a_message_the_add_on_removes_never_reaches_the_client() {
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new().receiving(Inbound::Control);
        // One message before it, so the direction has a numbering to keep.
        r.push_crypto(
            &in_message(2, "peer", "hello", None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        let dropped = in_message(3, "peer", &container::armor(&any_container()), Some(9));
        r.push_crypto(&dropped, &mut c, 1, &encrypt(), &mut out);
        // And one after it, which must land where the removed frame was.
        r.push_crypto(
            &in_message(4, "peer", "still here", None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );

        // Only the container goes to the engine: a message without armor is a
        // message from a client without the add-on and is left alone.
        assert_eq!(c.seen, vec!["peer".to_string()]);
        assert!(!out.windows(11).any(|w| w == b"still here"));
        assert!(!out.windows(8).any(|w| w == container::HINT.as_bytes()));
        let got = frames_of(&out);
        assert_eq!(got.len(), 3, "the sign-on, the two messages that stayed");
        let texts: Vec<String> = got
            .iter()
            .filter_map(|(_, p)| {
                let s = snac::parse(p)?;
                if s.food_group != snac::FOOD_ICBM {
                    return None;
                }
                Some(icbm::parse_to_client(s.body)?.text)
            })
            .collect();
        assert_eq!(texts, vec!["hello", "still here"], "the container is gone");
    }

    #[test]
    fn the_sequence_the_client_sees_stays_increasing_and_without_a_gap() {
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new()
            .receiving(Inbound::Control)
            .receiving(Inbound::Control);
        // Five messages, every second one a container the add-on takes out.
        r.push_crypto(
            &in_message(2, "peer", "one", None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        r.push_crypto(
            &in_message(3, "peer", &container::armor(&any_container()), None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        r.push_crypto(
            &in_message(4, "peer", "two", None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        r.push_crypto(
            &in_message(5, "peer", &container::armor(&any_container()), None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        r.push_crypto(
            &in_message(6, "peer", "three", None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );

        let seqs: Vec<u16> = frames_of(&out).iter().map(|(s, _)| *s).collect();
        // Nothing is taken out before the second frame, so it keeps the
        // number the server gave it. From the first container on, the
        // connection's own numbering takes over.
        assert_eq!(
            seqs,
            vec![100, 2, 3, 4],
            "each frame is numbered once, in order"
        );
        for pair in seqs[1..].windows(2) {
            assert_eq!(pair[1], pair[0] + 1, "no jump and no repeat in {seqs:?}");
        }
    }

    #[test]
    fn with_nothing_taken_out_or_put_in_the_senders_own_numbers_are_kept() {
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new().with_notes(&["[ICQ E2E] nothing to report."]);
        for seq in 2..8 {
            r.push_crypto(
                &in_message(seq, "peer", "hello", None),
                &mut c,
                1,
                &encrypt(),
                &mut out,
            );
        }
        let seqs: Vec<u16> = frames_of(&out).iter().map(|(s, _)| *s).collect();
        // Six client frames keep the numbers they came with; the note is the
        // one frame the add-on put in, and it takes the number after the last.
        assert_eq!(seqs, vec![100, 2, 3, 4, 5, 6, 7, 8]);
        assert!(
            texts_of(&frames_of(&out))
                .iter()
                .any(|t| t.contains("nothing to report.")),
            "the note went out"
        );
    }

    #[test]
    fn a_note_arrives_as_a_message_from_the_contact() {
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new()
            .receiving(Inbound::Control)
            .receiving(Inbound::Control)
            .with_notes(&["[ICQ E2E] The key of peer has changed."]);
        r.push_crypto(
            &in_message(2, "peer", "one", None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        r.push_crypto(
            &in_message(3, "peer", &container::armor(&any_container()), None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );

        let got = frames_of(&out);
        let note = texts_of(&got)
            .into_iter()
            .find(|t| t.contains("has changed"))
            .expect("the note is shown");
        assert!(
            note.starts_with("<HTML><BODY>[ICQ E2E] "),
            "an HTML document, as ICQ 6.5 and 7.2 write: {note:?}"
        );
        // It is a message from the contact, so it is filed in their chat.
        let from = got
            .iter()
            .filter_map(|(_, p)| icbm::parse_to_client(snac::parse(p)?.body))
            .find(|m| m.text.contains("has changed"))
            .map(|m| m.peer)
            .expect("the note names the contact");
        assert_eq!(from, "peer");
        // And it did not take the message's place on the wire: the sign-on and
        // the message are both still there.
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn a_control_message_is_asked_for_no_ack_and_stored_nothing() {
        let (mut r, mut out) = opened(Direction::Outbound);
        let sent = Fake::new();
        let mut lines = Vec::new();
        let mut sent = sent.sending(Outbound::Clear {
            text: String::from("hello there"),
            note: String::new(),
        });
        lines.extend(r.push_crypto(
            &out_message(1, "peer", "hello there"),
            &mut sent,
            1,
            &encrypt(),
            &mut out,
        ));
        assert!(
            sent.seen == vec!["peer".to_string()],
            "the engine saw the peer"
        );

        // A control message is due now, and is put in after the client's frame.
        let mut c = sent.with_control(any_container());
        assert!(r.inject_control("peer", &mut c, &mut out, &mut lines));
        let got = frames_of(&out);
        assert_eq!(
            got.len(),
            3,
            "the sign-on, the message, the control message"
        );

        let (_seq, payload) = got.last().expect("the control message");
        let s = snac::parse(payload).expect("a SNAC");
        assert_eq!(s.food_group, snac::FOOD_ICBM);
        assert_eq!(s.sub_group, snac::ICBM_MSG_TO_HOST);
        let msg = icbm::parse_to_host(s.body).expect("a channel-1 message to peer");
        assert_eq!(msg.peer, "peer");
        assert!(msg.text.starts_with(container::HINT), "{:?}", msg.text);
        // The two TLVs that must not be there.
        let head = 8 + 2 + 1 + "peer".len();
        let tags: Vec<u16> = snac::read_tlvs(&s.body[head..])
            .iter()
            .map(|t| t.tag)
            .collect();
        assert_eq!(
            tags,
            vec![icbm::TLV_AOL_IM_DATA],
            "no ack, no store-offline"
        );
        assert!(!tags.contains(&0x0003) && !tags.contains(&0x0006));
    }

    #[test]
    fn the_servers_answer_to_a_removed_message_never_reaches_the_client() {
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new().receiving(Inbound::Control);
        // A message asking for an ack, which the add-on takes out.
        let lines = r.push_crypto(
            &in_message(2, "peer", &container::armor(&any_container()), Some(0x1234)),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        assert!(lines.iter().any(|l| l.contains("is hidden")), "{lines:?}");

        // The ack the server sends for it, and one for a request of the
        // client's own that must still get through.
        let mut out2 = Vec::new();
        let mut s = hello().len();
        let ack = host_ack(3, 0x1234);
        let other = host_ack(4, 0x0011);
        r.push_crypto(&ack[..s + 4], &mut c, 1, &encrypt(), &mut out2);
        s += 4;
        r.push_crypto(&ack[s..], &mut c, 1, &encrypt(), &mut out2);
        r.push_crypto(&other, &mut c, 1, &encrypt(), &mut out2);
        out.append(&mut out2);

        let got = frames_of(&out);
        let ids: Vec<u32> = got
            .iter()
            .filter_map(|(_, p)| snac::parse(p))
            .filter(|s| s.sub_group == ICBM_HOST_ACK)
            .map(|s| s.request_id)
            .collect();
        assert_eq!(
            ids,
            vec![0x0011],
            "only the client's own ack is on the wire"
        );
        // The frame numbers still have no gap: two frames came out, one in.
        let seqs: Vec<u16> = got.iter().map(|(s, _)| *s).collect();
        for pair in seqs.windows(2) {
            assert_eq!(pair[1], pair[0] + 1, "{seqs:?}");
        }
    }

    #[test]
    fn the_answer_to_a_control_message_of_our_own_is_removed_too() {
        // Both directions of one socket share the list of hidden ids.
        let (mut out_side, mut out) = opened(Direction::Outbound);
        let mut c = Fake::new().with_control(any_container());
        let mut lines = Vec::new();
        assert!(out_side.inject_control("peer", &mut c, &mut out, &mut lines));
        let sent = frames_of(&out);
        let id = snac::parse(&sent.last().expect("the control message").1)
            .expect("a SNAC")
            .request_id;
        assert!(id >= INJECTED_ID_BASE && id < INJECTED_ID_BASE + INJECTED_ID_COUNT);

        let mut in_side = StreamRewriter::with_answers(Direction::Inbound, out_side.answers());
        let mut out2 = Vec::new();
        in_side.push_crypto(&hello(), &mut c, 1, &encrypt(), &mut out2);
        let mut out3 = Vec::new();
        let lines2 = in_side.push_crypto(&host_ack(2, id), &mut c, 1, &encrypt(), &mut out3);
        assert!(
            lines2.iter().any(|l| l.contains("of the add-on's own")),
            "{lines2:?}"
        );
        assert!(out3.is_empty(), "the ack never reaches the client");
    }

    #[test]
    fn with_injection_off_nothing_leaves_the_stream_and_nothing_enters_it() {
        let policy = Policy::from_settings(crate::config::Settings {
            mode: Some("encrypt"),
            directory: Some("https://example.invalid"),
            home: Some(" "),
            no_inject: Some("1"),
            ..Default::default()
        });
        assert!(!policy.may_inject());
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new()
            .receiving(Inbound::Control)
            .with_notes(&["[ICQ E2E] The key of peer has changed."]);
        let wire = in_message(2, "peer", &container::armor(&any_container()), None);
        let lines = r.push_crypto(&wire, &mut c, 1, &policy, &mut out);
        assert!(
            lines.iter().any(|l| l.contains("ICQE2E_NO_INJECT")),
            "{lines:?}"
        );
        // The frame count is the client's own: what went in came out.
        assert_eq!(out.len(), hello().len() + wire.len());
        assert_eq!(frames_of(&out).len(), 2);
    }

    #[test]
    fn every_note_has_a_cookie_of_its_own() {
        // ICQ 7 takes a cookie it has already seen for a duplicate and shows
        // nothing, so two notes must never share one - nor a note and a
        // control message.
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new().with_notes(&["[ICQ E2E] one", "[ICQ E2E] two"]);
        let mut lines = Vec::new();
        assert!(r.put_notes(&mut c, &encrypt(), &mut out, &mut lines));
        let cookies: Vec<Vec<u8>> = frames_of(&out)
            .iter()
            .filter_map(|(_, p)| snac::parse(p))
            .filter(|s| s.sub_group == snac::ICBM_MSG_TO_CLIENT)
            .map(|s| s.body[..8].to_vec())
            .collect();
        assert_eq!(cookies.len(), 2, "{lines:?}");
        assert_ne!(cookies[0], cookies[1]);
        assert_ne!(
            to_host_body("peer", "x")[..8],
            to_host_body("peer", "x")[..8]
        );
    }

    #[test]
    fn a_note_carries_the_user_info_the_server_puts_first() {
        let body = to_client_body("peer", "hello");
        let m = icbm::parse_to_client(&body).expect("a message the client reads");
        assert_eq!(
            (m.peer.as_str(), m.text.as_str()),
            ("peer", "<HTML><BODY>hello</BODY></HTML>")
        );
        let head = 8 + 2 + 1 + 4 + 2;
        assert_eq!(u16::from_be_bytes([body[head], body[head + 1]]), 3);
        let tags: Vec<u16> = snac::read_tlvs(&body[head + 2..])
            .iter()
            .map(|t| t.tag)
            .take(3)
            .collect();
        assert_eq!(tags, vec![0x0001, 0x0003, 0x0006], "class, sign-on, status");
    }

    #[test]
    fn a_note_is_sent_the_way_the_server_sends_a_message() {
        // ICQ 7.2 drops an ICBM whose request id reads as the answer to a
        // request it never made; the server marks its own with the high bit.
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new().with_notes(&["[ICQ E2E] a <b> & \"c\"
next"]);
        let mut lines = Vec::new();
        assert!(r.put_notes(&mut c, &encrypt(), &mut out, &mut lines));
        let got = frames_of(&out);
        let s = snac::parse(&got.last().expect("the note").1).expect("a SNAC");
        assert_eq!(s.request_id, REQ_ID_FROM_SERVER);
        assert_eq!(s.flags, 0);
        let m = icbm::parse_to_client(s.body).expect("a message");
        assert_eq!(m.form, "ch1/html");
        assert_eq!(m.charset, text::CHARSET_UNICODE, "UCS-2, as ICQ 7 writes");
        assert_eq!(
            m.text,
            "<HTML><BODY>[ICQ E2E] a &lt;b&gt; &amp; &quot;c&quot;<BR>next</BODY></HTML>"
        );
        // And its layout is logged once, next to a real message's.
        let layout = lines
            .iter()
            .find(|l| l.starts_with("layout of a note"))
            .expect("the layout is logged");
        assert!(
            layout.contains("req=0x80000000")
                && layout.contains("user-info=[0001/2 0003/4 0006/4]")
                && layout.contains("charset 0002"),
            "{layout}"
        );
        assert!(!layout.contains("next"), "never the text itself");
    }

    #[test]
    fn the_layout_of_a_real_message_is_logged_once() {
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new();
        let lines = r.push_crypto(
            &in_message(2, "peer", "secret words", None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        let layout: Vec<&String> = lines
            .iter()
            .filter(|l| l.starts_with("layout of a server message"))
            .collect();
        assert_eq!(layout.len(), 1, "{lines:?}");
        assert!(layout[0].contains("fragments=[0501[01 01] 0101[charset 0000"));
        assert!(!layout[0].contains("secret"));
        let again = r.push_crypto(
            &in_message(3, "peer", "more", None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        assert!(!again.iter().any(|l| l.starts_with("layout")));
    }

    #[test]
    fn a_note_the_engine_did_not_prefix_still_is_marked() {
        assert_eq!(note_text("[ICQ E2E] done"), "[ICQ E2E] done");
        assert_eq!(note_text("done"), "[ICQ E2E] done");
    }

    #[test]
    fn a_control_message_with_nowhere_to_go_is_not_sent() {
        let mut r = StreamRewriter::new(Direction::Outbound);
        let mut c = Fake::new().with_control(any_container());
        let mut out = Vec::new();
        let mut lines = Vec::new();
        assert!(!r.inject_control("peer", &mut c, &mut out, &mut lines));
        assert!(out.is_empty());
        assert!(
            lines.iter().any(|l| l.contains("nothing on the wire")),
            "{lines:?}"
        );
    }
}
