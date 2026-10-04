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
//! to 5. A stream whose opening is anything else (direct connections, file
//! transfer, a proxy) turns raw at once: bytes held so far are released
//! unchanged, and from then on everything passes straight through.
//!
//! A stream already recognised as FLAP never turns raw (fourth review,
//! finding B): a header that is not FLAP after that is a broken stream, not
//! another protocol. It turns [`State::Broken`]: the bytes from the bad
//! header on are dropped, nothing more passes either way, and the hooks
//! reset the connection ([`StreamRewriter::is_broken`]). Releasing them raw
//! would hand the rest of the connection - messages included - past the
//! rewriter.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::config::Policy;
use crate::container;
use crate::crypto::{Action, Crypto, Note};
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
    /// Was FLAP and lost its framing: nothing passes any more, and the
    /// connection is to be reset.
    Broken,
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
    /// Contacts that signed off since last taken.
    pub departed: Vec<String>,
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
    /// SNACs the add-on owes the far end in the client's name, for the
    /// outbound direction to send: the refusal of a call or a file proposal
    /// it did not let through (sixth audit of 2026-10, finding 3).
    owed_out: Arc<Mutex<Vec<Vec<u8>>>>,
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

    /// Queues `snac`, a SNAC payload to the server, for the outbound
    /// direction to send with the client's next frame. Bounded the same way.
    pub fn owe_out(&self, snac: Vec<u8>) {
        let mut v = self.owed_out.lock().expect("owed frames");
        if v.len() == Self::MAX {
            v.remove(0);
        }
        v.push(snac);
    }

    /// Takes every SNAC owed to the server, oldest first.
    pub fn take_owed_out(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.owed_out.lock().expect("owed frames"))
    }
}

/// How long, in seconds, an inbound frame that must be vouched for waits
/// for the announcement of the contact's add-on (sixth audit of 2026-10,
/// findings 3 and 4). The announcement goes before it on the same
/// connection, so it is normally there already; this only tolerates the
/// two being reordered on the way.
pub const HOLD_SECS: u64 = 3;
/// Frames held at most; the oldest is given up first.
const MAX_HELD: usize = 16;

/// An inbound frame waiting for the announcement that vouches for it.
struct Held {
    frame: Vec<u8>,
    action: Action,
    since: u64,
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
    /// Inbound frames held for the announcement that vouches for them.
    held: Vec<Held>,
    /// Whether held frames are being let through or given up right now, so
    /// a frame let through does not start the same again.
    settling: bool,
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
            held: Vec::new(),
            settling: false,
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

    /// Takes the contacts that signed off since last asked.
    pub fn take_departed(&mut self) -> Vec<String> {
        std::mem::take(&mut self.detected.departed)
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

    /// Whether a stream recognised as FLAP lost its framing: nothing of it
    /// passes any more, and the caller resets the connection.
    pub fn is_broken(&self) -> bool {
        self.state == State::Broken
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
        if self.state == State::Broken {
            return lines;
        }
        let mut buf = std::mem::take(&mut self.buf);
        buf.extend_from_slice(bytes);
        let mut used = 0;
        loop {
            let rest = &buf[used..];
            match self.check_header(rest) {
                Header::NeedMore => break,
                // Opening and not FLAP: another protocol, passed as it is.
                Header::NotFlap if self.state == State::Opening => {
                    self.state = State::Raw;
                    out.extend_from_slice(rest);
                    used = buf.len();
                    break;
                }
                // FLAP before, not FLAP now: the stream is broken. What is
                // left is dropped, never released past the rewriter.
                Header::NotFlap => {
                    self.state = State::Broken;
                    lines.push(format!(
                        "FLAP stream lost its framing ({} bytes after the last frame do not start a frame); the connection is reset",
                        rest.len()
                    ));
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

    /// The end of the stream: what is held is the start of a frame that
    /// never came whole (fifth audit of 2026-10, finding 3). Returns how many
    /// bytes were dropped.
    ///
    /// - `Raw`: nothing is held (every byte passed at once); anything that
    ///   were would go on as it is, since the stream is not FLAP.
    /// - `Opening`: the first bytes of a stream not yet recognised - the
    ///   start of a sign-on, or of another protocol - are dropped. No FLAP
    ///   frame can be in them, and nothing after them is coming.
    /// - `Flap`: a partial frame is dropped, never handed on: it has not been
    ///   through the rewriter, and its header and the start of its payload -
    ///   the start of a message - would reach the other side as they are.
    /// - `Broken`: nothing passes.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> usize {
        if self.state == State::Raw {
            out.append(&mut self.buf);
            return 0;
        }
        let dropped = self.buf.len();
        self.buf.clear();
        dropped
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
            // A keep-alive is time passing too, for the frames held.
            if self.dir == Direction::Inbound && may_add && !self.settling {
                if let Some(c) = ctx.as_deref_mut() {
                    self.settle_held(policy, c, out, lines);
                }
            }
            return;
        }
        let payload = &frame[HEADER_LEN..];
        // The SIP of a call (ICBM channel 6), with `calls_log=on`: its fields
        // are logged, and the frame goes on as it was (stage C0).
        if policy.calls_log {
            if let Some(l) = crate::calls::sip_line(self.dir, payload, crate::calls::server_addrs())
            {
                lines.push(l);
            }
        }
        // The key exchange of a call (`calls_encrypt=on`, callneg.rs): the
        // control messages for the peer go on the wire *before* the SIP
        // message they belong to, which goes on below exactly as it came.
        // The protection gate decides first (fourth review, finding E): a
        // call that must be encrypted and cannot be - the call hooks failed,
        // or there is no state to tell the contact's policy by - has its
        // signalling dropped both ways, so it is never set up.
        if policy.encrypts_calls() && may_add {
            if let (Some((peer, sip)), Some(c)) = (
                crate::calls::sip_message(self.dir, payload),
                ctx.as_deref_mut(),
            ) {
                let g = crate::gate::current();
                let verdict = crate::gate::media(
                    policy,
                    &g.bootstrap(),
                    &g.media(),
                    c.crypto.strictness(&peer),
                );
                if let crate::gate::Verdict::Block(why) = &verdict {
                    self.refuse(frame, &peer, "call", why, c, lines);
                    return;
                }
                // An incoming call in a protected contact's name goes on
                // only once the key offer their add-on sends before the
                // INVITE has come (sixth audit of 2026-10, finding 3).
                // Seventh audit: the offer must bind this INVITE's SDP and be
                // fresh, and once keys are agreed the callee's 200 OK must
                // carry the SDP their key answer bound.
                if self.dir == Direction::Inbound {
                    let action = if let Some((call_id, sdp)) = crate::callneg::invite_binding(sip) {
                        Some(Action::Call {
                            peer: peer.clone(),
                            call_id,
                            sdp,
                        })
                    } else {
                        crate::callneg::answer_binding(sip).map(|(call_id, sdp)| {
                            Action::CallAnswer {
                                peer: peer.clone(),
                                call_id,
                                sdp,
                            }
                        })
                    };
                    if let Some(action) = action {
                        if c.crypto.protected(&peer).is_none() {
                            c.crypto.shown_unencrypted(&peer, "call", c.now);
                        } else if !c.crypto.authenticated(&action, false, c.now) {
                            self.hold(frame, action, c, lines);
                            return;
                        }
                    }
                }
                match verdict {
                    crate::gate::Verdict::Block(_) => {}
                    crate::gate::Verdict::Plain(why) => {
                        if g.once(&format!("call-plain:{peer}"), c.now, 60) {
                            c.crypto.note(
                                &peer,
                                format!(
                                    "{}The call with {peer} is not end-to-end encrypted: {why}.",
                                    crate::policy::PREFIX
                                ),
                            );
                        }
                        lines.push(format!("call with {peer} left as it is: {why}"));
                    }
                    _ => {
                        let containers = c.crypto.call_sip(self.dir, &peer, sip, c.now, lines);
                        if self.dir == Direction::Outbound {
                            for container in containers {
                                self.put_control(&peer, &container, out, lines);
                            }
                        }
                    }
                }
            }
        }
        // A file transfer's rendezvous (ICBM channel 2, `CapFileTransfer`):
        // with `files_log=on` it is logged without name or address, and its
        // facts are kept so the socket hooks can tell its connections; with
        // `files_encrypt=on` the key exchange (filesneg.rs) goes on the wire
        // *before* the ICBM, which goes on below exactly as it came.
        if policy.files_log || policy.encrypts_files() {
            if let Some(rdv) = crate::files::rendezvous(self.dir, payload) {
                if policy.files_log {
                    lines.push(rdv.log_line());
                }
                // The gate first, as for a call: a transfer that must be
                // encrypted and cannot be never reaches the other side; a
                // cancel always passes.
                let mut keys_exchange = true;
                if policy.encrypts_files() && may_add && rdv.kind != crate::files::RDV_CANCEL {
                    if let Some(c) = ctx.as_deref_mut() {
                        let g = crate::gate::current();
                        match crate::gate::file(
                            policy,
                            &g.bootstrap(),
                            c.crypto.strictness(&rdv.peer),
                        ) {
                            crate::gate::Verdict::Block(why) => {
                                let peer = rdv.peer.clone();
                                self.refuse(frame, &peer, "file transfer", &why, c, lines);
                                return;
                            }
                            crate::gate::Verdict::Plain(why) => {
                                keys_exchange = false;
                                c.crypto.note(
                                    &rdv.peer,
                                    crate::policy::file_plain_note(&rdv.peer, &why),
                                );
                            }
                            _ => {}
                        }
                        // A file proposal in a protected contact's name goes
                        // on only once the key offer their add-on sends
                        // before it has come (sixth audit, finding 3).
                        if rdv.dir == Direction::Inbound && rdv.kind == crate::files::RDV_PROPOSE {
                            let action = Action::File {
                                peer: rdv.peer.clone(),
                                cookie: rdv.cookie,
                                digest: rdv.digest,
                            };
                            if c.crypto.protected(&rdv.peer).is_none() {
                                c.crypto
                                    .shown_unencrypted(&rdv.peer, "file transfer", c.now);
                            } else if !c.crypto.authenticated(&action, false, c.now) {
                                self.hold(frame, action, c, lines);
                                return;
                            }
                        }
                    }
                }
                crate::filesneg::lock(&crate::filesneg::shared())
                    .observe(&rdv, crate::filesneg::now_ms());
                if policy.encrypts_files() && may_add && keys_exchange {
                    if let Some(c) = ctx.as_deref_mut() {
                        let containers = c.crypto.file_icbm(&rdv, c.now, lines);
                        if self.dir == Direction::Outbound {
                            for container in containers {
                                self.put_control(&rdv.peer, &container, out, lines);
                            }
                        }
                    }
                }
            }
        }
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
        let mut processed = match ctx.as_mut() {
            Some(c) => {
                rewrite::process_crypto_for(self.dir, payload, c.crypto, c.now, policy.tls.server())
            }
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
        for contact in processed.e2e_departed {
            if self.e2e_contacts.remove(&contact).is_some() {
                lines.push(format!("contact {contact} signed off"));
            }
            self.detected.departed.push(contact);
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
        let controls = std::mem::take(&mut processed.controls);
        if let (Some(action), true) = (processed.hold.take(), may_add) {
            // Held for the contact's announcement, not dropped yet.
            if let Some(c) = ctx.as_deref_mut() {
                self.hold(frame, action, c, lines);
            }
        } else if processed.drop && !may_add {
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
                // A stand-in that does not fit: never the original instead
                // (fifth audit of 2026-10, finding 4).
                Some(_) => {
                    lines.push(
                        "frame dropped: its stand-in would exceed 64 KiB, and the original may not go"
                            .to_string(),
                    );
                    self.removed(seq_of(frame));
                }
                None => {
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
            // A direct-IM proposal kept from the server: the contact's
            // cancel is owed to the client, so it stops waiting.
            for snac in processed.owed {
                self.answers.owe(snac);
            }
            self.removed(seq_of(frame));
        } else {
            // Announcements the contact's add-on is owed before this frame
            // (a tZer's).
            if let (true, Some(to)) = (may_add, peer.as_deref()) {
                for container in &controls {
                    self.put_control(to, container, out, lines);
                }
            }
            match processed.payload {
                Some(p) if p.len() <= u16::MAX as usize => {
                    self.put_frame(&with_payload(frame, &p), Seq::Own, out);
                }
                // On the crypto path a rewrite is what protects the frame -
                // an encrypted message, a decrypted one, a control message's
                // carrier - so the original never goes in its place: the
                // frame is dropped with a note (fifth audit of 2026-10,
                // finding 4). The harness keeps its old behaviour.
                Some(p) if ctx.is_some() => {
                    lines.push(format!(
                        "frame would exceed 64 KiB ({} bytes) after the add-on's rewrite; dropped, the original is not sent in its place",
                        p.len()
                    ));
                    self.removed(seq_of(frame));
                    // As for any container taken out: the server's answer to
                    // it goes too.
                    if let Some(id) = processed.ack_request {
                        self.hide(id, lines);
                    }
                    if let Some(c) = ctx.as_deref_mut() {
                        let who = peer.clone().unwrap_or_else(|| NOTE_SENDER.to_string());
                        let what = match self.dir {
                            Direction::Outbound => format!(
                                "The message to {who} was NOT sent: encrypted, it would not fit in one frame. Nothing was sent unencrypted; send it in shorter parts."
                            ),
                            Direction::Inbound => format!(
                                "A message from {who} was not shown: once decrypted it would not fit in one frame. Nothing undecrypted was shown in its place."
                            ),
                        };
                        c.crypto
                            .note(&who, format!("{}{what}", crate::policy::PREFIX));
                    }
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
                    self.put_owed_out(out, lines);
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
        // Held frames: let through what is vouched for now, give up what
        // waited too long.
        if self.dir == Direction::Inbound && may_add && !self.settling {
            if let Some(c) = ctx.as_deref_mut() {
                self.settle_held(policy, c, out, lines);
            }
        }
    }

    /// Takes an inbound frame out of the stream until the announcement that
    /// vouches for `action` arrives ([`Self::settle_held`]), for at most
    /// [`HOLD_SECS`].
    fn hold(&mut self, frame: &[u8], action: Action, c: &mut Ctx<'_>, lines: &mut Vec<String>) {
        self.removed(seq_of(frame));
        lines.push(format!(
            "{} in {}'s name held for the announcement of their add-on (up to {HOLD_SECS} s)",
            action.what(),
            action.peer()
        ));
        if self.held.len() >= MAX_HELD {
            let old = self.held.remove(0);
            self.give_up(old, c, lines);
        }
        self.held.push(Held {
            frame: frame.to_vec(),
            action,
            since: c.now,
        });
    }

    /// Lets through every held frame that is vouched for now (or whose
    /// contact is no longer protected), in the order they came, and gives up
    /// those that waited [`HOLD_SECS`].
    fn settle_held(
        &mut self,
        policy: &Policy,
        c: &mut Ctx<'_>,
        out: &mut Vec<u8>,
        lines: &mut Vec<String>,
    ) {
        if self.held.is_empty() {
            return;
        }
        self.settling = true;
        for h in std::mem::take(&mut self.held) {
            let open = c.crypto.protected(h.action.peer()).is_none()
                || c.crypto.authenticated(&h.action, false, c.now);
            if open {
                lines.push(format!(
                    "{} in {}'s name: vouched for, let through",
                    h.action.what(),
                    h.action.peer()
                ));
                self.emit(&h.frame, policy, Some(&mut *c), out, lines);
            } else if c.now.saturating_sub(h.since) >= HOLD_SECS {
                self.give_up(h, c, lines);
            } else {
                self.held.push(h);
            }
        }
        self.settling = false;
    }

    /// A held frame that was never vouched for: dropped for good, with the
    /// warning, and the sender's client told no (a call is declined, a
    /// file proposal cancelled) so it does not wait.
    fn give_up(&mut self, h: Held, c: &mut Ctx<'_>, lines: &mut Vec<String>) {
        let peer = h.action.peer().to_string();
        let what = h.action.what();
        let why = c
            .crypto
            .protected(&peer)
            .unwrap_or_else(|| format!("{peer} is protected"));
        lines.push(format!(
            "{what} in {peer}'s name not let through: no announcement from their add-on within {HOLD_SECS} s ({why})"
        ));
        c.crypto.unauthenticated(
            &peer,
            what,
            crate::policy::unauthenticated_action_note(&peer, what, &why),
            c.now,
        );
        // Its id vouches for nothing later (seventh audit of 2026-10).
        c.crypto.refused(&h.action, c.now);
        let refusal = match &h.action {
            Action::Call { .. } => {
                crate::calls::sip_message(Direction::Inbound, &h.frame[HEADER_LEN..])
                    .and_then(|(_, sip)| crate::callneg::decline_to_host(&peer, sip))
            }
            Action::File { cookie, .. } => Some(crate::files::cancel_to_host(&peer, cookie)),
            Action::CallAnswer { .. } | Action::Tzer { .. } => None,
        };
        if let Some(r) = refusal {
            self.answers.owe_out(r);
            lines.push(format!("the {what}'s refusal is owed to {peer}"));
        }
    }

    /// Sends every SNAC the add-on owes the far end ([`Answers::owe_out`])
    /// as a frame of its own, with a request id of the add-on's whose
    /// answer the client never sees.
    fn put_owed_out(&mut self, out: &mut Vec<u8>, lines: &mut Vec<String>) {
        for mut snac in self.answers.take_owed_out() {
            if snac.len() < 10 || self.last_seq.is_none() {
                continue;
            }
            let id = self.next_injected_id();
            snac[6..10].copy_from_slice(&id.to_be_bytes());
            self.hide(id, lines);
            self.put_frame(&flap(FLAP_CHANNEL_SNAC, &snac), Seq::Ours, out);
            lines.push("a refusal owed to the far end sent".to_string());
        }
    }

    /// Drops a call's or a file transfer's frame the protection gate refused
    /// (`gate.rs`), with a note in the chat once a minute per contact. The
    /// frame leaves the stream as a held message does.
    fn refuse(
        &mut self,
        frame: &[u8],
        peer: &str,
        what: &str,
        why: &str,
        c: &mut Ctx<'_>,
        lines: &mut Vec<String>,
    ) {
        self.removed(seq_of(frame));
        lines.push(format!("{what} with {peer} not let through: {why}"));
        if crate::gate::current().once(&format!("{what}:{peer}"), c.now, 60) {
            c.crypto.note(
                peer,
                format!(
                    "{}This {what} with {peer} was not let through: {why}. Nothing of it is sent or shown unencrypted.",
                    crate::policy::PREFIX
                ),
            );
        }
    }

    /// Hands the client every answer the server owes it but will never send
    /// (an ack for a `/e2e` command), as the server would have sent it, and
    /// says whether there was any.
    fn put_owed(&mut self, out: &mut Vec<u8>, lines: &mut Vec<String>) -> bool {
        let owed = self.answers.take_owed();
        for snac in &owed {
            self.put_frame(&flap(FLAP_CHANNEL_SNAC, snac), Seq::Ours, out);
            lines.push("owed answer (an ack for a /e2e command, or a cancel of a direct-IM proposal) given to the client".to_string());
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
        let before = out.len();
        if !self.held.is_empty() {
            let mut c = Ctx {
                crypto: &mut *crypto,
                now: crate::crypto::unix_now(),
                add_frames: true,
            };
            self.settle_held(policy, &mut c, out, lines);
        }
        let mut put = self.put_owed(out, lines) || out.len() > before;
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
        self.put_control(peer, &container, out, lines)
    }

    /// Puts one control container to `peer` on the wire as a frame of the
    /// add-on's own, with no ack request and no offline copy.
    fn put_control(
        &mut self,
        peer: &str,
        container: &[u8],
        out: &mut Vec<u8>,
        lines: &mut Vec<String>,
    ) -> bool {
        // A frame with no FLAP frame before it has no number of its own to
        // take, so there is nowhere to put it.
        if self.last_seq.is_none() {
            lines.push(format!(
                "control message to {peer} not sent: nothing on the wire yet"
            ));
            return false;
        }
        let id = self.next_injected_id();
        let body = to_host_body(peer, &container::armor(container));
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

    /// Fourth review, finding B. Replaces `desync_later_releases_held_bytes`,
    /// which asserted that a stream already recognised as FLAP turned raw on
    /// a bad header and released everything after it - the rest of the
    /// connection, messages included, past the rewriter. Now: the frames
    /// before go on, the bytes from the bad header on never do, nothing
    /// later passes either, and the caller is told to reset the connection.
    #[test]
    fn a_flap_stream_that_loses_its_framing_is_broken_not_raw() {
        for garbage in [
            b"\x2A\x09garbage".to_vec(),
            b"plain text that is not a frame".to_vec(),
        ] {
            for dir in [Direction::Inbound, Direction::Outbound] {
                let mut r = StreamRewriter::new(dir);
                let before = frame(2, 101, b"a frame");
                let s = [hello(), before.clone(), garbage.clone()].concat();
                assert_eq!(run(&mut r, &s), [hello(), before].concat());
                assert!(r.is_broken() && !r.is_raw());
                // Nothing passes afterwards, not even a good frame.
                assert!(run(&mut r, &frame(2, 102, b"later")).is_empty());
                let mut out = Vec::new();
                r.finish(&mut out);
                assert!(out.is_empty(), "nothing is released at the end either");
            }
        }
        // The opening is still free to be another protocol.
        let mut r = StreamRewriter::new(Direction::Inbound);
        assert_eq!(run(&mut r, b"OFT2"), b"OFT2");
        assert!(r.is_raw() && !r.is_broken());
    }

    /// The same on the crypto path, with a container that would otherwise
    /// reach the client undecrypted behind the bad header.
    #[test]
    fn a_broken_stream_hands_no_container_to_the_client() {
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new();
        let container_text = container::armor(&any_container());
        let bad = [
            b"\x2A\x07".to_vec(),
            in_message(3, "100002", &container_text, None),
        ]
        .concat();
        let lines = r.push_crypto(&bad, &mut c, 1, &encrypt(), &mut out);
        assert_eq!(out, hello(), "{lines:?}");
        assert!(r.is_broken());
        assert!(c.seen.is_empty(), "the container never reached the engine");
    }

    /// Fifth audit of 2026-10, finding 3. Replaces
    /// `finish_releases_a_partial_frame`, which asserted that the end of the
    /// stream handed a partial frame on as it was - a frame that never went
    /// through the rewriter, with the start of a message in it. Now: in a
    /// FLAP stream, or one still opening, what is held is dropped; a raw
    /// stream holds nothing and passes everything; a broken one passes
    /// nothing.
    #[test]
    fn finish_hands_on_no_partial_frame() {
        // Still opening: the start of a sign-on.
        let mut r = StreamRewriter::new(Direction::Inbound);
        let partial = &frame(1, 1, &[0, 0, 0, 1, 9, 9])[..8];
        assert!(run(&mut r, partial).is_empty());
        let mut out = Vec::new();
        assert_eq!(r.finish(&mut out), partial.len());
        assert!(out.is_empty(), "the opening's partial frame is dropped");

        // FLAP: a message cut short, in both directions, harness and crypto.
        for dir in [Direction::Inbound, Direction::Outbound] {
            let mut r = StreamRewriter::new(dir);
            let msg = match dir {
                Direction::Outbound => out_message(2, "100002", "secret words"),
                Direction::Inbound => in_message(2, "100002", "secret words", None),
            };
            let cut = msg.len() - 4;
            assert_eq!(
                run(&mut r, &[hello(), msg[..cut].to_vec()].concat()),
                hello()
            );
            let mut out = Vec::new();
            assert_eq!(r.finish(&mut out), cut);
            assert!(out.is_empty(), "{dir:?}: the partial frame never goes on");

            let (mut r, _) = opened(dir);
            let mut out = Vec::new();
            r.push_crypto(&msg[..cut], &mut Fake::new(), 1, &encrypt(), &mut out);
            assert!(out.is_empty());
            assert_eq!(r.finish(&mut out), cut);
            assert!(out.is_empty(), "{dir:?}: nor on the crypto path");
        }

        // Raw: everything passed at once, nothing held, nothing to drop.
        let mut r = StreamRewriter::new(Direction::Inbound);
        assert_eq!(run(&mut r, b"OFT2 data"), b"OFT2 data");
        let mut out = Vec::new();
        assert_eq!(r.finish(&mut out), 0);
        assert!(out.is_empty());
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
        /// What `call_sip` answers, and the SIP it was shown.
        call: Vec<Vec<u8>>,
        sip_seen: Vec<(Direction, String)>,
        /// What `file_icbm` answers, and the rendezvous it was shown.
        file: Vec<Vec<u8>>,
        rdv_seen: Vec<(Direction, String)>,
        /// What `strictness` answers; notes the gate asked for.
        strict: Option<bool>,
        gate_notes: Vec<String>,
        /// What the contacts' add-ons announced (`authenticated`), and the
        /// tZer announcements `tzer_notice` hands out.
        vouched: Vec<Action>,
        notices: Vec<[u8; 16]>,
        /// What `account_key` answers: none, unless a test gives it keys.
        key: Option<[u8; 32]>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                outbound: Vec::new(),
                inbound: Vec::new(),
                notes: Vec::new(),
                control: None,
                seen: Vec::new(),
                call: Vec::new(),
                sip_seen: Vec::new(),
                file: Vec::new(),
                rdv_seen: Vec::new(),
                strict: Some(false),
                gate_notes: Vec::new(),
                vouched: Vec::new(),
                notices: Vec::new(),
                key: None,
            }
        }

        /// An engine with an account key, as one with a session has.
        fn with_keys(mut self) -> Self {
            self.key = Some([7; 32]);
            self
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
            self.key
        }

        fn outbound(&mut self, peer: &str, _: Form, _: &[u8], _: u64) -> Outbound {
            self.seen.push(peer.to_string());
            self.next_out()
        }

        fn inbound(&mut self, peer: &str, _: &Container, _: u64) -> Inbound {
            self.seen.push(peer.to_string());
            let got = self.next_in();
            // A tZer's announcement vouches for it, as in the engine.
            if let Inbound::Control(p) = &got {
                if let Some(n) = crate::tzer::Notice::decode(p) {
                    self.vouched.push(Action::Tzer {
                        peer: peer.to_string(),
                        hash: n.hash,
                    });
                }
            }
            got
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

        /// An automatic contact unless a test says otherwise.
        fn strictness(&self, _peer: &str) -> Option<bool> {
            self.strict
        }

        /// Refused exactly when the contact is not an automatic one, as the
        /// engine does.
        fn plain_inbound(&mut self, peer: &str, _now: u64) -> Option<String> {
            if self.strict == Some(false) {
                return None;
            }
            let n = format!("unencrypted message from {peer} not shown");
            self.gate_notes.push(n.clone());
            Some(n)
        }

        fn protected(&self, peer: &str) -> Option<String> {
            (self.strict != Some(false)).then(|| format!("{peer} is protected"))
        }

        fn unauthenticated(&mut self, _peer: &str, _what: &str, note: String, _now: u64) {
            self.gate_notes.push(note);
        }

        fn authenticated(&mut self, action: &Action, consume: bool, _now: u64) -> bool {
            match self.vouched.iter().position(|a| a == action) {
                Some(i) => {
                    if consume && matches!(action, Action::Tzer { .. }) {
                        self.vouched.remove(i);
                    }
                    true
                }
                None => false,
            }
        }

        fn tzer_notice(&mut self, _peer: &str, hash: [u8; 16], _now: u64) -> Option<Vec<u8>> {
            self.notices.push(hash);
            Some(any_container())
        }

        fn note(&mut self, _peer: &str, text: String) {
            self.gate_notes.push(text);
        }

        fn call_sip(
            &mut self,
            dir: Direction,
            peer: &str,
            _sip: &[u8],
            _now: u64,
            _lines: &mut Vec<String>,
        ) -> Vec<Vec<u8>> {
            self.sip_seen.push((dir, peer.to_string()));
            std::mem::take(&mut self.call)
        }

        fn file_icbm(
            &mut self,
            rdv: &crate::files::Rendezvous,
            _now: u64,
            _lines: &mut Vec<String>,
        ) -> Vec<Vec<u8>> {
            self.rdv_seen.push((rdv.dir, rdv.peer.clone()));
            std::mem::take(&mut self.file)
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
        let mut c = Fake::new().receiving(Inbound::Control(Vec::new()));
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
            .receiving(Inbound::Control(Vec::new()))
            .receiving(Inbound::Control(Vec::new()));
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
            .receiving(Inbound::Control(Vec::new()))
            .receiving(Inbound::Control(Vec::new()))
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
        let mut c = Fake::new().receiving(Inbound::Control(Vec::new()));
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
            .receiving(Inbound::Control(Vec::new()))
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

    /// With `calls_log=on` the SIP of a call is logged and its frame goes on
    /// byte for byte, in both directions; with it off nothing is said.
    #[test]
    fn call_signalling_is_logged_and_passed_through() {
        let sip = b"INVITE sip:100002@h SIP/2.0\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\r\n";
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8];
        body.extend_from_slice(&crate::calls::CHANNEL_SIP.to_be_bytes());
        body.push(6);
        body.extend_from_slice(b"100002");
        snac::put_tlv(&mut body, crate::calls::TLV_SIP, sip);
        let mut payload = Vec::new();
        payload.extend_from_slice(&snac::FOOD_ICBM.to_be_bytes());
        payload.extend_from_slice(&snac::ICBM_MSG_TO_HOST.to_be_bytes());
        payload.extend_from_slice(&[0, 0, 0, 0, 0, 9]);
        payload.extend_from_slice(&body);
        let f = frame(2, 101, &payload);
        for on in [true, false] {
            let mut policy = encrypt();
            policy.calls_log = on;
            let (mut r, _) = opened(Direction::Outbound);
            let mut out = Vec::new();
            let lines = r.push_crypto(&f, &mut Fake::new(), 1, &policy, &mut out);
            assert_eq!(out, f, "the frame goes on unchanged");
            assert_eq!(
                lines
                    .iter()
                    .any(|l| l.starts_with("call SIP OUT peer=100002 INVITE")),
                on,
                "{lines:?}"
            );
        }
    }

    /// A file proposal: with `files_log=on` it is logged without its name;
    /// with `files_encrypt=on` the engine sees it and its control message
    /// goes on the wire before it. The proposal itself always goes on byte
    /// for byte; with both off the engine is never asked.
    #[test]
    fn a_file_proposal_goes_on_unchanged_with_the_key_offer_before_it_only_when_on() {
        let payload = crate::files::tests::proposal(
            Direction::Outbound,
            "100002",
            [5; 8],
            1,
            std::net::Ipv4Addr::new(192, 168, 1, 20),
            5190,
            false,
        );
        let f = frame(2, 101, &payload);
        for (log, enc) in [(false, false), (true, false), (false, true)] {
            let mut policy = encrypt();
            policy.files_log = log;
            policy.files_encrypt = enc;
            let (mut r, _) = opened(Direction::Outbound);
            let mut c = Fake::new();
            c.file = vec![any_container()];
            let mut out = Vec::new();
            let lines = r.push_crypto(&f, &mut c, 1, &policy, &mut out);
            assert_eq!(
                lines
                    .iter()
                    .any(|l| l.starts_with("file rendezvous OUT peer=100002 propose")),
                log,
                "{lines:?}"
            );
            assert!(!lines.iter().any(|l| l.contains("secret")), "{lines:?}");
            if !enc {
                assert_eq!(out, f, "the client's own frame, nothing else");
                assert!(c.rdv_seen.is_empty());
                continue;
            }
            assert_eq!(
                c.rdv_seen,
                vec![(Direction::Outbound, "100002".to_string())]
            );
            let got = frames_of(&out);
            assert_eq!(got.len(), 2, "{lines:?}");
            let s0 = snac::parse(&got[0].1).unwrap();
            let m = icbm::parse_to_host(s0.body).unwrap();
            assert_eq!(m.peer, "100002");
            assert_eq!(container::find_armor(&m.text).unwrap(), any_container());
            assert_eq!(got[1].1, payload, "the proposal untouched");
        }
    }

    /// With `calls_encrypt=on` the engine sees the SIP of a call, and the
    /// control messages it gives go on the wire before the SIP frame, which
    /// goes on byte for byte. Off, the engine is never asked and the stream
    /// is the client's own.
    #[test]
    fn call_key_exchange_goes_before_the_sip_frame_only_when_on() {
        let sip = b"INVITE sip:100002@h SIP/2.0\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\r\n";
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8];
        body.extend_from_slice(&crate::calls::CHANNEL_SIP.to_be_bytes());
        body.push(6);
        body.extend_from_slice(b"100002");
        snac::put_tlv(&mut body, crate::calls::TLV_SIP, sip);
        let payload = snac_frame(snac::FOOD_ICBM, snac::ICBM_MSG_TO_HOST, 9, &body);
        let f = frame(2, 101, &payload);
        for on in [false, true] {
            let mut policy = encrypt();
            policy.calls_encrypt = on;
            let (mut r, _) = opened(Direction::Outbound);
            let mut c = Fake::new();
            c.call = vec![any_container()];
            let mut out = Vec::new();
            let lines = r.push_crypto(&f, &mut c, 1, &policy, &mut out);
            let got = frames_of(&out);
            if !on {
                assert_eq!(out, f, "off: the client's own frame, nothing else");
                assert!(c.sip_seen.is_empty());
                continue;
            }
            assert_eq!(
                c.sip_seen,
                vec![(Direction::Outbound, "100002".to_string())]
            );
            assert_eq!(got.len(), 2, "{lines:?}");
            // First the control message to the peer, as a channel-1 message.
            let s0 = snac::parse(&got[0].1).unwrap();
            let m = icbm::parse_to_host(s0.body).unwrap();
            assert_eq!(m.peer, "100002");
            assert_eq!(
                container::find_armor(&m.text).unwrap(),
                any_container(),
                "the engine's container"
            );
            // Then the SIP frame, its payload untouched.
            assert_eq!(got[1].1, payload);
            assert!(got[0].0 < got[1].0, "numbered in order");
        }
    }

    // ---- direct IM is kept off while encrypting (audit 2026-10, second part, finding 5) ----

    use crate::direct::{self, CAP_DIRECT_ICBM};
    use crate::files::{CAP_FILE_TRANSFER, RDV_CANCEL, RDV_PROPOSE};

    #[test]
    fn an_outbound_direct_im_proposal_never_reaches_the_wire_and_the_client_gets_a_cancel() {
        let (mut out_side, mut in_side) = StreamRewriter::pair();
        let mut c = Fake::new();
        let mut wire = Vec::new();
        out_side.push_crypto(&hello(), &mut c, 1, &encrypt(), &mut wire);
        let cookie = [0x42; 8];
        let p = direct::tests::rdv(
            Direction::Outbound,
            "100002",
            RDV_PROPOSE,
            cookie,
            CAP_DIRECT_ICBM,
        );
        let lines = out_side.push_crypto(
            &frame(FLAP_CHANNEL_SNAC, 2, &p),
            &mut c,
            1,
            &encrypt(),
            &mut wire,
        );
        assert_eq!(wire, hello(), "nothing but the sign-on left: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("direct IM")), "{lines:?}");

        // The client is handed the contact's cancel (and the ack it asked
        // for) with the next frame from the server.
        let mut to_client = Vec::new();
        in_side.push_crypto(&hello(), &mut c, 1, &encrypt(), &mut to_client);
        in_side.push_crypto(
            &in_message(2, "100002", "hi", None),
            &mut c,
            1,
            &encrypt(),
            &mut to_client,
        );
        let cancels: Vec<_> = frames_of(&to_client)
            .iter()
            .filter_map(|(_, p)| direct::rendezvous(Direction::Inbound, p))
            .collect();
        assert_eq!(cancels.len(), 1, "one cancel for the client");
        assert_eq!(
            (cancels[0].peer.as_str(), cancels[0].kind, cancels[0].cookie),
            ("100002", RDV_CANCEL, cookie)
        );
        assert!(frames_of(&to_client)
            .iter()
            .filter_map(|(_, p)| snac::parse(p))
            .any(|s| s.sub_group == ICBM_HOST_ACK));
    }

    #[test]
    fn an_inbound_direct_im_proposal_is_not_handed_to_the_client() {
        let (mut r, mut out) = opened(Direction::Inbound);
        let mut c = Fake::new();
        for kind in [RDV_PROPOSE, crate::files::RDV_ACCEPT] {
            let p = direct::tests::rdv(Direction::Inbound, "100002", kind, [7; 8], CAP_DIRECT_ICBM);
            r.push_crypto(
                &frame(FLAP_CHANNEL_SNAC, 2, &p),
                &mut c,
                1,
                &encrypt(),
                &mut out,
            );
        }
        assert_eq!(out, hello(), "neither the proposal nor the acceptance");
    }

    #[test]
    fn with_injection_off_a_direct_im_proposal_goes_on_only_as_a_cancel() {
        let policy = Policy::from_settings(crate::config::Settings {
            mode: Some("encrypt"),
            directory: Some("https://example.invalid"),
            home: Some(" "),
            no_inject: Some("1"),
            ..Default::default()
        });
        for dir in [Direction::Outbound, Direction::Inbound] {
            let mut r = StreamRewriter::new(dir);
            let mut out = Vec::new();
            r.push_crypto(&hello(), &mut Fake::new(), 1, &policy, &mut out);
            let p = direct::tests::rdv(dir, "100002", RDV_PROPOSE, [7; 8], CAP_DIRECT_ICBM);
            r.push_crypto(
                &frame(FLAP_CHANNEL_SNAC, 2, &p),
                &mut Fake::new(),
                1,
                &policy,
                &mut out,
            );
            let got = frames_of(&out);
            assert_eq!(got.len(), 2, "the frame count is the client's");
            assert_eq!(direct::rendezvous(dir, &got[1].1).unwrap().kind, RDV_CANCEL);
        }
    }

    #[test]
    fn file_transfer_and_call_frames_pass_untouched_while_direct_im_is_refused() {
        for dir in [Direction::Outbound, Direction::Inbound] {
            let mut r = StreamRewriter::new(dir);
            let mut out = Vec::new();
            r.push_crypto(&hello(), &mut Fake::new(), 1, &encrypt(), &mut out);
            let file = frame(
                FLAP_CHANNEL_SNAC,
                2,
                &direct::tests::rdv(dir, "100002", RDV_PROPOSE, [9; 8], CAP_FILE_TRANSFER),
            );
            // An ICBM on channel 6 (a call's SIP), whatever it carries.
            let mut body = vec![3; 8];
            body.extend_from_slice(&6u16.to_be_bytes());
            body.push(6);
            body.extend_from_slice(b"100002");
            if dir == Direction::Inbound {
                body.extend_from_slice(&[0, 0, 0, 0]);
            }
            snac::put_tlv(
                &mut body,
                icbm::TLV_RENDEZVOUS_DATA,
                b"INVITE sip:x SIP/2.0\r\n\r\n",
            );
            let sub = match dir {
                Direction::Outbound => snac::ICBM_MSG_TO_HOST,
                Direction::Inbound => snac::ICBM_MSG_TO_CLIENT,
            };
            let call = frame(
                FLAP_CHANNEL_SNAC,
                3,
                &snac_frame(snac::FOOD_ICBM, sub, 5, &body),
            );
            let mut c = Fake::new();
            r.push_crypto(&file, &mut c, 1, &encrypt(), &mut out);
            r.push_crypto(&call, &mut c, 1, &encrypt(), &mut out);
            assert_eq!(out, [hello(), file, call].concat(), "{dir:?}");
        }
    }

    /// A `LocateSetInfo` frame whose capability list holds direct IM.
    fn set_info_with_direct_im() -> Vec<u8> {
        let mut body = Vec::new();
        snac::put_tlv(&mut body, 0x0005, &[[0x11; 16], CAP_DIRECT_ICBM].concat());
        frame(
            FLAP_CHANNEL_SNAC,
            2,
            &snac_frame(snac::FOOD_LOCATE, snac::LOCATE_SET_INFO, 1, &body),
        )
    }

    fn names_direct_im(bytes: &[u8]) -> bool {
        bytes.windows(16).any(|w| w == CAP_DIRECT_ICBM)
    }

    fn names_e2e(bytes: &[u8]) -> bool {
        bytes.windows(16).any(|w| w == crate::caps::CAP_E2E)
    }

    /// The owner's live test of 2026-10-04: with a session open, a SetInfo
    /// carried the account key but never the add-on's capability, so every
    /// contact's add-on took this client for one without encryption. Both
    /// paths announce it now, while encrypting; e2e=off does not.
    #[test]
    fn the_e2e_capability_is_announced_with_a_session_and_without_one() {
        let (mut r, mut out) = opened(Direction::Outbound);
        r.push_crypto(
            &set_info_with_direct_im(),
            &mut Fake::new().with_keys(),
            1,
            &encrypt(),
            &mut out,
        );
        assert!(names_e2e(&out), "with a session");
        assert!(!names_direct_im(&out));

        let mut r = StreamRewriter::new(Direction::Outbound);
        let mut out = Vec::new();
        r.push(
            &[hello(), set_info_with_direct_im()].concat(),
            &encrypt(),
            &mut out,
        );
        assert!(names_e2e(&out), "without one");

        let mut r = StreamRewriter::new(Direction::Outbound);
        let mut out = Vec::new();
        r.push_crypto(
            &[hello(), set_info_with_direct_im()].concat(),
            &mut crate::crypto::Disabled::default(),
            1,
            &encrypt(),
            &mut out,
        );
        assert!(!names_e2e(&out), "e2e=off");

        // Held (no keys: another account signed on, a state file that
        // cannot be used): it could not read what a contact encrypts for it.
        let mut r = StreamRewriter::new(Direction::Outbound);
        let mut out = Vec::new();
        r.push_crypto(
            &[hello(), set_info_with_direct_im()].concat(),
            &mut crate::gate::Withheld::new("held".into()),
            1,
            &encrypt(),
            &mut out,
        );
        assert!(!names_e2e(&out), "held");
    }

    #[test]
    fn the_direct_im_capability_is_not_announced_while_encrypting_and_is_otherwise() {
        // Encrypting, with a session and without one.
        let (mut r, mut out) = opened(Direction::Outbound);
        r.push_crypto(
            &set_info_with_direct_im(),
            &mut Fake::new(),
            1,
            &encrypt(),
            &mut out,
        );
        assert!(!names_direct_im(&out));
        let mut r = StreamRewriter::new(Direction::Outbound);
        let mut out = Vec::new();
        r.push(
            &[hello(), set_info_with_direct_im()].concat(),
            &encrypt(),
            &mut out,
        );
        assert!(!names_direct_im(&out));
        // Observe, the harness and e2e=off leave it.
        for policy in [Policy::observe(), Policy::harness()] {
            let mut r = StreamRewriter::new(Direction::Outbound);
            let mut out = Vec::new();
            r.push(
                &[hello(), set_info_with_direct_im()].concat(),
                &policy,
                &mut out,
            );
            assert!(names_direct_im(&out));
        }
        let mut r = StreamRewriter::new(Direction::Outbound);
        let mut out = Vec::new();
        r.push_crypto(
            &[hello(), set_info_with_direct_im()].concat(),
            &mut crate::crypto::Disabled::default(),
            1,
            &encrypt(),
            &mut out,
        );
        assert!(names_direct_im(&out), "e2e=off");
    }

    #[test]
    fn direct_connection_addresses_are_zeroed_both_ways_while_encrypting() {
        let mut dc = vec![192, 168, 1, 20, 0, 0, 0x14, 0x46, 4, 0, 9];
        dc.extend_from_slice(&[0; 26]);
        let mut fields = Vec::new();
        snac::put_tlv(&mut fields, direct::TLV_DC_INFO, &dc);
        let own = frame(
            FLAP_CHANNEL_SNAC,
            2,
            &snac_frame(
                snac::FOOD_OSERVICE,
                direct::OSERVICE_SET_USER_INFO_FIELDS,
                1,
                &fields,
            ),
        );
        let mut info = vec![6];
        info.extend_from_slice(b"100002");
        info.extend_from_slice(&[0, 0, 0, 1]);
        snac::put_tlv(&mut info, direct::TLV_DC_INFO, &dc);
        let arrived = frame(
            FLAP_CHANNEL_SNAC,
            2,
            &snac_frame(snac::FOOD_BUDDY, snac::BUDDY_ARRIVED, 0, &info),
        );
        let addr = [192u8, 168, 1, 20];
        for (dir, f) in [(Direction::Outbound, &own), (Direction::Inbound, &arrived)] {
            let (mut r, mut out) = opened(dir);
            r.push_crypto(f, &mut Fake::new(), 1, &encrypt(), &mut out);
            assert_eq!(out.len(), hello().len() + f.len(), "same length");
            assert!(!out.windows(4).any(|w| w == addr), "{dir:?}");
            let mut r = StreamRewriter::new(dir);
            let mut out = Vec::new();
            r.push(&[hello(), f.clone()].concat(), &Policy::observe(), &mut out);
            assert!(out.windows(4).any(|w| w == addr), "observe leaves it");
        }
    }

    /// Third audit of 2026-10, finding 4: every SNAC that hands the client a
    /// peer's address - a Locate user info reply, a message's sender, chat
    /// users, the ICQ random chat partner and the rest - reaches it without
    /// one while encrypting, at the same length; observe mode leaves them.
    #[test]
    fn peer_addresses_are_zeroed_in_every_user_info_carrier_while_encrypting() {
        let addr = [192u8, 168, 1, 20];
        let has_addr = |b: &[u8]| {
            b.windows(4).any(|w| w == addr) || b.windows(12).any(|w| w == b"192.168.1.20")
        };
        for (what, payload) in direct::tests::address_carriers(true) {
            if what == "own user info" {
                // The user's own external address stays.
                continue;
            }
            let f = frame(FLAP_CHANNEL_SNAC, 2, &payload);
            let (mut r, mut out) = opened(Direction::Inbound);
            r.push_crypto(&f, &mut Fake::new(), 1, &encrypt(), &mut out);
            assert_eq!(out.len(), hello().len() + f.len(), "{what}: same length");
            assert!(!has_addr(&out), "{what}");
            let mut r = StreamRewriter::new(Direction::Inbound);
            let mut out = Vec::new();
            r.push(&[hello(), f.clone()].concat(), &Policy::observe(), &mut out);
            assert!(has_addr(&out), "{what}: observe leaves it");
        }
    }

    // ---- the protection gate (fourth review, findings A and E) ----

    /// A gate for this thread with the call hooks in `media`.
    fn gate_with_media(media: crate::gate::MediaHooks) {
        let g: &'static crate::gate::Gate = Box::leak(Box::new(crate::gate::Gate::ready(
            crate::gate::HookMask::ALL,
        )));
        g.set_media(1, media);
        crate::gate::use_for_this_thread(Some(g));
    }

    fn sip_frame(dir: Direction, seq: u16) -> Vec<u8> {
        let sip = b"INVITE sip:100002@h SIP/2.0\r\nCall-ID: g\r\nCSeq: 1 INVITE\r\n\r\n";
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8];
        body.extend_from_slice(&crate::calls::CHANNEL_SIP.to_be_bytes());
        body.push(6);
        body.extend_from_slice(b"100002");
        if dir == Direction::Inbound {
            body.extend_from_slice(&[0, 0, 0, 0]);
        }
        snac::put_tlv(&mut body, crate::calls::TLV_SIP, sip);
        let sub = match dir {
            Direction::Outbound => snac::ICBM_MSG_TO_HOST,
            Direction::Inbound => snac::ICBM_MSG_TO_CLIENT,
        };
        frame(2, seq, &snac_frame(snac::FOOD_ICBM, sub, 9, &body))
    }

    /// With calls encrypted, a call the gate refuses never reaches the other
    /// side, either way: the call hooks failed and the contact requires
    /// encryption (or `required`), or there is no state to tell the
    /// contact's policy by. A contact who does not require it gets the call
    /// as it is, with a note, and no key exchange claims it encrypted.
    #[test]
    fn a_call_the_gate_refuses_is_never_set_up() {
        let failed = crate::gate::MediaHooks::Failed("not patched".into());
        for dir in [Direction::Outbound, Direction::Inbound] {
            if calls_sip_is_known(dir) {
                for (media, strict, required, passes) in [
                    (failed.clone(), Some(true), false, false),
                    (failed.clone(), Some(false), true, false),
                    (failed.clone(), Some(false), false, true),
                    (crate::gate::MediaHooks::Ready, None, false, false),
                    (crate::gate::MediaHooks::NotLoaded, None, false, false),
                ] {
                    gate_with_media(media.clone());
                    let mut policy = encrypt();
                    policy.calls_encrypt = true;
                    policy.calls_required = required;
                    let (mut r, _) = opened(dir);
                    let mut c = Fake::new();
                    c.strict = strict;
                    c.call = vec![any_container()];
                    let mut out = Vec::new();
                    let f = sip_frame(dir, 2);
                    let lines = r.push_crypto(&f, &mut c, 1, &policy, &mut out);
                    let case = format!(
                        "{dir:?} {media:?} strict={strict:?} required={required}: {lines:?}"
                    );
                    assert!(c.sip_seen.is_empty(), "no key exchange: {case}");
                    if passes {
                        assert_eq!(out, f, "{case}");
                        assert!(
                            c.gate_notes
                                .iter()
                                .any(|n| n.contains("not end-to-end encrypted")),
                            "{case}"
                        );
                    } else {
                        assert!(out.is_empty(), "nothing of the call: {case}");
                        assert!(
                            c.gate_notes.iter().any(|n| n.contains("not let through")),
                            "{case}"
                        );
                    }
                }
            }
        }
        crate::gate::use_for_this_thread(None);
    }

    /// The SIP of a call is recognised in both directions by this build.
    fn calls_sip_is_known(dir: Direction) -> bool {
        crate::calls::sip_message(dir, &frames_of(&sip_frame(dir, 2))[0].1).is_some()
    }

    /// With files encrypted and no state to tell the contact's policy by, a
    /// proposal never reaches the other side; a cancel does.
    #[test]
    fn a_file_proposal_without_keys_is_not_let_through_and_a_cancel_is() {
        let mut policy = encrypt();
        policy.files_encrypt = true;
        for dir in [Direction::Outbound, Direction::Inbound] {
            for (kind, passes) in [(RDV_PROPOSE, false), (RDV_CANCEL, true)] {
                // A fresh gate: its note is said once a minute per contact.
                gate_with_media(crate::gate::MediaHooks::NotLoaded);
                let (mut r, _) = opened(dir);
                let mut c = Fake::new();
                c.strict = None;
                let f = frame(
                    FLAP_CHANNEL_SNAC,
                    2,
                    &direct::tests::rdv(dir, "100002", kind, [9; 8], CAP_FILE_TRANSFER),
                );
                let mut out = Vec::new();
                let lines = r.push_crypto(&f, &mut c, 1, &policy, &mut out);
                if passes {
                    assert_eq!(out, f, "{dir:?}: {lines:?}");
                } else {
                    assert!(c.rdv_seen.is_empty(), "no key exchange: {lines:?}");
                    assert!(out.is_empty(), "{dir:?}: {lines:?}");
                    assert!(c.gate_notes.iter().any(|n| n.contains("not let through")));
                }
            }
        }
        crate::gate::use_for_this_thread(None);
    }

    /// The engine that stands in without keys, through the stream: the
    /// message is held with a note, a container is not shown.
    #[test]
    fn without_keys_a_message_is_held_and_a_container_not_shown() {
        let mut w = crate::gate::Withheld::new("the state file cannot be read".into());
        let (mut out_side, mut in_side) = StreamRewriter::pair();
        let mut wire = Vec::new();
        out_side.push_crypto(&hello(), &mut w, 1, &encrypt(), &mut wire);
        let mut secret = to_host_body("100002", "a secret only for 100002");
        secret.truncate(secret.len());
        let msg = frame(
            FLAP_CHANNEL_SNAC,
            2,
            &snac_frame(snac::FOOD_ICBM, snac::ICBM_MSG_TO_HOST, 7, &secret),
        );
        out_side.push_crypto(&msg, &mut w, 1, &encrypt(), &mut wire);
        assert_eq!(wire, hello(), "nothing of the message reached the wire");
        let mut to_client = Vec::new();
        in_side.push_crypto(&hello(), &mut w, 1, &encrypt(), &mut to_client);
        let container_text = container::armor(&any_container());
        in_side.push_crypto(
            &in_message(2, "100002", &container_text, None),
            &mut w,
            1,
            &encrypt(),
            &mut to_client,
        );
        let shown = texts_of(&frames_of(&to_client));
        assert!(
            !shown.iter().any(|t| t.contains(&container_text)),
            "{shown:?}"
        );
        assert!(shown.iter().any(|t| t.contains("NOT sent")), "{shown:?}");
        assert!(
            shown.iter().any(|t| t.contains("could not be read")),
            "{shown:?}"
        );
    }

    // ---- fifth audit of 2026-10 ----

    /// A channel-4 message as the server relays it.
    fn in_ch4(seq: u16, sender: &str, msg_type: u8, text: &[u8]) -> Vec<u8> {
        use crate::test_frames as tf;
        let mut d = 100002u32.to_le_bytes().to_vec();
        d.push(msg_type);
        d.push(0);
        let mut t = text.to_vec();
        t.push(0);
        d.extend_from_slice(&(t.len() as u16).to_le_bytes());
        d.extend_from_slice(&t);
        let tlvs = tf::tlv(icbm::TLV_ICQ_DATA, &d);
        tf::data(
            seq,
            &tf::snac(0x0004, 0x0007, &tf::to_client_body(sender, 4, &tlvs)),
        )
    }

    /// Every way the server can hand the client a contact's words without a
    /// container, and two that carry no words.
    fn unencrypted_frames(
        text: &[u8],
    ) -> (Vec<(&'static str, Vec<u8>)>, Vec<(&'static str, Vec<u8>)>) {
        use crate::test_frames as tf;
        let with_type2 = |t: u8| {
            let mut svc = tf::type2_svc(text);
            svc[45] = t;
            let tlvs = tf::tlv(0x0005, &tf::ch2_fragment(tf::CAP_SERVER_RELAY, &svc));
            tf::data(
                2,
                &tf::snac(0x0004, 0x0007, &tf::to_client_body("100002", 2, &tlvs)),
            )
        };
        let offline = |t: u8| {
            let mut f = tf::offline_reply(2, 100002, text);
            f[40] = t;
            f
        };
        let shown = vec![
            (
                "ch1",
                in_message(2, "100002", std::str::from_utf8(text).unwrap(), Some(5)),
            ),
            ("ch2 plain", tf::in_ch2(2, "100002", text)),
            ("ch2 url", with_type2(icbm::MSG_TYPE_URL)),
            ("ch4 plain", in_ch4(2, "100002", icbm::MSG_TYPE_PLAIN, text)),
            ("ch4 url", in_ch4(2, "100002", icbm::MSG_TYPE_URL, text)),
            ("offline plain", tf::offline_reply(2, 100002, text)),
            ("offline url", offline(icbm::MSG_TYPE_URL)),
        ];
        let not_words = vec![
            ("ch2 plugin", with_type2(0x1A)),
            ("ch4 authorization request", in_ch4(2, "100002", 0x06, text)),
        ];
        (shown, not_words)
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Fifth audit of 2026-10, finding 1, on every inbound text path: an
    /// unencrypted message in a protected contact's name never reaches the
    /// client - live on channels 1, 2 and 4, or offline - and the chat is
    /// told; for an automatic contact it passes as it came; what carries no
    /// words (a plugin message, an authorization request) passes either way.
    /// With `ICQE2E_NO_INJECT` the frame stays with the add-on's words in
    /// place of the text.
    #[test]
    fn an_unencrypted_message_in_a_protected_contacts_name_is_shown_on_no_path() {
        let forged = b"FORGED by the server";
        let (shown, not_words) = unencrypted_frames(forged);
        for (what, f) in &shown {
            for strict in [Some(true), None] {
                let (mut r, _) = opened(Direction::Inbound);
                let mut c = Fake::new();
                c.strict = strict;
                let mut out = Vec::new();
                let lines = r.push_crypto(f, &mut c, 1, &encrypt(), &mut out);
                assert!(!contains(&out, forged), "{what} {strict:?}: {lines:?}");
                assert!(
                    c.gate_notes.iter().any(|n| n.contains("not shown")),
                    "{what}: {lines:?}"
                );
                // NO_INJECT: same frame count, the text is the add-on's.
                let mut no_inject = encrypt();
                no_inject.inject = false;
                let (mut r, _) = opened(Direction::Inbound);
                let mut out = Vec::new();
                let lines = r.push_crypto(f, &mut c, 1, &no_inject, &mut out);
                assert!(!contains(&out, forged), "{what} no-inject: {lines:?}");
                assert!(
                    contains(&out, b"was not shown"),
                    "{what} no-inject: {lines:?}"
                );
            }
            let (mut r, _) = opened(Direction::Inbound);
            let mut out = Vec::new();
            r.push_crypto(f, &mut Fake::new(), 1, &encrypt(), &mut out);
            assert_eq!(&out, f, "{what}: an automatic contact's passes as it came");
        }
        for (what, f) in &not_words {
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new();
            c.strict = Some(true);
            let mut out = Vec::new();
            r.push_crypto(f, &mut c, 1, &encrypt(), &mut out);
            if what.contains("authorization") {
                // Sixth audit, finding 2: the event stays, its text is not
                // the contact's.
                assert!(!contains(&out, forged), "{what}");
                assert!(
                    contains(&out, b"Authorization request attributed to 100002"),
                    "{what}"
                );
            } else {
                assert_eq!(&out, f, "{what}: no words, passes");
            }
        }
    }

    /// The same through the engine that stands in without keys: the
    /// contact's policy cannot be told, so it counts as protected.
    #[test]
    fn without_keys_an_unencrypted_message_is_not_shown_either() {
        let mut w = crate::gate::Withheld::new("the state file cannot be read".into());
        let (mut r, _) = opened(Direction::Inbound);
        let mut out = Vec::new();
        r.push_crypto(
            &in_message(2, "100002", "FORGED", None),
            &mut w,
            1,
            &encrypt(),
            &mut out,
        );
        assert!(!contains(&out, b"FORGED"));
        let shown = texts_of(&frames_of(&out));
        assert!(
            shown
                .iter()
                .any(|t| t.contains("was not shown") && t.contains("state file")),
            "{shown:?}"
        );
    }

    /// The tZer the server writes for ICQ 7.2 out of a 6.5 one is shown from
    /// a protected (verified) contact when their add-on announced it (sixth
    /// audit, finding 4); the same with text appended, with a foreign URL,
    /// or with no server configured is not a tZer of this server's, and
    /// dropped even announced.
    #[test]
    fn the_servers_tzer_form_is_shown_from_a_protected_contact_and_nothing_like_it() {
        use crate::test_frames as tf;
        let frame = |doc: &str| {
            let tlvs = tf::tlv(0x0002, &crate::tzer::tests::fragments(doc));
            tf::data(
                2,
                &tf::snac(0x0004, 0x0007, &tf::to_client_body("100002", 1, &tlvs)),
            )
        };
        let mut policy = encrypt();
        policy.tls = crate::config::TlsPolicy::On {
            server: "icq.example.org".into(),
            pins: Vec::new(),
        };
        let doc = crate::tzer::tests::DOC;
        let run_with = |f: &[u8], policy: &Policy| {
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new();
            c.strict = Some(true);
            for d in [doc.to_string(), format!("{doc}FORGED text")] {
                c.vouched.push(Action::Tzer {
                    peer: "100002".into(),
                    hash: crate::tzer::doc_hash(&d),
                });
            }
            let mut out = Vec::new();
            r.push_crypto(f, &mut c, 1, policy, &mut out);
            (out, c.gate_notes)
        };
        let f = frame(doc);
        let (out, notes) = run_with(&f, &policy);
        assert_eq!(out, f, "the tZer reaches the client as the server sent it");
        assert!(notes.is_empty(), "{notes:?}");
        for bad in [
            format!("{doc}FORGED text"),
            doc.replace("icq.example.org:8102", "evil.example.com"),
        ] {
            let (out, notes) = run_with(&frame(&bad), &policy);
            assert!(out.is_empty(), "{bad:?}");
            assert!(notes.iter().any(|n| n.contains("not shown")), "{bad:?}");
        }
        let (out, notes) = run_with(&f, &encrypt());
        assert!(out.is_empty(), "no server configured: not recognised");
        assert!(notes.iter().any(|n| n.contains("not shown")), "{notes:?}");
    }

    /// Fifth audit of 2026-10, finding 2: a message from the network - in
    /// clear or decrypted - that starts like a note of the add-on's is shown
    /// with "(from <contact>)" in front, so only the add-on's own notes
    /// start with the marker.
    #[test]
    fn text_from_the_network_cannot_pass_for_a_note() {
        let fake = "<HTML><BODY>[ICQ E2E] Encryption is on in this chat</BODY></HTML>";
        // In clear, from an automatic contact, on every path.
        let (shown, _) = unencrypted_frames(b"[icq e2e] Your safety number changed");
        for (what, f) in shown {
            let (mut r, _) = opened(Direction::Inbound);
            let mut out = Vec::new();
            let lines = r.push_crypto(&f, &mut Fake::new(), 1, &encrypt(), &mut out);
            assert!(
                contains(&out, b"(from 100002) [icq e2e] Your safety"),
                "{what}: {lines:?}"
            );
            assert_eq!(out.len(), f.len() + "(from 100002) ".len(), "{what}");
        }
        // Decrypted.
        let (mut r, _) = opened(Direction::Inbound);
        let mut c = Fake::new().receiving(Inbound::Text {
            text: fake.as_bytes().to_vec(),
            form: Form::Fragment {
                charset: 0,
                language: 0,
            },
            peer: "100002".into(),
            unverified: false,
        });
        c = c.with_notes(&["[ICQ E2E] A real note."]);
        let mut out = Vec::new();
        let armored = container::armor(&any_container());
        r.push_crypto(
            &in_message(2, "100002", &armored, None),
            &mut c,
            1,
            &encrypt(),
            &mut out,
        );
        let texts = texts_of(&frames_of(&out));
        assert!(
            texts.iter().any(|t| {
                t
                == "<HTML><BODY>(from 100002) [ICQ E2E] Encryption is on in this chat</BODY></HTML>"
            }),
            "{texts:?}"
        );
        // The add-on's own note still starts with the marker.
        assert!(
            texts
                .iter()
                .any(|t| crate::policy::looks_like_note(t) && t.contains("A real note")),
            "{texts:?}"
        );
        // Ordinary text is untouched.
        let f = in_message(2, "100002", "hello [ICQ E2E]", None);
        let (mut r, _) = opened(Direction::Inbound);
        let mut out = Vec::new();
        r.push_crypto(&f, &mut Fake::new(), 1, &encrypt(), &mut out);
        assert_eq!(out, f);
    }

    /// Fifth audit of 2026-10, finding 4: a rewrite on the crypto path that
    /// would not fit in a frame used to send the original frame instead -
    /// the plaintext of an outbound message, or the container of an inbound
    /// one. Reached here with a frame padded by a large TLV around a short
    /// text: the client's own messages never come near it (the container is
    /// at most `MAX_TEXT` bytes, and a decrypted text is shorter than its
    /// container).
    #[test]
    fn a_rewrite_too_large_for_a_frame_never_sends_the_original() {
        use crate::test_frames as tf;
        let pad = vec![0x55u8; 60_000];
        // Outbound: a short secret, padded, encrypted into 7000 bytes.
        let mut tlvs = tf::tlv(0x0002, &tf::ch1_fragments(0, b"the secret"));
        tlvs.extend(tf::tlv(0x7777, &pad));
        let f = tf::data(
            2,
            &tf::snac(0x0004, 0x0006, &tf::to_host_body("100002", 1, &tlvs)),
        );
        assert!(f.len() < 65_536);
        let (mut r, _) = opened(Direction::Outbound);
        let mut c = Fake::new().sending(Outbound::Encrypted("x".repeat(7000)));
        let mut out = Vec::new();
        let lines = r.push_crypto(&f, &mut c, 1, &encrypt(), &mut out);
        assert!(!contains(&out, b"the secret"), "{lines:?}");
        assert!(out.is_empty(), "nothing of it goes: {lines:?}");
        assert!(
            c.gate_notes.iter().any(|n| n.contains("NOT sent")),
            "{lines:?}"
        );
        // Inbound: a container, padded, decrypted into more than it was.
        let armored = container::armor(&any_container());
        let mut tlvs = tf::tlv(0x0002, &tf::ch1_fragments(0, armored.as_bytes()));
        tlvs.extend(tf::tlv(0x7777, &pad));
        let f = tf::data(
            2,
            &tf::snac(0x0004, 0x0007, &tf::to_client_body("100002", 1, &tlvs)),
        );
        let (mut r, _) = opened(Direction::Inbound);
        let mut c = Fake::new().receiving(Inbound::Text {
            text: vec![b'a'; 6000],
            form: Form::Fragment {
                charset: 0,
                language: 0,
            },
            peer: "100002".into(),
            unverified: false,
        });
        let mut out = Vec::new();
        let lines = r.push_crypto(&f, &mut c, 1, &encrypt(), &mut out);
        assert!(!contains(&out, armored.as_bytes()), "{lines:?}");
        assert!(!contains(&out, &pad[..64]), "{lines:?}");
        assert!(
            c.gate_notes.iter().any(|n| n.contains("not shown")),
            "{lines:?}"
        );
    }

    /// Fifth audit of 2026-10, finding 5: while a call module is not loaded
    /// and patched, a call that must be encrypted is not set up - one
    /// patched module no longer counts for both - and once every module the
    /// client has is patched (the other absent), it goes to the key
    /// exchange.
    #[test]
    fn a_strict_call_waits_for_every_call_module_to_be_patched() {
        use crate::gate::MediaHooks;
        for dir in [Direction::Outbound, Direction::Inbound] {
            if !calls_sip_is_known(dir) {
                continue;
            }
            for (media, strict, keyed) in [
                (
                    [MediaHooks::Ready, MediaHooks::NotLoaded],
                    Some(true),
                    false,
                ),
                (
                    [MediaHooks::NotLoaded, MediaHooks::NotLoaded],
                    Some(true),
                    false,
                ),
                (
                    [MediaHooks::NotLoaded, MediaHooks::Ready],
                    Some(false),
                    false,
                ),
                ([MediaHooks::Ready, MediaHooks::Absent], Some(true), true),
                ([MediaHooks::Ready, MediaHooks::Ready], Some(true), true),
            ] {
                let g: &'static crate::gate::Gate = Box::leak(Box::new(crate::gate::Gate::ready(
                    crate::gate::HookMask::ALL,
                )));
                g.set_media(0, media[0].clone());
                g.set_media(1, media[1].clone());
                crate::gate::use_for_this_thread(Some(g));
                let mut policy = encrypt();
                policy.calls_encrypt = true;
                let (mut r, _) = opened(dir);
                let mut c = Fake::new();
                c.strict = strict;
                // The caller's add-on offered keys first (sixth audit,
                // finding 3): this test is about the call modules.
                c.vouched.push(Action::Call {
                    peer: "100002".into(),
                    call_id: "g".into(),
                    sdp: crate::callneg::sdp_hash(None),
                });
                let mut out = Vec::new();
                let f = sip_frame(dir, 2);
                let lines = r.push_crypto(&f, &mut c, 1, &policy, &mut out);
                let case = format!("{dir:?} {media:?} {strict:?}: {lines:?}");
                assert_eq!(!c.sip_seen.is_empty(), keyed, "{case}");
                if strict == Some(true) && !keyed {
                    assert!(out.is_empty(), "never set up: {case}");
                }
            }
        }
        crate::gate::use_for_this_thread(None);
    }

    // ---- sixth audit of 2026-10 ----

    /// Sixth audit, finding 1: text that only carries the armor tag (here
    /// `IQE1:AQE=`, a version and a scheme and nothing else) is not a
    /// container and is never taken to the engine as one. On every inbound
    /// path: in a protected contact's name it is not shown (also with the
    /// marker in front); from an automatic contact it is shown with the
    /// marker taken off; with `e2e=off` too, a whole container included.
    #[test]
    fn text_with_the_armor_tag_but_no_container_is_unencrypted_text_on_every_path() {
        for text in [
            &b"hello IQE1:AQE="[..],
            b"[ICQ E2E] Encryption is on IQE1:AQE=",
        ] {
            let (shown, _) = unencrypted_frames(text);
            for (what, f) in &shown {
                let (mut r, _) = opened(Direction::Inbound);
                let mut c = Fake::new();
                c.strict = Some(true);
                let mut out = Vec::new();
                let lines = r.push_crypto(f, &mut c, 1, &encrypt(), &mut out);
                assert!(!contains(&out, b"IQE1:AQE="), "{what}: {lines:?}");
                assert!(c.seen.is_empty(), "{what}: never taken for a container");
                assert!(
                    c.gate_notes.iter().any(|n| n.contains("not shown")),
                    "{what}: {lines:?}"
                );
            }
        }
        let (shown, _) = unencrypted_frames(b"[ICQ E2E] Encryption is on IQE1:AQE=");
        for (what, f) in &shown {
            let (mut r, _) = opened(Direction::Inbound);
            let mut out = Vec::new();
            let lines = r.push_crypto(f, &mut Fake::new(), 1, &encrypt(), &mut out);
            assert!(
                contains(&out, b"(from 100002) [ICQ E2E] Encryption is on IQE1:AQE="),
                "{what}: {lines:?}"
            );
        }
        // e2e=off: nothing is decrypted, so a whole container is text too,
        // and is unmarked like any other.
        let armored = format!(
            "[ICQ E2E] Encryption is on {}",
            container::armor(&any_container())
        );
        let (mut r, _) = opened(Direction::Inbound);
        let mut out = Vec::new();
        r.push_crypto(
            &in_message(2, "100002", &armored, None),
            &mut crate::crypto::Disabled::default(),
            1,
            &encrypt(),
            &mut out,
        );
        let texts = texts_of(&frames_of(&out));
        assert_eq!(texts, vec![format!("(from 100002) {armored}")]);
    }

    /// A Feedbag authorization event to the client, as the server sends it.
    fn feedbag_frame(sub: u16, reason: &[u8]) -> Vec<u8> {
        frame(
            FLAP_CHANNEL_SNAC,
            2,
            &crate::authz::tests::feedbag(sub, "100002", reason),
        )
    }

    /// Sixth audit, finding 2: every authorization event in a protected
    /// contact's name - Feedbag request and reply, channel 4 and offline
    /// request and denial - reaches the client with the add-on's words in
    /// place of the contact's text, the event itself kept; from an
    /// automatic contact it passes as it came, unmarked if it starts like a
    /// note.
    #[test]
    fn an_authorization_event_in_a_protected_contacts_name_shows_none_of_its_text() {
        use crate::test_frames as tf;
        let forged = b"FORGED: add me, I am your bank";
        let request = [&b"nick\xFEfirst\xFElast\xFEmail\xFE1\xFE"[..], forged].concat();
        let offline = |t: u8, text: &[u8]| {
            let mut f = tf::offline_reply(2, 100002, text);
            f[40] = t;
            f
        };
        let events = |text: &[u8], req: &[u8]| {
            vec![
                (
                    "feedbag request",
                    feedbag_frame(crate::authz::FEEDBAG_REQUEST_AUTHORIZE_TO_CLIENT, text),
                ),
                (
                    "feedbag reply",
                    feedbag_frame(crate::authz::FEEDBAG_RESPOND_AUTHORIZE_TO_CLIENT, text),
                ),
                ("ch4 request", in_ch4(2, "100002", 0x06, req)),
                ("ch4 denial", in_ch4(2, "100002", 0x07, text)),
                ("offline request", offline(0x06, req)),
                ("offline denial", offline(0x07, text)),
            ]
        };
        for strict in [Some(true), None] {
            for (what, f) in events(forged, &request) {
                let (mut r, _) = opened(Direction::Inbound);
                let mut c = Fake::new();
                c.strict = strict;
                let mut out = Vec::new();
                let lines = r.push_crypto(&f, &mut c, 1, &encrypt(), &mut out);
                assert!(!contains(&out, forged), "{what}: {lines:?}");
                assert!(
                    contains(
                        &out,
                        b" attributed to 100002 was not end-to-end authenticated"
                    ),
                    "{what}: the event is kept with the add-on's words: {lines:?}"
                );
                if what.contains("request") && !what.contains("feedbag") {
                    assert!(
                        contains(&out, b"nick\xFEfirst\xFElast\xFEmail\xFE1\xFE[ICQ E2E]"),
                        "{what}: the directory fields stay"
                    );
                }
            }
        }
        // Automatic: as it came; a note's marker is taken off.
        for (what, f) in events(forged, &request) {
            let (mut r, _) = opened(Direction::Inbound);
            let mut out = Vec::new();
            r.push_crypto(&f, &mut Fake::new(), 1, &encrypt(), &mut out);
            assert_eq!(out, f, "{what}");
        }
        let marked = b"[ICQ E2E] 100002 is marked verified";
        let marked_req = [&b"n\xFEf\xFEl\xFEe\xFE1\xFE"[..], marked].concat();
        for (what, f) in events(marked, &marked_req) {
            let (mut r, _) = opened(Direction::Inbound);
            let mut out = Vec::new();
            r.push_crypto(&f, &mut Fake::new(), 1, &encrypt(), &mut out);
            assert!(
                contains(&out, b"(from 100002) [ICQ E2E] 100002 is marked verified"),
                "{what}"
            );
        }
    }

    /// A Locate user info reply about 100002 with `profile` and `away`, and
    /// a "buddy arrived" with the status text `status`.
    fn profile_frames(profile: &[u8], away: &[u8], status: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use crate::test_frames as tf;
        let mut info = vec![6];
        info.extend_from_slice(b"100002");
        info.extend_from_slice(&[0, 0]);
        let mut bart = 2u16.to_be_bytes().to_vec();
        bart.push(0x04);
        let mut item = (status.len() as u16).to_be_bytes().to_vec();
        item.extend_from_slice(status);
        item.extend_from_slice(&[0, 0]);
        bart.push(item.len() as u8);
        bart.extend_from_slice(&item);
        let user_tlvs = [tf::tlv(0x0001, &[0, 0x50]), tf::tlv(0x001D, &bart)].concat();
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&user_tlvs);
        let mut locate = info.clone();
        locate.extend(tf::tlv(0x0001, b"text/aolrtf; charset=\"us-ascii\""));
        locate.extend(tf::tlv(0x0002, profile));
        locate.extend(tf::tlv(0x0003, b"text/aolrtf; charset=\"us-ascii\""));
        locate.extend(tf::tlv(0x0004, away));
        (
            tf::data(2, &tf::snac(0x0002, 0x0006, &locate)),
            tf::data(2, &tf::snac(0x0003, 0x000B, &info)),
        )
    }

    /// An ICQ away message reply (`0x0004/0x000B`, channel 2) from 100002.
    fn auto_reply(text: &[u8]) -> Vec<u8> {
        use crate::test_frames as tf;
        let mut svc = tf::type2_svc(text);
        svc[45] = 0xE8;
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8, 0, 2, 6];
        body.extend_from_slice(b"100002");
        body.extend_from_slice(&[0, 3]);
        body.extend_from_slice(&svc);
        tf::data(2, &tf::snac(0x0004, 0x000B, &body))
    }

    /// Sixth audit, finding 2: a profile, an away message and a status text
    /// that start like a note of the add-on's are shown with "(from <uin>)"
    /// in front, whoever the contact is; ordinary ones are not touched.
    #[test]
    fn a_profile_away_message_or_status_cannot_pass_for_a_note() {
        for strict in [Some(false), Some(true)] {
            let (locate, arrived) = profile_frames(
                b"<HTML>[ICQ E2E] Safety number verified</HTML>",
                b"[icq e2e] away",
                b"[ICQ E2E] verified",
            );
            for (what, f, want) in [
                (
                    "profile",
                    &locate,
                    &b"<HTML>(from 100002) [ICQ E2E] Safety number verified</HTML>"[..],
                ),
                ("away message", &locate, b"(from 100002) [icq e2e] away"),
                ("status", &arrived, b"(from 100002) [ICQ E2E] verified"),
            ] {
                let (mut r, _) = opened(Direction::Inbound);
                let mut c = Fake::new();
                c.strict = strict;
                let mut out = Vec::new();
                let lines = r.push_crypto(f, &mut c, 1, &encrypt(), &mut out);
                assert!(contains(&out, want), "{what}: {lines:?}");
            }
            let reply = auto_reply(b"[ICQ E2E] Encryption is on");
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new();
            c.strict = strict;
            let mut out = Vec::new();
            r.push_crypto(&reply, &mut c, 1, &encrypt(), &mut out);
            assert!(
                contains(&out, b"(from 100002) [ICQ E2E] Encryption is on\0"),
                "an away message reply"
            );
            let (locate, arrived) = profile_frames(b"<HTML>Hi</HTML>", b"brb", b"at work");
            for f in [locate, arrived, auto_reply(b"Out for lunch")] {
                let (mut r, _) = opened(Direction::Inbound);
                let mut out = Vec::new();
                r.push_crypto(&f, &mut Fake::new(), 1, &encrypt(), &mut out);
                assert_eq!(out, f, "an ordinary profile is not touched");
            }
        }
    }

    /// An incoming INVITE with all the headers a response copies.
    fn invite_frame(seq: u16) -> Vec<u8> {
        let sip = b"INVITE sip:100001@h SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKx\r\nFrom: <sip:100002@h>;tag=a1\r\nTo: <sip:100001@h>\r\nCall-ID: g\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8];
        body.extend_from_slice(&crate::calls::CHANNEL_SIP.to_be_bytes());
        body.push(6);
        body.extend_from_slice(b"100002");
        body.extend_from_slice(&[0, 0, 0, 0]);
        snac::put_tlv(&mut body, crate::calls::TLV_SIP, sip);
        frame(
            FLAP_CHANNEL_SNAC,
            seq,
            &snac_frame(snac::FOOD_ICBM, snac::ICBM_MSG_TO_CLIENT, 9, &body),
        )
    }

    /// An inbound file proposal with cookie `[9; 8]`.
    fn proposal_frame(seq: u16) -> Vec<u8> {
        frame(
            FLAP_CHANNEL_SNAC,
            seq,
            &direct::tests::rdv(
                Direction::Inbound,
                "100002",
                RDV_PROPOSE,
                [9; 8],
                CAP_FILE_TRANSFER,
            ),
        )
    }

    /// Sixth audit, finding 3: an incoming call or file proposal in a
    /// protected contact's name reaches the client only once the key offer
    /// their add-on sends before it has come. Already there: at once. Late
    /// but within `HOLD_SECS`: let through right after it. Never: dropped
    /// with a warning, and the caller's client gets a 603 Decline / the
    /// sender's a cancel, so neither waits. An automatic contact's: as
    /// before.
    #[test]
    fn a_call_or_file_proposal_in_a_protected_contacts_name_waits_for_its_key_offer() {
        gate_with_media(crate::gate::MediaHooks::Ready);
        let mut policy = encrypt();
        policy.calls_encrypt = true;
        policy.files_encrypt = true;
        let cases = [
            (
                "call",
                invite_frame(2),
                Action::Call {
                    peer: "100002".into(),
                    call_id: "g".into(),
                    sdp: crate::callneg::sdp_hash(None),
                },
            ),
            (
                "file transfer",
                proposal_frame(2),
                Action::File {
                    peer: "100002".into(),
                    cookie: [9; 8],
                    digest: crate::files::rendezvous(
                        Direction::Inbound,
                        &frames_of(&proposal_frame(2))[0].1,
                    )
                    .unwrap()
                    .digest,
                },
            ),
        ];
        let offered = |c: &Fake, what: &str| match what {
            "call" => !c.sip_seen.is_empty(),
            _ => c.rdv_seen.iter().any(|(d, _)| *d == Direction::Inbound),
        };
        let later = frame(5, 3, &[]);
        for (what, f, action) in &cases {
            // The offer is there already.
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new();
            c.strict = Some(true);
            c.vouched.push(action.clone());
            let mut out = Vec::new();
            let lines = r.push_crypto(f, &mut c, 100, &policy, &mut out);
            assert!(!out.is_empty(), "{what}: {lines:?}");
            assert!(offered(&c, what), "{what}: {lines:?}");

            // Late, within the window: held, then let through after the
            // frame that brought it.
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new();
            c.strict = Some(true);
            let mut out = Vec::new();
            let lines = r.push_crypto(f, &mut c, 100, &policy, &mut out);
            assert!(out.is_empty(), "{what}: held: {lines:?}");
            assert!(!offered(&c, what));
            c.vouched.push(action.clone());
            let lines = r.push_crypto(&later, &mut c, 102, &policy, &mut out);
            assert_eq!(frames_of(&out).len(), 2, "{what}: {lines:?}");
            assert!(offered(&c, what), "{what}: {lines:?}");

            // Never: given up after the window, the sender told no.
            let (mut out_side, mut in_side) = StreamRewriter::pair();
            let mut wire = Vec::new();
            out_side.push_crypto(&hello(), &mut Fake::new(), 100, &policy, &mut wire);
            let mut shown = Vec::new();
            in_side.push_crypto(&hello(), &mut Fake::new(), 100, &policy, &mut shown);
            let mut c = Fake::new();
            c.strict = Some(true);
            in_side.push_crypto(f, &mut c, 100, &policy, &mut shown);
            in_side.push_crypto(&later, &mut c, 100 + HOLD_SECS, &policy, &mut shown);
            assert!(!offered(&c, what), "{what}");
            assert_eq!(
                frames_of(&shown).len(),
                2,
                "{what}: the sign-on and the later message only"
            );
            assert!(
                c.gate_notes
                    .iter()
                    .any(|n| n.contains("WARNING") && n.contains("100002")),
                "{what}: {:?}",
                c.gate_notes
            );
            let mut sent = Vec::new();
            out_side.push_crypto(
                &out_message(2, "100004", "hi"),
                &mut Fake::new().sending(Outbound::Clear {
                    text: "hi".into(),
                    note: String::new(),
                }),
                100 + HOLD_SECS,
                &policy,
                &mut sent,
            );
            let refusal = match *what {
                "call" => &b"SIP/2.0 603 Decline\r\nVia: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKx\r\nFrom: <sip:100002@h>;tag=a1\r\nTo: <sip:100001@h>;tag=e2e"[..],
                _ => &[0x00, 0x01, 9, 9, 9, 9, 9, 9, 9, 9][..],
            };
            assert!(contains(&sent, refusal), "{what}: the refusal goes out");
            assert!(contains(&sent, b"\x06100002"), "{what}: to 100002");

            // Automatic: as it came, at once.
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new();
            let mut out = Vec::new();
            r.push_crypto(f, &mut c, 100, &policy, &mut out);
            assert_eq!(out, *f, "{what}");
            assert!(offered(&c, what), "{what}");
        }
        crate::gate::use_for_this_thread(None);
    }

    /// The tZer forms of `core/tests/fixtures/tzer_forms.txt`, made by the
    /// server's own code (`foodgroup/icbm_tzer.go`): the TLV value named.
    fn tzer_form(name: &str) -> Vec<u8> {
        let all = include_str!("../tests/fixtures/tzer_forms.txt");
        let hex = all
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
            .expect("fixture");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// An ICBM carrying a tZer: channel 1 (`TLV 0x0002`) or 2 (`0x0005`).
    fn tzer_frame(dir: Direction, channel: u16, value: &[u8]) -> Vec<u8> {
        use crate::test_frames as tf;
        let tag = if channel == 1 { 0x0002 } else { 0x0005 };
        match dir {
            Direction::Outbound => tf::data(
                2,
                &tf::snac(
                    0x0004,
                    0x0006,
                    &tf::to_host_body("100002", channel, &tf::tlv(tag, value)),
                ),
            ),
            Direction::Inbound => tf::data(
                2,
                &tf::snac(
                    0x0004,
                    0x0007,
                    &tf::to_client_body("100002", channel, &tf::tlv(tag, value)),
                ),
            ),
        }
    }

    fn with_server() -> Policy {
        let mut policy = encrypt();
        policy.tls = crate::config::TlsPolicy::On {
            server: "icq.example.org".into(),
            pins: Vec::new(),
        };
        policy
    }

    /// Sixth audit, finding 4, the way out: a tZer of either client goes on
    /// unencrypted - the server must be able to translate it - with the
    /// add-on's announcement to the contact before it; the engine never
    /// sees it as a message. A "tZer" that is not one of this server's is
    /// text, and encrypted as before.
    #[test]
    fn a_tzer_goes_unencrypted_and_announced() {
        let doc = crate::tzer::tests::DOC;
        for (what, f) in [
            (
                "7.2",
                tzer_frame(Direction::Outbound, 1, &tzer_form("client72_im_data")),
            ),
            (
                "6.5",
                tzer_frame(Direction::Outbound, 2, &tzer_form("client65_rdv_data")),
            ),
        ] {
            let (mut r, _) = opened(Direction::Outbound);
            let mut c = Fake::new().sending(Outbound::Encrypted("IQE1:x".into()));
            c.strict = Some(true);
            let mut out = Vec::new();
            let lines = r.push_crypto(&f, &mut c, 1, &with_server(), &mut out);
            let frames = frames_of(&out);
            assert_eq!(frames.len(), 2, "{what}: {lines:?}");
            assert!(texts_of(&frames).is_empty());
            assert!(contains(
                &frames[0].1,
                container::armor(&any_container()).as_bytes()
            ));
            assert_eq!(frames[1].1, f[HEADER_LEN..], "{what}: the tZer as it was");
            assert!(c.seen.is_empty(), "{what}: never encrypted as a message");
            assert_eq!(c.notices, vec![crate::tzer::doc_hash(doc)], "{what}");
        }
        // Not one of this server's: a message, encrypted.
        let other = crate::tzer::tests::fragments(&doc.replace("icq.example.org", "evil.example"));
        let (mut r, _) = opened(Direction::Outbound);
        let mut c = Fake::new().sending(Outbound::Encrypted("IQE1:x".into()));
        let mut out = Vec::new();
        r.push_crypto(
            &tzer_frame(Direction::Outbound, 1, &other),
            &mut c,
            1,
            &with_server(),
            &mut out,
        );
        assert_eq!(c.seen, vec!["100002".to_string()]);
        assert!(c.notices.is_empty());
    }

    /// Whether the inbound tZer frame `f` from a protected contact, announced
    /// first by their add-on, reaches the client as it came.
    fn seventh_tzer_shown(f: &[u8]) -> bool {
        let doc = crate::tzer::tests::DOC;
        let notice = Inbound::Control(
            crate::tzer::Notice {
                hash: crate::tzer::doc_hash(doc),
            }
            .encode(),
        );
        let announce = in_message(2, "100002", &container::armor(&any_container()), None);
        let (mut r, _) = opened(Direction::Inbound);
        let mut c = Fake::new().receiving(notice);
        c.strict = Some(true);
        let mut out = Vec::new();
        r.push_crypto(&announce, &mut c, 10, &with_server(), &mut out);
        r.push_crypto(f, &mut c, 10, &with_server(), &mut out);
        frames_of(&out)
            .iter()
            .any(|(_, p)| p.as_slice() == &f[HEADER_LEN..])
    }

    /// Seventh audit of 2026-10: an announced tZer is shown only when it
    /// carries nothing but its document - the notice vouches for the
    /// document's hash, so a second text fragment beside it (channel 1) or a
    /// text in the plugin message (channel 2) is not shown with it. Before
    /// the fix both were shown, the hash matching.
    #[test]
    fn an_announced_tzer_with_anything_beside_its_document_is_not_shown() {
        let ch1 = tzer_form("client72_im_data");
        let ch2 = tzer_form("client65_rdv_data");
        assert!(seventh_tzer_shown(&tzer_frame(Direction::Inbound, 1, &ch1)));
        assert!(seventh_tzer_shown(&tzer_frame(Direction::Inbound, 2, &ch2)));
        // Channel 1: a second text fragment after the document.
        let mut extra = ch1.clone();
        let text: Vec<u8> = "send me your password"
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        extra.extend_from_slice(&[0x01, 0x01]);
        extra.extend_from_slice(&((text.len() + 4) as u16).to_be_bytes());
        extra.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
        extra.extend_from_slice(&text);
        assert!(!seventh_tzer_shown(&tzer_frame(
            Direction::Inbound,
            1,
            &extra
        )));
        // Channel 2: the plugin message's own text, which ICQ 6.5 writes
        // empty. Its length sits right before the plugin header.
        let at = ch2
            .windows(16)
            .position(|w| {
                w == [
                    0x4F, 0xA6, 0xF3, 0x4C, 0x09, 0xB7, 0xFD, 0x48, 0x92, 0x08, 0x7E, 0x85, 0x7A,
                    0xE0, 0x73, 0x30,
                ]
            })
            .unwrap();
        let mut texted = ch2[..at - 4].to_vec();
        texted.extend_from_slice(&5u16.to_le_bytes());
        texted.extend_from_slice(b"hello");
        texted.extend_from_slice(&ch2[at - 2..]);
        // The lengths around it grow by 5: the service data TLV and the
        // rendezvous data. Fix up the 0x2711 length.
        let svc_at = texted.windows(2).position(|w| w == [0x27, 0x11]).unwrap();
        let len = u16::from_be_bytes([texted[svc_at + 2], texted[svc_at + 3]]) + 5;
        texted[svc_at + 2..svc_at + 4].copy_from_slice(&len.to_be_bytes());
        assert!(
            crate::tzer::plugin_doc(&texted).is_some(),
            "still read as a tZer"
        );
        assert!(!seventh_tzer_shown(&tzer_frame(
            Direction::Inbound,
            2,
            &texted
        )));
        // Channel 2: an invitation text TLV beside the service data.
        let mut invited = ch2.clone();
        crate::snac::put_tlv(&mut invited, 0x000C, b"open me");
        assert!(!seventh_tzer_shown(&tzer_frame(
            Direction::Inbound,
            2,
            &invited
        )));
    }

    /// An inbound SIP answer from the server, with the Call-ID `g`.
    fn answer_frame(seq: u16, port: u16) -> Vec<u8> {
        let sip = format!(
            "SIP/2.0 200 OK\r\nCall-ID: g\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nm=audio {port} RTP/AVP 0\r\n"
        );
        let mut body = vec![1, 2, 3, 4, 5, 6, 7, 8];
        body.extend_from_slice(&crate::calls::CHANNEL_SIP.to_be_bytes());
        body.push(6);
        body.extend_from_slice(b"100002");
        body.extend_from_slice(&[0, 0, 0, 0]);
        snac::put_tlv(&mut body, crate::calls::TLV_SIP, sip.as_bytes());
        frame(
            FLAP_CHANNEL_SNAC,
            seq,
            &snac_frame(snac::FOOD_ICBM, snac::ICBM_MSG_TO_CLIENT, 9, &body),
        )
    }

    /// Seventh audit of 2026-10: a 200 OK in a protected contact's name
    /// reaches the client only when it is the answer their add-on keyed (the
    /// engine's [`Crypto::authenticated`] with [`Action::CallAnswer`]);
    /// another is held and dropped with the warning, and no 603 goes back.
    #[test]
    fn a_call_answer_that_is_not_the_keyed_one_is_not_put_through() {
        gate_with_media(crate::gate::MediaHooks::Ready);
        let mut policy = encrypt();
        policy.calls_encrypt = true;
        let f = answer_frame(2, 20000);
        let payload = &frames_of(&f)[0].1;
        let (_, sip) = crate::calls::sip_message(Direction::Inbound, payload).unwrap();
        let (call_id, sdp) = crate::callneg::answer_binding(sip).unwrap();
        let keyed = Action::CallAnswer {
            peer: "100002".into(),
            call_id,
            sdp,
        };
        // The keyed answer: through at once.
        let (mut r, _) = opened(Direction::Inbound);
        let mut c = Fake::new();
        c.strict = Some(true);
        c.vouched.push(keyed.clone());
        let mut out = Vec::new();
        r.push_crypto(&f, &mut c, 100, &policy, &mut out);
        assert_eq!(frames_of(&out).len(), 1);
        // Another SDP: held, then dropped with the warning.
        let other = answer_frame(2, 6666);
        let (mut r, _) = opened(Direction::Inbound);
        let mut c = Fake::new();
        c.strict = Some(true);
        c.vouched.push(keyed);
        let mut out = Vec::new();
        r.push_crypto(&other, &mut c, 100, &policy, &mut out);
        assert!(out.is_empty());
        r.push_crypto(
            &frame(5, 3, &[]),
            &mut c,
            100 + HOLD_SECS,
            &policy,
            &mut out,
        );
        assert!(!contains(&out, b"m=audio 6666"));
        assert!(
            c.gate_notes
                .iter()
                .any(|n| n.contains("An answer to your call in 100002's name")),
            "{:?}",
            c.gate_notes
        );
        assert!(c.sip_seen.is_empty(), "never taken to the key exchange");
    }

    /// Sixth audit, finding 4, the way in, both directions through the
    /// server's translation: ICQ 7.2's tZer as the server hands it to ICQ
    /// 6.5 (channel 2) and ICQ 6.5's as it hands it to ICQ 7.2 (channel 1),
    /// and each client's own form (7.2 to 7.2, 6.5 to 6.5). From a
    /// protected contact: shown when announced, also when the announcement
    /// comes within the window; one announcement vouches for one tZer; not
    /// announced, dropped after the window with a warning. From an
    /// automatic contact: as it came.
    #[test]
    fn a_tzer_in_a_protected_contacts_name_is_shown_only_when_announced() {
        let doc = crate::tzer::tests::DOC;
        let notice = Inbound::Control(
            crate::tzer::Notice {
                hash: crate::tzer::doc_hash(doc),
            }
            .encode(),
        );
        let announce = |seq| in_message(seq, "100002", &container::armor(&any_container()), None);
        for (what, f) in [
            (
                "7.2 to 6.5",
                tzer_frame(Direction::Inbound, 2, &tzer_form("server_to65_rdv_data")),
            ),
            (
                "6.5 to 7.2",
                tzer_frame(Direction::Inbound, 1, &tzer_form("server_to72_im_data")),
            ),
            (
                "7.2 to 7.2",
                tzer_frame(Direction::Inbound, 1, &tzer_form("client72_im_data")),
            ),
            (
                "6.5 to 6.5",
                tzer_frame(Direction::Inbound, 2, &tzer_form("client65_rdv_data")),
            ),
        ] {
            let body_of = |out: &[u8]| {
                frames_of(out)
                    .into_iter()
                    .map(|(_, p)| p)
                    .collect::<Vec<_>>()
            };
            // Announced first, as the sender's add-on does it.
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new().receiving(notice.clone());
            c.strict = Some(true);
            let mut out = Vec::new();
            r.push_crypto(&announce(2), &mut c, 10, &with_server(), &mut out);
            assert!(out.is_empty(), "{what}: the announcement shows nothing");
            let lines = r.push_crypto(&f, &mut c, 10, &with_server(), &mut out);
            assert_eq!(
                body_of(&out),
                vec![f[HEADER_LEN..].to_vec()],
                "{what}: {lines:?}"
            );
            // The same tZer again: the announcement was spent.
            let mut again = Vec::new();
            r.push_crypto(&f, &mut c, 10, &with_server(), &mut again);
            r.push_crypto(
                &in_message(4, "100004", "x", None),
                &mut c,
                10 + HOLD_SECS,
                &with_server(),
                &mut again,
            );
            assert!(
                !contains(&again, &f[HEADER_LEN + 40..]),
                "{what}: a replay is not shown"
            );
            assert!(
                c.gate_notes
                    .iter()
                    .any(|n| n.contains("A tZer in 100002's name was not shown")),
                "{what}"
            );

            // Announced late, within the window.
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new().receiving(notice.clone());
            c.strict = Some(true);
            let mut out = Vec::new();
            r.push_crypto(&f, &mut c, 10, &with_server(), &mut out);
            assert!(out.is_empty(), "{what}: held");
            r.push_crypto(&announce(3), &mut c, 11, &with_server(), &mut out);
            assert_eq!(
                body_of(&out),
                vec![f[HEADER_LEN..].to_vec()],
                "{what}: let through"
            );

            // Never announced.
            let (mut r, _) = opened(Direction::Inbound);
            let mut c = Fake::new();
            c.strict = Some(true);
            let mut out = Vec::new();
            r.push_crypto(&f, &mut c, 10, &with_server(), &mut out);
            r.push_crypto(
                &in_message(3, "100004", "x", None),
                &mut c,
                10 + HOLD_SECS,
                &with_server(),
                &mut out,
            );
            assert!(!contains(&out, &f[HEADER_LEN + 40..]), "{what}");
            assert!(
                c.gate_notes
                    .iter()
                    .any(|n| n.contains("A tZer in 100002's name was not shown")),
                "{what}"
            );

            // Automatic.
            let (mut r, _) = opened(Direction::Inbound);
            let mut out = Vec::new();
            r.push_crypto(&f, &mut Fake::new(), 10, &with_server(), &mut out);
            assert_eq!(out, f, "{what}");
        }
    }
}
