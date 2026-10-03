//! What the stream asks of the encryption.
//!
//! The stream - [`stream`] and [`rewrite`] - only knows frames, and must not
//! know about olm, sessions or the key directory. Everything it needs is
//! behind the [`Crypto`] trait: the bearer token, whether we have announced
//! the add-on, what to do with an outbound fragment, what came out of an
//! inbound one, and which control messages and notes are waiting.
//!
//! [`Publisher`] is the other half: the steps that put our keys into the
//! directory, in the order the API needs them (KEY-DIRECTORY-API.md 3.3), and
//! the answers it may give. It runs on the worker thread, not in a hook.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::container::{self, Form};
use crate::directory::UserDevices;
use crate::directory::{DeviceState, DirError, DirectoryApi, SignedKey};
use crate::keys::{self, Inbound, Outbound, OwnKeys, ONE_TIME_REFILL_BELOW, ONE_TIME_TARGET};
use crate::kt;
use crate::policy::{self, Command, Held, Remembered, Setting, Status};
use crate::safety;
use crate::sign;

/// How long to keep asking after `403 not_announced`: the account key goes out
/// in the `SetInfo` the client sends while signing on, and the HTTPS request
/// can overtake it. Thirty seconds at two is what the API document records.
pub const ANNOUNCE_RETRY: Duration = Duration::from_secs(30);
/// The gap between those attempts.
pub const ANNOUNCE_EVERY: Duration = Duration::from_secs(2);
/// A token is refreshed this long before it expires.
pub const TOKEN_REFRESH_BEFORE: Duration = Duration::from_secs(3600);
/// Our copy of the key log is brought up to date at most this often, in
/// seconds - and at once when a contact's keys are not in it.
pub const LOG_SYNC_EVERY: u64 = 60;

/// What the stream needs to know about us without touching any keys.
pub trait Crypto {
    /// The bearer to call the directory with, if we have a token.
    fn bearer(&self) -> Option<String>;

    /// Whether the account key has been announced on the connection and the
    /// directory has taken our keys. Only then may a message be encrypted.
    fn ready(&self) -> bool;

    /// Our account key, the 32 raw bytes that `LocateSetInfo` TLV 0x0E2E
    /// announces. The directory only accepts a first publish or a reset for a
    /// key announced on the connection the token belongs to.
    fn account_key(&self) -> Option<[u8; 32]>;

    /// Encrypts `out` for `peer`, or explains why it will not go. A contact
    /// without the add-on gets clear text and a note, not an error.
    fn outbound(&mut self, peer: &str, form: Form, text: &[u8], now: u64) -> Outbound;

    /// Decrypts a container that arrived from `peer`, or gives the note to
    /// show in its place.
    fn inbound(&mut self, peer: &str, container: &crate::container::Container, now: u64)
        -> Inbound;

    /// A container from `peer` of a version or scheme this build cannot read
    /// (a newer add-on's): the note to show in its place, which is also
    /// queued for the chat. Nothing else happens (CHECKLIST 9.8).
    fn unsupported(&mut self, peer: &str, version: u8, scheme: u8) -> Inbound;

    /// A note that has not been shown yet, and will not be again, with the
    /// chat it belongs in.
    fn take_note(&mut self) -> Option<Note>;

    /// A command typed in the chat with `peer` (`/e2e on`, ...): carried out,
    /// answered with a note, and `true` so the message is never sent
    /// (CHECKLIST 10.2). `false` for an ordinary message.
    fn command(&mut self, peer: &str, text: &str, now: u64) -> bool {
        let _ = (peer, text, now);
        false
    }

    /// Whether messages go through [`Self::outbound`] and [`Self::inbound`] at
    /// all. `false` for [`Disabled`]: the message bytes are then the client's
    /// own both ways, and only [`Self::command`] is asked.
    fn encrypts(&self) -> bool {
        true
    }

    /// A control message to send, if one is due: after an incoming key
    /// exchange, or after [`HEARTBEAT`] messages without one going out.
    fn take_control(&mut self, peer: &str) -> Option<Vec<u8>>;

    /// How many messages have gone to `peer` since we last sent a control
    /// message, which is what the heartbeat counts.
    fn since_control(&self, peer: &str) -> u32;

    /// Whether `peer`'s policy requires encryption (`/e2e on` or verified),
    /// for the protection gate (`gate.rs`) to decide a call or a file
    /// transfer by. `None` when it cannot be told - no state, or a stand-in
    /// state - which the gate takes as "protected". No default: every
    /// engine says what it knows.
    fn strictness(&self, peer: &str) -> Option<bool>;

    /// Whether a message in `peer`'s name that did not come through end-to-
    /// end encryption may be shown: `None` when it may, otherwise the reason
    /// for the log, with the warning queued for the chat and raised as a
    /// security alert (both rate-limited). The one decision every inbound
    /// text path asks - live messages on channels 1, 2 and 4, and offline
    /// messages (fifth audit of 2026-10, finding 1): if a contact is
    /// protected, nothing unauthenticated is shown in their name. No
    /// default: an engine that cannot tell the contact's policy refuses.
    fn plain_inbound(&mut self, peer: &str, now: u64) -> Option<String>;

    /// Whether `peer` is protected, and why: `None` when they are not.
    /// Protected means nothing is shown to the user as an action or words of
    /// theirs that did not pass end-to-end authentication - the rule of
    /// [`Self::plain_inbound`] (`/e2e on`, seen encrypting, verified; every
    /// contact while the policy cannot be read), without its warning. Asked
    /// for what is not a message: an authorization event, an incoming call,
    /// a file proposal, a tZer (sixth audit of 2026-10). No default.
    fn protected(&self, peer: &str) -> Option<String>;

    /// Something in `peer`'s name that was not authenticated end to end was
    /// kept from the client (`what`: "call", "file", "tzer", ...): `note`
    /// goes into the chat at most once a minute per contact and kind, and
    /// is raised as a security alert. No default: every engine that can be
    /// asked shows it somewhere.
    fn unauthenticated(&mut self, peer: &str, what: &str, note: String, now: u64);

    /// Whether `action` in its contact's name was authenticated end to end:
    /// the contact's add-on announced it over the Olm session before it
    /// came (a call's key offer `IQC1`, a file transfer's `IQF1`, a tZer's
    /// `IQT1`). `consume` takes a one-time announcement (a tZer's) so it
    /// cannot vouch for a second copy. `false` by default: an engine without
    /// sessions authenticates nothing.
    fn authenticated(&mut self, action: &Action, consume: bool, now: u64) -> bool {
        let _ = (action, consume, now);
        false
    }

    /// `action` was held for its announcement and given up: nothing may
    /// vouch for its id later - not a late offer, not a delayed one (seventh
    /// audit of 2026-10). Nothing by default.
    fn refused(&mut self, action: &Action, now: u64) {
        let _ = (action, now);
    }

    /// The control container that announces a tZer with document hash
    /// `hash` to `peer` (`IQT1`, [`crate::tzer::Notice`]), sent just before
    /// the tZer itself; `None` when there is no session to send it over.
    fn tzer_notice(&mut self, peer: &str, hash: [u8; 16], now: u64) -> Option<Vec<u8>> {
        let _ = (peer, hash, now);
        None
    }

    /// A note for the chat with `peer`: the gate's refusal of a call or a
    /// transfer. Dropped by an engine that shows no notes.
    fn note(&mut self, peer: &str, text: String) {
        let _ = (peer, text);
    }

    /// The SIP message of a call with `peer` (ICBM channel 6) passing in
    /// `dir`, with `calls_encrypt=on` (`callneg.rs`). Returns the control
    /// containers to put on the wire to `peer` *before* that message; the
    /// message itself is never changed. Nothing by default: an engine that
    /// does not encrypt calls leaves them as they are.
    fn call_sip(
        &mut self,
        dir: crate::icbm::Direction,
        peer: &str,
        sip: &[u8],
        now: u64,
        lines: &mut Vec<String>,
    ) -> Vec<Vec<u8>> {
        let _ = (dir, peer, sip, now, lines);
        Vec::new()
    }

    /// A file rendezvous ICBM (channel 2, `CapFileTransfer`) passing in its
    /// direction, with `files_encrypt=on` (`filesneg.rs`). Returns the control
    /// containers to put on the wire to the peer *before* that ICBM; the ICBM
    /// itself is never changed. Nothing by default: an engine that does not
    /// encrypt files leaves them as they are.
    fn file_icbm(
        &mut self,
        rdv: &crate::files::Rendezvous,
        now: u64,
        lines: &mut Vec<String>,
    ) -> Vec<Vec<u8>> {
        let _ = (rdv, now, lines);
        Vec::new()
    }
}

/// How old an announcement (`IQC1`, `IQF1`, `IQT1`) may be, by its sender's
/// clock, and still vouch for an action (seventh audit of 2026-10), in
/// seconds. The sender's time is the authenticated `time` of the Olm
/// envelope the announcement came in, which the server cannot change; the
/// envelope check alone lets a message be up to
/// [`crate::keys::TIME_SKEW_PAST`] (14 days) old, for offline messages.
pub const ANNOUNCE_MAX_AGE: u64 = 120;
/// How far an announcement's sender's clock may be ahead of ours.
pub const ANNOUNCE_MAX_AHEAD: u64 = 60;

/// Whether an announcement written at `sent` by its sender's clock is fresh
/// at `now` by ours (both seconds): less than [`ANNOUNCE_MAX_AGE`] old and at
/// most [`ANNOUNCE_MAX_AHEAD`] in the future. A server that holds a genuine
/// announcement back can present it later only within this window.
pub fn announcement_fresh(sent: u64, now: u64) -> bool {
    sent <= now.saturating_add(ANNOUNCE_MAX_AHEAD) && now.saturating_sub(sent) < ANNOUNCE_MAX_AGE
}

/// Something a contact does that is not a message, which the client shows as
/// theirs and which their add-on announces over the Olm session before it
/// happens (sixth audit of 2026-10, findings 3 and 4). Since the seventh
/// audit each one names everything its announcement binds: the contact,
/// the action's id, and a digest of the signalling as the client will act
/// on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// An incoming call: the INVITE with this Call-ID and an SDP hashing to
    /// `sdp` ([`crate::callneg::sdp_hash`]).
    Call {
        peer: String,
        call_id: String,
        sdp: [u8; 16],
    },
    /// A success answer to our INVITE with this Call-ID and SDP hash: the
    /// one the callee's key answer bound, once keys are agreed.
    CallAnswer {
        peer: String,
        call_id: String,
        sdp: [u8; 16],
    },
    /// A file proposal with this rendezvous cookie and canonical digest
    /// ([`crate::files::Rendezvous::digest`]).
    File {
        peer: String,
        cookie: [u8; 8],
        digest: [u8; 16],
    },
    /// A tZer whose document hashes to this ([`crate::tzer::doc_hash`]).
    Tzer { peer: String, hash: [u8; 16] },
}

impl Action {
    /// Whose action it is said to be.
    pub fn peer(&self) -> &str {
        match self {
            Action::Call { peer, .. }
            | Action::CallAnswer { peer, .. }
            | Action::File { peer, .. }
            | Action::Tzer { peer, .. } => peer,
        }
    }

    /// What it is, for the log and the warning's key.
    pub fn what(&self) -> &'static str {
        match self {
            Action::Call { .. } => "call",
            Action::CallAnswer { .. } => "call answer",
            Action::File { .. } => "file transfer",
            Action::Tzer { .. } => "tZer",
        }
    }
}

/// [`Crypto::unauthenticated`] for an engine that keeps notes: `note` into
/// the chat at most once every [`PLAIN_DROPPED_EVERY`] per contact and kind,
/// and a security alert (itself rate-limited).
pub fn unauthenticated_note(
    said: &mut HashMap<String, u64>,
    notes: &mut Vec<Note>,
    peer: &str,
    what: &str,
    note: String,
    now: u64,
) {
    let key = format!("{what}:{}", sign::ident(peer));
    let due = said
        .get(&key)
        .is_none_or(|at| now.saturating_sub(*at) >= PLAIN_DROPPED_EVERY);
    if due {
        said.insert(key.clone(), now);
        notes.push(Note::to(peer, note.clone()));
    }
    crate::alert::raise(&format!("unauth:{key}"), &note, now);
}

/// The engine of an install with `e2e=off` (the patch's "encrypted connection
/// to the server" row on its own): it encrypts nothing, has no keys and never
/// calls the key directory. It only takes a `/e2e` command out of the chat and
/// answers it, so a command typed by mistake never reaches the contact as
/// text.
#[derive(Debug, Default)]
pub struct Disabled {
    notes: Vec<Note>,
}

impl Disabled {
    /// A note about the add-on itself, for the chat last used.
    pub fn say(&mut self, text: String) {
        self.notes.push(Note { peer: None, text });
    }
}

impl Crypto for Disabled {
    fn bearer(&self) -> Option<String> {
        None
    }

    fn ready(&self) -> bool {
        false
    }

    /// None, so nothing is announced in `SetInfo`.
    fn account_key(&self) -> Option<[u8; 32]> {
        None
    }

    fn encrypts(&self) -> bool {
        false
    }

    /// Never asked ([`Self::encrypts`] is false); the text would go as typed.
    fn outbound(&mut self, _peer: &str, _form: Form, text: &[u8], _now: u64) -> Outbound {
        Outbound::Clear {
            text: String::from_utf8_lossy(text).into_owned(),
            note: "e2e=off: sent as typed".to_string(),
        }
    }

    /// Never asked ([`Self::encrypts`] is false): a container from a contact
    /// with the add-on is shown as the armoured text it is, as a client
    /// without the add-on would show it.
    fn inbound(&mut self, _peer: &str, _c: &container::Container, _now: u64) -> Inbound {
        Inbound::Unreadable("e2e=off: not decrypted".to_string())
    }

    fn unsupported(&mut self, _peer: &str, _version: u8, _scheme: u8) -> Inbound {
        Inbound::Unreadable("e2e=off: not decrypted".to_string())
    }

    fn take_note(&mut self) -> Option<Note> {
        (!self.notes.is_empty()).then(|| self.notes.remove(0))
    }

    fn command(&mut self, peer: &str, text: &str, _now: u64) -> bool {
        if policy::parse_command(text).is_none() {
            return false;
        }
        self.notes.push(Note::to(peer, policy::e2e_off_note(peer)));
        true
    }

    fn take_control(&mut self, _peer: &str) -> Option<Vec<u8>> {
        None
    }

    fn since_control(&self, _peer: &str) -> u32 {
        0
    }

    /// `e2e=off` encrypts no call or transfer; the gate never asks it, as
    /// calls and files are encrypted only in encrypt mode.
    fn strictness(&self, _peer: &str) -> Option<bool> {
        Some(false)
    }

    /// `e2e=off`: nothing is encrypted on this install, so nothing is
    /// protected and every message is shown as it came.
    fn plain_inbound(&mut self, _peer: &str, _now: u64) -> Option<String> {
        None
    }

    /// Nothing is protected on an install that encrypts nothing.
    fn protected(&self, _peer: &str) -> Option<String> {
        None
    }

    fn unauthenticated(&mut self, peer: &str, _what: &str, note: String, _now: u64) {
        self.notes.push(Note::to(peer, note));
    }

    fn note(&mut self, peer: &str, text: String) {
        self.notes.push(Note::to(peer, text));
    }
}

/// How often the warning about unencrypted messages in one contact's name
/// is put in the chat: once in this many seconds, however many come (each
/// is logged).
pub const PLAIN_DROPPED_EVERY: u64 = 60;

/// Queues the warning for an unencrypted message in `peer`'s name that was
/// not shown, at most once per [`PLAIN_DROPPED_EVERY`] per contact, and
/// raises the security alert. Shared by the engines. Returns the note.
pub fn plain_dropped(
    said: &mut HashMap<String, u64>,
    notes: &mut Vec<Note>,
    peer: &str,
    why: &str,
    now: u64,
) -> String {
    let note = policy::plain_dropped_note(peer, why);
    let key = sign::ident(peer);
    let due = said
        .get(&key)
        .is_none_or(|at| now.saturating_sub(*at) >= PLAIN_DROPPED_EVERY);
    if due {
        said.insert(key.clone(), now);
        notes.push(Note::to(peer, note.clone()));
    }
    crate::alert::raise(&format!("plain:{key}"), &note, now);
    note
}

/// After this many messages to one contact without a control message of our
/// own, one is sent so a contact that has come online again hears from us
/// first.
pub const HEARTBEAT: u32 = 50;

/// What a sign-on has published so far, so a second attempt knows where to
/// pick up rather than starting over and spending keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Published {
    pub account: bool,
    pub device: bool,
    /// How many one-time keys the directory holds.
    pub one_time: u32,
    pub fallback: bool,
}

impl Published {
    /// Whether everything a message needs is in place.
    pub fn complete(&self) -> bool {
        self.account && self.device && self.fallback
    }
}

/// What the caller should do after a publish attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// Everything is in the directory, and something was sent to get it there.
    Done(Published),
    /// Everything was already in the directory, and nothing was sent.
    ///
    /// Distinct from `Done` because the two want different things said about
    /// them. `Done` means "the directory now holds 50 one-time keys" and is
    /// worth one line. `Quiet` means "it still holds 50 one-time keys", which
    /// is what a poll every two seconds asked, and is worth no line at all -
    /// reporting it put `Keys published: 50 one-time key(s)` on screen two
    /// hundred times for the life of the client without a single request
    /// having been made.
    Quiet(Published),
    /// The key has not been announced on the connection yet; `again` says when
    /// to try, and nothing else may be sent until it has.
    Wait {
        again: Duration,
        note: Option<String>,
    },
    /// The answers the API gives that change this device rather than failing.
    /// `new_device` means a fresh Olm account and a fresh id, keeping the
    /// account key; `off` means encryption stays off for now.
    Off { note: String },
    /// The directory could not be reached, or answered something we do not
    /// act on. `note` is what the log says.
    Retry { note: String },
}

impl Progress {
    /// The line to write to the log.
    pub fn note(&self) -> Option<&str> {
        match self {
            Progress::Wait { note, .. } => note.as_deref(),
            Progress::Retry { note } | Progress::Off { note } => Some(note),
            Progress::Done(_) | Progress::Quiet(_) => None,
        }
    }
}

/// The steps that put our keys into the directory.
///
/// The order matters and is the API's: the account key first (a first publish
/// needs it announced on the connection), then the device, then its pool of
/// one-time keys, then the fallback key that opens a conversation when the pool
/// is empty (CHECKLIST 1.2, 1.4).
pub struct Publisher {
    dir: Arc<dyn DirectoryApi>,
}

impl Publisher {
    pub fn new(dir: Arc<dyn DirectoryApi>) -> Publisher {
        Publisher { dir }
    }

    /// Publishes whatever is missing, in order, and stops at the first step the
    /// directory refuses. `done` is what a previous attempt got through, so a
    /// retry does not spend a second pool of one-time keys.
    pub fn publish(&self, keys: &mut OwnKeys, bearer: &str, done: Published, now: u64) -> Progress {
        let mut done = done;
        // What the directory was told before this call, so the end can say
        // whether anything was said at all.
        let sent = done;
        if !done.account {
            match self.account(keys, bearer) {
                Ok(()) => done.account = true,
                Err(p) => return p,
            }
        }
        if !done.device {
            match self.device(keys, bearer) {
                Ok(state) => {
                    done.device = true;
                    done.one_time = state.one_time_key_count;
                    done.fallback = state.has_fallback_key;
                }
                Err(p) => return p,
            }
        }
        // The pool is topped up whenever it has fallen below the low water mark,
        // so a contact is never left without a key to claim (CHECKLIST 1.2).
        if done.one_time < ONE_TIME_REFILL_BELOW {
            match self.one_time_keys(keys, bearer, done.one_time) {
                Ok(n) => done.one_time = n,
                Err(p) => return p,
            }
        }
        // A fallback key that is due - a week old, or used to open a session
        // (audit 2026-10, finding 3) - is replaced on the next poll of the
        // sign-on, not only at the next sign-on.
        let rotate = done.fallback && keys.fallback_due(now);
        if !done.fallback || rotate {
            match self.fallback_key(keys, bearer, now) {
                Ok(()) => done.fallback = true,
                Err(p) => return p,
            }
            if rotate {
                // A new key was made and sent: the state file must keep it.
                return Progress::Done(done);
            }
        }
        // Whether anything was actually sent, or whether the account, the
        // device and both kinds of key were all in place already and this
        // poll had nothing to do.
        if sent == done {
            Progress::Quiet(done)
        } else {
            Progress::Done(done)
        }
    }

    /// `PUT /account`: the key that signs our devices. A first publish needs it
    /// announced on this connection; otherwise the directory answers
    /// `403 not_announced` and the caller comes back later.
    fn account(&self, keys: &mut OwnKeys, bearer: &str) -> Result<(), Progress> {
        let (key, signature) = keys.account_object();
        match self.dir.put_account(bearer, &key, &signature) {
            Ok(()) => Ok(()),
            Err(e) => Err(self.react(e, "the account key")),
        }
    }

    /// `PUT /devices/{id}`: this device's own signed keys.
    fn device(&self, keys: &mut OwnKeys, bearer: &str) -> Result<DeviceState, Progress> {
        let id = keys.device_id;
        let Some((curve, ed, signature)) = keys.device_object() else {
            return Err(Progress::Off {
                note: "this device's keys cannot be read; encryption stays off".into(),
            });
        };
        match self.dir.put_device(bearer, id, &curve, &ed, &signature) {
            Ok(state) => Ok(state),
            // 409 device_conflict: that id belongs to another device, so this
            // one takes a new one and publishes again.
            Err(e) if e.code() == "device_conflict" => {
                keys.new_device_id();
                Err(Progress::Retry {
                    note: format!("device {id} is taken; publishing as {}", keys.device_id),
                })
            }
            // 410 device_revoked: our own id was revoked, so this is a new
            // device with a new Olm account, keeping the account key.
            Err(e) if e.code() == "device_revoked" => {
                keys.new_device();
                Err(Progress::Retry {
                    note: format!("device {id} was revoked; publishing as {}", keys.device_id),
                })
            }
            Err(e) => Err(self.react(e, "the device")),
        }
    }

    /// `POST /devices/{id}/one-time-keys`: a full pool, signed by the account.
    fn one_time_keys(
        &self,
        keys: &mut OwnKeys,
        bearer: &str,
        published: u32,
    ) -> Result<u32, Progress> {
        let id = keys.device_id;
        let fresh = keys.new_one_time_keys(published);
        if fresh.is_empty() {
            // Nothing could be made - an unreadable account - rather than a
            // silent "published" that leaves the pool where it was.
            return Err(Progress::Off {
                note: "one-time keys cannot be made; encryption stays off".into(),
            });
        }
        self.upload(keys, bearer, id, &fresh)
    }

    /// `PUT /devices/{id}/fallback-key`: replaced once a week, and only then.
    fn fallback_key(&self, keys: &mut OwnKeys, bearer: &str, now: u64) -> Result<(), Progress> {
        let id = keys.device_id;
        match keys.rotate_fallback_key(now) {
            Some(key) => self
                .dir
                .put_fallback_key(bearer, id, &key)
                .map_err(|e| self.react(e, "the fallback key")),
            // Not due yet: the key already published is good for its week.
            None => Ok(()),
        }
    }

    /// Uploads a pool, retrying once with a fresh id if the device turned out
    /// to be someone else's.
    fn upload(
        &self,
        keys: &mut OwnKeys,
        bearer: &str,
        device: u32,
        fresh: &[SignedKey],
    ) -> Result<u32, Progress> {
        match self.dir.upload_one_time_keys(bearer, device, fresh) {
            Ok(n) => Ok(n),
            Err(e) if e.code() == "device_conflict" => {
                keys.new_device_id();
                Err(Progress::Retry {
                    note: format!("device {device} is taken; publishing as {}", keys.device_id),
                })
            }
            Err(e) if e.code() == "device_revoked" => {
                keys.new_device();
                Err(Progress::Retry {
                    note: format!(
                        "device {device} was revoked; publishing as {}",
                        keys.device_id
                    ),
                })
            }
            Err(e) => Err(match e.code() {
                "not_announced" => Progress::Wait {
                    again: ANNOUNCE_EVERY,
                    note: Some(format!(
                        "{} is not announced on the connection yet",
                        e.code()
                    )),
                },
                _ => Progress::Retry {
                    note: format!("the directory refused the keys: {e}"),
                },
            }),
        }
    }

    /// What an error from any step means for this device.
    fn react(&self, e: DirError, what: &str) -> Progress {
        match e.code() {
            // The SetInfo is on its way out; try again shortly.
            "not_announced" => Progress::Wait {
                again: ANNOUNCE_EVERY,
                note: Some(format!("{what} is not announced on the connection yet")),
            },
            // Another device of this account is still active, so the account
            // key cannot be replaced. Encryption stays off: a key change that
            // the directory will not take is not a key change.
            "active_devices" => Progress::Off {
                note: format!(
                    "{what} was refused: another device of this account is still signed on; encryption stays off"
                ),
            },
            "device_conflict" | "device_revoked" => Progress::Retry {
                note: format!("{what} was refused: {e}"),
            },
            // A network failure or anything we do not recognise: the keys stay
            // as they are and the next attempt starts again from the top.
            _ => Progress::Retry {
                note: format!("{what} could not be published: {e}"),
            },
        }
    }

    /// The device state after a publish, for the state file.
    pub fn own_state(&self, bearer: &str, device_id: u32) -> Option<DeviceState> {
        keys::OwnKeys::own_device_state(&*self.dir, bearer, device_id)
    }
}

/// How long is left before the token expires. `POST /token` is called once
/// this has fallen under [`TOKEN_REFRESH_BEFORE`], not after the token is dead.
pub fn until_expiry(now: u64, expires_at: u64) -> Duration {
    Duration::from_secs(expires_at.saturating_sub(now))
}

/// Whether a token should be refreshed now: inside the last hour before it
/// expires, or already past it, since a dead token is still one to replace.
pub fn refresh_due(now: u64, expires_at: u64) -> bool {
    until_expiry(now, expires_at) <= TOKEN_REFRESH_BEFORE
}

/// Whether the fallback key is due to be replaced, which is also how a device
/// that never published one is noticed.
pub fn fallback_due(keys: &OwnKeys, now: u64) -> bool {
    keys.fallback_due(now)
}

/// Whether the pool is low enough to top up.
pub fn pool_low(count: u32) -> bool {
    count < ONE_TIME_REFILL_BELOW
}

/// How many one-time keys a full pool holds, so the caller can tell a pool that
/// is short from one that is merely unused.
pub fn pool_target() -> u32 {
    ONE_TIME_TARGET
}

/// A note for the user, and the chat it belongs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The contact whose chat it goes into, as the client names them; `None`
    /// for a note about the add-on itself, which goes into the chat last used.
    pub peer: Option<String>,
    pub text: String,
}

impl Note {
    /// A note for the chat with `peer`.
    pub fn to(peer: &str, text: impl Into<String>) -> Note {
        Note {
            peer: Some(peer.to_string()),
            text: text.into(),
        }
    }
}

/// What the next message to a contact does, before anything is encrypted.
enum Decision {
    /// Encrypt it for these devices.
    Encrypt(keys::Contact),
    /// Send it as the client wrote it.
    Clear(ClearWhy),
    /// Do not send it at all (CHECKLIST 10.7, 10.8).
    Hold(Held),
}

/// Why a message goes in clear.
enum ClearWhy {
    /// The user switched encryption off for this contact.
    Off,
    /// `/e2e plain`, once.
    Plain,
    /// Our keys are not in the directory yet, and the contact was never seen
    /// encrypting.
    NotPublished,
    /// The contact has no keys and was never seen encrypting.
    NoKeys,
    /// The directory could not be reached, for a contact never seen
    /// encrypting and not announcing the add-on.
    Unreachable(String),
}

/// The [`Crypto`] the stream actually runs against: our own keys, a directory,
/// and the notes and control messages that come out of them.
///
/// Everything that changes state - a session advancing, a note being made, a
/// message being counted, a contact's setting - happens here, and the caller
/// saves the state file afterwards when [`Engine::take_changed`] says so
/// ([`OwnKeys`] is only as durable as the last [`crate::store::Store::save`]).
pub struct Engine {
    dir: Arc<dyn DirectoryApi>,
    keys: OwnKeys,
    token: Option<crate::token::Token>,
    /// Everything published this sign-on, so a retry does not spend a second
    /// pool of one-time keys.
    published: Published,
    /// Whether the keys we hold are the ones the directory has accepted. No
    /// message is encrypted until they are.
    ready: bool,
    /// Notes waiting to be shown in the chat, oldest first.
    notes: Vec<Note>,
    /// Contacts that sent us a key exchange, so we answer each once.
    owed_control: Vec<String>,
    /// Messages sent per contact since we last sent it a control message.
    counted: HashMap<String, u32>,
    /// Contacts the directory has no keys for, this sign-on, so a contact
    /// never seen encrypting costs one directory call and not one per message.
    known_clear: HashSet<String>,
    /// Contacts whose user info announces the add-on. Only a hint (CHECKLIST
    /// 10.6): a server can strip it, so it never decides that a message goes
    /// in clear, only that an unreachable directory holds a message back.
    announces: HashSet<String>,
    /// The status last shown in each chat this sign-on (CHECKLIST 10.3).
    shown: HashMap<String, Status>,
    /// Notes already shown this sign-on that are only worth saying once.
    said: HashSet<String>,
    /// Contacts whose next message goes in clear, once (`/e2e plain`).
    plain_once: HashSet<String>,
    /// The contact's account key behind the safety number last shown with
    /// `/e2e safety` this sign-on. `/e2e verify` verifies only that key, so
    /// the user never verifies a number they were not shown.
    safety_shown: HashMap<String, String>,
    /// Whether the keys or a contact's setting changed since the state file
    /// was last written.
    changed: bool,
    /// A publish this sign-on failed in a way the user was told about, so a
    /// later success is worth one note.
    publish_failed: bool,
    /// `calls_encrypt=on`: calls are offered, answered and encrypted
    /// ([`crate::callneg`]). Off, a call payload is an ordinary control
    /// message, exactly as for an add-on without call support.
    calls_encrypt: bool,
    /// The calls, shared with the media hooks.
    calls: Arc<std::sync::Mutex<crate::callneg::CallTable>>,
    /// `files_encrypt=on`: file transfers are offered, answered and
    /// encrypted ([`crate::filesneg`]). Off, a file payload is an ordinary
    /// control message, exactly as for an add-on without file support.
    files_encrypt: bool,
    /// The file transfers, shared with the socket hooks.
    files: Arc<std::sync::Mutex<crate::filesneg::FileTable>>,
    /// When our copy of the key log was last brought up to date, and how
    /// that went.
    log_synced_at: Option<u64>,
    log_status: LogStatus,
    /// What the log's auditors said about our copy, last time we looked.
    audit_status: AuditStatus,
    /// The `auditors =` line of `icq-e2e.ini`, read: exactly the auditors
    /// trusted, instead of the ones the server names on first sight.
    pinned_auditors: Option<Vec<String>>,
    /// Writes the state file, when the engine runs inside a session: a
    /// message whose ratchet moved on is let go - out to the contact, or in
    /// to the client - only once this has kept the new state (audit 2026-10,
    /// finding 5). `None` for an engine without a state file (the tests).
    persist: Option<Persist>,
    /// Contacts whose last message could not be let go because the state
    /// could not be saved: encryption with them waits for a save that works.
    unsaved: HashSet<String>,
    /// Why this engine has no keys of its own: another process holds the
    /// account's state file (audit 2026-10, finding 6). Every message is
    /// then held, never sent in clear, and nothing is published.
    locked_out: Option<String>,
    /// When the warning about an unencrypted message in a contact's name
    /// was last put in the chat ([plain_dropped]), and the warnings about
    /// other things kept from the client ([`unauthenticated_note`]).
    plain_said: HashMap<String, u64>,
    /// tZers announced by their senders' add-ons (`IQT1`), not yet seen:
    /// the contact, the document's hash, and when the sender wrote it by
    /// its own clock ([`crate::tzer::Notice`]); each vouches for one tZer
    /// while [`announcement_fresh`] (seventh audit of 2026-10).
    tzer_notices: Vec<(String, [u8; 16], u64)>,
}

impl Engine {
    /// An engine over `keys` and `dir`, with no token yet: one exists only
    /// once the server has sent the MOTD.
    pub fn new(dir: Arc<dyn DirectoryApi>, keys: OwnKeys) -> Engine {
        Engine {
            dir,
            keys,
            token: None,
            published: Published::default(),
            ready: false,
            notes: Vec::new(),
            owed_control: Vec::new(),
            counted: HashMap::new(),
            known_clear: HashSet::new(),
            announces: HashSet::new(),
            shown: HashMap::new(),
            said: HashSet::new(),
            plain_once: HashSet::new(),
            safety_shown: HashMap::new(),
            changed: false,
            publish_failed: false,
            calls_encrypt: false,
            calls: crate::callneg::shared(),
            files_encrypt: false,
            files: crate::filesneg::shared(),
            log_synced_at: None,
            log_status: LogStatus::Unknown,
            audit_status: AuditStatus::Unknown,
            pinned_auditors: None,
            persist: None,
            unsaved: HashSet::new(),
            locked_out: None,
            plain_said: HashMap::new(),
            tzer_notices: Vec::new(),
        }
    }

    /// Locks the engine out: another process holds the account's state file.
    /// It announces and publishes nothing, holds every outgoing message and
    /// reads no incoming one, each with a note saying why.
    pub fn lock_out(&mut self, why: String) {
        self.locked_out = Some(why);
        self.ready = false;
    }

    /// The note for a message the locked-out engine does not handle.
    fn locked_out_note(&mut self, peer: &str, outbound: bool) -> Option<String> {
        let why = self.locked_out.clone()?;
        let note = if outbound {
            format!(
                "{}The message to {peer} was NOT sent: {why}, so this one has no keys to encrypt with and does not send it unencrypted. Close the other ICQ and sign on again.",
                policy::PREFIX
            )
        } else {
            format!(
                "{}An encrypted message from {peer} was not shown: {why}, so this one has no keys to read it with. It is shown in the other one.",
                policy::PREFIX
            )
        };
        self.queue(Note::to(peer, note.clone()));
        Some(note)
    }

    /// Gives the engine the way to write its state file, which it then uses
    /// before any message whose ratchet moved on is let go.
    pub fn set_persist(&mut self, persist: Persist) {
        self.persist = Some(persist);
    }

    /// Writes the state file now. Nothing to do without one.
    fn persist_now(&mut self) -> Result<(), String> {
        let Some(save) = self.persist.as_mut() else {
            return Ok(());
        };
        save(&self.keys)?;
        self.changed = false;
        Ok(())
    }

    /// Whether encryption with `peer` waits for a save that works, trying
    /// one first: a save that works now releases every contact.
    fn waits_for_save(&mut self, peer: &str) -> Option<String> {
        if !self.unsaved.contains(&sign::ident(peer)) {
            return None;
        }
        match self.persist_now() {
            Ok(()) => {
                self.unsaved.clear();
                None
            }
            Err(why) => Some(why),
        }
    }

    /// A message to or from `peer` that is not let go because the state it
    /// moved on could not be saved; the note says so, in that chat.
    fn not_saved(&mut self, peer: &str, why: &str, outbound: bool) -> String {
        self.unsaved.insert(sign::ident(peer));
        let note = if outbound {
            format!(
                "{}The message to {peer} was NOT sent: this add-on's state could not be saved ({why}), and an encrypted message goes out only once the state it moved on is safe on disk. Messages to {peer} wait until it can be saved; send it again then.",
                policy::PREFIX
            )
        } else {
            format!(
                "{}An encrypted message from {peer} was not shown: this add-on's state could not be saved ({why}), and a message is shown only once the state it moved on is safe on disk. Ask {peer} to send it again.",
                policy::PREFIX
            )
        };
        self.queue(Note::to(peer, note.clone()));
        note
    }

    /// Trusts exactly these auditors (the `auditors =` line of
    /// `icq-e2e.ini`), or, with `None`, the ones the server names when the
    /// log is first audited.
    pub fn set_auditors(&mut self, keys: Option<Vec<String>>) {
        self.keys.audit_configured = keys.is_some();
        self.pinned_auditors = keys;
    }

    /// Switches call encryption on or off (`calls_encrypt=` of the ini).
    pub fn set_calls_encrypt(&mut self, on: bool) {
        self.calls_encrypt = on;
    }

    /// Switches file transfer encryption on or off (`files_encrypt=` of the
    /// ini).
    pub fn set_files_encrypt(&mut self, on: bool) {
        self.files_encrypt = on;
    }

    /// Gives the engine a file table of its own instead of the one the hooks
    /// share: two engines in one test process.
    pub fn use_file_table(&mut self, t: Arc<std::sync::Mutex<crate::filesneg::FileTable>>) {
        self.files = t;
    }

    /// Switches the strict level of call encryption on or off
    /// (`calls_encrypt=required`): a call that did not agree on keys is not
    /// let through. On the call table, which the media hooks share.
    pub fn set_calls_required(&mut self, on: bool) {
        lock_calls(&self.calls).set_required(on);
    }

    /// Switches the strict level of file transfer encryption on or off
    /// (`files_encrypt=required`): a transfer that did not agree on keys is
    /// not sent. On the file table, which the socket hooks share.
    pub fn set_files_required(&mut self, on: bool) {
        crate::filesneg::lock(&self.files).set_required(on);
    }

    /// Gives the engine a call table of its own instead of the one the hooks
    /// share: two engines in one test process.
    pub fn use_call_table(&mut self, t: Arc<std::sync::Mutex<crate::callneg::CallTable>>) {
        self.calls = t;
    }

    /// What a call note needs to know about `peer`: under `/e2e on`, or
    /// verified.
    fn peer_info(&self, peer: &str) -> crate::callneg::PeerInfo {
        let verified = self.keys.pinned(peer).is_some_and(|p| p.is_verified());
        crate::callneg::PeerInfo {
            strict: verified || self.remembered(peer).setting == Setting::On,
            verified,
        }
    }

    /// This device, for a call key exchange with `peer`, or why there is
    /// none: the same rules as a message, minus anything that would hold a
    /// call (a call is never held, only left unencrypted).
    fn call_me(&mut self, peer: &str, now: u64) -> Result<crate::callneg::Me, String> {
        if self.remembered(peer).setting == Setting::Off {
            return Err("encryption is off in this chat (/e2e off)".into());
        }
        if !self.ready || self.token.is_none() {
            return Err("this add-on's keys are not in the key directory yet".into());
        }
        if self.keys.pinned(peer).is_some_and(|p| p.held) {
            return Err(format!(
                "{peer}'s safety number changed and is not verified again yet (/e2e safety)"
            ));
        }
        match self.contact(peer, now) {
            Ok(_) => {}
            Err(Lookup::NoKeys) => {
                return Err(format!(
                    "{peer} has no encryption keys in the key directory"
                ))
            }
            Err(Lookup::Transient(e)) => {
                return Err(format!("the key directory could not be reached ({e})"))
            }
            Err(Lookup::NotInLog(why)) | Err(Lookup::NotYet(why)) => return Err(why),
        }
        let key = self
            .keys
            .account()
            .map(|a| *a.curve25519_key().as_bytes())
            .ok_or("this device's keys cannot be read")?;
        Ok(crate::callneg::Me {
            uin: self.keys.screen_name.clone(),
            device: self.keys.device_id,
            key,
        })
    }

    /// A call payload as a control container for `peer`, through the Olm
    /// session with each of their devices.
    fn encrypt_call_payload(
        &mut self,
        peer: &str,
        payload: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, String> {
        let bearer = self.bearer().ok_or("no key directory token")?;
        let contact = match self.contact(peer, now) {
            Ok(c) => c,
            Err(Lookup::NoKeys) => return Err(format!("{peer} has no encryption keys")),
            Err(Lookup::Transient(e)) | Err(Lookup::NotInLog(e)) | Err(Lookup::NotYet(e)) => {
                return Err(e)
            }
        };
        if self.keys.pinned(peer).is_some_and(|k| k.held) {
            return Err(format!("{peer}'s safety number changed"));
        }
        let out = keys::Outgoing {
            peer: peer.to_string(),
            form: Form::Fragment {
                charset: 0,
                language: 0,
            },
            text: payload.to_vec(),
            now,
        };
        self.changed = true;
        match self
            .keys
            .encrypt_control(&*self.dir, &bearer, &out, &contact)
        {
            Ok(Outbound::Encrypted(wire)) => {
                // The ratchet moved on: not sent unless that is on disk
                // (audit 2026-10, finding 5).
                if let Err(why) = self.persist_now() {
                    self.unsaved.insert(sign::ident(peer));
                    return Err(format!("the add-on's state could not be saved ({why})"));
                }
                container::find_armor(&wire).ok_or_else(|| "no container".to_string())
            }
            Ok(Outbound::Refused(note)) => Err(note),
            Ok(Outbound::Clear { note, .. }) => Err(note),
            Err(e) => Err(e.to_string()),
        }
    }

    /// The keys, for the state file to be written from.
    pub fn keys(&self) -> &OwnKeys {
        &self.keys
    }

    /// The keys, so a step that changes the device id can be kept.
    pub fn keys_mut(&mut self) -> &mut OwnKeys {
        self.changed = true;
        &mut self.keys
    }

    /// Whether anything the state file holds changed since the last call: a
    /// ratchet step, a pinned key, a contact's setting. Clears the flag.
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// What is remembered about `peer`: the user's setting and whether they
    /// were ever seen encrypting.
    pub fn remembered(&self, peer: &str) -> Remembered {
        self.keys
            .contacts
            .get(&sign::ident(peer))
            .copied()
            .unwrap_or_default()
    }

    /// Takes the token out of the MOTD and the bearer that goes with it.
    pub fn set_token(&mut self, raw: &[u8]) -> Option<&str> {
        let t = crate::token::Token::parse(raw)?;
        self.token = Some(t);
        self.token.as_ref().map(|t| t.bearer.as_str())
    }

    /// A fresh token from `POST /token`, an hour before the old one runs out.
    pub fn refresh_token(&mut self) -> bool {
        let Some(old) = self.token.clone() else {
            return false;
        };
        if !refresh_due(unix_now(), old.expires_at) {
            return false;
        }
        match self.dir.refresh_token(&old.bearer) {
            Ok(bearer) => {
                if let Some(t) = crate::token::Token::from_bearer(&bearer) {
                    self.token = Some(t);
                    return true;
                }
                self.note_once(
                    None,
                    "token:unreadable".into(),
                    "[ICQ E2E] The server sent a token this build cannot read; encryption stays off."
                        .into(),
                );
                false
            }
            Err(e) => {
                self.publish_failed = true;
                self.note_once(
                    None,
                    "token:refresh".into(),
                    format!("[ICQ E2E] The token could not be refreshed: {e}."),
                );
                false
            }
        }
    }

    /// A publish attempt. `Wait` means the key is not announced on the
    /// connection yet, and nothing may be sent until it is.
    ///
    /// What it says goes to the log only (the session writes it): a publish
    /// step is about the add-on, not about any one chat.
    pub fn publish(&mut self, now: u64) -> Progress {
        if let Some(why) = &self.locked_out {
            return Progress::Off {
                note: format!("{why}; encryption is held in this one"),
            };
        }
        let Some(bearer) = self.token.as_ref().map(|t| t.bearer.clone()) else {
            return Progress::Off {
                note: "no token yet; encryption stays off".into(),
            };
        };
        let p =
            Publisher::new(self.dir.clone()).publish(&mut self.keys, &bearer, self.published, now);
        match &p {
            Progress::Done(d) => {
                self.published = *d;
                self.ready = true;
                self.changed = true;
            }
            // Only a published, accepted key may encrypt: otherwise a contact
            // would get a container nobody can open.
            Progress::Off { .. } => self.ready = false,
            // A retry may have given the device a new id or a new account.
            Progress::Retry { .. } => self.changed = true,
            _ => {}
        }
        self.say_publish_state(&p);
        // Our own account in the key log, once our keys are in.
        if self.ready {
            self.sync_log(now, false);
        }
        p
    }

    // --- the key log (docs/e2e/KEY-TRANSPARENCY.md) -------------------------

    /// Brings our copy of the key log up to date - at most once a minute
    /// unless `force` - and looks at our own account in it. Whether it did.
    fn sync_log(&mut self, now: u64, force: bool) -> bool {
        if !force
            && self
                .log_synced_at
                .is_some_and(|t| now < t.saturating_add(LOG_SYNC_EVERY))
        {
            return false;
        }
        self.log_synced_at = Some(now);
        // A log that broke after we trusted it stays broken until `/e2e
        // resetlog` (audit 2026-10, finding 4): the copy is frozen as it was
        // last trusted, and nothing the server says now changes it.
        if let Some(why) = self.keys.log.broken.clone() {
            self.alert_once("kt:broken", policy::log_broken_note(&why), now);
            self.log_status = LogStatus::Broken(why);
            self.set_inbound_gate(now);
            return true;
        }
        match kt::sync(&*self.dir, &self.keys.log) {
            Ok(next) => {
                if next != self.keys.log {
                    self.keys.log = next;
                    self.changed = true;
                }
                self.log_status = LogStatus::Ok;
                // A device the log no longer shows has no session any more
                // (audit 2026-10, finding 2).
                if self.keys.forget_devices_not_in_log() {
                    self.changed = true;
                }
                self.check_own_log();
                self.audit_log(now, true);
            }
            Err(kt::SyncError::NoLog) => self.log_status = LogStatus::NoLog,
            // A log trusted before that cannot be read now is not "no log":
            // the last trusted copy stands and nothing new is taken until it
            // can be read again (second audit of 2026-10, finding 2).
            Err(kt::SyncError::Net(e)) => self.log_status = LogStatus::Failed(e),
            Err(e) => {
                let why = e.to_string();
                self.log_broke(&why);
            }
        }
        self.set_inbound_gate(now);
        true
    }

    /// Tells the keys what a new inbound session needs now.
    fn set_inbound_gate(&mut self, now: u64) {
        self.keys.inbound_gate = match self.trust_at(now) {
            kt::Trust::NeverHadLog => keys::InboundGate::Open,
            kt::Trust::Trusted if self.keys.audit_required() => keys::InboundGate::Vouched,
            kt::Trust::Trusted => keys::InboundGate::Log,
            _ => keys::InboundGate::Frozen,
        };
    }

    /// The key log does not add up: said once, and, if we had trusted it
    /// before, remembered as broken for good (audit 2026-10, finding 4).
    fn log_broke(&mut self, why: &str) {
        self.alert_once("kt:broken", policy::log_broken_note(why), unix_now());
        self.log_status = LogStatus::Broken(why.to_string());
        if self.keys.log.was_trusted() && self.keys.log.broken.is_none() {
            self.keys.log.broken = Some(why.to_string());
            self.changed = true;
        }
    }

    /// What the key log can be relied on for, as of the last look at it.
    pub fn log_trust(&self) -> kt::Trust {
        self.trust_at(self.log_synced_at.unwrap_or(0))
    }

    /// What the key log can be relied on for at `now`:
    ///
    /// - broken after it was trusted: sticky until `/e2e resetlog` (audit
    ///   2026-10, finding 4);
    /// - read and adding up: trusted - unless a pinned auditor vouched for
    ///   this copy before and none has within [`kt::AUDIT_MAX_AGE`], which
    ///   is unaudited (second audit of 2026-10, finding 3);
    /// - not readable now, on a state that trusted a log before: temporarily
    ///   unavailable, never "no log" (second audit, finding 2);
    /// - never read on this state: no log.
    ///
    /// With an auditor configured (`auditors =`) or pinned, its word is
    /// required from the start (third audit of 2026-10, finding 1): no fresh
    /// cosignature yet is unaudited, and a log that cannot be read, or that
    /// the server says it does not keep, is never "no log".
    pub fn trust_at(&self, now: u64) -> kt::Trust {
        let log = &self.keys.log;
        let audited = self.keys.audit_required();
        match (&log.broken, &self.log_status) {
            (Some(why), _) => kt::Trust::BrokenAfterTrust(why.clone()),
            (None, LogStatus::Ok) if audited && !log.audit_fresh(now) => {
                kt::Trust::Unaudited(match &self.audit_status {
                    AuditStatus::Stale(why) => why.clone(),
                    _ => "no auditor of the key log has vouched for it within the hour".into(),
                })
            }
            (None, LogStatus::Ok) => kt::Trust::Trusted,
            (None, status) if log.was_trusted() || audited => {
                kt::Trust::TemporarilyUnavailableAfterTrust(match status {
                    LogStatus::Failed(e) => e.clone(),
                    LogStatus::NoLog => {
                        "the server says it keeps none, though auditors of it are pinned".into()
                    }
                    _ => "it has not been read yet".into(),
                })
            }
            _ => kt::Trust::NeverHadLog,
        }
    }

    /// Looks at the cosignatures of the log's auditors (stage 2). A
    /// checkpoint any of them saw that is not in our copy means the server
    /// shows us another log than it showed that auditor: the log is not
    /// trusted from then on, as for a rewritten one. No recent cosignature by
    /// any of them is a warning, once per sign-on.
    fn audit_log(&mut self, now: u64, may_resync: bool) {
        let (mut next, r) = kt::audit(
            &*self.dir,
            &self.keys.log,
            now,
            self.pinned_auditors.as_deref(),
        );
        // The part of the copy a pinned auditor cosigned in agreement is
        // what new keys are taken from (second audit of 2026-10, finding 3).
        // Not after a split view; a read that fails is tried at the next
        // look.
        // Only a cosignature fresh now moves it, however much more of the
        // log a stale one covers (third audit of 2026-10, finding 2).
        if !matches!(r, Err(kt::AuditError::SplitView(_))) {
            let size = next.fresh_audited_size(now);
            if let Err(kt::SyncError::Violation(why) | kt::SyncError::Rewritten(why)) =
                kt::vouch(&*self.dir, &mut next, size)
            {
                self.keys.log = next;
                self.changed = true;
                self.log_broke(&why);
                return;
            }
        }
        if next != self.keys.log {
            self.keys.log = next;
            self.changed = true;
        }
        self.audit_status = match r {
            Ok(a) => AuditStatus::Ok(a),
            Err(kt::AuditError::Behind) if may_resync => {
                // The auditor is ahead of the checkpoint we read a moment ago.
                if let Ok(next) = kt::sync(&*self.dir, &self.keys.log) {
                    self.keys.log = next;
                    self.changed = true;
                }
                return self.audit_log(now, false);
            }
            Err(kt::AuditError::Behind) => {
                AuditStatus::Failed("the auditor is ahead of the log".into())
            }
            Err(kt::AuditError::NoAuditor) => AuditStatus::None,
            Err(kt::AuditError::Net(e)) => AuditStatus::Failed(e),
            Err(kt::AuditError::Stale(why)) => {
                self.alert_once("kt:stale", policy::audit_stale_note(&why), now);
                AuditStatus::Stale(why)
            }
            Err(kt::AuditError::SplitView(why)) => {
                self.log_broke(&why);
                AuditStatus::Stale(why)
            }
        };
    }

    /// The auditor's part of `/e2e status`.
    fn describe_audit(&self, now: u64) -> String {
        match &self.audit_status {
            AuditStatus::Unknown => String::new(),
            AuditStatus::None => "; no auditor".into(),
            AuditStatus::Ok(views) => {
                // "audited by A (1 min ago), B (2 min ago); C silent 3 h"
                let fresh: Vec<String> = views
                    .iter()
                    .filter(|v| v.fresh(now))
                    .filter_map(|v| v.last.as_ref())
                    .map(|a| format!("{} ({})", a.auditor, kt::age(now, a.time)))
                    .collect();
                let mut out = format!(", audited by {}", fresh.join(", "));
                for v in views.iter().filter(|v| !v.fresh(now)) {
                    out += &match &v.last {
                        Some(a) => format!("; {} silent {}", v.name, kt::age(now, a.time)),
                        None => format!("; {} silent (no cosignature)", v.name),
                    };
                }
                out
            }
            AuditStatus::Failed(e) => format!("; the auditor's word could not be read ({e})"),
            AuditStatus::Stale(why) => format!("; NOT AUDITED: {why}"),
        }
    }

    /// Our account in the key log must hold our account key and only devices
    /// the user knows of: anything else is said, once per key or device.
    fn check_own_log(&mut self) {
        if !self.ready {
            return;
        }
        let Some(acc) = self.keys.log.accounts.get(&self.keys.screen_name).cloned() else {
            return;
        };
        if acc.key != self.keys.account_key_b64() {
            if self.keys.log.own_key_said.as_deref() != Some(acc.key.as_str()) {
                self.keys.log.own_key_said = Some(acc.key);
                self.changed = true;
                self.say(policy::log_own_key_note());
            }
            return;
        }
        let own = self.keys.device_id;
        if !self.keys.log.own_seen.contains(&own) {
            self.keys.log.own_seen.push(own);
            self.changed = true;
        }
        for id in acc.devices.keys() {
            if !self.keys.log.own_seen.contains(id) {
                self.keys.log.own_seen.push(*id);
                self.changed = true;
                self.say(policy::log_own_device_note(*id));
            }
        }
    }

    /// What the key log has to say about a contact's keys from the directory:
    /// `Err` if they are not to be used now, else the ids of devices to leave
    /// out. Never "no constraints" once a log was trusted on this state:
    ///
    /// - an up-to-date copy: the account key must be the log's and a device
    ///   the log's with the same keys;
    /// - and once an auditor has vouched for this copy: anything new - a
    ///   contact never pinned, a changed key, a device without a session -
    ///   must also be in the part an auditor vouched for (second audit of
    ///   2026-10, finding 3);
    /// - a log that broke, cannot be read now, or has no auditor's recent
    ///   word: only what was checked before goes on
    ///   ([`Engine::frozen_log_check`]).
    fn log_check(&self, peer: &str, ud: &UserDevices, now: u64) -> Result<Vec<u32>, Lookup> {
        let trust = self.trust_at(now);
        let mut left_out = Vec::new();
        if matches!(trust, kt::Trust::Trusted | kt::Trust::Unaudited(_)) {
            let Some(acc) = self.keys.log.accounts.get(&sign::ident(peer)) else {
                return Err(Lookup::NotInLog(format!(
                    "{peer}'s keys are not in the server's key log"
                )));
            };
            if acc.key != ud.account_key {
                return Err(Lookup::NotInLog(format!(
                    "{peer}'s account key in the key directory is not the one the server's key log shows"
                )));
            }
            left_out = ud
                .devices
                .iter()
                .filter(|d| d.revoked_at.is_none())
                .filter(|d| {
                    acc.devices.get(&d.device_id).is_none_or(|l| {
                        l.curve25519_key != d.curve25519_key
                            || l.ed25519_key != d.ed25519_key
                            || l.account_signature != d.account_signature
                    })
                })
                .map(|d| d.device_id)
                .collect();
        }
        let more = match &trust {
            kt::Trust::NeverHadLog => return Ok(left_out),
            kt::Trust::Trusted if !self.keys.audit_required() => return Ok(left_out),
            kt::Trust::Trusted => self.vouched_log_check(peer, ud)?,
            kt::Trust::Unaudited(why) => {
                self.frozen_log_check(peer, ud, &Frozen::Unaudited(why))?
            }
            kt::Trust::TemporarilyUnavailableAfterTrust(why) => {
                self.frozen_log_check(peer, ud, &Frozen::Unavailable(why))?
            }
            kt::Trust::BrokenAfterTrust(why) => {
                self.frozen_log_check(peer, ud, &Frozen::Broken(why))?
            }
        };
        for id in more {
            if !left_out.contains(&id) {
                left_out.push(id);
            }
        }
        Ok(left_out)
    }

    /// The part of [`Engine::log_check`] for an up-to-date copy an auditor
    /// vouched for lately: a key not pinned yet must be the vouched part's,
    /// and a device without a session must be in it; the devices left out.
    fn vouched_log_check(&self, peer: &str, ud: &UserDevices) -> Result<Vec<u32>, Lookup> {
        let pinned = self
            .keys
            .pinned(peer)
            .is_some_and(|p| p.key == ud.account_key);
        let vouched_key = self
            .keys
            .log
            .vouched
            .accounts
            .get(&sign::ident(peer))
            .is_some_and(|a| a.key == ud.account_key);
        if !pinned && !vouched_key {
            return Err(Lookup::NotYet(format!(
                "{peer}'s keys are newer than what the key log's auditor has vouched for, and they are taken once it has (it looks every minute)"
            )));
        }
        Ok(ud
            .devices
            .iter()
            .filter(|d| d.revoked_at.is_none())
            .filter(|d| {
                self.keys.session(peer, d.device_id).is_none()
                    && !self.keys.vouched_shows(peer, &ud.account_key, d)
            })
            .map(|d| d.device_id)
            .collect())
    }

    /// [`Engine::log_check`] while the log cannot vouch for anything new:
    /// only what was vouched for before is used. The account key must be
    /// the one pinned - a contact never pinned, or a changed key, is refused
    /// - and a device must already have a session with us or be in the
    /// trusted copy of the log (the part an auditor vouched for, once one
    /// has); any other device is left out.
    fn frozen_log_check(
        &self,
        peer: &str,
        ud: &UserDevices,
        why: &Frozen,
    ) -> Result<Vec<u32>, Lookup> {
        match self.keys.pinned(peer) {
            Some(p) if p.key == ud.account_key => {}
            Some(_) => return Err(why.lookup(format!("{peer}'s account key changed"))),
            None => return Err(why.lookup(format!("{peer}'s keys were never checked"))),
        }
        let audited = self.keys.audit_required();
        Ok(ud
            .devices
            .iter()
            .filter(|d| d.revoked_at.is_none())
            .filter(|d| {
                self.keys.session(peer, d.device_id).is_none()
                    && !(self.keys.log_shows(peer, &ud.account_key, d)
                        && (!audited || self.keys.vouched_shows(peer, &ud.account_key, d)))
            })
            .map(|d| d.device_id)
            .collect())
    }

    /// [`Engine::log_check`] against a copy of the log that is up to date: a
    /// change the contact made a moment ago may not be in our copy yet.
    fn logged(&mut self, peer: &str, ud: &UserDevices, now: u64) -> Result<Vec<u32>, Lookup> {
        let fresh = self.sync_log(now, false);
        match self.log_check(peer, ud, now) {
            Ok(none) if none.is_empty() => Ok(none),
            _ if !fresh => {
                self.sync_log(now, true);
                self.log_check(peer, ud, now)
            }
            other => other,
        }
    }

    /// The key log's part of `/e2e status`.
    fn describe_log(&mut self, peer: &str, now: u64) -> String {
        self.sync_log(now, false);
        let size = self.keys.log.size;
        match &self.log_status {
            LogStatus::Unknown => String::new(),
            LogStatus::NoLog if self.keys.audit_required() => {
                "; key log: the server says it keeps none, though auditors of it are pinned; only contacts and devices checked before are used and anything new is held".into()
            }
            LogStatus::NoLog => {
                "; key log: the server keeps none, so keys are trusted on first use".into()
            }
            LogStatus::Failed(e) if self.keys.log.was_trusted() || self.keys.audit_required() => format!(
                "; key log: could not be read ({e}); until it can, only contacts and devices checked before are used and anything new is held"
            ),
            LogStatus::Failed(e) => format!("; key log: could not be read ({e})"),
            LogStatus::Broken(why) => {
                format!("; key log: NOT TRUSTED - {why}; only keys checked before it broke are used (/e2e resetlog once the operator explains)")
            }
            LogStatus::Ok => {
                let logged = self
                    .keys
                    .log
                    .accounts
                    .get(&sign::ident(peer))
                    .map(|a| a.key.clone());
                let mut audit = self.describe_audit(now);
                if let kt::Trust::Unaudited(_) = self.trust_at(now) {
                    audit += "; new contacts, devices and keys are held until an auditor vouches again";
                }
                if let Some(why) = self.keys.key_recovery(peer) {
                    audit += &format!(
                        "; WARNING: {peer}'s keys were replaced without {peer}'s key (operator recovery: {why})"
                    );
                }
                match (logged, self.keys.pinned(peer)) {
                    (Some(l), Some(p)) if l == p.key => format!(
                        "; key log: {peer}'s keys are in it, checked ({size} entries){audit}"
                    ),
                    (Some(_), Some(_)) => format!(
                        "; key log: {peer}'s key is NOT the one it shows ({size} entries){audit}"
                    ),
                    (None, Some(_)) => {
                        format!("; key log: {peer}'s keys are NOT in it ({size} entries){audit}")
                    }
                    (_, None) => format!("; key log: checked ({size} entries){audit}"),
                }
            }
        }
    }

    /// Tells the user, in the chat, about a publish that leaves encryption
    /// not working - once per sign-on for each kind of failure, with the
    /// reason - and once that it works after all. A publish that goes
    /// through, or a refill that fails while the keys are already in the
    /// directory, says nothing: encryption works either way.
    fn say_publish_state(&mut self, p: &Progress) {
        match p {
            Progress::Off { note } => {
                self.publish_failed = true;
                self.note_once(
                    None,
                    "publish:off".into(),
                    policy::publish_failed_note(note),
                );
            }
            Progress::Retry { note } if !self.ready => {
                self.publish_failed = true;
                let kind = if note.contains("unreachable") || note.contains("could not be reached")
                {
                    "publish:unreachable"
                } else {
                    "publish:refused"
                };
                self.note_once(None, kind.into(), policy::publish_failed_note(note));
            }
            Progress::Done(_) | Progress::Quiet(_) if self.publish_failed && self.ready => {
                self.publish_failed = false;
                self.note_once(None, "publish:ready".into(), policy::ready_note());
            }
            _ => {}
        }
    }

    /// Records what a contact's user info said about the add-on. Only a hint
    /// (CHECKLIST 10.6): it never sends a message in clear.
    pub fn note_contacts(&mut self, contacts: &[(String, bool)]) {
        for (name, has_addon) in contacts {
            let p = sign::ident(name);
            if *has_addon {
                self.announces.insert(p);
            } else {
                self.announces.remove(&p);
            }
        }
    }

    /// Queues a note about no contact in particular, shown in the chat last
    /// used. For what the hooks have to say to the user, such as a connection
    /// to the server that is not encrypted (`tls=off`).
    pub fn say(&mut self, text: String) {
        self.queue(Note { peer: None, text });
    }

    /// Queues a note for the stream to show.
    fn queue(&mut self, note: Note) {
        self.notes.push(note);
    }

    /// Queues a note once per sign-on, keyed by `key`; whether it did.
    fn note_once(&mut self, peer: Option<&str>, key: String, text: String) -> bool {
        if self.said.insert(key) {
            self.queue(Note {
                peer: peer.map(str::to_string),
                text,
            });
            return true;
        }
        false
    }

    /// [`Self::note_once`] for an event about the key log that the user
    /// must be able to trust: also raised as a security alert (fifth audit
    /// of 2026-10, finding 2).
    fn alert_once(&mut self, key: &str, text: String, now: u64) {
        if self.note_once(None, key.to_string(), text.clone()) {
            crate::alert::raise(&format!("{key}:{text}"), &text, now);
        }
    }

    /// Changes what is remembered about `peer`, and marks the state file for
    /// writing if it really changed.
    fn remember(&mut self, peer: &str, f: impl FnOnce(&mut Remembered)) {
        let e = self.keys.contacts.entry(sign::ident(peer)).or_default();
        let before = *e;
        f(e);
        if *e != before {
            self.changed = true;
        }
    }

    /// Shows the chat's status if it is not the one shown last (CHECKLIST
    /// 10.3): the first message of a sign-on, and every change after it.
    fn show_status(&mut self, peer: &str, status: Status) {
        let p = sign::ident(peer);
        if self.shown.get(&p) != Some(&status) {
            self.shown.insert(p, status);
            self.queue(Note::to(peer, policy::status_note(peer, status)));
        }
    }

    /// Counts a message to `peer` against the heartbeat.
    fn count(&mut self, peer: &str) {
        *self.counted.entry(sign::ident(peer)).or_default() += 1;
    }

    /// The contact as the directory has it, pinned and checked, and if there
    /// is none, why: the directory has no keys for them, or could not be
    /// reached. A contact with signed devices is remembered as encrypting
    /// (CHECKLIST 10.7).
    fn contact(&mut self, peer: &str, now: u64) -> Result<keys::Contact, Lookup> {
        match self.dir.user_devices(peer) {
            Ok(ud) => {
                // A key the log does not show is never pinned.
                let left_out = self.logged(peer, &ud, now)?;
                let mut c = self.keys.checked_contact(&ud, now);
                // The pin may have been made or moved.
                self.changed = true;
                if !left_out.is_empty() {
                    let p = sign::ident(peer);
                    c.devices.retain(|d| !left_out.contains(&d.device_id));
                    let in_log = self.keys.log.accounts.get(&p).cloned();
                    for id in &left_out {
                        let unvouched = in_log.as_ref().is_some_and(|a| {
                            ud.devices
                                .iter()
                                .find(|d| d.device_id == *id)
                                .is_some_and(|d| {
                                    a.devices.get(id).is_some_and(|l| {
                                        l.curve25519_key == d.curve25519_key
                                            && l.ed25519_key == d.ed25519_key
                                            && l.account_signature == d.account_signature
                                    })
                                })
                        });
                        let note = if unvouched {
                            policy::log_device_unvouched_note(peer, *id)
                        } else {
                            policy::log_device_left_out_note(peer, *id)
                        };
                        self.note_once(Some(peer), format!("kt:device:{p}:{id}"), note);
                    }
                }
                if c.usable() {
                    self.remember(peer, |r| r.seen_encrypting = true);
                    Ok(c)
                } else if let Some(why) = self.keys.log.broken.clone() {
                    // Every device left out because the log is broken: held,
                    // never sent in clear as for a contact without keys.
                    Err(Lookup::NotInLog(format!(
                        "no device of {peer} was checked before the server's key log broke ({why})"
                    )))
                } else if !left_out.is_empty() {
                    // Every device left out by the log: held, never sent in
                    // clear as for a contact without keys.
                    Err(Lookup::NotYet(format!(
                        "no device of {peer} is vouched for by the server's key log yet"
                    )))
                } else {
                    Err(Lookup::NoKeys)
                }
            }
            Err(e) if e.code() == "no_account" => Err(Lookup::NoKeys),
            Err(e) => Err(Lookup::Transient(e.to_string())),
        }
    }

    /// What the next message to `peer` does (CHECKLIST 10.1, 10.6-10.8).
    /// `consume_plain` takes a pending `/e2e plain` with it; `/e2e status`
    /// asks without it.
    fn decide(&mut self, peer: &str, now: u64, consume_plain: bool) -> Decision {
        let p = sign::ident(peer);
        let rem = self.remembered(peer);
        if rem.setting == Setting::Off {
            return Decision::Clear(ClearWhy::Off);
        }
        if self.plain_once.contains(&p) {
            if consume_plain {
                self.plain_once.remove(&p);
            }
            return Decision::Clear(ClearWhy::Plain);
        }
        if !self.ready || self.token.is_none() {
            return if rem.strict() {
                Decision::Hold(Held::NotPublished)
            } else {
                Decision::Clear(ClearWhy::NotPublished)
            };
        }
        // A contact without keys this sign-on is not asked again - unless it
        // must never get clear text, in which case every message asks.
        if !rem.strict() && self.known_clear.contains(&p) {
            return Decision::Clear(ClearWhy::NoKeys);
        }
        match self.contact(peer, now) {
            // A verified contact whose safety number changed: nothing goes to
            // the new key until the user says so (CHECKLIST 10.10).
            Ok(_) if self.keys.pinned(peer).is_some_and(|p| p.held) => {
                Decision::Hold(Held::SafetyChanged)
            }
            Ok(c) => Decision::Encrypt(c),
            Err(Lookup::NoKeys) => {
                if rem.setting == Setting::On {
                    Decision::Hold(Held::OnByHand)
                } else if rem.seen_encrypting {
                    Decision::Hold(Held::Downgrade)
                } else {
                    self.known_clear.insert(p);
                    Decision::Clear(ClearWhy::NoKeys)
                }
            }
            // An outage is not remembered: it is not the contact's doing.
            Err(Lookup::Transient(e)) => {
                if rem.strict() || self.announces.contains(&p) {
                    Decision::Hold(Held::Unreachable(e))
                } else {
                    Decision::Clear(ClearWhy::Unreachable(e))
                }
            }
            Err(Lookup::NotInLog(why)) => Decision::Hold(Held::NotInLog(why)),
            Err(Lookup::NotYet(why)) => Decision::Hold(Held::NotYet(why)),
        }
    }

    /// A message that is not sent, and the note that says why.
    fn hold(&mut self, peer: &str, why: Held) -> Outbound {
        let note = policy::held_note(peer, &why);
        self.queue(Note::to(peer, note.clone()));
        Outbound::Refused(note)
    }

    /// An incoming encrypted message from `peer`: they are remembered as
    /// encrypting, and encryption switches on for them unless the user
    /// switched it off by hand (CHECKLIST 10.5). It cannot be forged without
    /// keys, so a server cannot use this to switch anything.
    fn encrypted_from(&mut self, peer: &str) {
        let p = sign::ident(peer);
        let was = self.remembered(peer);
        self.remember(peer, |r| r.seen_encrypting = true);
        self.known_clear.remove(&p);
        if was.setting == Setting::Off {
            self.note_once(
                Some(peer),
                format!("hint:{p}"),
                policy::encrypts_while_off_note(peer),
            );
            return;
        }
        match self.shown.get(&p) {
            Some(Status::On) => {}
            // The first word this sign-on about a contact already known to
            // encrypt is the plain status; anything else is a switch.
            None if was.seen_encrypting => self.show_status(peer, Status::On),
            _ => {
                self.shown.insert(p, Status::On);
                self.queue(Note::to(peer, policy::switched_on_note(peer)));
            }
        }
    }

    /// The answer to `/e2e status`.
    fn describe(&mut self, peer: &str, now: u64) -> String {
        let rem = self.remembered(peer);
        let setting = match rem.setting {
            Setting::Auto => "setting auto (encrypted whenever they have keys)",
            Setting::On => "setting on (switched on by you)",
            Setting::Off => "setting off (switched off by you)",
        };
        let keys = if !self.ready {
            "this add-on's keys are not in the key directory yet".to_string()
        } else {
            // Through the key log like any lookup, so asking never pins a key
            // the log does not show.
            match self.contact(peer, now) {
                Ok(c) => format!(
                    "{peer} has {} signed device(s) in the key directory",
                    c.devices.len()
                ),
                Err(Lookup::NoKeys) => {
                    format!("{peer} has no encryption keys in the key directory")
                }
                Err(Lookup::NotInLog(why)) | Err(Lookup::NotYet(why)) => {
                    format!("{peer}'s keys are not used: {why}")
                }
                Err(Lookup::Transient(e)) => {
                    format!("the key directory could not be reached ({e})")
                }
            }
        };
        let log = if self.ready {
            self.describe_log(peer, now)
        } else {
            String::new()
        };
        let verified = match self.keys.pinned(peer) {
            Some(p) if p.is_verified() => "; verified: yes (safety number compared)",
            Some(p) if p.held => {
                "; verified: no - the safety number changed after you verified it (/e2e safety, then /e2e verify or /e2e accept)"
            }
            Some(_) => "; verified: no (/e2e safety to compare)",
            None => "",
        };
        let next = match self.decide(peer, now, false) {
            Decision::Encrypt(_) => "encrypted",
            Decision::Clear(ClearWhy::Plain) => "unencrypted, once (/e2e plain)",
            Decision::Clear(_) => "unencrypted",
            Decision::Hold(_) => "nowhere: it is held, not sent unencrypted",
        };
        // `decide` may just have learned that the contact encrypts.
        let seen = if self.remembered(peer).seen_encrypting {
            "; seen encrypting: yes, so never switched to unencrypted silently"
        } else {
            "; seen encrypting: no"
        };
        format!(
            "{}Encryption with {peer}: {setting}; {keys}{log}{verified}{seen}. The next message goes {next}. Commands: {}.",
            policy::PREFIX,
            policy::COMMANDS
        )
    }

    /// The answer to `/e2e safety`: the safety number for the contact's key as
    /// the directory has it now (CHECKLIST 10.10). The key behind it is kept,
    /// so `/e2e verify` verifies what was shown.
    fn safety(&mut self, peer: &str, now: u64) -> String {
        let pre = policy::PREFIX;
        let looked = self.contact(peer, now);
        let p = sign::ident(peer);
        let Some(digits) = self.keys.safety_number(peer) else {
            self.safety_shown.remove(&p);
            return match looked {
                Err(Lookup::Transient(e)) => format!(
                    "{pre}There is no safety number with {peer} yet: the key directory could not be reached ({e})."
                ),
                Err(Lookup::NotInLog(why)) | Err(Lookup::NotYet(why)) => format!(
                    "{pre}There is no safety number with {peer}: {why}."
                ),
                _ => format!(
                    "{pre}There is no safety number with {peer}: they have no encryption keys in the key directory."
                ),
            };
        };
        let pin = self.keys.pinned(peer).expect("a number comes from a pin");
        let (key, verified) = (pin.key.clone(), pin.is_verified());
        self.safety_shown.insert(p, key);
        let mut note = policy::safety_note(peer, &safety::grouped(&digits, "\n"), verified);
        if let Err(Lookup::NotInLog(why)) | Err(Lookup::NotYet(why)) = &looked {
            note.push_str(&format!(
                " (This is the number for the key you had before: the key directory now gives {peer} another one, and {why}.)"
            ));
        }
        if let Err(Lookup::Transient(e)) = looked {
            note.push_str(&format!(
                " (The key directory could not be reached to look for a newer key: {e}.)"
            ));
        }
        note
    }

    /// The answer to `/e2e verify`: the key behind the number shown last is
    /// marked verified, if it is still the contact's key.
    fn verify(&mut self, peer: &str, now: u64) -> String {
        let pre = policy::PREFIX;
        let p = sign::ident(peer);
        // A fresh look, so a key that changed since the number was shown is
        // caught here rather than verified unseen.
        let _ = self.contact(peer, now);
        let current = self.keys.pinned(peer).map(|k| k.key.clone());
        match (self.safety_shown.get(&p), current) {
            (_, None) => format!(
                "{pre}There is nothing to verify: {peer} has no encryption keys in the key directory."
            ),
            (Some(shown), Some(key)) if *shown == key => {
                self.keys.verify(peer);
                self.changed = true;
                let digits = self.keys.safety_number(peer).unwrap_or_default();
                format!(
                    "{pre}{peer} is marked verified, for the safety number {}. If it changes, you are told and messages to {peer} are held until you check it again.",
                    safety::grouped(&digits, " ")
                )
            }
            (Some(_), Some(_)) => {
                self.safety_shown.remove(&p);
                format!(
                    "{pre}Nothing was verified: {peer}'s safety number changed after it was shown. Type /e2e safety to see the new number and compare it again."
                )
            }
            (None, Some(_)) => format!(
                "{pre}Nothing was verified: type /e2e safety first, compare the number with {peer} in person or by phone, then /e2e verify."
            ),
        }
    }

    /// Moves a note a pinned-key change made into the queue for the stream,
    /// once: it is taken out of the state file as it is shown.
    fn drain_pin_notes(&mut self, peer: &str) {
        let key = format!("pin:{}", sign::ident(peer));
        if let Some(note) = self.keys.said.remove(&key) {
            self.changed = true;
            // A verified contact's key changed (or a protected contact's was
            // replaced by the operator): messages to them are held, and the
            // user hears it where the network cannot write (fifth audit of
            // 2026-10, finding 2).
            if self.keys.pinned(peer).is_some_and(|p| p.held) {
                crate::alert::raise(&format!("pin:{note}"), &note, unix_now());
            }
            self.queue(Note::to(peer, note));
        }
    }
}

impl Crypto for Engine {
    fn bearer(&self) -> Option<String> {
        self.token.as_ref().map(|t| t.bearer.clone())
    }

    fn ready(&self) -> bool {
        self.ready && self.locked_out.is_none()
    }

    /// None while locked out: the stand-in keys must never be announced.
    fn account_key(&self) -> Option<[u8; 32]> {
        if self.locked_out.is_some() {
            return None;
        }
        Some(self.keys.account_key_bytes())
    }

    fn command(&mut self, peer: &str, text: &str, now: u64) -> bool {
        let Some(cmd) = policy::parse_command(text) else {
            return false;
        };
        if let Some(why) = self.locked_out.clone() {
            let note = format!(
                "{}Encryption is held in this ICQ: {why}. Commands work in the other one.",
                policy::PREFIX
            );
            self.queue(Note::to(peer, note));
            return true;
        }
        let p = sign::ident(peer);
        let pre = policy::PREFIX;
        let note = match cmd {
            Command::On => {
                self.remember(peer, |r| r.setting = Setting::On);
                self.plain_once.remove(&p);
                self.shown.insert(p, Status::On);
                let mut note = format!(
                    "{pre}Encryption is on in this chat (switched on by you): nothing is sent to {peer} unencrypted."
                );
                if self.ready {
                    match self.contact(peer, now) {
                        Ok(_) => {}
                        Err(Lookup::NoKeys) => note.push_str(&format!(
                            " {peer} has no encryption keys yet, so messages to them are held until they have."
                        )),
                        Err(Lookup::Transient(e)) => note.push_str(&format!(
                            " The key directory could not be reached to check {peer}'s keys ({e})."
                        )),
                        Err(Lookup::NotInLog(why)) | Err(Lookup::NotYet(why)) => note.push_str(
                            &format!(" Messages to {peer} are held: {why}."),
                        ),
                    }
                }
                note
            }
            Command::Off => {
                self.remember(peer, |r| r.setting = Setting::Off);
                self.plain_once.remove(&p);
                self.shown.insert(p, Status::Off);
                policy::status_note(peer, Status::Off)
            }
            Command::Auto => {
                self.remember(peer, |r| r.setting = Setting::Auto);
                self.plain_once.remove(&p);
                // The next message says the status the automatic rule gives.
                self.shown.remove(&p);
                format!(
                    "{pre}Encryption with {peer} is automatic again. {}",
                    self.describe(peer, now).trim_start_matches(pre)
                )
            }
            Command::Status => self.describe(peer, now),
            Command::Plain => {
                let rem = self.remembered(peer);
                if !policy::plain_allowed(rem.setting) {
                    format!(
                        "{pre}/e2e plain does nothing here: encryption is on in this chat by your choice, so nothing goes to {peer} unencrypted. Type /e2e off first."
                    )
                } else if rem.setting == Setting::Off {
                    format!(
                        "{pre}Encryption is off in this chat already: messages to {peer} go unencrypted."
                    )
                } else {
                    self.plain_once.insert(p);
                    format!(
                        "{pre}The next message to {peer} goes unencrypted, once: the server can read it. The messages after it are protected again."
                    )
                }
            }
            Command::Safety => self.safety(peer, now),
            Command::Verify => self.verify(peer, now),
            Command::Unverify => {
                self.safety_shown.remove(&p);
                if self.keys.unverify(peer) {
                    self.changed = true;
                    format!(
                        "{pre}{peer} is no longer marked verified. Messages to {peer} are still encrypted."
                    )
                } else {
                    format!("{pre}{peer} was not marked verified.")
                }
            }
            Command::Accept => {
                if self.keys.pinned(peer).is_some_and(|k| k.held) {
                    self.keys.unverify(peer);
                    self.changed = true;
                    format!(
                        "{pre}Messages to {peer} go on, encrypted to their new key, without verifying it: {peer} is not verified now. Type /e2e safety to compare the number when you can."
                    )
                } else {
                    format!(
                        "{pre}/e2e accept does nothing here: no message to {peer} is held for a changed safety number."
                    )
                }
            }
            Command::ResetLog => {
                self.keys.log = kt::LogState::default();
                self.keys.inbound_gate = keys::InboundGate::Open;
                self.log_synced_at = None;
                self.log_status = LogStatus::Unknown;
                self.audit_status = AuditStatus::Unknown;
                self.said.remove("kt:broken");
                self.changed = true;
                format!(
                    "{pre}Your copy of the server's key log is forgotten: it is read anew, and its key trusted on first use again. Do this only when the server's operator says the log was restored from a backup or started afresh."
                )
            }
            Command::Help => format!(
                "{pre}Unknown command. The commands are: {}.",
                policy::COMMANDS
            ),
        };
        // A command that looked the contact up may have found their safety
        // number changed; that is said first.
        self.drain_pin_notes(peer);
        // What decides whom to trust is also shown where the network cannot
        // write (fifth audit of 2026-10, finding 2).
        if matches!(
            cmd,
            Command::Safety | Command::Verify | Command::Unverify | Command::Accept
        ) {
            crate::alert::raise(&format!("cmd:{note}"), &note, now);
        }
        self.queue(Note::to(peer, note));
        true
    }

    fn outbound(&mut self, peer: &str, form: Form, text: &[u8], now: u64) -> Outbound {
        if let Some(note) = self.locked_out_note(peer, true) {
            return Outbound::Refused(note);
        }
        let contact = match self.decide(peer, now, true) {
            Decision::Encrypt(c) => c,
            Decision::Hold(why) => {
                // A change of the safety number found by this lookup is said
                // before the hold that follows from it.
                self.drain_pin_notes(peer);
                return self.hold(peer, why);
            }
            Decision::Clear(why) => {
                let note = match why {
                    ClearWhy::Off => {
                        self.show_status(peer, Status::Off);
                        policy::status_note(peer, Status::Off)
                    }
                    ClearWhy::NoKeys => {
                        self.show_status(peer, Status::Unavailable);
                        policy::status_note(peer, Status::Unavailable)
                    }
                    ClearWhy::Plain => {
                        let n = format!(
                            "{}This message to {peer} was sent unencrypted, as asked with /e2e plain.",
                            policy::PREFIX
                        );
                        self.queue(Note::to(peer, n.clone()));
                        n
                    }
                    ClearWhy::NotPublished => {
                        let n = format!(
                            "[ICQ E2E] Messages to {peer} are sent unencrypted: the keys are not published yet."
                        );
                        self.note_once(
                            Some(peer),
                            format!("unpublished:{}", sign::ident(peer)),
                            n.clone(),
                        );
                        n
                    }
                    ClearWhy::Unreachable(e) => {
                        let n = format!(
                            "[ICQ E2E] The key directory could not be reached ({e}); messages to {peer} go unencrypted."
                        );
                        self.queue(Note::to(peer, n.clone()));
                        n
                    }
                };
                return Outbound::Clear {
                    text: String::from_utf8_lossy(text).into_owned(),
                    note,
                };
            }
        };
        let out = keys::Outgoing {
            peer: peer.to_string(),
            form,
            text: text.to_vec(),
            now,
        };
        let Some(bearer) = self.bearer() else {
            return self.hold(peer, Held::NotPublished);
        };
        if let Some(why) = self.waits_for_save(peer) {
            return Outbound::Refused(self.not_saved(peer, &why, true));
        }
        self.changed = true;
        match self.keys.encrypt(&*self.dir, &bearer, &out, &contact) {
            Ok(Outbound::Encrypted(wire)) => {
                // The ratchet moved on: the message goes out only once that
                // is on disk, or a restart could send another message under
                // the same key (audit 2026-10, finding 5).
                if let Err(why) = self.persist_now() {
                    return Outbound::Refused(self.not_saved(peer, &why, true));
                }
                self.count(peer);
                self.show_status(peer, Status::On);
                // Encrypting may have made a note (a pinned key that changed);
                // it waits for the stream like any other.
                self.drain_pin_notes(peer);
                Outbound::Encrypted(wire)
            }
            // The contact was checked usable above, so this does not happen;
            // if it did, it would not be a reason to send clear text.
            Ok(Outbound::Clear { .. }) => self.hold(peer, Held::Downgrade),
            Ok(Outbound::Refused(note)) => {
                self.queue(Note::to(peer, note.clone()));
                Outbound::Refused(note)
            }
            Err(e) => {
                let note = format!("[ICQ E2E] The message to {peer} was not sent: {e}.");
                self.queue(Note::to(peer, note.clone()));
                Outbound::Refused(note)
            }
        }
    }

    fn inbound(
        &mut self,
        peer: &str,
        container: &crate::container::Container,
        now: u64,
    ) -> Inbound {
        if let Some(note) = self.locked_out_note(peer, false) {
            return Inbound::Unreadable(note);
        }
        // A new session from a key our copy of the key log does not have may
        // only mean the copy is behind: once more with a fresh one. A message
        // that did not open left no ratchet step and spent no one-time key.
        // Only a pre-key message can make a new session.
        let pre_key = container
            .wrap_for(self.keys.device_id)
            .is_some_and(|w| w.olm_type == 0);
        // Every message, not only a pre-key one: a device the log no longer
        // shows loses its session here (audit 2026-10, finding 2).
        let fresh = self.sync_log(now, false) && pre_key;
        // What the message may change, to put back if it cannot be saved.
        let before = self.persist.is_some().then(|| self.keys.snapshot(peer));
        let mut got = self.keys.decrypt(&*self.dir, peer, container, now);
        if pre_key
            && matches!(got, Inbound::Unreadable(_))
            && self.keys.inbound_gate != keys::InboundGate::Open
            && !fresh
        {
            self.sync_log(now, true);
            got = self.keys.decrypt(&*self.dir, peer, container, now);
        }
        self.changed = true;
        // What opened moved the ratchet on: it reaches the client only once
        // that is on disk (audit 2026-10, finding 5). Otherwise it is
        // dropped with a note and the keys go back to what the disk has; the
        // sender sends again, or the server's offline copy comes again, and
        // it opens then.
        if matches!(got, Inbound::Text { .. } | Inbound::Control(_)) {
            if let Err(why) = self.persist_now() {
                // Memory goes back to what the disk has, so the same message
                // opens when it comes again.
                if let Some(before) = before {
                    self.keys.restore(before);
                }
                return Inbound::Unreadable(self.not_saved(peer, &why, false));
            }
        }
        // When the sender wrote it, by the sender's clock: an announcement
        // vouches only while that is fresh (seventh audit of 2026-10).
        let sent = self.keys.last_sent_at;
        // A tZer's announcement (sixth audit of 2026-10, finding 4): kept
        // for the tZer that follows it, whatever calls and files do.
        if let Inbound::Control(payload) = &got {
            if let Some(n) = crate::tzer::Notice::decode(payload) {
                let p = sign::ident(peer);
                self.tzer_notices
                    .retain(|(_, _, at)| announcement_fresh(*at, now));
                if announcement_fresh(sent, now) {
                    if self.tzer_notices.len() >= crate::tzer::MAX_NOTICES {
                        self.tzer_notices.remove(0);
                    }
                    self.tzer_notices.push((p, n.hash, sent));
                }
                self.remember(peer, |r| r.seen_encrypting = true);
                return got;
            }
        }
        // A call key exchange (`calls_encrypt=on` only): it goes to the call
        // table and is answered by the call's own SIP, not by a control
        // message of ours. Off, it is taken below like any control message,
        // as an add-on without call support takes it.
        if self.calls_encrypt {
            if let Inbound::Control(payload) = &got {
                if let Some(msg) = crate::callneg::Msg::decode(payload) {
                    let table = self.calls.clone();
                    lock_calls(&table).control(
                        peer,
                        container.sender_device,
                        msg,
                        sent,
                        now * 1000,
                    );
                    self.remember(peer, |r| r.seen_encrypting = true);
                    return got;
                }
            }
        }
        // The same for a file transfer's key exchange (`files_encrypt=on`).
        if self.files_encrypt {
            if let Inbound::Control(payload) = &got {
                if let Some(msg) = crate::filesneg::Msg::decode(payload) {
                    let table = self.files.clone();
                    crate::filesneg::lock(&table).control(
                        peer,
                        container.sender_device,
                        msg,
                        sent,
                        now * 1000,
                    );
                    self.remember(peer, |r| r.seen_encrypting = true);
                    return got;
                }
            }
        }
        match &got {
            // An incoming key exchange means the contact may keep sending them,
            // so one control message of our own is due (CHECKLIST 2.2). It is
            // an encrypted exchange too, so the contact is remembered as
            // encrypting; nothing is shown for it.
            Inbound::Control(_) => {
                let p = sign::ident(peer);
                if !self.owed_control.contains(&p) {
                    self.owed_control.push(p);
                }
                self.remember(peer, |r| r.seen_encrypting = true);
            }
            Inbound::Unreadable(note) => self.queue(Note::to(peer, note.clone())),
            Inbound::Text { .. } => {
                self.encrypted_from(peer);
                self.drain_pin_notes(peer);
            }
        }
        got
    }

    fn unsupported(&mut self, peer: &str, version: u8, scheme: u8) -> Inbound {
        let note = keys::unsupported(&sign::ident(peer), version, scheme);
        self.queue(Note::to(peer, note.clone()));
        Inbound::Unreadable(note)
    }

    fn take_note(&mut self) -> Option<Note> {
        if self.calls_encrypt {
            let table = self.calls.clone();
            let mut t = lock_calls(&table);
            self.notes.extend(t.take_notes());
        }
        if self.files_encrypt {
            let table = self.files.clone();
            let mut t = crate::filesneg::lock(&table);
            self.notes.extend(t.take_notes());
        }
        if self.notes.is_empty() {
            None
        } else {
            Some(self.notes.remove(0))
        }
    }

    fn take_control(&mut self, peer: &str) -> Option<Vec<u8>> {
        if self.locked_out.is_some() {
            return None;
        }
        // A call's confirmation that no SIP message has carried yet.
        if self.calls_encrypt {
            let table = self.calls.clone();
            let waiting = lock_calls(&table).take_outbox(peer);
            if let Some(payload) = waiting {
                match self.encrypt_call_payload(peer, &payload, unix_now()) {
                    Ok(c) => return Some(c),
                    Err(why) => lock_calls(&table).send_failed(&payload, &why),
                }
            }
        }
        // A file answer that no rendezvous ICBM has carried yet.
        if self.files_encrypt {
            let table = self.files.clone();
            let waiting = crate::filesneg::lock(&table).take_outbox(peer);
            if let Some(payload) = waiting {
                match self.encrypt_call_payload(peer, &payload, unix_now()) {
                    Ok(c) => return Some(c),
                    Err(why) => crate::filesneg::lock(&table).send_failed(&payload, &why),
                }
            }
        }
        let p = sign::ident(peer);
        let owed = self.owed_control.iter().any(|x| *x == p);
        let due = self.counted.get(&p).copied().unwrap_or(0) >= HEARTBEAT;
        if !owed && !due {
            return None;
        }
        self.owed_control.retain(|x| *x != p);
        self.counted.insert(p.clone(), 0);

        let bearer = self.bearer()?;
        let contact = self.contact(peer, unix_now()).ok()?;
        // Nothing, not even an empty control message, goes to a changed key
        // of a verified contact before the user accepts it.
        if self.keys.pinned(peer).is_some_and(|k| k.held) {
            return None;
        }
        // A control message is an empty container: it carries no text, only the
        // ratchet step, and it never gets stored offline.
        let out = keys::Outgoing {
            peer: peer.to_string(),
            form: Form::Fragment {
                charset: 0,
                language: 0,
            },
            text: Vec::new(),
            now: unix_now(),
        };
        if self.waits_for_save(peer).is_some() {
            return None;
        }
        self.changed = true;
        match self.keys.encrypt(&*self.dir, &bearer, &out, &contact) {
            Ok(Outbound::Encrypted(wire)) => {
                if self.persist_now().is_err() {
                    self.unsaved.insert(sign::ident(peer));
                    return None;
                }
                container::find_armor(&wire)
            }
            Ok(Outbound::Refused(note)) => {
                self.queue(Note::to(peer, note));
                None
            }
            _ => None,
        }
    }

    fn since_control(&self, peer: &str) -> u32 {
        self.counted.get(&sign::ident(peer)).copied().unwrap_or(0)
    }

    /// Unknown while locked out: the keys in memory are a stand-in, and the
    /// contact's real setting is in the state file this engine cannot read.
    fn strictness(&self, peer: &str) -> Option<bool> {
        if self.locked_out.is_some() {
            return None;
        }
        Some(self.peer_info(peer).strict)
    }

    /// Fifth audit of 2026-10, finding 1: protected - switched on by hand,
    /// seen encrypting, or verified (also a verified contact whose key
    /// changed and is held) - means nothing unauthenticated is shown in the
    /// contact's name; `/e2e off` shows it; a contact never seen encrypting
    /// is shown, as without the add-on. Locked out, the contact's settings
    /// are in a state file this engine cannot read: refused.
    fn plain_inbound(&mut self, peer: &str, now: u64) -> Option<String> {
        let why = self.protected(peer)?;
        plain_dropped(&mut self.plain_said, &mut self.notes, peer, &why, now);
        Some(why)
    }

    fn protected(&self, peer: &str) -> Option<String> {
        match &self.locked_out {
            Some(locked) => Some(format!(
                "the add-on cannot read its settings for {peer}: {locked}"
            )),
            None => {
                let verified = self
                    .keys
                    .pinned(peer)
                    .is_some_and(|p| p.is_verified() || p.held);
                policy::plain_inbound_refusal(peer, Some(self.remembered(peer)), verified)
            }
        }
    }

    fn unauthenticated(&mut self, peer: &str, what: &str, note: String, now: u64) {
        unauthenticated_note(&mut self.plain_said, &mut self.notes, peer, what, note, now);
    }

    /// A call or a file proposal is authenticated by the key offer that
    /// came for it (or by the call or transfer it belongs to, which only
    /// such an offer, or our own side, started); a tZer by its `IQT1`.
    /// Locked out, nothing is.
    fn authenticated(&mut self, action: &Action, consume: bool, now: u64) -> bool {
        if self.locked_out.is_some() {
            return false;
        }
        // Seventh audit of 2026-10: the contact, the action's id, the digest
        // of its signalling and a fresh sender's time - never "the id is in
        // a table".
        match action {
            Action::Call { peer, call_id, sdp } => {
                self.calls_encrypt
                    && lock_calls(&self.calls).vouched(peer, call_id, sdp, now * 1000)
            }
            Action::CallAnswer { peer, call_id, sdp } => {
                !self.calls_encrypt || lock_calls(&self.calls).answer_vouched(peer, call_id, sdp)
            }
            Action::File {
                peer,
                cookie,
                digest,
            } => {
                self.files_encrypt
                    && crate::filesneg::lock(&self.files).vouched(peer, cookie, digest, now * 1000)
            }
            Action::Tzer { peer, hash } => {
                let p = sign::ident(peer);
                let at = self.tzer_notices.iter().position(|(who, h, sent)| {
                    *who == p && h == hash && announcement_fresh(*sent, now)
                });
                match at {
                    Some(i) => {
                        if consume {
                            self.tzer_notices.remove(i);
                        }
                        true
                    }
                    None => false,
                }
            }
        }
    }

    fn refused(&mut self, action: &Action, now: u64) {
        match action {
            Action::Call { call_id, .. } => lock_calls(&self.calls).refuse(call_id, now * 1000),
            Action::File { cookie, .. } => {
                crate::filesneg::lock(&self.files).refuse(cookie, now * 1000)
            }
            Action::CallAnswer { .. } | Action::Tzer { .. } => {}
        }
    }

    fn tzer_notice(&mut self, peer: &str, hash: [u8; 16], now: u64) -> Option<Vec<u8>> {
        if self.locked_out.is_some() {
            return None;
        }
        let payload = crate::tzer::Notice { hash }.encode();
        self.encrypt_call_payload(peer, &payload, now).ok()
    }

    fn note(&mut self, peer: &str, text: String) {
        self.queue(Note::to(peer, text));
    }

    fn call_sip(
        &mut self,
        dir: crate::icbm::Direction,
        peer: &str,
        sip: &[u8],
        now: u64,
        lines: &mut Vec<String>,
    ) -> Vec<Vec<u8>> {
        if !self.calls_encrypt {
            return Vec::new();
        }
        let Some(parsed) = crate::callneg::Sip::parse(sip) else {
            return Vec::new();
        };
        let info = self.peer_info(peer);
        let table = self.calls.clone();
        let payloads = {
            let mut t = lock_calls(&table);
            let mut me = || self.call_me(peer, now);
            t.sip(dir, peer, &parsed, info, &mut me, now * 1000)
        };
        let mut out = Vec::new();
        for p in payloads {
            match self.encrypt_call_payload(peer, &p, now) {
                Ok(c) => out.push(c),
                Err(why) => lock_calls(&table).send_failed(&p, &why),
            }
        }
        lines.extend(lock_calls(&table).take_log());
        out
    }

    fn file_icbm(
        &mut self,
        rdv: &crate::files::Rendezvous,
        now: u64,
        lines: &mut Vec<String>,
    ) -> Vec<Vec<u8>> {
        if !self.files_encrypt {
            return Vec::new();
        }
        let peer = rdv.peer.clone();
        let info = self.peer_info(&peer);
        let table = self.files.clone();
        let payloads = {
            let mut t = crate::filesneg::lock(&table);
            let mut me = || self.call_me(&peer, now);
            t.icbm(rdv, info, &mut me, now * 1000)
        };
        let mut out = Vec::new();
        for p in payloads {
            match self.encrypt_call_payload(&peer, &p, now) {
                Ok(c) => out.push(c),
                Err(why) => crate::filesneg::lock(&table).send_failed(&p, &why),
            }
        }
        lines.extend(crate::filesneg::lock(&table).take_log());
        out
    }
}

/// How an engine writes its state file: [`crate::session::Session`] gives it
/// one over its [`crate::store::Store`].
pub type Persist = Box<dyn FnMut(&OwnKeys) -> Result<(), String> + Send>;

/// The call table, even if a panic poisoned its lock.
fn lock_calls(
    t: &std::sync::Mutex<crate::callneg::CallTable>,
) -> std::sync::MutexGuard<'_, crate::callneg::CallTable> {
    t.lock().unwrap_or_else(|e| e.into_inner())
}

/// Why a contact was not found, which decides whether the answer is worth
/// remembering: a fact about them, or a moment when the directory was down.
enum Lookup {
    /// The directory has no account for this contact, or no device of theirs
    /// checks out.
    NoKeys,
    /// The directory could not be reached, or did not answer.
    Transient(String),
    /// The directory gives the contact an account key the key log does not
    /// show for them.
    NotInLog(String),
    /// The key log cannot vouch for the contact's keys right now: it cannot
    /// be read, no auditor has vouched for it lately, or the auditors have
    /// not reached them yet. Held, not an attack in itself.
    NotYet(String),
}

/// Why the key log cannot vouch for anything new, for
/// [`Engine::frozen_log_check`].
enum Frozen<'a> {
    Broken(&'a str),
    Unavailable(&'a str),
    Unaudited(&'a str),
}

impl Frozen<'_> {
    /// `what` (a contact never checked, a changed key) refused for this
    /// reason.
    fn lookup(&self, what: String) -> Lookup {
        match self {
            Frozen::Broken(why) => Lookup::NotInLog(format!(
                "{what} while the server's key log is broken ({why}); it is not taken until the log is trusted again (/e2e resetlog once the operator explains)"
            )),
            Frozen::Unavailable(why) => Lookup::NotYet(format!(
                "{what}, and the server's key log cannot be read right now ({why}); it is taken once the log can be checked again"
            )),
            Frozen::Unaudited(why) => Lookup::NotYet(format!(
                "{what}, and no auditor has vouched for the server's key log lately ({why}); it is taken once one has"
            )),
        }
    }
}

/// What the key log's auditor said, last time we looked (stage 2).
#[derive(Debug, Clone, PartialEq, Eq)]
enum AuditStatus {
    /// Not looked at yet this sign-on.
    Unknown,
    /// The server names no auditor.
    None,
    /// Every trusted auditor's cosignature agrees with our copy, and at
    /// least one is recent; what each of them last said.
    Ok(Vec<kt::AuditorView>),
    /// The auditor's cosignatures could not be read just now.
    Failed(String),
    /// No recent cosignature, or one that does not agree with our copy.
    Stale(String),
}

/// How the last look at the key log went.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LogStatus {
    /// Not looked at yet this sign-on.
    Unknown,
    /// Our copy is up to date and adds up: contacts' keys are checked
    /// against it.
    Ok,
    /// The server keeps no log, and we never saw one.
    NoLog,
    /// The log could not be read just now; nothing is checked against it
    /// until it can be.
    Failed(String),
    /// The log was rewritten or is signed by another key: the user was told,
    /// and nothing is checked against it.
    Broken(String),
}

/// The current time in Unix seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::MemoryDirectory;
    use crate::keys;
    use crate::keys::FALLBACK_KEY_LIFETIME;
    use crate::token::Token;
    use std::time::Instant;

    const NOW: u64 = 1_790_000_000;

    fn bearer(dir: &MemoryDirectory, who: &str) -> String {
        Token::parse(&dir.token(who)).unwrap().bearer
    }

    /// Announces `keys`' account key, which the API wants before a first publish.
    fn announce(dir: &MemoryDirectory, keys: &OwnKeys) {
        let key = keys.account_key_bytes();
        dir.announce(&keys.screen_name, &key);
    }

    #[test]
    fn publishing_walks_the_api_in_its_order() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut keys = OwnKeys::create("100001");
        announce(&dir, &keys);
        let p = Publisher::new(dir.clone());

        let done = match p.publish(
            &mut keys,
            &bearer(&dir, "100001"),
            Published::default(),
            NOW,
        ) {
            Progress::Done(d) => d,
            other => panic!("expected a completed publish, got {other:?}"),
        };
        assert!(done.account && done.device && done.fallback);
        assert_eq!(done.one_time, ONE_TIME_TARGET, "a full pool is published");
        // The order the API was called in: account, device, pool, fallback.
        let log = dir.requests();
        assert_eq!(log[0], "PUT account", "the account key goes first");
        assert!(log
            .iter()
            .any(|r| r == &format!("PUT devices/{}", keys.device_id)));
        assert!(log.iter().any(|r| r.contains("one-time-keys")));
        assert!(log.iter().any(|r| r.contains("fallback-key")));
    }

    #[test]
    fn an_unannounced_key_is_waited_for_and_then_published() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut keys = OwnKeys::create("100001");
        let p = Publisher::new(dir.clone());

        // No announcement yet: the API says so and nothing else is tried.
        let first = p.publish(
            &mut keys,
            &bearer(&dir, "100001"),
            Published::default(),
            NOW,
        );
        assert!(
            matches!(first, Progress::Wait { .. }),
            "an unannounced key must wait, got {first:?}"
        );
        assert!(
            dir.requests().iter().all(|r| r == "PUT account"),
            "only the account step ran, and it stopped there: {:?}",
            dir.requests()
        );

        // Once the client has sent its SetInfo, the same call goes through.
        announce(&dir, &keys);
        assert!(matches!(
            p.publish(
                &mut keys,
                &bearer(&dir, "100001"),
                Published::default(),
                NOW
            ),
            Progress::Done(_)
        ));
    }

    #[test]
    fn publishing_again_does_not_spend_a_second_pool() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut keys = OwnKeys::create("100001");
        announce(&dir, &keys);
        let p = Publisher::new(dir.clone());
        let done = match p.publish(
            &mut keys,
            &bearer(&dir, "100001"),
            Published::default(),
            NOW,
        ) {
            Progress::Done(d) => d,
            other => panic!("{other:?}"),
        };

        // A second sign-on with the pool still full must not upload again, and
        // must not claim to have: `Quiet` is what says "nothing was sent", and
        // it is the difference between one line in the log and one every two
        // seconds for as long as the client runs.
        let before = dir.requests().len();
        let again = match p.publish(&mut keys, &bearer(&dir, "100001"), done, NOW) {
            Progress::Quiet(d) => d,
            other => panic!("a second publish with a full pool must be quiet, got {other:?}"),
        };
        assert_eq!(again, done, "nothing changed, so nothing was published");
        assert_eq!(dir.requests().len(), before);
    }

    #[test]
    fn a_low_pool_is_topped_up_and_a_full_one_is_not() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut keys = OwnKeys::create("100001");
        announce(&dir, &keys);
        let p = Publisher::new(dir.clone());
        let done = match p.publish(
            &mut keys,
            &bearer(&dir, "100001"),
            Published::default(),
            NOW,
        ) {
            Progress::Done(d) => d,
            other => panic!("{other:?}"),
        };

        // The pool has really fallen: a contact opened sessions against it, so
        // the private halves are gone from our account too, not only from the
        // directory's count.
        let mut low = done;
        low.one_time = ONE_TIME_REFILL_BELOW - 1;
        // A one-time key is spent per *session*, so each peer is a separate
        // account: one pre-key message each, and one of our keys gone.
        for i in 0..(ONE_TIME_TARGET - ONE_TIME_REFILL_BELOW + 1) {
            let uin = format!("1000{:02}", 10 + i);
            let mut peer = OwnKeys::create(&uin);
            announce(&dir, &peer);
            let pb = bearer(&dir, &uin);
            let (pk, psig) = peer.account_object();
            dir.put_account(&pb, &pk, &psig).unwrap();
            let (curve, ed, sig) = peer.device_object().unwrap();
            dir.put_device(&pb, peer.device_id, &curve, &ed, &sig)
                .unwrap();

            let contact = keys::fetch_contact(&dir, "100001").unwrap();
            let out = keys::Outgoing {
                peer: "100001".into(),
                form: Form::Fragment {
                    charset: 2,
                    language: 0,
                },
                text: format!("claim {i}").into_bytes(),
                now: NOW,
            };
            // The peer encrypts to us and we open it, which is what spends one
            // of our one-time keys.
            let wire = match peer.encrypt(&dir, &pb, &out, &contact).unwrap() {
                Outbound::Encrypted(w) => w,
                other => panic!("{other:?}"),
            };
            let c = crate::container::Container::from_bytes(
                &crate::container::find_armor(&wire).unwrap(),
            )
            .unwrap();
            let got = keys.decrypt(&dir, &uin, &c, NOW);
            assert!(matches!(got, Inbound::Text { .. }), "claim {i}: {got:?}");
        }
        // 26 sessions spent 26 keys, so the pool is below the mark of 25 - which
        // is exactly the state the refill exists for.
        assert!(
            pool_low(dir.pool("100001", keys.device_id) as u32),
            "the pool must have fallen under the mark, it is {}",
            dir.pool("100001", keys.device_id)
        );
        let filled = match p.publish(&mut keys, &bearer(&dir, "100001"), low, NOW) {
            Progress::Done(d) => d,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            filled.one_time, ONE_TIME_TARGET,
            "a refill brings the pool back to the target, not past it"
        );
        assert_eq!(dir.pool("100001", keys.device_id), ONE_TIME_TARGET as usize);

        // Just at the mark is still enough: the refill is below it, not at it.
        assert!(!pool_low(ONE_TIME_REFILL_BELOW));
        assert!(pool_low(ONE_TIME_REFILL_BELOW - 1));
    }

    #[test]
    fn a_device_whose_id_is_taken_takes_a_new_one() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut keys = OwnKeys::create("100001");
        announce(&dir, &keys);
        let p = Publisher::new(dir.clone());
        p.publish(
            &mut keys,
            &bearer(&dir, "100001"),
            Published::default(),
            NOW,
        );
        let first_id = keys.device_id;

        // The directory now holds a different device under this id.
        dir.revoke("100001", first_id);

        let note = match p.publish(
            &mut keys,
            &bearer(&dir, "100001"),
            Published::default(),
            NOW,
        ) {
            Progress::Retry { note } => note,
            other => panic!("a taken id must be retried under a new one, got {other:?}"),
        };
        assert_ne!(keys.device_id, first_id);
        assert!(note.contains(&first_id.to_string()), "{note}");

        // The account key is the same one - it belongs to the UIN, not a device.
        assert!(matches!(
            p.publish(
                &mut keys,
                &bearer(&dir, "100001"),
                Published::default(),
                NOW
            ),
            Progress::Done(_)
        ));
    }

    #[test]
    fn another_active_device_turns_encryption_off_rather_than_forcing_a_key_change() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut keys = OwnKeys::create("100001");
        announce(&dir, &keys);
        let p = Publisher::new(dir.clone());
        p.publish(
            &mut keys,
            &bearer(&dir, "100001"),
            Published::default(),
            NOW,
        );

        // A second device of the same UIN: a different Olm account under the
        // same account key, which is what another signed-in client looks like.
        let mut other = OwnKeys::create("100001");
        other.account_key = keys.account_key;
        other.device_id = keys.device_id.wrapping_add(1);
        let t = bearer(&dir, "100001");
        let (curve, ed, sig) = other.device_object().unwrap();
        dir.put_device(&t, other.device_id, &curve, &ed, &sig)
            .unwrap();

        // Resetting to a different account key while that device is active is
        // refused: the directory will not drop a device that is signed in.
        let mut reset = OwnKeys::create("100001");
        reset.device_id = keys.device_id;
        announce(&dir, &reset);
        let (key, signature) = reset.account_object();
        let e = dir.put_account(&t, &key, &signature).unwrap_err();
        assert_eq!(e.code(), "active_devices");
        assert!(
            matches!(p.react(e, "the account key"), Progress::Off { .. }),
            "a key change the directory will not take is not a key change"
        );
    }

    #[test]
    fn an_unreachable_directory_is_retried_and_keeps_the_keys() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut keys = OwnKeys::create("100001");
        announce(&dir, &keys);
        let p = Publisher::new(dir.clone());
        let before = keys.account_key_b64();
        dir.set_offline(true);

        assert!(matches!(
            p.publish(
                &mut keys,
                &bearer(&dir, "100001"),
                Published::default(),
                NOW
            ),
            Progress::Retry { .. }
        ));
        assert_eq!(keys.account_key_b64(), before, "an outage changes nothing");

        // And the next attempt goes through once it is back.
        dir.set_offline(false);
        assert!(matches!(
            p.publish(
                &mut keys,
                &bearer(&dir, "100001"),
                Published::default(),
                NOW
            ),
            Progress::Done(_)
        ));
    }

    #[test]
    fn the_wait_between_attempts_is_bounded() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut keys = OwnKeys::create("100001");
        let p = Publisher::new(dir.clone());
        let start = Instant::now();
        let mut again;
        // The same wait the worker would make, bounded so the test is quick.
        loop {
            match p.publish(
                &mut keys,
                &bearer(&dir, "100001"),
                Published::default(),
                NOW,
            ) {
                Progress::Wait { again: a, .. } => {
                    again = a;
                    if start.elapsed() > ANNOUNCE_RETRY / 20 {
                        break;
                    }
                    std::thread::sleep(a);
                }
                other => panic!("nothing announced, so every attempt waits: {other:?}"),
            }
        }
        assert!(again <= ANNOUNCE_EVERY);
        assert!(ANNOUNCE_EVERY * 15 <= ANNOUNCE_RETRY);
    }

    #[test]
    fn a_token_is_refreshed_an_hour_before_it_expires() {
        let hour = 3600u64;
        // Comfortably valid: nothing to do.
        assert_eq!(
            until_expiry(NOW, NOW + 5 * hour),
            Duration::from_secs(5 * hour)
        );
        assert!(
            !refresh_due(NOW, NOW + 5 * hour),
            "five hours is not yet an hour"
        );
        assert!(
            !refresh_due(NOW, NOW + hour + 60),
            "a minute past the hour is not yet due"
        );
        // At the hour, and inside it: refresh.
        assert!(
            refresh_due(NOW, NOW + hour),
            "exactly an hour left is due now"
        );
        assert!(
            refresh_due(NOW, NOW + hour - 60),
            "fifty-nine minutes left is due"
        );
        assert!(refresh_due(NOW, NOW + 60));
        // Already expired: the caller replaces it rather than waiting for it.
        assert_eq!(until_expiry(NOW, NOW - 1), Duration::ZERO);
        assert!(refresh_due(NOW, NOW - 1));
    }

    #[test]
    fn the_fallback_key_is_only_replaced_once_it_is_due() {
        let mut keys = OwnKeys::create("100001");
        assert!(
            fallback_due(&keys, NOW),
            "a device that never published one"
        );
        keys.rotate_fallback_key(NOW).unwrap();
        assert!(!fallback_due(&keys, NOW + FALLBACK_KEY_LIFETIME - 1));
        assert!(fallback_due(&keys, NOW + FALLBACK_KEY_LIFETIME));
    }

    // --- the engine ---------------------------------------------------------

    /// A two-party directory where both accounts are published, so the engine
    /// has real keys on both sides.
    fn two_published() -> (Arc<MemoryDirectory>, OwnKeys, OwnKeys) {
        let dir = Arc::new(MemoryDirectory::new());
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        for k in [&mut a, &mut b] {
            announce(&dir, k);
            let t = bearer(&dir, &k.screen_name);
            let (key, sig) = k.account_object();
            dir.put_account(&t, &key, &sig).unwrap();
            let (curve, ed, dsig) = k.device_object().unwrap();
            dir.put_device(&t, k.device_id, &curve, &ed, &dsig).unwrap();
            let pool = k.new_one_time_keys(0);
            dir.upload_one_time_keys(&t, k.device_id, &pool).unwrap();
        }
        (dir, a, b)
    }

    fn form() -> Form {
        Form::Fragment {
            charset: 2,
            language: 0,
        }
    }

    #[test]
    fn a_message_is_encrypted_only_after_the_keys_are_published() {
        let (dir, keys, _) = two_published();
        let mut e = Engine::new(dir.clone(), keys);
        e.set_token(&dir.token("100001"));
        assert!(!e.ready(), "a fresh engine has published nothing");

        // Not ready: the text goes out as it is, with a note saying why.
        match e.outbound("100002", form(), b"hi", NOW) {
            Outbound::Clear { text, note } => {
                assert_eq!(text, "hi");
                assert!(note.contains("not published"), "{note}");
            }
            other => panic!("nothing may be encrypted before publishing, got {other:?}"),
        }

        assert!(matches!(e.publish(NOW), Progress::Done(_)));
        assert!(e.ready());
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));

        // The pool is refilled and the keys checked every two seconds, and those
        // passes send nothing. A pass that changes nothing must leave encryption
        // on: reading it as anything short of done would switch messages back to
        // clear text a second after they started being encrypted.
        for _ in 0..5 {
            assert!(
                matches!(e.publish(NOW + 2), Progress::Quiet(_)),
                "a full pool needs no publishing"
            );
            assert!(e.ready(), "and encryption stays on");
            assert!(
                matches!(
                    e.outbound("100002", form(), b"hi", NOW + 2),
                    Outbound::Encrypted(_)
                ),
                "so the next message is still encrypted"
            );
        }
    }

    #[test]
    fn a_message_travels_through_the_engine_and_comes_back_as_text() {
        let (dir, a, b) = two_published();
        let mut ea = Engine::new(dir.clone(), a);
        let mut eb = Engine::new(dir.clone(), b);
        ea.set_token(&dir.token("100001"));
        eb.set_token(&dir.token("100002"));
        ea.publish(NOW);
        eb.publish(NOW);

        let wire = match ea.outbound("100002", form(), b"hello there", NOW) {
            Outbound::Encrypted(w) => w,
            other => panic!("{other:?}"),
        };
        assert_eq!(ea.since_control("100002"), 1);

        let bytes = container::find_armor(&wire).unwrap();
        let c = container::Container::from_bytes(&bytes).unwrap();
        match eb.inbound("100001", &c, NOW) {
            Inbound::Text { text, peer, .. } => {
                assert_eq!(text, b"hello there");
                assert_eq!(peer, "100001");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_contact_without_the_add_on_gets_clear_text_and_one_note() {
        let (dir, a, _) = two_published();
        // 100009 has published nothing, so the directory knows no devices.
        let mut e = Engine::new(dir.clone(), a);
        e.set_token(&dir.token("100001"));
        e.publish(NOW);

        let first = e.outbound("100009", form(), b"hi", NOW);
        let shown = match &first {
            Outbound::Clear { text, note } => {
                assert_eq!(text, "hi");
                note.clone()
            }
            other => panic!("{other:?}"),
        };
        assert!(shown.contains("unencrypted"), "{shown}");
        // A second message to the same contact makes no new note.
        assert!(matches!(
            e.outbound("100009", form(), b"again", NOW),
            Outbound::Clear { .. }
        ));
        // The note waits for the stream, addressed to that contact's chat. It
        // used to be taken out of the queue and written only to the log, so
        // the chat with a contact without the add-on never said anything.
        assert_eq!(
            notes(&mut e),
            vec![Note::to("100009", shown)],
            "the note is made once, for the chat with 100009"
        );
    }

    #[test]
    fn a_contact_known_to_be_clear_is_never_asked_again() {
        let (dir, a, _) = two_published();
        let mut e = Engine::new(dir.clone(), a);
        e.set_token(&dir.token("100001"));
        e.publish(NOW);
        e.outbound("100009", form(), b"hi", NOW);

        let before = dir.requests().len();
        for _ in 0..3 {
            assert!(matches!(
                e.outbound("100009", form(), b"hi", NOW),
                Outbound::Clear { .. }
            ));
        }
        assert_eq!(
            dir.requests().len(),
            before,
            "a contact known to be clear costs no directory call: {:?}",
            dir.requests()
        );
    }

    #[test]
    fn an_incoming_key_exchange_is_answered_once_with_a_control_message() {
        let (dir, a, b) = two_published();
        let mut ea = Engine::new(dir.clone(), a);
        let mut eb = Engine::new(dir.clone(), b);
        ea.set_token(&dir.token("100001"));
        eb.set_token(&dir.token("100002"));
        ea.publish(NOW);
        eb.publish(NOW);

        // b sends a control message to a: an empty container, no text.
        let empty = vec![];
        let wire = match eb.outbound("100001", form(), &empty, NOW) {
            Outbound::Encrypted(w) => w,
            other => panic!("{other:?}"),
        };
        let c = container::Container::from_bytes(&container::find_armor(&wire).unwrap()).unwrap();
        assert!(matches!(ea.inbound("100002", &c, NOW), Inbound::Control(_)));
        assert!(
            ea.since_control("100001") == 0,
            "a control message is not counted"
        );

        // a owes b one control message of its own, once.
        assert!(
            ea.take_control("100002").is_some(),
            "an exchange is answered"
        );
        assert!(ea.take_control("100002").is_none(), "and only once");
    }

    #[test]
    fn the_heartbeat_is_sent_after_fifty_messages_and_not_before() {
        let (dir, a, _) = two_published();
        let mut e = Engine::new(dir.clone(), a);
        e.set_token(&dir.token("100001"));
        e.publish(NOW);

        for _ in 0..(HEARTBEAT - 1) {
            assert!(matches!(
                e.outbound("100002", form(), b"x", NOW),
                Outbound::Encrypted(_)
            ));
            assert!(e.take_control("100002").is_none(), "not yet due");
        }
        assert!(matches!(
            e.outbound("100002", form(), b"x", NOW),
            Outbound::Encrypted(_)
        ));
        assert!(
            e.take_control("100002").is_some(),
            "fifty messages without one is the heartbeat"
        );
        assert_eq!(e.since_control("100002"), 0, "the count starts again");
    }

    #[test]
    fn a_control_message_is_an_empty_container() {
        let (dir, a, _) = two_published();
        let mut e = Engine::new(dir.clone(), a);
        e.set_token(&dir.token("100001"));
        e.publish(NOW);
        // Make one due by counting, then take it.
        for _ in 0..HEARTBEAT {
            let _ = e.outbound("100002", form(), b"x", NOW);
        }
        let bytes = e.take_control("100002").expect("due");
        let c = container::Container::from_bytes(&bytes).expect("a container");
        assert!(c.is_control(), "it carries the control flag");
    }

    #[test]
    fn an_unreachable_directory_leaves_messages_in_clear_and_says_why() {
        let (dir, a, _) = two_published();
        let mut e = Engine::new(dir.clone(), a);
        e.set_token(&dir.token("100001"));
        e.publish(NOW);
        dir.set_offline(true);

        // The note comes back with the message, so it is shown in this
        // conversation; it blames the directory, not the contact - an outage is
        // not their doing, and the contact is not remembered as clear.
        match e.outbound("100002", form(), b"hi", NOW) {
            Outbound::Clear { text, note } => {
                assert_eq!(text, "hi");
                assert!(
                    note.contains("could not be reached"),
                    "an outage is not the contact's doing: {note}"
                );
            }
            other => panic!("an outage must not produce an unopenable container: {other:?}"),
        }

        // And the outage is not remembered as "this contact has no add-on":
        // once the directory is back, the message is encrypted again.
        dir.set_offline(false);
        assert!(matches!(
            e.outbound("100002", form(), b"hi again", NOW),
            Outbound::Encrypted(_)
        ));
    }

    // --- the user's control (CHECKLIST 10) ------------------------------------

    /// Every note waiting, oldest first.
    fn notes(e: &mut Engine) -> Vec<Note> {
        std::iter::from_fn(|| e.take_note()).collect()
    }

    /// An engine for `keys` with its token and its keys published.
    fn running(dir: &Arc<MemoryDirectory>, keys: OwnKeys) -> Engine {
        let who = keys.screen_name.clone();
        let mut e = Engine::new(dir.clone(), keys);
        e.set_token(&dir.token(&who));
        assert!(matches!(e.publish(NOW), Progress::Done(_)));
        e
    }

    /// Puts `k`'s account, device and keys into the directory.
    fn publish_keys(dir: &MemoryDirectory, k: &mut OwnKeys) {
        announce(dir, k);
        let t = bearer(dir, &k.screen_name);
        let (key, sig) = k.account_object();
        dir.put_account(&t, &key, &sig).unwrap();
        let (curve, ed, dsig) = k.device_object().unwrap();
        dir.put_device(&t, k.device_id, &curve, &ed, &dsig).unwrap();
        let pool = k.new_one_time_keys(0);
        dir.upload_one_time_keys(&t, k.device_id, &pool).unwrap();
    }

    /// The container out of an encrypted message.
    fn container_of(out: Outbound) -> container::Container {
        let wire = match out {
            Outbound::Encrypted(w) => w,
            other => panic!("expected an encrypted message, got {other:?}"),
        };
        container::Container::from_bytes(&container::find_armor(&wire).unwrap()).unwrap()
    }

    /// The state file's round trip: what a restart reads back.
    fn restarted(dir: &Arc<MemoryDirectory>, e: &Engine) -> Engine {
        let json = serde_json::to_string(e.keys()).unwrap();
        running(dir, serde_json::from_str(&json).unwrap())
    }

    #[test]
    fn a_new_chat_is_encrypted_when_the_contact_has_keys_and_says_so_once() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        let n = notes(&mut e);
        assert_eq!(n.len(), 1, "{n:?}");
        assert_eq!(n[0].peer.as_deref(), Some("100002"));
        assert!(n[0].text.contains("Encryption is on"), "{n:?}");
        // The status is said when the chat is first used, not every message.
        assert!(matches!(
            e.outbound("100002", form(), b"again", NOW),
            Outbound::Encrypted(_)
        ));
        assert!(notes(&mut e).is_empty());
        // And it is remembered that 100002 encrypts.
        assert!(e.remembered("100002").seen_encrypting);
        assert!(e.take_changed(), "which the state file has to keep");
    }

    #[test]
    fn commands_are_recognised_and_answered_in_their_chat() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(!e.command("100002", "hello", NOW), "an ordinary message");
        assert!(e.command("100002", "/e2e status", NOW));
        let n = notes(&mut e);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].peer.as_deref(), Some("100002"));
        assert!(n[0].text.contains("1 signed device"), "{n:?}");
        assert!(n[0].text.contains("next message goes encrypted"), "{n:?}");

        assert!(e.command("100002", "/e2e nonsense", NOW));
        assert!(notes(&mut e)[0].text.contains("/e2e on, /e2e off"));
    }

    #[test]
    fn off_by_hand_sends_clear_and_survives_a_restart() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(e.command("100002", "/e2e off", NOW));
        assert!(notes(&mut e)[0].text.contains("Encryption is off"));
        assert!(e.take_changed(), "the setting goes into the state file");
        match e.outbound("100002", form(), b"hi", NOW) {
            Outbound::Clear { text, .. } => assert_eq!(text, "hi"),
            other => panic!("switched off, so clear text: {other:?}"),
        }
        assert!(
            notes(&mut e).is_empty(),
            "the status was said by the command"
        );

        let mut again = restarted(&dir, &e);
        assert_eq!(again.remembered("100002").setting, Setting::Off);
        assert!(matches!(
            again.outbound("100002", form(), b"hi", NOW),
            Outbound::Clear { .. }
        ));
        // A new sign-on says the status once, in that chat.
        let n = notes(&mut again);
        assert_eq!(n.len(), 1);
        assert!(n[0].text.contains("switched off by you"), "{n:?}");

        // And on again.
        assert!(again.command("100002", "/e2e on", NOW));
        assert!(matches!(
            again.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
    }

    #[test]
    fn a_contact_seen_encrypting_is_never_switched_to_clear_silently() {
        let (dir, a, b) = two_published();
        let b_device = b.device_id;
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        notes(&mut e);

        // The server now shows no keys for 100002 - after a restart, too.
        dir.revoke("100002", b_device);
        let mut e = restarted(&dir, &e);
        for _ in 0..2 {
            match e.outbound("100002", form(), b"secret", NOW) {
                Outbound::Refused(note) => assert!(note.contains("NOT sent"), "{note}"),
                other => panic!("held, never clear: {other:?}"),
            }
            let n = notes(&mut e);
            assert_eq!(n.len(), 1, "every held message is said: {n:?}");
            assert!(n[0].text.contains("used encryption before"), "{n:?}");
            assert!(n[0].text.contains("/e2e plain"), "{n:?}");
        }

        // `/e2e plain` lets exactly one message through.
        assert!(e.command("100002", "/e2e plain", NOW));
        notes(&mut e);
        match e.outbound("100002", form(), b"this one", NOW) {
            Outbound::Clear { text, .. } => assert_eq!(text, "this one"),
            other => panic!("{other:?}"),
        }
        assert!(notes(&mut e)[0].text.contains("as asked with /e2e plain"));
        assert!(
            matches!(
                e.outbound("100002", form(), b"next", NOW),
                Outbound::Refused(_)
            ),
            "and the one after it is held again"
        );
    }

    #[test]
    fn a_contact_never_seen_encrypting_is_trust_on_first_use() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(!e.remembered("100009").strict());
        assert!(matches!(
            e.outbound("100009", form(), b"hi", NOW),
            Outbound::Clear { .. }
        ));
    }

    #[test]
    fn on_by_hand_never_sends_clear_text() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(e.command("100009", "/e2e on", NOW));
        let n = notes(&mut e);
        assert!(n[0].text.contains("has no encryption keys yet"), "{n:?}");

        match e.outbound("100009", form(), b"hi", NOW) {
            Outbound::Refused(note) => assert!(note.contains("switched on by you"), "{note}"),
            other => panic!("{other:?}"),
        }
        notes(&mut e);
        // Not even with /e2e plain (10.8).
        assert!(e.command("100009", "/e2e plain", NOW));
        assert!(notes(&mut e)[0].text.contains("does nothing here"));
        assert!(matches!(
            e.outbound("100009", form(), b"hi", NOW),
            Outbound::Refused(_)
        ));
        // Only switching it off sends clear text.
        assert!(e.command("100009", "/e2e off", NOW));
        assert!(matches!(
            e.outbound("100009", form(), b"hi", NOW),
            Outbound::Clear { .. }
        ));
    }

    #[test]
    fn an_encrypted_message_switches_encryption_on() {
        let dir = Arc::new(MemoryDirectory::new());
        let mut a = OwnKeys::create("100001");
        publish_keys(&dir, &mut a);
        let mut ea = running(&dir, a);

        // 100002 has no keys yet: clear text, and the chat says so.
        assert!(matches!(
            ea.outbound("100002", form(), b"hi", NOW),
            Outbound::Clear { .. }
        ));
        assert!(notes(&mut ea)[0].text.contains("do not have the add-on"));

        // Then 100002 installs the add-on and writes, encrypted.
        let mut b = OwnKeys::create("100002");
        publish_keys(&dir, &mut b);
        let mut eb = running(&dir, b);
        let c = container_of(eb.outbound("100001", form(), b"now encrypted", NOW));
        assert!(matches!(
            ea.inbound("100002", &c, NOW),
            Inbound::Text { .. }
        ));
        let n = notes(&mut ea);
        assert_eq!(n.len(), 1, "{n:?}");
        assert!(n[0].text.contains("switched on"), "{n:?}");
        assert!(ea.remembered("100002").seen_encrypting);

        // The answer goes encrypted, though 100002 was known to be clear.
        assert!(matches!(
            ea.outbound("100002", form(), b"reply", NOW),
            Outbound::Encrypted(_)
        ));
        assert!(notes(&mut ea).is_empty(), "the status did not change");
    }

    #[test]
    fn switched_off_by_hand_an_encrypted_message_is_read_but_only_hinted() {
        let (dir, a, b) = two_published();
        let mut ea = running(&dir, a);
        let mut eb = running(&dir, b);
        assert!(ea.command("100002", "/e2e off", NOW));
        notes(&mut ea);

        for i in 0..2 {
            let c = container_of(eb.outbound("100001", form(), b"secret", NOW));
            // Always decrypted, whatever the setting (10.4).
            match ea.inbound("100002", &c, NOW) {
                Inbound::Text { text, .. } => assert_eq!(text, b"secret"),
                other => panic!("{other:?}"),
            }
            let n = notes(&mut ea);
            if i == 0 {
                assert_eq!(n.len(), 1, "{n:?}");
                assert!(n[0].text.contains("/e2e on to answer encrypted"), "{n:?}");
            } else {
                assert!(n.is_empty(), "the hint is given once: {n:?}");
            }
        }
        assert_eq!(
            ea.remembered("100002").setting,
            Setting::Off,
            "not switched on"
        );
        assert!(matches!(
            ea.outbound("100002", form(), b"hi", NOW),
            Outbound::Clear { .. }
        ));
    }

    #[test]
    fn the_capability_alone_decides_nothing() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        // The server strips the capability from the user info of 100002: the
        // directory still has their signed device, so it is encrypted.
        e.note_contacts(&[("100002".to_string(), false)]);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));

        // A contact announcing the add-on, with the directory down: held, not
        // sent in clear.
        e.note_contacts(&[("100007".to_string(), true)]);
        dir.set_offline(true);
        assert!(matches!(
            e.outbound("100007", form(), b"hi", NOW),
            Outbound::Refused(_)
        ));
        // And so is one seen encrypting before.
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Refused(_)
        ));
        // One never seen and not announcing goes in clear, with a note.
        assert!(matches!(
            e.outbound("100008", form(), b"hi", NOW),
            Outbound::Clear { .. }
        ));
    }

    #[test]
    fn a_strict_contact_waits_for_our_keys_to_be_published() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(e.command("100002", "/e2e on", NOW));
        // A new sign-on, before the keys are accepted by the directory.
        let json = serde_json::to_string(e.keys()).unwrap();
        let mut fresh = Engine::new(dir.clone(), serde_json::from_str(&json).unwrap());
        fresh.set_token(&dir.token("100001"));
        match fresh.outbound("100002", form(), b"hi", NOW) {
            Outbound::Refused(note) => {
                assert!(note.contains("not in the key directory yet"), "{note}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn auto_forgets_the_manual_setting_but_not_that_they_encrypted() {
        let (dir, a, b) = two_published();
        let b_device = b.device_id;
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        assert!(e.command("100002", "/e2e off", NOW));
        notes(&mut e);

        assert!(e.command("100002", "/e2e auto", NOW));
        let n = notes(&mut e);
        assert_eq!(n.len(), 1, "{n:?}");
        assert!(n[0].text.contains("automatic again"), "{n:?}");
        assert!(n[0].text.contains("setting auto"), "{n:?}");
        assert!(n[0].text.contains("seen encrypting: yes"), "{n:?}");
        let rem = e.remembered("100002");
        assert_eq!(rem.setting, Setting::Auto);
        assert!(rem.seen_encrypting, "the sticky protection stays");

        // Back to automatic: encrypted, and the status is said again.
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        assert!(notes(&mut e)[0].text.contains("Encryption is on"));
        // And a downgrade is still held.
        dir.revoke("100002", b_device);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Refused(_)
        ));
    }

    #[test]
    fn status_says_the_setting_and_whether_they_encrypted() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(e.command("100009", "/e2e status", NOW));
        let t = notes(&mut e).remove(0).text;
        assert!(t.contains("setting auto"), "{t}");
        assert!(t.contains("seen encrypting: no"), "{t}");
        assert!(e.command("100009", "/e2e on", NOW));
        notes(&mut e);
        assert!(e.command("100009", "/e2e status", NOW));
        assert!(notes(&mut e)[0].text.contains("setting on"));
    }

    #[test]
    fn a_publish_that_fails_is_said_once_and_its_recovery_once() {
        let dir = Arc::new(MemoryDirectory::new());
        let k = OwnKeys::create("100001");
        announce(&dir, &k);
        let mut e = Engine::new(dir.clone(), k);
        e.set_token(&dir.token("100001"));

        dir.set_offline(true);
        for _ in 0..3 {
            assert!(matches!(e.publish(NOW), Progress::Retry { .. }));
        }
        let n = notes(&mut e);
        assert_eq!(n.len(), 1, "once per sign-on: {n:?}");
        assert_eq!(n[0].peer, None, "about the add-on, not a contact");
        assert!(n[0].text.contains("Encryption is not working"), "{n:?}");
        assert!(n[0].text.contains("unreachable"), "{n:?}");

        dir.set_offline(false);
        assert!(matches!(e.publish(NOW), Progress::Done(_)));
        let n = notes(&mut e);
        assert_eq!(n.len(), 1, "{n:?}");
        assert!(n[0].text.contains("Encryption is ready"), "{n:?}");
        assert!(matches!(e.publish(NOW), Progress::Quiet(_)));
        assert!(notes(&mut e).is_empty());
    }

    #[test]
    fn a_publish_that_works_says_nothing_in_the_chat() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(notes(&mut e).is_empty());
        // A refill that fails while the keys are in place leaves encryption
        // working, so it is not the user's business either.
        dir.set_offline(true);
        e.publish(NOW);
        assert!(notes(&mut e).is_empty());
    }

    // --- safety numbers (CHECKLIST 10.10) ------------------------------------

    /// The 60 digits out of a `/e2e safety` note.
    fn digits_of(note: &str) -> String {
        let (_, rest) = note.split_once('\n').expect("the number starts a line");
        let block: String = rest.lines().take(3).collect::<Vec<_>>().join(" ");
        let d: String = block.chars().filter(char::is_ascii_digit).collect();
        assert_eq!(d.len(), 60, "{note}");
        d
    }

    fn safety_of(e: &mut Engine, peer: &str) -> String {
        assert!(e.command(peer, "/e2e safety", NOW));
        let n = notes(e);
        let last = n.last().expect("an answer");
        assert!(last.text.contains("Your safety number with"), "{n:?}");
        last.text.clone()
    }

    /// The contact 100002 starts again with a new account key: its old device
    /// revoked, a fresh state published - what resetting its state file does.
    fn reset_contact(dir: &MemoryDirectory, old: &OwnKeys) -> OwnKeys {
        dir.revoke("100002", old.device_id);
        let mut fresh = OwnKeys::create("100002");
        publish_keys(dir, &mut fresh);
        fresh
    }

    #[test]
    fn both_sides_see_the_same_safety_number_and_nothing_is_said_at_first_contact() {
        let (dir, a, b) = two_published();
        let mut ea = running(&dir, a);
        let mut eb = running(&dir, b);
        ea.outbound("100002", form(), b"hi", NOW);
        let n = notes(&mut ea);
        assert!(
            n.iter().all(|n| !n.text.contains("safety")),
            "first contact is silent: {n:?}"
        );
        let from_a = safety_of(&mut ea, "100002");
        let from_b = safety_of(&mut eb, "100001");
        assert_eq!(digits_of(&from_a), digits_of(&from_b));
        assert!(from_a.contains("100002 is not verified"), "{from_a}");
        assert!(from_a.contains("in person or by phone"), "{from_a}");
        // Grouped like Signal: three lines of four groups of five.
        let lines: Vec<&str> = from_a.lines().skip(1).take(3).collect();
        for l in &lines {
            assert_eq!(l.split(' ').count(), 4, "{from_a}");
            assert!(l.split(' ').all(|g| g.len() == 5), "{from_a}");
        }
    }

    #[test]
    fn verify_takes_the_number_shown_and_survives_a_restart() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(e.command("100002", "/e2e verify", NOW));
        assert!(notes(&mut e)[0].text.contains("type /e2e safety first"));
        assert!(!e.keys().pinned("100002").unwrap().is_verified());

        safety_of(&mut e, "100002");
        assert!(e.command("100002", "/e2e verify", NOW));
        assert!(notes(&mut e)[0].text.contains("100002 is marked verified"));
        assert!(e.take_changed());

        let mut again = restarted(&dir, &e);
        assert!(again.keys().pinned("100002").unwrap().is_verified());
        assert!(again.command("100002", "/e2e status", NOW));
        assert!(notes(&mut again)[0].text.contains("verified: yes"));
        assert!(safety_of(&mut again, "100002").contains("100002 is verified"));

        assert!(again.command("100002", "/e2e unverify", NOW));
        assert!(notes(&mut again)[0]
            .text
            .contains("no longer marked verified"));
        assert!(!again.keys().pinned("100002").unwrap().is_verified());
    }

    #[test]
    fn a_changed_number_of_an_unverified_contact_is_said_once_and_sending_goes_on() {
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        e.outbound("100002", form(), b"hi", NOW);
        let before = digits_of(&safety_of(&mut e, "100002"));
        notes(&mut e);

        reset_contact(&dir, &b);
        assert!(matches!(
            e.outbound("100002", form(), b"after", NOW),
            Outbound::Encrypted(_)
        ));
        let n = notes(&mut e);
        let changed: Vec<_> = n
            .iter()
            .filter(|n| {
                n.text
                    .contains("Your safety number with 100002 has changed")
            })
            .collect();
        assert_eq!(changed.len(), 1, "{n:?}");
        assert!(changed[0].text.contains("still encrypted"), "{n:?}");

        assert!(matches!(
            e.outbound("100002", form(), b"again", NOW),
            Outbound::Encrypted(_)
        ));
        assert!(notes(&mut e).is_empty(), "said once per change");
        assert_ne!(before, digits_of(&safety_of(&mut e, "100002")));
    }

    #[test]
    fn a_changed_number_of_a_verified_contact_holds_until_verified_or_accepted() {
        for confirm in ["/e2e verify", "/e2e accept"] {
            let (dir, a, b) = two_published();
            let mut e = running(&dir, a);
            safety_of(&mut e, "100002");
            assert!(e.command("100002", "/e2e verify", NOW));
            notes(&mut e);

            reset_contact(&dir, &b);
            assert!(matches!(
                e.outbound("100002", form(), b"after", NOW),
                Outbound::Refused(_)
            ));
            let n = notes(&mut e);
            assert_eq!(n.len(), 2, "{n:?}");
            assert!(n[0].text.contains("has changed"), "{n:?}");
            assert!(n[0].text.contains("verification is cleared"), "{n:?}");
            assert!(n[1].text.contains("was NOT sent"), "{n:?}");
            assert!(n[1].text.contains("/e2e accept"), "{n:?}");
            assert!(!e.keys().pinned("100002").unwrap().is_verified());

            // Held on every try, the change said only once.
            assert!(matches!(
                e.outbound("100002", form(), b"again", NOW),
                Outbound::Refused(_)
            ));
            let n = notes(&mut e);
            assert_eq!(n.len(), 1, "{n:?}");
            assert!(
                e.take_control("100002").is_none(),
                "no control message either"
            );
            // The hold is in the state file, so a restart does not release it.
            let mut e = restarted(&dir, &e);
            assert!(matches!(
                e.outbound("100002", form(), b"restarted", NOW),
                Outbound::Refused(_)
            ));
            notes(&mut e);

            if confirm == "/e2e verify" {
                // Verifying needs the new number shown first.
                safety_of(&mut e, "100002");
            }
            assert!(e.command("100002", confirm, NOW));
            notes(&mut e);
            assert!(matches!(
                e.outbound("100002", form(), b"released", NOW),
                Outbound::Encrypted(_)
            ));
            assert_eq!(
                e.keys().pinned("100002").unwrap().is_verified(),
                confirm == "/e2e verify",
                "{confirm}"
            );
        }
    }

    /// Fifth audit of 2026-10, finding 2: a verified contact's key change,
    /// and what the user answers to it, are also security alerts - the chat
    /// note alone can be imitated by any message in the contact's name.
    #[test]
    fn a_verified_contacts_key_change_is_a_security_alert() {
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        safety_of(&mut e, "100002");
        assert!(e.command("100002", "/e2e verify", NOW));
        notes(&mut e);
        let _ = crate::alert::take_shown();
        reset_contact(&dir, &b);
        assert!(matches!(
            e.outbound("100002", form(), b"after", NOW),
            Outbound::Refused(_)
        ));
        let alerts = crate::alert::take_shown();
        assert!(
            alerts
                .iter()
                .any(|a| a.contains("has changed") && a.contains("verification is cleared")),
            "{alerts:?}"
        );
        assert!(e.command("100002", "/e2e accept", NOW));
        let alerts = crate::alert::take_shown();
        assert!(
            alerts.iter().any(|a| a.contains("without verifying it")),
            "{alerts:?}"
        );
        // An unverified contact's change is said in the chat only.
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        safety_of(&mut e, "100002");
        notes(&mut e);
        let _ = crate::alert::take_shown();
        reset_contact(&dir, &b);
        let _ = e.outbound("100002", form(), b"after", NOW);
        assert!(notes(&mut e).iter().any(|n| n.text.contains("has changed")));
        assert!(crate::alert::take_shown().is_empty());
        // With security_popups off nothing is raised.
        crate::alert::enable_for_this_thread(false);
        assert!(e.command("100002", "/e2e safety", NOW + 120));
        assert!(crate::alert::take_shown().is_empty());
        crate::alert::enable_for_this_thread(true);
    }

    #[test]
    fn accept_does_nothing_without_a_hold() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(e.command("100002", "/e2e accept", NOW));
        assert!(notes(&mut e)[0].text.contains("does nothing here"));
    }

    #[test]
    fn a_changed_number_found_by_an_incoming_message_is_said_and_holds_the_reply() {
        let (dir, a, b) = two_published();
        let mut ea = running(&dir, a);
        safety_of(&mut ea, "100002");
        assert!(ea.command("100002", "/e2e verify", NOW));
        notes(&mut ea);

        // 100002 starts again and writes first: the message is read, the
        // change is said with it, and the reply is held.
        let mut eb = running(&dir, reset_contact(&dir, &b));
        let c = container_of(eb.outbound("100001", form(), b"new phone", NOW));
        match ea.inbound("100002", &c, NOW) {
            Inbound::Text { text, .. } => assert_eq!(text, b"new phone"),
            other => panic!("{other:?}"),
        }
        let n = notes(&mut ea);
        assert!(
            n.iter().any(|n| n
                .text
                .contains("Your safety number with 100002 has changed")
                && n.text.contains("verification is cleared")),
            "{n:?}"
        );
        assert!(matches!(
            ea.outbound("100002", form(), b"reply", NOW),
            Outbound::Refused(_)
        ));
    }

    // --- file transfers (files_encrypt) ----------------------------------------

    type FileTableRef = Arc<std::sync::Mutex<crate::filesneg::FileTable>>;

    /// Two running engines, each with its own file table and files on or off.
    fn senders(a_on: bool, b_on: bool) -> (Engine, Engine, FileTableRef, FileTableRef) {
        let (dir, a, b) = two_published();
        let mut ea = running(&dir, a);
        let mut eb = running(&dir, b);
        let (ta, tb): (FileTableRef, FileTableRef) = Default::default();
        ea.use_file_table(ta.clone());
        eb.use_file_table(tb.clone());
        ea.set_files_encrypt(a_on);
        eb.set_files_encrypt(b_on);
        (ea, eb, ta, tb)
    }

    const FILE_COOKIE: [u8; 8] = [0xF1, 0x1E, 1, 2, 3, 4, 5, 6];

    fn file_rdv(dir: crate::icbm::Direction, peer: &str, kind: u16) -> crate::files::Rendezvous {
        let payload = if kind == crate::files::RDV_PROPOSE {
            crate::files::tests::proposal(
                dir,
                peer,
                FILE_COOKIE,
                1,
                std::net::Ipv4Addr::new(192, 168, 1, 20),
                5190,
                false,
            )
        } else {
            crate::files::tests::rdv_payload(dir, peer, kind, FILE_COOKIE, &[])
        };
        crate::files::rendezvous(dir, &payload).unwrap()
    }

    /// A sends B a file: proposal out, B sees it, B accepts - every step
    /// through the engines and their Olm sessions.
    fn send_file(ea: &mut Engine, eb: &mut Engine) {
        use crate::icbm::Direction;
        let mut lines = Vec::new();
        let offer = ea.file_icbm(
            &file_rdv(Direction::Outbound, "100002", crate::files::RDV_PROPOSE),
            NOW,
            &mut lines,
        );
        hand(eb, "100001", offer);
        assert!(eb
            .file_icbm(
                &file_rdv(Direction::Inbound, "100001", crate::files::RDV_PROPOSE),
                NOW,
                &mut lines
            )
            .is_empty());
        let answer = eb.file_icbm(
            &file_rdv(Direction::Outbound, "100001", crate::files::RDV_ACCEPT),
            NOW,
            &mut lines,
        );
        hand(ea, "100002", answer);
    }

    #[test]
    fn a_file_transfer_between_two_add_ons_with_files_on_is_keyed_the_same() {
        use crate::filestream::KeySource;
        let (mut ea, mut eb, ta, tb) = senders(true, true);
        send_file(&mut ea, &mut eb);
        let (ka, kb) = (
            crate::filesneg::lock(&ta).agreement(&FILE_COOKIE),
            crate::filesneg::lock(&tb).agreement(&FILE_COOKIE),
        );
        let (ka, kb) = (ka.expect("A keyed"), kb.expect("B keyed"));
        assert_eq!(ka.root, kb.root);
        assert_eq!(ka.confirm, kb.confirm);
        assert_eq!(ka.answerer_device, kb.answerer_device);
        // No ordinary control message is owed for a file exchange.
        assert!(ea.take_control("100002").is_none() && eb.take_control("100001").is_none());
        // Nothing is said before the data connection says it.
        assert!(texts(&mut ea).is_empty() && texts(&mut eb).is_empty());
    }

    #[test]
    fn a_receiver_with_files_off_takes_the_offer_as_an_old_add_on_would() {
        use crate::icbm::Direction;
        let (mut ea, mut eb, ta, tb) = senders(true, false);
        let mut lines = Vec::new();
        let offer = ea.file_icbm(
            &file_rdv(Direction::Outbound, "100002", crate::files::RDV_PROPOSE),
            NOW,
            &mut lines,
        );
        assert_eq!(offer.len(), 1, "an offer is made");
        let got = hand(&mut eb, "100001", offer);
        assert!(matches!(got[0], Inbound::Control(_)));
        assert!(
            eb.take_control("100001").is_some(),
            "an ordinary control message back"
        );
        assert!(eb
            .file_icbm(
                &file_rdv(Direction::Outbound, "100001", crate::files::RDV_ACCEPT),
                NOW,
                &mut lines
            )
            .is_empty());
        assert_eq!(crate::filesneg::lock(&tb).state_of(&FILE_COOKIE), None);
        assert_eq!(
            crate::filesneg::lock(&ta).state_of(&FILE_COOKIE),
            Some("offered"),
            "A waits for a hello on the data connection, then goes plain"
        );
        assert!(texts(&mut eb).is_empty(), "B, with files off, says nothing");
    }

    #[test]
    fn a_sender_with_files_off_offers_nothing_and_the_receiver_says_plain() {
        use crate::icbm::Direction;
        let (mut ea, mut eb, ta, tb) = senders(false, true);
        let mut lines = Vec::new();
        assert!(ea
            .file_icbm(
                &file_rdv(Direction::Outbound, "100002", crate::files::RDV_PROPOSE),
                NOW,
                &mut lines
            )
            .is_empty());
        assert_eq!(crate::filesneg::lock(&ta).state_of(&FILE_COOKIE), None);
        eb.file_icbm(
            &file_rdv(Direction::Inbound, "100001", crate::files::RDV_PROPOSE),
            NOW,
            &mut lines,
        );
        assert_eq!(
            crate::filesneg::lock(&tb).state_of(&FILE_COOKIE),
            Some("plain")
        );
        assert!(texts(&mut eb).iter().any(|n| n
            .contains("This file transfer with 100001 is not end-to-end encrypted")
            && n.contains("did not offer")));
    }

    #[test]
    fn e2e_off_for_the_sender_declines_the_file_and_both_say_why() {
        let (mut ea, mut eb, ta, tb) = senders(true, true);
        assert!(eb.command("100001", "/e2e off", NOW));
        texts(&mut eb);
        send_file(&mut ea, &mut eb);
        assert_eq!(
            crate::filesneg::lock(&ta).state_of(&FILE_COOKIE),
            Some("plain")
        );
        assert_eq!(
            crate::filesneg::lock(&tb).state_of(&FILE_COOKIE),
            Some("plain")
        );
        assert!(texts(&mut ea).iter().any(|n| n.contains("declined")));
        assert!(texts(&mut eb).iter().any(|n| n.contains("/e2e off")));
    }

    // --- calls (calls_encrypt) ------------------------------------------------

    use crate::callmedia::Verdict;
    use crate::callneg::CallTable;
    use crate::icbm::Direction;
    use std::sync::Mutex;

    type Table = Arc<Mutex<CallTable>>;

    /// Two running engines, each with its own call table and calls on or off.
    fn callers(a_on: bool, b_on: bool) -> (Engine, Engine, Table, Table) {
        let (dir, a, b) = two_published();
        let mut ea = running(&dir, a);
        let mut eb = running(&dir, b);
        let (ta, tb): (Table, Table) = Default::default();
        ea.use_call_table(ta.clone());
        eb.use_call_table(tb.clone());
        ea.set_calls_encrypt(a_on);
        eb.set_calls_encrypt(b_on);
        (ea, eb, ta, tb)
    }

    fn sip(first: &str, call: &str, cseq: &str, port: Option<u16>) -> Vec<u8> {
        let mut m = format!("{first}\r\nCall-ID: {call}\r\nCSeq: {cseq}\r\n");
        match port {
            Some(p) => m.push_str(&format!(
                "Content-Type: application/sdp\r\n\r\nv=0\r\nm=audio {p} RTP/AVP 103\r\n"
            )),
            None => m.push_str("\r\n"),
        }
        m.into_bytes()
    }

    fn invite(call: &str) -> Vec<u8> {
        sip("INVITE sip:100002@h SIP/2.0", call, "1 INVITE", Some(16384))
    }

    fn ok200(call: &str) -> Vec<u8> {
        sip("SIP/2.0 200 OK", call, "1 INVITE", Some(20000))
    }

    fn ack(call: &str) -> Vec<u8> {
        sip("ACK sip:100002@h SIP/2.0", call, "1 ACK", None)
    }

    /// What the receiving engine makes of control containers, as the stream
    /// hands them over. Every one is flagged as a control message, so an
    /// add-on without call support shows nothing for it.
    fn hand(to: &mut Engine, from: &str, containers: Vec<Vec<u8>>) -> Vec<Inbound> {
        containers
            .iter()
            .map(|c| {
                let c = container::Container::from_bytes(c).unwrap();
                assert!(c.is_control());
                to.inbound(from, &c, NOW)
            })
            .collect()
    }

    /// One call from A (100001) to B (100002), every step through the
    /// engines and their Olm sessions.
    fn place_call(ea: &mut Engine, eb: &mut Engine, call: &str) {
        let mut lines = Vec::new();
        let offer = ea.call_sip(
            Direction::Outbound,
            "100002",
            &invite(call),
            NOW,
            &mut lines,
        );
        hand(eb, "100001", offer);
        assert!(eb
            .call_sip(Direction::Inbound, "100001", &invite(call), NOW, &mut lines)
            .is_empty());
        let answer = eb.call_sip(Direction::Outbound, "100001", &ok200(call), NOW, &mut lines);
        hand(ea, "100002", answer);
        ea.call_sip(Direction::Inbound, "100002", &ok200(call), NOW, &mut lines);
        let confirm = ea.call_sip(Direction::Outbound, "100002", &ack(call), NOW, &mut lines);
        hand(eb, "100001", confirm);
        eb.call_sip(Direction::Inbound, "100001", &ack(call), NOW, &mut lines);
    }

    fn rtp(seq: u16) -> Vec<u8> {
        let mut p = vec![0x80, 103];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 1, 0, 0xAB, 0xCD, 0xEF, 0x01]);
        p.extend_from_slice(&[0x77; 40]);
        p
    }

    fn texts(e: &mut Engine) -> Vec<String> {
        notes(e).into_iter().map(|n| n.text).collect()
    }

    #[test]
    fn a_call_between_two_add_ons_with_calls_on_is_encrypted() {
        let (mut ea, mut eb, ta, tb) = callers(true, true);
        place_call(&mut ea, &mut eb, "c1@h");
        assert_eq!(ta.lock().unwrap().state_of("c1@h"), Some("agreed"));
        assert_eq!(tb.lock().unwrap().state_of("c1@h"), Some("agreed"));
        let (na, nb) = (texts(&mut ea), texts(&mut eb));
        assert!(
            na.iter()
                .any(|n| n.contains("This call with 100002 is end-to-end encrypted")),
            "{na:?}"
        );
        assert!(
            nb.iter()
                .any(|n| n.contains("This call with 100001 is end-to-end encrypted")),
            "{nb:?}"
        );
        // No ordinary control message is owed for a call exchange.
        assert!(ea.take_control("100002").is_none() && eb.take_control("100001").is_none());
        // The media keys are the same on both sides.
        let e = match ta.lock().unwrap().media_out(16384, &rtp(1), NOW * 1000) {
            Verdict::Replace(e) => e,
            v => panic!("{v:?}"),
        };
        assert_ne!(e, rtp(1));
        assert_eq!(
            tb.lock().unwrap().media_in(20000, &e, NOW * 1000),
            Verdict::Replace(rtp(1))
        );
    }

    #[test]
    fn a_callee_with_calls_off_takes_the_offer_as_an_old_add_on_would() {
        let (mut ea, mut eb, ta, tb) = callers(true, false);
        let mut lines = Vec::new();
        let offer = ea.call_sip(
            Direction::Outbound,
            "100002",
            &invite("c2@h"),
            NOW,
            &mut lines,
        );
        assert_eq!(offer.len(), 1, "an offer is made");
        // B (calls off, or an add-on from before calls) sees an ordinary
        // control message: nothing shown, one control message owed back.
        let got = hand(&mut eb, "100001", offer);
        assert!(matches!(got[0], Inbound::Control(_)));
        assert!(eb.take_control("100001").is_some());
        assert!(eb
            .call_sip(
                Direction::Outbound,
                "100001",
                &ok200("c2@h"),
                NOW,
                &mut lines
            )
            .is_empty());
        assert_eq!(
            tb.lock().unwrap().state_of("c2@h"),
            None,
            "B's table is untouched"
        );
        // A sees the 200 OK with no answer: plain, and says why.
        ea.call_sip(
            Direction::Inbound,
            "100002",
            &ok200("c2@h"),
            NOW,
            &mut lines,
        );
        assert_eq!(ta.lock().unwrap().state_of("c2@h"), Some("plain"));
        let n = texts(&mut ea);
        assert!(
            n.iter()
                .any(|n| n.contains("is not end-to-end encrypted") && n.contains("did not answer")),
            "{n:?}"
        );
        assert_eq!(
            ta.lock().unwrap().media_out(16384, &rtp(1), NOW * 1000),
            Verdict::Pass,
            "the media is the client's own"
        );
        assert!(texts(&mut eb).is_empty(), "B, with calls off, says nothing");
    }

    #[test]
    fn a_caller_with_calls_off_sends_nothing_and_the_callee_goes_plain() {
        let (mut ea, mut eb, ta, tb) = callers(false, true);
        let mut lines = Vec::new();
        assert!(ea
            .call_sip(
                Direction::Outbound,
                "100002",
                &invite("c3@h"),
                NOW,
                &mut lines
            )
            .is_empty());
        assert_eq!(ta.lock().unwrap().state_of("c3@h"), None);
        eb.call_sip(
            Direction::Inbound,
            "100001",
            &invite("c3@h"),
            NOW,
            &mut lines,
        );
        assert!(eb
            .call_sip(
                Direction::Outbound,
                "100001",
                &ok200("c3@h"),
                NOW,
                &mut lines
            )
            .is_empty());
        assert_eq!(tb.lock().unwrap().state_of("c3@h"), Some("plain"));
        assert!(texts(&mut eb).iter().any(|n| n.contains("did not offer")));
    }

    #[test]
    fn e2e_off_for_the_caller_declines_and_both_say_why() {
        let (mut ea, mut eb, ta, tb) = callers(true, true);
        assert!(eb.command("100001", "/e2e off", NOW));
        texts(&mut eb);
        place_call(&mut ea, &mut eb, "c4@h");
        assert_eq!(ta.lock().unwrap().state_of("c4@h"), Some("plain"));
        assert_eq!(tb.lock().unwrap().state_of("c4@h"), Some("plain"));
        assert!(texts(&mut ea).iter().any(|n| n.contains("declined")));
        assert!(texts(&mut eb).iter().any(|n| n.contains("/e2e off")));
    }

    #[test]
    fn a_contact_under_e2e_on_whose_call_is_not_encrypted_is_not_let_through() {
        let (mut ea, mut eb, ta, _) = callers(true, false);
        assert!(ea.command("100002", "/e2e on", NOW));
        texts(&mut ea);
        let mut lines = Vec::new();
        let offer = ea.call_sip(
            Direction::Outbound,
            "100002",
            &invite("c5@h"),
            NOW,
            &mut lines,
        );
        hand(&mut eb, "100001", offer);
        ea.call_sip(
            Direction::Inbound,
            "100002",
            &ok200("c5@h"),
            NOW,
            &mut lines,
        );
        // Encryption is on for 100002, for calls as for messages (audit
        // 2026-10, finding 8): the call is not let through.
        let n = texts(&mut ea);
        assert!(
            n.iter()
                .any(|n| n.contains("not let through") && n.contains("/e2e on")),
            "{n:?}"
        );
        assert!(matches!(
            ta.lock().unwrap().media_out(1, &rtp(1), NOW * 1000),
            Verdict::Drop(_)
        ));
    }

    // --- the key log (docs/e2e/KEY-TRANSPARENCY.md) -------------------------

    fn status_of(e: &mut Engine, peer: &str, now: u64) -> String {
        assert!(e.command(peer, "/e2e status", now));
        notes(e).pop().unwrap().text
    }

    /// A device for `owner`'s account, signed by `owner`'s account key, with
    /// the keys of a device that is not theirs: what a server would plant.
    fn planted_device(owner: &OwnKeys, id: u32) -> crate::directory::Device {
        let other = OwnKeys::create("100009");
        let (curve, ed, _) = other.device_object().unwrap();
        let raw = |k: &str| vodozemac::base64_decode(k).unwrap();
        let msg = sign::device(
            &owner.screen_name,
            id,
            &raw(&curve).try_into().unwrap(),
            &raw(&ed).try_into().unwrap(),
        );
        crate::directory::Device {
            device_id: id,
            curve25519_key: curve,
            ed25519_key: ed,
            account_signature: owner.account_key.sign(&msg).to_base64(),
            created_at: 1,
            last_seen_at: 1,
            revoked_at: None,
        }
    }

    #[test]
    fn a_contacts_keys_are_checked_against_the_log() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        let s = status_of(&mut e, "100002", NOW);
        assert!(
            s.contains("key log: 100002's keys are in it, checked (4 entries)"),
            "{s}"
        );
        // The copy survives a restart and needs nothing new.
        let mut again = restarted(&dir, &e);
        assert_eq!(again.keys().log.size, 4);
        assert!(status_of(&mut again, "100002", NOW).contains("checked"));
    }

    #[test]
    fn a_key_the_log_does_not_show_holds_the_message_and_is_not_pinned() {
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        e.outbound("100002", form(), b"hi", NOW);
        notes(&mut e);

        // The directory hands out a new key for 100002 and leaves the log
        // alone.
        dir.pause_log(true);
        reset_contact(&dir, &b);
        let out = e.outbound("100002", form(), b"secret", NOW);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        let n = notes(&mut e);
        assert!(
            n.iter().any(|n| n.text.contains("was NOT sent")
                && n.text.contains("not the one the server's key log shows")),
            "{n:?}"
        );
        assert!(
            !n.iter()
                .any(|n| n.text.contains("safety number with 100002 has changed")),
            "{n:?}"
        );
        assert_eq!(e.keys().pinned("100002").unwrap().key, b.account_key_b64());
        let s = status_of(&mut e, "100002", NOW);
        assert!(s.contains("nowhere: it is held"), "{s}");
        assert!(s.contains("100002's keys are not used"), "{s}");
        // Asking does not pin the key either.
        assert_eq!(e.keys().pinned("100002").unwrap().key, b.account_key_b64());
    }

    #[test]
    fn a_new_session_from_a_key_the_log_does_not_show_is_not_accepted() {
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        e.outbound("100002", form(), b"hi", NOW);
        notes(&mut e);

        // Someone with a key the log does not show writes as 100002.
        dir.pause_log(true);
        let fake = reset_contact(&dir, &b);
        let mut ef = Engine::new(dir.clone(), fake);
        ef.set_token(&dir.token("100002"));
        // Its own publish went through the directory, not the log; it writes
        // anyway.
        let _ = ef.publish(NOW);
        let sent = ef.keys_mut().encrypt(
            &*dir,
            &bearer(&dir, "100002"),
            &keys::Outgoing {
                peer: "100001".into(),
                form: form(),
                text: b"it is me".to_vec(),
                now: NOW,
            },
            &keys::fetch_contact(&*dir, "100001").unwrap(),
        );
        let c = container_of(sent.unwrap());
        assert!(matches!(
            e.inbound("100002", &c, NOW),
            Inbound::Unreadable(_)
        ));
        assert_eq!(e.keys().pinned("100002").unwrap().key, b.account_key_b64());
        assert!(e.keys().session("100002", ef.keys().device_id).is_none());
    }

    #[test]
    fn a_device_the_log_does_not_show_gets_nothing() {
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        dir.pause_log(true);
        dir.plant_device("100002", planted_device(&b, 777));
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        let n = notes(&mut e);
        assert!(
            n.iter().any(|n| n.text.contains("(device 777)")
                && n.text.contains("not in the server's key log")),
            "{n:?}"
        );
        // Encrypted for the device in the log only.
        assert!(e.keys().session("100002", 777).is_none());
        assert!(e.keys().session("100002", b.device_id).is_some());
    }

    #[test]
    fn a_device_added_to_our_account_is_said_once() {
        let (dir, a, b) = two_published();
        let _ea = running(&dir, a);
        let mut eb = running(&dir, b);
        assert!(notes(&mut eb).is_empty());

        // The server puts its own device into 100002's account, in the log.
        let planted = planted_device(eb.keys(), 4242);
        dir.plant_device("100002", planted);
        let said = |n: &[Note]| n.iter().filter(|n| n.text.contains("device 4242")).count();
        assert!(eb.command("100001", "/e2e status", NOW + LOG_SYNC_EVERY));
        assert_eq!(said(&notes(&mut eb)), 1);
        assert!(eb.keys().log.own_seen.contains(&4242));

        // Not again, in this sign-on or after a restart.
        assert!(eb.command("100001", "/e2e status", NOW + 3 * LOG_SYNC_EVERY));
        assert_eq!(said(&notes(&mut eb)), 0);
        let mut again = restarted(&dir, &eb);
        assert!(again.command("100001", "/e2e status", NOW + 5 * LOG_SYNC_EVERY));
        assert_eq!(said(&notes(&mut again)), 0);
    }

    #[test]
    fn the_note_about_a_device_added_to_our_account_names_it() {
        let (dir, _, b) = two_published();
        let mut eb = running(&dir, b);
        dir.plant_device("100002", planted_device(eb.keys(), 4242));
        assert!(eb.command("100001", "/e2e status", NOW + LOG_SYNC_EVERY));
        let n = notes(&mut eb);
        assert!(
            n.iter().any(|n| n.peer.is_none()
                && n.text.contains("A device was added to your account")
                && n.text.contains("device 4242")),
            "{n:?}"
        );
    }

    /// Audit 2026-10, finding 4: a log that was trusted and then broke used
    /// to put every key back on trust on first use - a new contact, a new
    /// device, a changed account key all taken unchecked, the moment the
    /// server rewrote its log. Now the break is remembered across sign-ons
    /// until `/e2e resetlog`, the sessions already made go on, and nothing
    /// new is taken.
    #[test]
    fn a_log_broken_after_it_was_trusted_takes_nothing_new_until_resetlog() {
        let (dir, a, b) = two_published();
        let mut c = OwnKeys::create("100003");
        publish_keys(&dir, &mut c);
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        notes(&mut e);

        // The first entry again, at another time: the history changed, and
        // the log read anew from the start still keeps the rules.
        let own = e.keys().account_key_bytes();
        dir.rewrite_log(
            0,
            kt::build_leaf("account", "100001", 999, &[b"publish", &own]),
        );
        let later = NOW + LOG_SYNC_EVERY;
        // The contact checked before goes on, over its session.
        assert!(matches!(
            e.outbound("100002", form(), b"hi again", later),
            Outbound::Encrypted(_)
        ));
        let n = notes(&mut e);
        let warned = n
            .iter()
            .filter(|n| n.text.contains("WARNING: the key log was rewritten"))
            .count();
        assert_eq!(warned, 1, "{n:?}");
        // Also where the network cannot write (fifth audit of 2026-10,
        // finding 2).
        assert!(crate::alert::take_shown()
            .iter()
            .any(|a| a.contains("WARNING: the key log was rewritten")));
        assert!(matches!(e.log_trust(), kt::Trust::BrokenAfterTrust(_)));
        // The copy that was good is kept, frozen.
        assert_eq!(e.keys().log.size, 6);

        // A contact never checked: held, not trusted on first use.
        let out = e.outbound("100003", form(), b"new contact", later);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        assert!(e.keys().pinned("100003").is_none());
        let n = notes(&mut e);
        assert!(n.iter().any(|n| n.text.contains("never checked")), "{n:?}");

        // A new session from a contact never checked: not read.
        let sent = c
            .encrypt(
                &*dir,
                &bearer(&dir, "100003"),
                &keys::Outgoing {
                    peer: "100001".into(),
                    form: form(),
                    text: b"hello".to_vec(),
                    now: later,
                },
                &keys::fetch_contact(&*dir, "100001").unwrap(),
            )
            .unwrap();
        let got = e.inbound("100003", &container_of(sent), later);
        assert!(matches!(got, Inbound::Unreadable(_)), "{got:?}");
        assert!(e.keys().session("100003", c.device_id).is_none());

        // A changed account key of a contact checked before: held.
        reset_contact(&dir, &b);
        let out = e.outbound("100002", form(), b"to the new key", later);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        assert_eq!(e.keys().pinned("100002").unwrap().key, b.account_key_b64());

        // Sticky: a restart reads it back broken, and still holds.
        let mut again = restarted(&dir, &e);
        assert!(matches!(again.log_trust(), kt::Trust::BrokenAfterTrust(_)));
        assert!(status_of(&mut again, "100003", later).contains("key log: NOT TRUSTED"));
        let out = again.outbound("100003", form(), b"still held", later);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");

        // The operator explains; the user starts the copy afresh.
        assert!(again.command("100003", "/e2e resetlog", later));
        assert!(notes(&mut again)
            .iter()
            .any(|n| n.text.contains("forgotten")));
        assert!(status_of(&mut again, "100003", later).contains("100003's keys are in it, checked"));
        assert!(matches!(
            again.outbound("100003", form(), b"now", later),
            Outbound::Encrypted(_)
        ));
    }

    /// An older server, or a log never seen: trust on first use, as before
    /// the log existed - not the state of a log that broke.
    #[test]
    fn a_server_that_never_had_a_log_is_not_a_broken_one() {
        let (dir, a, _) = two_published();
        dir.set_log(false);
        let mut e = running(&dir, a);
        assert_eq!(e.log_trust(), kt::Trust::NeverHadLog);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        assert!(e.keys().log.broken.is_none());
    }

    #[test]
    fn a_log_restored_from_an_old_backup_or_signed_by_another_key_is_not_trusted() {
        for (what, says) in [
            ("truncate", "4 before"),
            ("rekey", "signature is wrong"),
            ("drop", "no longer has it"),
        ] {
            let (dir, a, _) = two_published();
            let mut e = running(&dir, a);
            match what {
                "truncate" => dir.truncate_log(2),
                "rekey" => dir.rekey_log(),
                _ => dir.set_log(false),
            }
            let s = status_of(&mut e, "100002", NOW + LOG_SYNC_EVERY);
            assert!(s.contains("NOT TRUSTED") && s.contains(says), "{what}: {s}");
        }
    }

    #[test]
    fn a_server_without_a_log_works_as_before() {
        let (dir, a, _) = two_published();
        dir.set_log(false);
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        assert!(status_of(&mut e, "100002", NOW).contains("key log: the server keeps none"));
        assert_eq!(e.keys().log, kt::LogState::default());
    }

    // --- the auditor (stage 2) ------------------------------------------------

    #[test]
    fn an_audited_log_says_so() {
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        dir.audit_log(NOW - 120);
        let mut e = running(&dir, a);
        let s = status_of(&mut e, "100002", NOW);
        assert!(
            s.contains("checked (4 entries), audited by auditor.test/icq (2 min ago)"),
            "{s}"
        );
        assert!(notes(&mut e).is_empty());
        assert_eq!(e.keys().log.auditors.len(), 1);
        assert_eq!(e.keys().log.audited.as_ref().unwrap().size, 4);

        // The auditor checked fewer entries than there are now: a contact
        // that came in after its look is not taken until it has looked again
        // (second audit of 2026-10, finding 3).
        let mut c = OwnKeys::create("100003");
        publish_keys(&dir, &mut c);
        let s = status_of(&mut e, "100003", NOW + LOG_SYNC_EVERY);
        assert!(
            s.contains("100003's keys are not used")
                && s.contains("newer than what the key log's auditor has vouched for")
                && s.contains("checked (6 entries), audited by"),
            "{s}"
        );
        dir.audit_log(NOW + LOG_SYNC_EVERY);
        let s = status_of(&mut e, "100003", NOW + 2 * LOG_SYNC_EVERY);
        assert!(
            s.contains("100003's keys are in it, checked (6 entries), audited by"),
            "{s}"
        );
    }

    #[test]
    fn a_log_the_auditor_never_saw_is_not_trusted() {
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        // The server showed the auditor another log of the same size.
        dir.audit_root(4, [7; 32], NOW);
        let mut e = running(&dir, a);
        let n = notes(&mut e);
        assert!(
            n.iter().any(|n| n.text.contains("WARNING")
                && n.text.contains("saw a different log (4 entries)")),
            "{n:?}"
        );
        let s = status_of(&mut e, "100002", NOW);
        assert!(s.contains("key log: NOT TRUSTED"), "{s}");
        // A contact whose keys were never checked is not trusted on first
        // use now: the log broke after it was trusted (audit 2026-10,
        // finding 4). The message is held, never sent in clear.
        let out = e.outbound("100002", form(), b"hi", NOW);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        assert!(e.keys().pinned("100002").is_none());
    }

    #[test]
    fn an_old_or_missing_cosignature_is_a_warning() {
        for when in [Some(NOW - 2 * kt::AUDIT_MAX_AGE), None] {
            let (dir, a, _) = two_published();
            dir.set_auditor(true);
            if let Some(t) = when {
                dir.audit_log(t);
            }
            let mut e = running(&dir, a);
            let n = notes(&mut e);
            let warned: Vec<_> = n.iter().filter(|n| n.text.contains("Warning:")).collect();
            assert_eq!(warned.len(), 1, "{n:?}");
            assert!(crate::alert::take_shown()
                .iter()
                .any(|a| a.contains("Warning:") && a.contains("auditor")));
            let want = if when.is_some() {
                "last vouched for it 120 minutes ago"
            } else {
                "no auditor has cosigned"
            };
            assert!(warned[0].text.contains(want), "{n:?}");
            let s = status_of(&mut e, "100002", NOW + LOG_SYNC_EVERY);
            assert!(
                s.contains("NOT AUDITED") && s.contains("checked (4 entries)"),
                "{s}"
            );
            assert!(notes(&mut e).is_empty(), "once per sign-on");
            // An auditor vouched for this log once and has not lately, or
            // one is pinned and has never cosigned: a contact never checked
            // is not taken now (second audit of 2026-10, finding 3; third
            // audit, finding 1 - it used to go when no auditor ever had).
            let out = e.outbound("100002", form(), b"hi", NOW);
            assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
            let want = if when.is_some() {
                "no auditor has vouched"
            } else {
                "no auditor has cosigned"
            };
            assert!(
                notes(&mut e).iter().any(|n| n.text.contains(want)),
                "{when:?}"
            );
        }
    }

    #[test]
    fn the_auditor_is_pinned_and_another_one_is_not_taken() {
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        dir.audit_log(NOW);
        let mut e = running(&dir, a);
        let pinned = e.keys().log.auditors.clone();
        // The server stops naming it: the pin stays, and its cosignature is
        // still asked for.
        dir.set_auditor(false);
        let s = status_of(&mut e, "100002", NOW + LOG_SYNC_EVERY);
        assert!(s.contains("audited by auditor.test/icq"), "{s}");
        assert_eq!(e.keys().log.auditors, pinned);
        let again = restarted(&dir, &e);
        assert_eq!(again.keys().log.auditors, pinned);
    }

    // --- several auditors, and auditors pinned by the patch -------------------

    const B_AUDITOR: &str = "b.test/icq";
    const B_SEED: [u8; 32] = [0xb0; 32];
    const C_AUDITOR: &str = "c.test/icq";
    const C_SEED: [u8; 32] = [0xc0; 32];

    /// An engine like [`running`] that trusts exactly `pinned`, as the
    /// `auditors =` line of `icq-e2e.ini` says.
    fn running_pinned(dir: &Arc<MemoryDirectory>, keys: OwnKeys, pinned: Vec<String>) -> Engine {
        let who = keys.screen_name.clone();
        let mut e = Engine::new(dir.clone(), keys);
        e.set_auditors(Some(pinned));
        e.set_token(&dir.token(&who));
        assert!(matches!(e.publish(NOW), Progress::Done(_)));
        e
    }

    #[test]
    fn one_fresh_auditor_is_enough_and_each_is_listed() {
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        dir.add_auditor(B_AUDITOR, B_SEED);
        dir.add_auditor(C_AUDITOR, C_SEED);
        dir.audit_log(NOW - 3 * 3600);
        dir.audit_log_as(B_AUDITOR, &B_SEED, NOW - 60);
        // C never cosigned.
        let mut e = running(&dir, a);
        assert!(notes(&mut e).is_empty(), "no warning while one is fresh");
        assert_eq!(
            e.keys().log.auditors.len(),
            3,
            "all three pinned on first use"
        );
        let s = status_of(&mut e, "100002", NOW);
        assert!(
            s.contains(
                "audited by b.test/icq (1 min ago); auditor.test/icq silent 3 h; c.test/icq silent (no cosignature)"
            ),
            "{s}"
        );
        assert_eq!(e.keys().log.audits.len(), 2);
        assert_eq!(e.keys().log.audited.as_ref().unwrap().auditor, B_AUDITOR);

        // Every one of them stale: one warning, naming each.
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        dir.add_auditor(B_AUDITOR, B_SEED);
        dir.audit_log(NOW - 3 * 3600);
        dir.audit_log_as(B_AUDITOR, &B_SEED, NOW - 2 * 3600);
        let mut e = running(&dir, a);
        let n = notes(&mut e);
        assert!(
            n.iter().any(|n| n.text.contains("Warning:")
                && n.text
                    .contains("auditor.test/icq last vouched for it 180 minutes ago")
                && n.text
                    .contains("b.test/icq last vouched for it 120 minutes ago")),
            "{n:?}"
        );
        assert!(status_of(&mut e, "100002", NOW).contains("NOT AUDITED"));
    }

    #[test]
    fn any_auditor_that_saw_another_log_is_a_split_view() {
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        dir.add_auditor(B_AUDITOR, B_SEED);
        // The usual auditor agrees and is fresh; B, older, was shown another
        // log of the same size.
        dir.audit_log(NOW);
        dir.audit_root_as(B_AUDITOR, &B_SEED, 4, [7; 32], NOW - 2 * 3600);
        let mut e = running(&dir, a);
        let n = notes(&mut e);
        assert!(
            n.iter().any(|n| n.text.contains("WARNING")
                && n.text
                    .contains("auditor b.test/icq saw a different log (4 entries)")),
            "{n:?}"
        );
        assert!(status_of(&mut e, "100002", NOW).contains("key log: NOT TRUSTED"));
    }

    #[test]
    fn pinned_auditors_are_the_only_ones_trusted() {
        let (dir, a, _) = two_published();
        // The server names its own auditor, which cosigns, and even one that
        // saw another log; neither is ours.
        dir.set_auditor(true);
        dir.add_auditor(C_AUDITOR, C_SEED);
        dir.audit_log(NOW);
        dir.audit_root_as(C_AUDITOR, &C_SEED, 4, [7; 32], NOW);
        let b_key = kt::cosign(B_AUDITOR, &B_SEED, "", 0).1;
        let mut e = running_pinned(&dir, a, vec![b_key.clone()]);
        assert_eq!(e.keys().log.auditors, vec![b_key.clone()]);
        let n = notes(&mut e);
        assert!(
            n.iter()
                .any(|n| n.text.contains("Warning:") && n.text.contains("no auditor has cosigned")),
            "{n:?}"
        );
        assert!(!n.iter().any(|n| n.text.contains("WARNING")), "{n:?}");
        let s = status_of(&mut e, "100002", NOW);
        assert!(
            s.contains("NOT AUDITED") && !s.contains("NOT TRUSTED"),
            "{s}"
        );

        // Our auditor cosigns, without the server naming it: audited.
        dir.audit_log_as(B_AUDITOR, &B_SEED, NOW + LOG_SYNC_EVERY);
        let s = status_of(&mut e, "100002", NOW + 2 * LOG_SYNC_EVERY);
        assert!(s.contains("audited by b.test/icq (1 min ago)"), "{s}");
        assert!(!s.contains("auditor.test/icq"), "{s}");
    }

    #[test]
    fn the_patchs_auditors_replace_the_ones_pinned_on_first_use() {
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        dir.audit_log(NOW);
        let e = running(&dir, a);
        assert_eq!(e.keys().log.auditors.len(), 1);
        assert_eq!(e.keys().log.audits.len(), 1);

        // The patch is applied again and pins B and the usual auditor.
        let usual = kt::cosign(
            crate::directory::MEMORY_AUDITOR,
            &crate::directory::MEMORY_AUDITOR_SEED,
            "",
            0,
        )
        .1;
        let b_key = kt::cosign(B_AUDITOR, &B_SEED, "", 0).1;
        let keys: OwnKeys =
            serde_json::from_str(&serde_json::to_string(e.keys()).unwrap()).unwrap();
        let mut e = running_pinned(&dir, keys, vec![b_key.clone(), usual.clone()]);
        assert_eq!(e.keys().log.auditors, vec![b_key.clone(), usual.clone()]);
        let s = status_of(&mut e, "100002", NOW);
        assert!(
            s.contains(
                "audited by auditor.test/icq (0 min ago); b.test/icq silent (no cosignature)"
            ),
            "{s}"
        );

        // Without the line again (an older patch), the pinned set stays and
        // the server's naming no one changes nothing.
        dir.set_auditor(false);
        let again = restarted(&dir, &e);
        assert_eq!(again.keys().log.auditors, vec![b_key, usual]);
    }

    #[test]
    fn a_state_file_from_before_several_auditors_reads() {
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        dir.audit_log(NOW);
        let e = running(&dir, a);
        let mut json: serde_json::Value = serde_json::to_value(e.keys()).unwrap();
        json["log"].as_object_mut().unwrap().remove("audits");
        let mut old = Engine::new(dir.clone(), serde_json::from_value(json).unwrap());
        old.set_token(&dir.token("100001"));
        assert!(matches!(old.publish(NOW), Progress::Done(_)));
        assert!(status_of(&mut old, "100002", NOW).contains("audited by auditor.test/icq"));
        assert_eq!(old.keys().log.audits.len(), 1);
    }

    // --- second audit of 2026-10 ----------------------------------------------

    /// A message from `from` to `to`, encrypted with `from`'s keys outside
    /// any engine, as a container.
    fn written_by(
        dir: &Arc<MemoryDirectory>,
        from: &mut OwnKeys,
        to: &str,
        text: &[u8],
        now: u64,
    ) -> container::Container {
        let who = from.screen_name.clone();
        let sent = from
            .encrypt(
                &**dir,
                &bearer(dir, &who),
                &keys::Outgoing {
                    peer: to.into(),
                    form: form(),
                    text: text.to_vec(),
                    now,
                },
                &keys::fetch_contact(&**dir, to).unwrap(),
            )
            .unwrap();
        container_of(sent)
    }

    /// Finding 1: keys the operator replaced without the contact's own key
    /// are a new identity. A contact under `/e2e on` is held until
    /// `/e2e accept` (or verify), and the warning comes every time it
    /// happens; `/e2e status` says it.
    #[test]
    fn keys_the_operator_replaced_are_a_new_identity_held_under_e2e_on() {
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        assert!(e.command("100002", "/e2e on", NOW));
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        notes(&mut e);

        // The operator revokes the device (management API), and a new key
        // comes as a reset.
        let fresh = reset_contact(&dir, &b);
        let later = NOW + LOG_SYNC_EVERY;
        let out = e.outbound("100002", form(), b"to whom?", later);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        let n = notes(&mut e);
        assert!(
            n.iter().any(|n| n
                .text
                .contains("WARNING: the server replaced 100002's keys without 100002's key (operator recovery")
                && n.text.contains("held until")),
            "{n:?}"
        );
        assert!(e.keys().pinned("100002").unwrap().held);
        let s = status_of(&mut e, "100002", later);
        assert!(
            s.contains("keys were replaced without 100002's key (operator recovery"),
            "{s}"
        );
        assert!(e.command("100002", "/e2e accept", later));
        assert!(matches!(
            e.outbound("100002", form(), b"now", later),
            Outbound::Encrypted(_)
        ));
        notes(&mut e);

        // Again: said again, held again.
        reset_contact(&dir, &fresh);
        let later = later + LOG_SYNC_EVERY;
        assert!(matches!(
            e.outbound("100002", form(), b"again", later),
            Outbound::Refused(_)
        ));
        let n = notes(&mut e);
        assert!(
            n.iter().any(|n| n
                .text
                .contains("WARNING: the server replaced 100002's keys")),
            "{n:?}"
        );
    }

    /// Finding 1: a contact in automatic mode gets the warning, and the
    /// messages go on to the new key.
    #[test]
    fn a_recovered_key_of_an_automatic_contact_is_said_loudly_and_used() {
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        e.outbound("100002", form(), b"hi", NOW);
        notes(&mut e);
        reset_contact(&dir, &b);
        assert!(matches!(
            e.outbound("100002", form(), b"after", NOW + LOG_SYNC_EVERY),
            Outbound::Encrypted(_)
        ));
        let n = notes(&mut e);
        assert!(
            n.iter()
                .any(|n| n.text.contains("WARNING: the server replaced")
                    && n.text.contains("still encrypted")),
            "{n:?}"
        );
    }

    /// Finding 1: a revoke the owner did not sign and that is no recovery
    /// breaks the key log for the client as for the auditor; one the owner
    /// signed does not, and is no recovery.
    #[test]
    fn a_revoke_without_the_owners_signature_breaks_the_log() {
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        e.outbound("100002", form(), b"hi", NOW);
        notes(&mut e);
        dir.append_leaf(kt::build_leaf(
            "revoke",
            "100002",
            9,
            &[&b.device_id.to_be_bytes()],
        ));
        let s = status_of(&mut e, "100002", NOW + LOG_SYNC_EVERY);
        assert!(
            s.contains("NOT TRUSTED") && s.contains("without the owner's signature"),
            "{s}"
        );
        assert!(matches!(e.log_trust(), kt::Trust::BrokenAfterTrust(_)));

        // The owner's own revoke, signed by the account key.
        let (dir, a, b) = two_published();
        let mut e = running(&dir, a);
        e.outbound("100002", form(), b"hi", NOW);
        notes(&mut e);
        let sig = b
            .account_key
            .sign(&sign::revoke("100002", b.device_id, NOW))
            .to_bytes();
        dir.revoke_signed("100002", b.device_id, NOW, &sig);
        let s = status_of(&mut e, "100002", NOW + LOG_SYNC_EVERY);
        assert!(!s.contains("NOT TRUSTED") && !s.contains("WARNING"), "{s}");
        assert_eq!(e.log_trust(), kt::Trust::Trusted);
        assert!(e.keys().session("100002", b.device_id).is_none());
    }

    /// Finding 2: a log trusted before that cannot be read now is not "no
    /// log". What is known goes on; a new contact, a changed key and a new
    /// session from a contact never checked wait until the log is read again
    /// - and only until then.
    #[test]
    fn a_trusted_log_that_cannot_be_read_takes_nothing_new_until_it_can() {
        let (dir, a, b) = two_published();
        let mut c = OwnKeys::create("100003");
        publish_keys(&dir, &mut c);
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        notes(&mut e);

        dir.set_log_unreachable(true);
        let later = NOW + LOG_SYNC_EVERY;
        // Known: goes on.
        assert!(matches!(
            e.outbound("100002", form(), b"still", later),
            Outbound::Encrypted(_)
        ));
        assert!(matches!(
            e.log_trust(),
            kt::Trust::TemporarilyUnavailableAfterTrust(_)
        ));
        // A contact never checked: held, never pinned, never in clear.
        let out = e.outbound("100003", form(), b"new", later);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        assert!(e.keys().pinned("100003").is_none());
        assert!(notes(&mut e)
            .iter()
            .any(|n| n.text.contains("cannot be read right now")));
        // A new session from it: unreadable, nothing made.
        let got = e.inbound(
            "100003",
            &written_by(&dir, &mut c, "100001", b"hello", later),
            later,
        );
        assert!(matches!(got, Inbound::Unreadable(_)), "{got:?}");
        assert!(e.keys().session("100003", c.device_id).is_none());
        // A changed key of a known contact: held.
        reset_contact(&dir, &b);
        let out = e.outbound("100002", form(), b"to the new key", later);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        assert_eq!(e.keys().pinned("100002").unwrap().key, b.account_key_b64());
        let s = status_of(&mut e, "100003", later);
        assert!(
            s.contains("could not be read") && s.contains("anything new is held"),
            "{s}"
        );

        // Not sticky: the log is back, and so is everything.
        dir.set_log_unreachable(false);
        let back = later + LOG_SYNC_EVERY;
        assert!(matches!(
            e.outbound("100003", form(), b"now", back),
            Outbound::Encrypted(_)
        ));
        assert_eq!(e.log_trust(), kt::Trust::Trusted);
    }

    /// Finding 2: a state that never trusted a log is not frozen by a log
    /// that cannot be read: trust on first use, as before.
    #[test]
    fn a_log_never_trusted_that_cannot_be_read_is_no_log() {
        let (dir, a, _) = two_published();
        dir.set_log_unreachable(true);
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        assert_eq!(e.log_trust(), kt::Trust::NeverHadLog);
    }

    /// Finding 3: once an auditor vouched for this copy, new keys are taken
    /// only from the part an auditor cosigned - a contact, a device or a new
    /// session the server added after the auditor's last word waits - and
    /// with no fresh cosignature at all, nothing new is taken while what is
    /// known goes on.
    #[test]
    fn new_keys_are_taken_only_from_what_a_fresh_cosignature_covers() {
        let (dir, a, b) = two_published();
        dir.set_auditor(true);
        dir.audit_log(NOW);
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        assert_eq!(e.keys().log.vouched_size, 4);
        notes(&mut e);

        // The server adds a contact and a device of 100002 to its log, and
        // keeps the auditor's newer cosignatures to itself.
        let mut c = OwnKeys::create("100003");
        publish_keys(&dir, &mut c);
        dir.plant_device("100002", planted_device(&b, 777));
        let t = NOW + LOG_SYNC_EVERY;
        let out = e.outbound("100003", form(), b"new", t);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        assert!(e.keys().pinned("100003").is_none());
        let got = e.inbound(
            "100003",
            &written_by(&dir, &mut c, "100001", b"hello", t),
            t,
        );
        assert!(matches!(got, Inbound::Unreadable(_)), "{got:?}");
        assert!(e.keys().session("100003", c.device_id).is_none());
        // The device is in the log, not yet vouched for: left out.
        assert!(matches!(
            e.outbound("100002", form(), b"known", t),
            Outbound::Encrypted(_)
        ));
        assert!(e.keys().session("100002", 777).is_none());
        assert!(notes(&mut e)
            .iter()
            .any(|n| n.text.contains("(device 777)") && n.text.contains("not yet vouched")));

        // An hour later, still no newer cosignature: unaudited.
        let stale = NOW + kt::AUDIT_MAX_AGE + 120;
        assert!(matches!(
            e.outbound("100002", form(), b"still known", stale),
            Outbound::Encrypted(_)
        ));
        assert!(matches!(e.log_trust(), kt::Trust::Unaudited(_)));
        let out = e.outbound("100003", form(), b"still new", stale);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");

        // The auditor's word on the log as it is now: taken.
        dir.audit_log(stale);
        let t = stale + LOG_SYNC_EVERY;
        assert!(matches!(
            e.outbound("100003", form(), b"vouched", t),
            Outbound::Encrypted(_)
        ));
        assert_eq!(e.keys().log.vouched_size, e.keys().log.size);
    }

    /// Finding 3: a state file from before the vouched copy, of a log an
    /// auditor already vouched for, fills it at the next look.
    #[test]
    fn a_state_file_from_before_the_vouched_copy_fills_it() {
        let (dir, a, _) = two_published();
        dir.set_auditor(true);
        dir.audit_log(NOW);
        let e = running(&dir, a);
        let mut json: serde_json::Value = serde_json::to_value(e.keys()).unwrap();
        let log = json["log"].as_object_mut().unwrap();
        log.remove("vouched");
        log.remove("vouched_size");
        let mut old = Engine::new(dir.clone(), serde_json::from_value(json).unwrap());
        old.set_token(&dir.token("100001"));
        assert!(matches!(old.publish(NOW), Progress::Done(_)));
        assert_eq!(old.keys().log.vouched_size, 4);
        assert!(matches!(
            old.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
    }

    // --- third audit of 2026-10 -----------------------------------------------

    /// The key of the in-memory auditor, as an `auditors =` line names it.
    fn usual_auditor() -> String {
        kt::cosign(
            crate::directory::MEMORY_AUDITOR,
            &crate::directory::MEMORY_AUDITOR_SEED,
            "",
            0,
        )
        .1
    }

    /// Finding 1: with an auditor named by `auditors =`, its word is
    /// required from the start. Before any cosignature, a contact and a
    /// session already known go on; a new contact, a new device of a known
    /// one and a new inbound session are not taken - until the auditor
    /// cosigns.
    #[test]
    fn with_auditors_configured_nothing_new_is_taken_before_the_first_cosignature() {
        let (dir, a, b) = two_published();
        let mut c = OwnKeys::create("100003");
        publish_keys(&dir, &mut c);
        // Known before: a session with 100002, made with no auditor at all.
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        let keys: OwnKeys =
            serde_json::from_str(&serde_json::to_string(e.keys()).unwrap()).unwrap();

        // The patch pins the auditor; the server hands out no cosignature.
        dir.plant_device("100002", planted_device(&b, 777));
        let mut e = running_pinned(&dir, keys, vec![usual_auditor()]);
        notes(&mut e);
        let t = NOW + LOG_SYNC_EVERY;
        assert!(matches!(
            e.outbound("100002", form(), b"known", t),
            Outbound::Encrypted(_)
        ));
        assert!(matches!(e.log_trust(), kt::Trust::Unaudited(_)));
        assert!(e.keys().session("100002", 777).is_none());
        let out = e.outbound("100003", form(), b"new", t);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        assert!(e.keys().pinned("100003").is_none());
        let got = e.inbound(
            "100003",
            &written_by(&dir, &mut c, "100001", b"hello", t),
            t,
        );
        assert!(matches!(got, Inbound::Unreadable(_)), "{got:?}");
        assert!(e.keys().session("100003", c.device_id).is_none());
        assert!(status_of(&mut e, "100003", t).contains("NOT AUDITED"));

        // The auditor cosigns the log as it is: taken.
        dir.audit_log(t);
        let t = t + LOG_SYNC_EVERY;
        assert!(matches!(
            e.outbound("100003", form(), b"vouched", t),
            Outbound::Encrypted(_)
        ));
        assert_eq!(e.log_trust(), kt::Trust::Trusted);
    }

    /// Finding 1: with an auditor named by `auditors =`, a log that cannot
    /// be read or that the server says it does not keep is not trust on
    /// first use, even on a state that never read one.
    #[test]
    fn with_auditors_configured_a_missing_log_is_not_trust_on_first_use() {
        for unreachable in [true, false] {
            let (dir, a, _) = two_published();
            if unreachable {
                dir.set_log_unreachable(true);
            } else {
                dir.set_log(false);
            }
            let mut e = running_pinned(&dir, a, vec![usual_auditor()]);
            let out = e.outbound("100002", form(), b"hi", NOW);
            assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
            assert!(e.keys().pinned("100002").is_none());
            assert!(matches!(
                e.log_trust(),
                kt::Trust::TemporarilyUnavailableAfterTrust(_)
            ));
        }
        // Guard: with no auditor named anywhere, an older server without a
        // log is still trust on first use.
        let (dir, a, _) = two_published();
        dir.set_log(false);
        let mut e = running(&dir, a);
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
        assert_eq!(e.log_trust(), kt::Trust::NeverHadLog);
    }

    /// Finding 2: a stale cosignature over more of the log vouches for
    /// nothing a fresh one does not cover. Auditor A cosigned 6 entries two
    /// hours ago, auditor B 4 entries now: the vouched part stops at 4, and
    /// a contact published in entries 5 and 6 is not taken.
    #[test]
    fn a_stale_cosignature_over_more_of_the_log_vouches_for_nothing_new() {
        let (dir, a, _) = two_published();
        dir.audit_log_as(B_AUDITOR, &B_SEED, NOW);
        let mut c = OwnKeys::create("100003");
        publish_keys(&dir, &mut c);
        assert_eq!(dir.log_size(), 6);
        dir.audit_log(NOW - 2 * kt::AUDIT_MAX_AGE);
        let b_key = kt::cosign(B_AUDITOR, &B_SEED, "", 0).1;
        let mut e = running_pinned(&dir, a, vec![usual_auditor(), b_key]);
        assert_eq!(e.keys().log.size, 6);
        assert_eq!(e.keys().log.vouched_size, 4);
        assert_eq!(e.log_trust(), kt::Trust::Trusted);
        assert!(matches!(
            e.outbound("100002", form(), b"vouched", NOW),
            Outbound::Encrypted(_)
        ));
        let out = e.outbound("100003", form(), b"not vouched", NOW);
        assert!(matches!(out, Outbound::Refused(_)), "{out:?}");
        assert!(e.keys().pinned("100003").is_none());
        let got = e.inbound(
            "100003",
            &written_by(&dir, &mut c, "100001", b"hello", NOW),
            NOW,
        );
        assert!(matches!(got, Inbound::Unreadable(_)), "{got:?}");
        assert!(e.keys().session("100003", c.device_id).is_none());
    }

    /// Sixth audit of 2026-10, findings 3 and 4, through two real engines and
    /// their Olm session: what B lets through in A's name is what A's
    /// add-on announced. A call's key offer vouches for its INVITE, a file
    /// offer for its proposal (neither is spent by the check); a tZer's
    /// `IQT1` for one tZer with that document, from that contact, for
    /// `NOTICE_TTL`. Nothing is vouched for before.
    #[test]
    fn an_announcement_over_the_session_vouches_for_a_call_a_file_and_one_tzer() {
        use crate::crypto::Action;
        use crate::icbm::Direction;
        let (dir, a, b) = two_published();
        let mut ea = running(&dir, a);
        let mut eb = running(&dir, b);
        for e in [&mut ea, &mut eb] {
            e.use_call_table(Default::default());
            e.use_file_table(Default::default());
            e.set_calls_encrypt(true);
            e.set_files_encrypt(true);
        }
        let mut lines = Vec::new();
        let call = Action::Call {
            peer: "100001".into(),
            call_id: "six-call".into(),
            sdp: crate::callneg::sdp_hash(None),
        };
        let file = Action::File {
            peer: "100001".into(),
            cookie: FILE_COOKIE,
            digest: file_rdv(Direction::Inbound, "100001", crate::files::RDV_PROPOSE).digest,
        };
        let hash = crate::tzer::doc_hash(crate::tzer::tests::DOC);
        let tzer = Action::Tzer {
            peer: "100001".into(),
            hash,
        };
        for a in [&call, &file, &tzer] {
            assert!(!eb.authenticated(a, false, NOW), "{a:?} before");
        }
        assert_eq!(eb.protected("100001"), None, "a contact not seen yet");

        let offer = ea.call_sip(
            Direction::Outbound,
            "100002",
            b"INVITE sip:100002@h SIP/2.0\r\nCall-ID: six-call\r\nCSeq: 1 INVITE\r\n\r\n",
            NOW,
            &mut lines,
        );
        hand(&mut eb, "100001", offer);
        assert!(eb.authenticated(&call, false, NOW));
        assert!(eb.authenticated(&call, true, NOW), "not spent by a check");
        assert!(eb.protected("100001").is_some(), "seen encrypting now");
        let other_call = Action::Call {
            peer: "100001".into(),
            call_id: "another".into(),
            sdp: crate::callneg::sdp_hash(None),
        };
        assert!(!eb.authenticated(&other_call, false, NOW));

        let offer = ea.file_icbm(
            &file_rdv(Direction::Outbound, "100002", crate::files::RDV_PROPOSE),
            NOW,
            &mut lines,
        );
        hand(&mut eb, "100001", offer);
        assert!(eb.authenticated(&file, false, NOW));

        let notice = ea.tzer_notice("100002", hash, NOW).expect("a session");
        assert!(matches!(
            hand(&mut eb, "100001", vec![notice])[..],
            [Inbound::Control(_)]
        ));
        let not_ours = Action::Tzer {
            peer: "100003".into(),
            hash,
        };
        assert!(!eb.authenticated(&not_ours, true, NOW), "another contact");
        let other_doc = Action::Tzer {
            peer: "100001".into(),
            hash: crate::tzer::doc_hash("<tzerRoot id=\"boo\"/>"),
        };
        assert!(!eb.authenticated(&other_doc, true, NOW), "another tZer");
        assert!(
            eb.authenticated(&tzer, false, NOW),
            "a look does not spend it"
        );
        assert!(eb.authenticated(&tzer, true, NOW));
        assert!(!eb.authenticated(&tzer, true, NOW), "one tZer per notice");

        let notice = ea.tzer_notice("100002", hash, NOW).expect("a session");
        hand(&mut eb, "100001", vec![notice]);
        assert!(!eb.authenticated(&tzer, true, NOW + crate::tzer::NOTICE_TTL));
    }

    // ---- seventh audit of 2026-10: binding, freshness, replay ----

    /// [`hand`] at another time than `NOW`: what the server can do by
    /// holding a container back.
    fn hand_at(to: &mut Engine, from: &str, containers: Vec<Vec<u8>>, now: u64) -> Vec<Inbound> {
        containers
            .iter()
            .map(|c| to.inbound(from, &container::Container::from_bytes(c).unwrap(), now))
            .collect()
    }

    /// Two engines with calls and files on, each with a table of its own;
    /// B's tables are returned to look into.
    #[allow(clippy::type_complexity)]
    fn seventh_pair() -> (
        Engine,
        Engine,
        Arc<std::sync::Mutex<crate::callneg::CallTable>>,
        Arc<std::sync::Mutex<crate::filesneg::FileTable>>,
    ) {
        let (dir, a, b) = two_published();
        let mut ea = running(&dir, a);
        let mut eb = running(&dir, b);
        let (tb, fb): (
            Arc<std::sync::Mutex<crate::callneg::CallTable>>,
            Arc<std::sync::Mutex<crate::filesneg::FileTable>>,
        ) = Default::default();
        ea.use_call_table(Default::default());
        ea.use_file_table(Default::default());
        eb.use_call_table(tb.clone());
        eb.use_file_table(fb.clone());
        for e in [&mut ea, &mut eb] {
            e.set_calls_encrypt(true);
            e.set_files_encrypt(true);
        }
        (ea, eb, tb, fb)
    }

    const SDP_H1: &[u8] = b"INVITE sip:100002@h SIP/2.0\r\nCall-ID: X\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n";
    const SDP_H2: &[u8] = b"INVITE sip:100002@h SIP/2.0\r\nCall-ID: X\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nc=IN IP4 203.0.113.66\r\nm=audio 6666 RTP/AVP 0\r\n";

    fn call_action(invite: &[u8]) -> Action {
        let (call_id, sdp) = crate::callneg::invite_binding(invite).unwrap();
        Action::Call {
            peer: "100001".into(),
            call_id,
            sdp,
        }
    }

    /// The owner's case: an authenticated `IQC1` Offer for Call-ID X binds
    /// SDP hash H1; a legacy INVITE with Call-ID X and SDP H2 is not vouched
    /// for, and does not take the offer. Before the fix the INVITE was
    /// vouched for (`vouched(peer, call_id)` looked at the Call-ID only), it
    /// took the offer ("INVITE in, with a key offer") and B answered with
    /// keys for it ("answered; key answer sent first").
    #[test]
    fn a_key_offer_vouches_only_for_the_invite_whose_sdp_it_bound() {
        use crate::icbm::Direction;
        let (mut ea, mut eb, tb, _) = seventh_pair();
        let mut lines = Vec::new();
        let offer = ea.call_sip(Direction::Outbound, "100002", SDP_H1, NOW, &mut lines);
        hand(&mut eb, "100001", offer);
        assert!(
            !eb.authenticated(&call_action(SDP_H2), false, NOW),
            "H2 is not what the offer bound"
        );
        assert!(eb.authenticated(&call_action(SDP_H1), false, NOW), "H1 is");
        // Even where nothing holds it (an automatic contact), the INVITE
        // with H2 does not take the offer and gets no keys.
        eb.call_sip(Direction::Inbound, "100001", SDP_H2, NOW, &mut lines);
        let answer = eb.call_sip(
            Direction::Outbound,
            "100001",
            b"SIP/2.0 200 OK\r\nCall-ID: X\r\nCSeq: 1 INVITE\r\n\r\n",
            NOW,
            &mut lines,
        );
        assert!(answer.is_empty(), "no key answer: {lines:?}");
        assert_eq!(tb.lock().unwrap().state_of("X"), Some("plain"), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("another SDP than this INVITE carries")),
            "{lines:?}"
        );
    }

    /// A genuine `IQC1`, `IQF1` or `IQT1` the server held back is no
    /// announcement any more once it is [`ANNOUNCE_MAX_AGE`] old by its
    /// sender's clock: delivered late, or delivered in time and its action
    /// presented late. Before the fix the time it arrived counted (the
    /// envelope's own limit is 14 days).
    #[test]
    fn a_delayed_announcement_vouches_for_nothing() {
        use crate::icbm::Direction;
        let late = NOW + ANNOUNCE_MAX_AGE;
        let mut lines = Vec::new();
        // Call: the offer delivered late.
        let (mut ea, mut eb, _, _) = seventh_pair();
        let offer = ea.call_sip(Direction::Outbound, "100002", SDP_H1, NOW, &mut lines);
        hand_at(&mut eb, "100001", offer, late);
        assert!(!eb.authenticated(&call_action(SDP_H1), false, late));
        // Call: the offer in time, the INVITE late.
        let (mut ea, mut eb, _, _) = seventh_pair();
        let offer = ea.call_sip(Direction::Outbound, "100002", SDP_H1, NOW, &mut lines);
        hand_at(&mut eb, "100001", offer, NOW + 1);
        assert!(eb.authenticated(&call_action(SDP_H1), false, NOW + 1));
        assert!(!eb.authenticated(&call_action(SDP_H1), false, late));
        // File: the offer delivered late.
        let (mut ea, mut eb, _, _) = seventh_pair();
        let prop = file_rdv(Direction::Outbound, "100002", crate::files::RDV_PROPOSE);
        let offer = ea.file_icbm(&prop, NOW, &mut lines);
        hand_at(&mut eb, "100001", offer, late);
        let file = Action::File {
            peer: "100001".into(),
            cookie: FILE_COOKIE,
            digest: prop.digest,
        };
        assert!(!eb.authenticated(&file, false, late));
        // File: in time, then the proposal late.
        let (mut ea, mut eb, _, _) = seventh_pair();
        let offer = ea.file_icbm(&prop, NOW, &mut lines);
        hand_at(&mut eb, "100001", offer, NOW + 1);
        assert!(eb.authenticated(&file, false, NOW + 1));
        assert!(!eb.authenticated(&file, false, late));
        // tZer: the notice delivered late, with a matching tZer.
        let hash = crate::tzer::doc_hash(crate::tzer::tests::DOC);
        let tzer = Action::Tzer {
            peer: "100001".into(),
            hash,
        };
        let (mut ea, mut eb, _, _) = seventh_pair();
        let notice = ea.tzer_notice("100002", hash, NOW).unwrap();
        hand_at(&mut eb, "100001", vec![notice], late);
        assert!(!eb.authenticated(&tzer, true, late));
        // A clock too far ahead is not fresh either.
        let (mut ea, mut eb, _, _) = seventh_pair();
        let notice = ea
            .tzer_notice("100002", hash, NOW + ANNOUNCE_MAX_AHEAD + 1)
            .unwrap();
        hand_at(&mut eb, "100001", vec![notice], NOW);
        assert!(!eb.authenticated(&tzer, true, NOW));
        // In time: one tZer.
        let (mut ea, mut eb, _, _) = seventh_pair();
        let notice = ea.tzer_notice("100002", hash, NOW).unwrap();
        hand_at(&mut eb, "100001", vec![notice], NOW + 5);
        assert!(eb.authenticated(&tzer, true, NOW + 5));
        assert!(!eb.authenticated(&tzer, true, NOW + 5));
    }

    /// The same `IQT1` container delivered twice opens once (its message key
    /// is spent), so it vouches for one tZer. A guard: true before the fix
    /// too.
    #[test]
    fn a_duplicated_tzer_notice_vouches_for_one_tzer() {
        let (mut ea, mut eb, _, _) = seventh_pair();
        let hash = crate::tzer::doc_hash(crate::tzer::tests::DOC);
        let notice = ea.tzer_notice("100002", hash, NOW).unwrap();
        let got = hand(&mut eb, "100001", vec![notice.clone(), notice]);
        assert!(matches!(got[0], Inbound::Control(_)), "{got:?}");
        assert!(matches!(got[1], Inbound::Unreadable(_)), "{got:?}");
        let tzer = Action::Tzer {
            peer: "100001".into(),
            hash,
        };
        assert!(eb.authenticated(&tzer, true, NOW));
        assert!(!eb.authenticated(&tzer, true, NOW));
    }

    /// A genuine `IQF1` binds its proposal: the same cookie with another
    /// port, address, proxy flag, stage, file count, size, name or
    /// invitation is not vouched for; the requester address the server
    /// rewrites and the verified address it adds are not part of it. Before
    /// the fix every one of them was vouched for (the cookie alone).
    #[test]
    fn a_file_offer_vouches_only_for_the_proposal_it_bound() {
        use crate::files::{self, tests::rdv_payload, RDV_PROPOSE};
        use crate::icbm::Direction;
        let svc = |n: u16, size: u32, name: &[u8]| {
            let mut v = vec![0, 1];
            v.extend_from_slice(&n.to_be_bytes());
            v.extend_from_slice(&size.to_be_bytes());
            v.extend_from_slice(name);
            v
        };
        let base = || -> Vec<(u16, Vec<u8>)> {
            vec![
                (files::RDV_TLV_SEQ, 1u16.to_be_bytes().to_vec()),
                (files::RDV_TLV_RDV_IP, vec![192, 168, 1, 20]),
                (files::RDV_TLV_REQUESTER_IP, vec![192, 168, 1, 20]),
                (files::RDV_TLV_PORT, 5190u16.to_be_bytes().to_vec()),
                (crate::icbm::RDV_TLV_SVC_DATA, svc(1, 5000, b"plans.pdf\0")),
            ]
        };
        let rdv = |dir, tlvs: &[(u16, Vec<u8>)]| {
            files::rendezvous(
                dir,
                &rdv_payload(dir, "100002", RDV_PROPOSE, FILE_COOKIE, tlvs),
            )
            .unwrap()
        };
        let (mut ea, mut eb, _, _) = seventh_pair();
        let mut lines = Vec::new();
        let sent = rdv(Direction::Outbound, &base());
        let offer = ea.file_icbm(&sent, NOW, &mut lines);
        hand(&mut eb, "100001", offer);
        let vouched = |eb: &mut Engine, tlvs: &[(u16, Vec<u8>)]| {
            let r = rdv(Direction::Inbound, tlvs);
            eb.authenticated(
                &Action::File {
                    peer: "100001".into(),
                    cookie: FILE_COOKIE,
                    digest: r.digest,
                },
                false,
                NOW,
            )
        };
        assert!(vouched(&mut eb, &base()), "the proposal as sent");
        // What the server does to it on the way (addExternalIP): still it.
        let mut served = base();
        served[2].1 = vec![203, 0, 113, 9];
        served.push((files::RDV_TLV_VERIFIED_IP, vec![203, 0, 113, 9]));
        assert!(vouched(&mut eb, &served), "requester and verified address");
        let changed: Vec<(&str, Vec<(u16, Vec<u8>)>)> = vec![
            ("port", {
                let mut t = base();
                t[3].1 = 6666u16.to_be_bytes().to_vec();
                t
            }),
            ("proposed address", {
                let mut t = base();
                t[1].1 = vec![198, 51, 100, 66];
                t
            }),
            ("proxy", {
                let mut t = base();
                t.push((files::RDV_TLV_USE_ARS, Vec::new()));
                t
            }),
            ("stage", {
                let mut t = base();
                t[0].1 = 3u16.to_be_bytes().to_vec();
                t
            }),
            ("file count", {
                let mut t = base();
                t[4].1 = svc(2, 5000, b"plans.pdf\0");
                t
            }),
            ("size", {
                let mut t = base();
                t[4].1 = svc(1, 9_999_999, b"plans.pdf\0");
                t
            }),
            ("name", {
                let mut t = base();
                t[4].1 = svc(1, 5000, b"plans.pdf.exe\0");
                t
            }),
            ("invitation text", {
                let mut t = base();
                t.push((0x000C, b"open this now".to_vec()));
                t
            }),
        ];
        for (what, t) in changed {
            assert!(!vouched(&mut eb, &t), "{what} changed");
        }
    }

    /// A genuine offer for a proposal that is not let through (held and
    /// given up) is no use later: the cookie is burned. And a call's
    /// Call-ID likewise.
    #[test]
    fn a_refused_action_cannot_be_vouched_for_later() {
        use crate::icbm::Direction;
        let (mut ea, mut eb, _, _) = seventh_pair();
        let mut lines = Vec::new();
        let call = call_action(SDP_H1);
        let prop = file_rdv(Direction::Outbound, "100002", crate::files::RDV_PROPOSE);
        let file = Action::File {
            peer: "100001".into(),
            cookie: FILE_COOKIE,
            digest: prop.digest,
        };
        // The INVITE and the proposal came first, were held and given up.
        eb.refused(&call, NOW);
        eb.refused(&file, NOW);
        // Then the server lets the offers through, and repeats the frames.
        let offer = ea.call_sip(Direction::Outbound, "100002", SDP_H1, NOW, &mut lines);
        hand(&mut eb, "100001", offer);
        let offer = ea.file_icbm(&prop, NOW, &mut lines);
        hand(&mut eb, "100001", offer);
        assert!(!eb.authenticated(&call, false, NOW + 1));
        assert!(!eb.authenticated(&file, false, NOW + 1));
    }
}
