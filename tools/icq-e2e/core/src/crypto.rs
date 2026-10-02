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
use crate::directory::{DeviceState, DirError, DirectoryApi, SignedKey};
use crate::keys::{
    self, Inbound, Outbound, OwnKeys, FALLBACK_KEY_LIFETIME, ONE_TIME_REFILL_BELOW, ONE_TIME_TARGET,
};
use crate::policy::{self, Command, Held, Remembered, Setting, Status};
use crate::sign;

/// How long to keep asking after `403 not_announced`: the account key goes out
/// in the `SetInfo` the client sends while signing on, and the HTTPS request
/// can overtake it. Thirty seconds at two is what the API document records.
pub const ANNOUNCE_RETRY: Duration = Duration::from_secs(30);
/// The gap between those attempts.
pub const ANNOUNCE_EVERY: Duration = Duration::from_secs(2);
/// A token is refreshed this long before it expires.
pub const TOKEN_REFRESH_BEFORE: Duration = Duration::from_secs(3600);

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

    /// A control message to send, if one is due: after an incoming key
    /// exchange, or after [`HEARTBEAT`] messages without one going out.
    fn take_control(&mut self, peer: &str) -> Option<Vec<u8>>;

    /// How many messages have gone to `peer` since we last sent a control
    /// message, which is what the heartbeat counts.
    fn since_control(&self, peer: &str) -> u32;
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
        if !done.fallback {
            match self.fallback_key(keys, bearer, now) {
                Ok(()) => done.fallback = true,
                Err(p) => return p,
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
    keys.fallback_key_at == 0 || now >= keys.fallback_key_at + FALLBACK_KEY_LIFETIME
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
    /// Whether the keys or a contact's setting changed since the state file
    /// was last written.
    changed: bool,
    /// A publish this sign-on failed in a way the user was told about, so a
    /// later success is worth one note.
    publish_failed: bool,
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
            changed: false,
            publish_failed: false,
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
        p
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

    /// Queues a note once per sign-on, keyed by `key`.
    fn note_once(&mut self, peer: Option<&str>, key: String, text: String) {
        if self.said.insert(key) {
            self.queue(Note {
                peer: peer.map(str::to_string),
                text,
            });
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
                let c = self.keys.checked_contact(&ud, now);
                // The pin may have been made or moved.
                self.changed = true;
                if c.usable() {
                    self.remember(peer, |r| r.seen_encrypting = true);
                    Ok(c)
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
            match self.dir.user_devices(peer) {
                Ok(ud) => {
                    let n = self.keys.checked_contact(&ud, now).devices.len();
                    self.changed = true;
                    if n > 0 {
                        format!("{peer} has {n} signed device(s) in the key directory")
                    } else {
                        format!("{peer} has no encryption keys in the key directory")
                    }
                }
                Err(e) if e.code() == "no_account" => {
                    format!("{peer} has no encryption keys in the key directory")
                }
                Err(e) => format!("the key directory could not be reached ({e})"),
            }
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
            "{}Encryption with {peer}: {setting}; {keys}{seen}. The next message goes {next}. Commands: {}.",
            policy::PREFIX,
            policy::COMMANDS
        )
    }

    /// Moves a note a pinned-key change made into the queue for the stream,
    /// once: it is taken out of the state file as it is shown.
    fn drain_pin_notes(&mut self, peer: &str) {
        let key = format!("pin:{}", sign::ident(peer));
        if let Some(note) = self.keys.said.remove(&key) {
            self.changed = true;
            self.queue(Note::to(peer, note));
        }
    }
}

impl Crypto for Engine {
    fn bearer(&self) -> Option<String> {
        self.token.as_ref().map(|t| t.bearer.clone())
    }

    fn ready(&self) -> bool {
        self.ready
    }

    fn account_key(&self) -> Option<[u8; 32]> {
        Some(self.keys.account_key_bytes())
    }

    fn command(&mut self, peer: &str, text: &str, now: u64) -> bool {
        let Some(cmd) = policy::parse_command(text) else {
            return false;
        };
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
            Command::Help => format!(
                "{pre}Unknown command. The commands are: {}.",
                policy::COMMANDS
            ),
        };
        self.queue(Note::to(peer, note));
        true
    }

    fn outbound(&mut self, peer: &str, form: Form, text: &[u8], now: u64) -> Outbound {
        let contact = match self.decide(peer, now, true) {
            Decision::Encrypt(c) => c,
            Decision::Hold(why) => return self.hold(peer, why),
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
        self.changed = true;
        match self.keys.encrypt(&*self.dir, &bearer, &out, &contact) {
            Ok(Outbound::Encrypted(wire)) => {
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
        let got = self.keys.decrypt(&*self.dir, peer, container, now);
        self.changed = true;
        match &got {
            // An incoming key exchange means the contact may keep sending them,
            // so one control message of our own is due (CHECKLIST 2.2). It is
            // an encrypted exchange too, so the contact is remembered as
            // encrypting; nothing is shown for it.
            Inbound::Control => {
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
        if self.notes.is_empty() {
            None
        } else {
            Some(self.notes.remove(0))
        }
    }

    fn take_control(&mut self, peer: &str) -> Option<Vec<u8>> {
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
        self.changed = true;
        match self.keys.encrypt(&*self.dir, &bearer, &out, &contact) {
            Ok(Outbound::Encrypted(wire)) => container::find_armor(&wire),
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
}

/// Why a contact was not found, which decides whether the answer is worth
/// remembering: a fact about them, or a moment when the directory was down.
enum Lookup {
    /// The directory has no account for this contact, or no device of theirs
    /// checks out.
    NoKeys,
    /// The directory could not be reached, or did not answer.
    Transient(String),
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
        assert!(matches!(ea.inbound("100002", &c, NOW), Inbound::Control));
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
}
