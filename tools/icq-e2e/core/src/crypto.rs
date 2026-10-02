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
use crate::keys::{
    self, Inbound, Outbound, OwnKeys, FALLBACK_KEY_LIFETIME, ONE_TIME_REFILL_BELOW, ONE_TIME_TARGET,
};
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
    /// When our copy of the key log was last brought up to date, and how
    /// that went.
    log_synced_at: Option<u64>,
    log_status: LogStatus,
    /// What the log's auditors said about our copy, last time we looked.
    audit_status: AuditStatus,
    /// The `auditors =` line of `icq-e2e.ini`, read: exactly the auditors
    /// trusted, instead of the ones the server names on first sight.
    pinned_auditors: Option<Vec<String>>,
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
            log_synced_at: None,
            log_status: LogStatus::Unknown,
            audit_status: AuditStatus::Unknown,
            pinned_auditors: None,
        }
    }

    /// Trusts exactly these auditors (the `auditors =` line of
    /// `icq-e2e.ini`), or, with `None`, the ones the server names when the
    /// log is first audited.
    pub fn set_auditors(&mut self, keys: Option<Vec<String>>) {
        self.pinned_auditors = keys;
    }

    /// Switches call encryption on or off (`calls_encrypt=` of the ini).
    pub fn set_calls_encrypt(&mut self, on: bool) {
        self.calls_encrypt = on;
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
            Err(Lookup::NotInLog(why)) => return Err(why),
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
            Err(Lookup::Transient(e)) | Err(Lookup::NotInLog(e)) => return Err(e),
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
        self.keys.log_trusted = false;
        match kt::sync(&*self.dir, &self.keys.log) {
            Ok(next) => {
                if next != self.keys.log {
                    self.keys.log = next;
                    self.changed = true;
                }
                self.log_status = LogStatus::Ok;
                self.keys.log_trusted = true;
                self.check_own_log();
                self.audit_log(now, true);
            }
            Err(kt::SyncError::NoLog) => self.log_status = LogStatus::NoLog,
            Err(kt::SyncError::Net(e)) => self.log_status = LogStatus::Failed(e),
            Err(e) => {
                let why = e.to_string();
                self.note_once(None, "kt:broken".into(), policy::log_broken_note(&why));
                self.log_status = LogStatus::Broken(why);
            }
        }
        true
    }

    /// Looks at the cosignatures of the log's auditors (stage 2). A
    /// checkpoint any of them saw that is not in our copy means the server
    /// shows us another log than it showed that auditor: the log is not
    /// trusted from then on, as for a rewritten one. No recent cosignature by
    /// any of them is a warning, once per sign-on.
    fn audit_log(&mut self, now: u64, may_resync: bool) {
        let (next, r) = kt::audit(
            &*self.dir,
            &self.keys.log,
            now,
            self.pinned_auditors.as_deref(),
        );
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
                self.note_once(None, "kt:stale".into(), policy::audit_stale_note(&why));
                AuditStatus::Stale(why)
            }
            Err(kt::AuditError::SplitView(why)) => {
                self.note_once(None, "kt:broken".into(), policy::log_broken_note(&why));
                self.log_status = LogStatus::Broken(why.clone());
                self.keys.log_trusted = false;
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
    /// `Err` if their account key is not the log's, else the ids of devices
    /// the log does not have with these keys. Nothing while the log is not
    /// readable.
    fn log_check(&self, peer: &str, ud: &UserDevices) -> Result<Vec<u32>, String> {
        if self.log_status != LogStatus::Ok {
            return Ok(Vec::new());
        }
        let Some(acc) = self.keys.log.accounts.get(&sign::ident(peer)) else {
            return Err(format!("{peer}'s keys are not in the server's key log"));
        };
        if acc.key != ud.account_key {
            return Err(format!(
                "{peer}'s account key in the key directory is not the one the server's key log shows"
            ));
        }
        Ok(ud
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
            .collect())
    }

    /// [`Engine::log_check`] against a copy of the log that is up to date: a
    /// change the contact made a moment ago may not be in our copy yet.
    fn logged(&mut self, peer: &str, ud: &UserDevices, now: u64) -> Result<Vec<u32>, String> {
        let fresh = self.sync_log(now, false);
        match self.log_check(peer, ud) {
            Ok(none) if none.is_empty() => Ok(none),
            _ if !fresh => {
                self.sync_log(now, true);
                self.log_check(peer, ud)
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
            LogStatus::NoLog => {
                "; key log: the server keeps none, so keys are trusted on first use".into()
            }
            LogStatus::Failed(e) => format!("; key log: could not be read ({e})"),
            LogStatus::Broken(why) => {
                format!("; key log: NOT TRUSTED - {why} (/e2e resetlog once the operator explains)")
            }
            LogStatus::Ok => {
                let logged = self
                    .keys
                    .log
                    .accounts
                    .get(&sign::ident(peer))
                    .map(|a| a.key.clone());
                let audit = self.describe_audit(now);
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
                // A key the log does not show is never pinned.
                let left_out = self.logged(peer, &ud, now).map_err(Lookup::NotInLog)?;
                let mut c = self.keys.checked_contact(&ud, now);
                // The pin may have been made or moved.
                self.changed = true;
                if !left_out.is_empty() {
                    let p = sign::ident(peer);
                    c.devices.retain(|d| !left_out.contains(&d.device_id));
                    for id in left_out {
                        self.note_once(
                            Some(peer),
                            format!("kt:device:{p}:{id}"),
                            policy::log_device_left_out_note(peer, id),
                        );
                    }
                }
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
                Err(Lookup::NotInLog(why)) => format!("{peer}'s keys are not used: {why}"),
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
                Err(Lookup::NotInLog(why)) => format!(
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
        if let Err(Lookup::NotInLog(why)) = &looked {
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
                        Err(Lookup::NotInLog(why)) => note.push_str(&format!(
                            " Messages to {peer} are held: {why}."
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
                self.keys.log_trusted = false;
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
        self.queue(Note::to(peer, note));
        true
    }

    fn outbound(&mut self, peer: &str, form: Form, text: &[u8], now: u64) -> Outbound {
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
        // A new session from a key our copy of the key log does not have may
        // only mean the copy is behind: once more with a fresh one. A message
        // that did not open left no ratchet step and spent no one-time key.
        // Only a pre-key message can make a new session.
        let pre_key = container
            .wrap_for(self.keys.device_id)
            .is_some_and(|w| w.olm_type == 0);
        let fresh = pre_key && self.sync_log(now, false);
        let mut got = self.keys.decrypt(&*self.dir, peer, container, now);
        if pre_key && matches!(got, Inbound::Unreadable(_)) && self.keys.log_trusted && !fresh {
            self.sync_log(now, true);
            got = self.keys.decrypt(&*self.dir, peer, container, now);
        }
        self.changed = true;
        // A call key exchange (`calls_encrypt=on` only): it goes to the call
        // table and is answered by the call's own SIP, not by a control
        // message of ours. Off, it is taken below like any control message,
        // as an add-on without call support takes it.
        if self.calls_encrypt {
            if let Inbound::Control(payload) = &got {
                if let Some(msg) = crate::callneg::Msg::decode(payload) {
                    let table = self.calls.clone();
                    lock_calls(&table).control(peer, container.sender_device, msg, now * 1000);
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
        if self.notes.is_empty() {
            None
        } else {
            Some(self.notes.remove(0))
        }
    }

    fn take_control(&mut self, peer: &str) -> Option<Vec<u8>> {
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
}

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
    fn a_verified_contact_s_plain_call_is_said_in_strong_words_not_blocked() {
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
        let n = texts(&mut ea);
        assert!(
            n.iter().any(|n| n.contains("calls are never blocked")),
            "{n:?}"
        );
        assert_eq!(
            ta.lock().unwrap().media_out(1, &rtp(1), NOW * 1000),
            Verdict::Pass
        );
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

    #[test]
    fn a_rewritten_log_is_said_and_keys_fall_back_to_first_use() {
        let (dir, a, _) = two_published();
        let mut e = running(&dir, a);
        dir.rewrite_log(
            0,
            kt::build_leaf("account", "100009", 1, &[b"publish", &[9; 32]]),
        );
        let later = NOW + LOG_SYNC_EVERY;
        assert!(matches!(
            e.outbound("100002", form(), b"hi", later),
            Outbound::Encrypted(_)
        ));
        let n = notes(&mut e);
        let warned: Vec<_> = n
            .iter()
            .filter(|n| n.text.contains("WARNING: the key log was rewritten"))
            .collect();
        assert_eq!(warned.len(), 1, "{n:?}");
        assert!(
            status_of(&mut e, "100002", later + LOG_SYNC_EVERY).contains("key log: NOT TRUSTED")
        );
        // The copy that was good is kept.
        assert_eq!(e.keys().log.size, 4);

        // The operator explains; the user starts the copy afresh.
        assert!(e.command("100002", "/e2e resetlog", later));
        assert!(notes(&mut e)[0].text.contains("forgotten"));
        assert!(status_of(&mut e, "100002", later).contains("100002's keys are in it, checked"));
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

        // The auditor checked fewer entries than there are now: still fine.
        let mut c = OwnKeys::create("100003");
        publish_keys(&dir, &mut c);
        let s = status_of(&mut e, "100003", NOW + LOG_SYNC_EVERY);
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
        // Messages still go, trusted on first use as without a log.
        assert!(matches!(
            e.outbound("100002", form(), b"hi", NOW),
            Outbound::Encrypted(_)
        ));
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
            // Messages still go, checked against the log.
            assert!(matches!(
                e.outbound("100002", form(), b"hi", NOW),
                Outbound::Encrypted(_)
            ));
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
}
