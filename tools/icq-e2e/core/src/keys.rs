//! Own keys, sessions with other devices, and what a contact's keys have to
//! prove before a message goes to them (docs/e2e/STAGE-3-CLIENT-CRYPTO.md).
//!
//! One device per account in this stage. The account key is a vodozemac
//! `Ed25519SecretKey` that signs the device; the device is a vodozemac `Account`
//! (Curve25519 identity key, Ed25519 signing key, one-time keys, fallback key).
//! One Olm session per peer device, built only when a message is about to go out
//! (CHECKLIST 2.1) by claiming a one-time key, or the fallback key when the pool
//! is empty - the owner's decision, since requiring a one-time key would let any
//! signed-on account block new conversations by claiming the pool empty.
//!
//! Every key a contact claims is checked before it is used: the account key
//! against the one pinned on first use, the device against the account key, and
//! the claimed key against the device's Ed25519 key. The server is untrusted
//! (CHECKLIST 4.1, 4.3), so the checks here are the ones that matter.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, KeyId};

use crate::container::{
    self, Container, Envelope, Form, Kind, Wrap, FLAG_CONTROL, OLM_NORMAL, OLM_PRE_KEY,
};
use crate::directory::{
    Claim, Device, DeviceState, DirError, DirResult, DirectoryApi, SignedKey, UserDevices,
};
use crate::sign;

/// Which of the key directory's two key kinds is being signed: the signed
/// byte string differs only in its purpose field (KEY-DIRECTORY-API.md 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    OneTime,
    Fallback,
}

/// The Olm session configuration, the one without the experimental feature.
pub const SESSION_CONFIG: SessionConfig = SessionConfig::version_1();

/// How a new session's first secret is agreed: the one step in front of the
/// Double Ratchet that a post-quantum handshake replaces (CHECKLIST 9.1, 9.8).
///
/// Everything after it - the ratchet, the wraps, the container, the state
/// file's session pickles - is the same for every kind, because each kind
/// ends in a vodozemac [`Session`]. PQXDH will be a second variant that
/// claims the extra ML-KEM key, runs Signal's PQXDH, and hands the result to
/// vodozemac's hazmat `Session::from_root_key_material` (feature
/// `low-level-api`); the receiving side needs a matching constructor, which
/// vodozemac 0.11.1 does not have yet (see CHECKLIST 9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handshake {
    /// Olm's own triple Diffie-Hellman, vodozemac's `create_outbound_session`
    /// and `create_inbound_session`: container scheme 1.
    Olm3Dh,
}

/// The handshake this build starts sessions with.
pub const HANDSHAKE: Handshake = Handshake::Olm3Dh;

impl Handshake {
    /// The container scheme whose sessions this handshake makes.
    pub fn scheme(self) -> u8 {
        match self {
            Handshake::Olm3Dh => container::SCHEME_OLM,
        }
    }

    /// The sender's side: a session to a device, from its identity key and
    /// the key claimed for it.
    fn start_outbound(
        self,
        account: &Account,
        their_identity: Curve25519PublicKey,
        their_one_time: Curve25519PublicKey,
    ) -> Result<Session, String> {
        match self {
            Handshake::Olm3Dh => account
                .create_outbound_session(SESSION_CONFIG, their_identity, their_one_time)
                .map_err(|e| e.to_string()),
        }
    }

    /// The receiver's side: a session from the first message a device sent,
    /// and that message's plaintext. Uses up the one-time key it names.
    fn start_inbound(
        self,
        account: &mut Account,
        their_identity: Curve25519PublicKey,
        first: &vodozemac::olm::PreKeyMessage,
    ) -> Option<(Session, Vec<u8>)> {
        match self {
            Handshake::Olm3Dh => account
                .create_inbound_session(SESSION_CONFIG, their_identity, first)
                .ok()
                .map(|r| (r.session, r.plaintext)),
        }
    }
}

/// How many one-time keys the pool holds, and the count below which it is
/// refilled (CHECKLIST 1.2). vodozemac publishes at most 50 at a time.
pub const ONE_TIME_TARGET: u32 = 50;
pub const ONE_TIME_REFILL_BELOW: u32 = 25;

/// How often the fallback key is replaced. vodozemac keeps the previous private
/// half until `forget_fallback_key`, which runs this long after a replacement,
/// so a message claimed before the swap still opens (CHECKLIST 1.4).
pub const FALLBACK_KEY_LIFETIME: u64 = 7 * 24 * 60 * 60;

/// How far a received message's send time may sit from ours (CHECKLIST 3.5).
/// Offline messages are stored by the server for hours, so the past is generous;
/// the future is tight, since a far-future stamp is a replay attempt.
pub const TIME_SKEW_PAST: u64 = 14 * 24 * 60 * 60;
pub const TIME_SKEW_FUTURE: u64 = 10 * 60;

/// vodozemac's own limits bound what we keep for skipped message keys
/// (CHECKLIST 2.4): at most 40 skipped keys per receiving chain, a gap of at
/// most 2000 messages, and 5 receiving chains at a time. The add-on adds
/// nothing of its own, so an out-of-order flood cannot make it grow without
/// bound; these are named here so the bound is written down, not only
/// inherited.
pub const SKIPPED_KEYS_PER_CHAIN: usize = 40;
pub const MAX_MESSAGE_GAP: u64 = 2000;
pub const MAX_RECEIVING_CHAINS: usize = 5;

/// One device of ours, the account key that signs it, and the sessions and
/// pins that go with it. Everything here is what the state file holds, so it
/// serialises: vodozemac objects are stored as their pickles.
#[derive(Serialize, Deserialize)]
pub struct OwnKeys {
    /// The state file's format, [`crate::store::STATE_VERSION`] once loaded or
    /// made; 0 in a file written before the version was recorded.
    #[serde(default)]
    pub version: u32,
    /// The account's screen name in ident form.
    pub screen_name: String,
    /// The account key: one per UIN, shared by its devices, signs the devices.
    pub account_key: Ed25519SecretKey,
    pub device_id: u32,
    /// The Olm account: identity keys, one-time keys and fallback key, as the
    /// JSON of its vodozemac pickle.
    pub account: String,
    /// When the fallback key was replaced, Unix seconds; 0 if never.
    #[serde(default)]
    pub fallback_key_at: u64,
    /// Contacts whose account key we pinned, and when.
    #[serde(default)]
    pub pins: HashMap<String, PinnedKey>,
    /// Sessions with peers, by screen name and then device id. vodozemac's
    /// `SessionPickle` is neither `Clone` nor `Copy`, so each one is kept as
    /// the JSON it serialises to and turned back with `Session::from_pickle`
    /// on use; the same is true of the account pickle.
    #[serde(default)]
    pub sessions: HashMap<String, HashMap<u32, String>>,
    /// Notes waiting to be shown once: a pinned key that changed, under
    /// `pin:<uin>`, taken out when it is shown.
    #[serde(default)]
    pub said: HashMap<String, String>,
    /// What the user chose for each contact and whether the contact was ever
    /// seen encrypting (CHECKLIST 10.1, 10.7), by screen name in ident form.
    #[serde(default)]
    pub contacts: HashMap<String, crate::policy::Remembered>,
    /// Our copy of the key log (docs/e2e/KEY-TRANSPARENCY.md).
    #[serde(default)]
    pub log: crate::kt::LogState,
    /// Set by the engine while its copy of the key log is up to date and
    /// trusted: a new inbound session is then made only with a key the log
    /// shows. Not kept in the state file.
    #[serde(skip)]
    pub log_trusted: bool,
}

/// A contact's account key as we pinned it, and when, and whether the user
/// verified it by comparing safety numbers (CHECKLIST 10.10).
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct PinnedKey {
    pub key: String,
    pub at: u64,
    /// The account key the user verified with `/e2e verify`. The contact is
    /// verified only while this is the pinned key: verification belongs to
    /// one key, never to the contact as such. Cleared when the key changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<String>,
    /// The key changed while the contact was verified: messages to them are
    /// held until the user verifies the new safety number (`/e2e verify`) or
    /// sends on without verifying (`/e2e accept`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
}

impl PinnedKey {
    fn new(key: &str, at: u64) -> PinnedKey {
        PinnedKey {
            key: key.to_string(),
            at,
            verified: None,
            held: false,
        }
    }

    /// Whether the user verified the key that is pinned now.
    pub fn is_verified(&self) -> bool {
        self.verified.as_deref() == Some(self.key.as_str())
    }
}

/// A message on its way out, as the caller found it on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub peer: String,
    /// How the text was carried: channel-1 fragment or 8-bit text.
    pub form: Form,
    /// The text exactly as the client produced it, HTML and smileys included.
    pub text: Vec<u8>,
    /// The send time, Unix seconds.
    pub now: u64,
}

/// What became of an outbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// The armoured container: the whole wire text.
    Encrypted(String),
    /// The contact is not in the directory, so clear text goes out and the user
    /// is told once per sign-on (CHECKLIST 3.7).
    Clear { text: String, note: String },
    /// The contact announces the add-on but no session could be made, so nothing
    /// goes out in clear and the user is told.
    Refused(String),
}

/// What came out of an inbound container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// The original text, as the sending client produced it.
    Text {
        text: Vec<u8>,
        form: Form,
        /// The contact's screen name, from the envelope.
        peer: String,
        /// Set when the sender could not be checked against the directory.
        unverified: bool,
    },
    /// A control message: nothing to show, the ratchet has advanced. It may
    /// carry a payload for the add-on itself (a call key exchange,
    /// `callneg.rs`); an empty one only moves the ratchet.
    Control(Vec<u8>),
    /// It could not be read; show `note` and never start a session because of
    /// it (CHECKLIST 2.5).
    Unreadable(String),
}

/// What the directory says about one contact, already checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contact {
    pub screen_name: String,
    /// Active devices whose `device` signature verifies under the account key.
    pub devices: Vec<Device>,
}

impl Contact {
    /// Whether a message can be encrypted for this contact.
    pub fn usable(&self) -> bool {
        !self.devices.is_empty()
    }
}

impl OwnKeys {
    /// A fresh account for `screen_name`: an account key, a random device id and
    /// a fresh Olm account. Nothing is in the directory yet.
    pub fn create(screen_name: &str) -> Self {
        OwnKeys {
            version: crate::store::STATE_VERSION,
            screen_name: sign::ident(screen_name),
            account_key: Ed25519SecretKey::new(),
            device_id: random_device_id(),
            account: pickle_json(&Account::new().pickle()),
            fallback_key_at: 0,
            pins: HashMap::new(),
            sessions: HashMap::new(),
            said: HashMap::new(),
            contacts: HashMap::new(),
            log: crate::kt::LogState::default(),
            log_trusted: false,
        }
    }

    /// The account key's public half, base64 as the directory writes it.
    pub fn account_key_b64(&self) -> String {
        self.account_key.public_key().to_base64()
    }

    /// The raw 32 bytes of the account key, for `LocateSetInfo` TLV `0x0E2E`
    /// (KEY-DIRECTORY-API.md 3.3).
    pub fn account_key_bytes(&self) -> [u8; 32] {
        *self.account_key.public_key().as_bytes()
    }

    /// The signed account object for `PUT /account`: the key and its
    /// self-signature.
    pub fn account_object(&self) -> (String, String) {
        let key = self.account_key_b64();
        let msg = sign::account(&self.screen_name, self.account_key.public_key().as_bytes());
        (key, self.account_key.sign(&msg).to_base64())
    }

    /// The signed device object for `PUT /devices/{id}`: the two keys and the
    /// account key's signature over them. `None` when the state file's account
    /// pickle does not read back, which is a corrupt file.
    pub fn device_object(&self) -> Option<(String, String, String)> {
        let a = self.account()?;
        let (curve, ed) = (a.curve25519_key(), a.ed25519_key());
        let msg = sign::device(
            &self.screen_name,
            self.device_id,
            curve.as_bytes(),
            ed.as_bytes(),
        );
        Some((
            curve.to_base64(),
            ed.to_base64(),
            self.account_key.sign(&msg).to_base64(),
        ))
    }

    /// The Olm account this state file describes. A pickle that does not read
    /// back is a corrupt state file, which the caller treats as "no keys"; it
    /// must never be silently replaced, or the device would change identity.
    pub fn account(&self) -> Option<Account> {
        let pickle: AccountPickle = serde_json::from_str(&self.account).ok()?;
        Some(Account::from_pickle(pickle))
    }

    /// The Olm session with a peer device, if we hold one.
    pub fn session(&self, peer: &str, device: u32) -> Option<Session> {
        let json = self.sessions.get(&sign::ident(peer))?.get(&device)?;
        let pickle: SessionPickle = serde_json::from_str(json).ok()?;
        Some(Session::from_pickle(pickle))
    }

    /// Keeps a session in the state file.
    fn set_session(&mut self, peer: &str, device: u32, session: &Session) {
        let json = pickle_json(&session.pickle());
        self.sessions
            .entry(sign::ident(peer))
            .or_default()
            .insert(device, json);
    }

    /// Picks another device id, for `409 device_conflict`.
    pub fn new_device_id(&mut self) -> u32 {
        self.device_id = random_device_id();
        self.device_id
    }

    /// Makes a new device, keeping the account key, for `410 device_revoked`
    /// and for a reset: a fresh Olm account, a fresh id, no sessions.
    pub fn new_device(&mut self) {
        self.account = pickle_json(&Account::new().pickle());
        self.fallback_key_at = 0;
        self.sessions.clear();
        self.device_id = random_device_id();
    }

    // --- keys to publish ---------------------------------------------------

    /// Generates one-time keys up to [`ONE_TIME_TARGET`] and returns the new
    /// ones, signed, ready for `POST /devices/{id}/one-time-keys`. Empty when
    /// the account already holds that many or the state file is unreadable.
    ///
    /// The gap is measured against the keys this account *holds*, not against
    /// what the directory has been told: after a claim the held count falls
    /// while the server's does not, and generating against the server's number
    /// would push the pool past the target on every sign-on.
    pub fn new_one_time_keys(&mut self, published: u32) -> Vec<SignedKey> {
        let mut account = match self.account() {
            Some(a) => a,
            None => return Vec::new(),
        };
        let held = account.stored_one_time_key_count();
        // Keys already made but not yet uploaded count towards the target too,
        // or a retry would make a second set and drop the first.
        let unpublished = account.one_time_keys().len();
        if held >= ONE_TIME_TARGET as usize || published >= ONE_TIME_TARGET {
            return Vec::new();
        }
        let missing = ONE_TIME_TARGET as usize - held;
        account.generate_one_time_keys(missing);
        let signed = self.sign_keys(&account, &account.one_time_keys(), Purpose::OneTime);
        debug_assert!(
            signed.len() + unpublished <= ONE_TIME_TARGET as usize,
            "a refill must not push the pool past the target"
        );
        account.mark_keys_as_published();
        self.account = pickle_json(&account.pickle());
        signed
    }

    /// Replaces the fallback key when it is [`FALLBACK_KEY_LIFETIME`] old, and
    /// forgets the private half of the one before that. Returns the new key to
    /// publish, if there is one (CHECKLIST 1.4).
    pub fn rotate_fallback_key(&mut self, now: u64) -> Option<SignedKey> {
        let due = self.fallback_key_at == 0 || now >= self.fallback_key_at + FALLBACK_KEY_LIFETIME;
        if !due {
            return None;
        }
        let mut account = self.account()?;
        account.generate_fallback_key();
        let signed = self.sign_keys(&account, &account.fallback_key(), Purpose::Fallback);
        account.mark_keys_as_published();
        // The private half of the replaced key is kept this long, so a message
        // claimed before the swap still opens; forgetting it now would drop it
        // at once, so the previous half is only released on a later rotation.
        self.account = pickle_json(&account.pickle());
        self.fallback_key_at = now;
        signed.into_iter().next()
    }

    /// Signs a set of public keys with the device's own Ed25519 key, under the
    /// purpose the key directory expects. The signature is made by the same
    /// `Account` the keys came from, so it is always over the right key.
    fn sign_keys(
        &self,
        account: &Account,
        keys: &HashMap<KeyId, Curve25519PublicKey>,
        purpose: Purpose,
    ) -> Vec<SignedKey> {
        keys.iter()
            .map(|(id, key)| {
                let id = id.to_base64();
                let msg = match purpose {
                    Purpose::OneTime => {
                        sign::one_time_key(&self.screen_name, self.device_id, &id, key.as_bytes())
                    }
                    Purpose::Fallback => {
                        sign::fallback_key(&self.screen_name, self.device_id, &id, key.as_bytes())
                    }
                };
                SignedKey {
                    key_id: id,
                    public_key: key.to_base64(),
                    signature: account.sign(&msg).to_base64(),
                }
            })
            .collect()
    }

    // --- trust -------------------------------------------------------------

    /// Pins a contact's account key on first use, silently, as Signal does.
    /// A key that differs from the pin is a change of the safety number: the
    /// caller is told once and the new key is pinned (CHECKLIST 4.3, 10.10).
    /// For an unverified contact that is all - messages go on, to the new key.
    /// For a verified one the verification is cleared and the contact is
    /// marked [`PinnedKey::held`], so the next message waits for the user.
    /// Returns the note, if there is one.
    pub fn pin(&mut self, peer: &str, account_key: &str, now: u64) -> Option<String> {
        let peer = sign::ident(peer);
        match self.pins.get(&peer) {
            None => {
                self.pins.insert(peer, PinnedKey::new(account_key, now));
                None
            }
            Some(p) if p.key == account_key => None,
            Some(p) => {
                let was_verified = p.is_verified() || p.held;
                let mut next = PinnedKey::new(account_key, now);
                next.held = was_verified;
                self.pins.insert(peer.clone(), next);
                Some(crate::policy::safety_changed_note(&peer, was_verified))
            }
        }
    }

    /// The pinned key of `peer`, if any.
    pub fn pinned(&self, peer: &str) -> Option<&PinnedKey> {
        self.pins.get(&sign::ident(peer))
    }

    /// The safety number with `peer` for the account key pinned for them:
    /// the 60 digits both sides compare ([`crate::safety`]). `None` without a
    /// pin, or with one that is not an Ed25519 key.
    pub fn safety_number(&self, peer: &str) -> Option<String> {
        let theirs = Ed25519PublicKey::from_base64(&self.pinned(peer)?.key).ok()?;
        Some(crate::safety::safety_number(
            &self.screen_name,
            &self.account_key_bytes(),
            peer,
            theirs.as_bytes(),
        ))
    }

    /// Marks the key pinned for `peer` as verified - that key, not the
    /// contact - and releases a message hold after a change. `false` without
    /// a pin.
    pub fn verify(&mut self, peer: &str) -> bool {
        let Some(p) = self.pins.get_mut(&sign::ident(peer)) else {
            return false;
        };
        p.verified = Some(p.key.clone());
        p.held = false;
        true
    }

    /// Takes a verification back, and releases a hold after a change: an
    /// unverified contact is never held. Whether there was anything to clear.
    pub fn unverify(&mut self, peer: &str) -> bool {
        let Some(p) = self.pins.get_mut(&sign::ident(peer)) else {
            return false;
        };
        let was = p.verified.is_some() || p.held;
        p.verified = None;
        p.held = false;
        was
    }

    /// Reads a contact's devices from the directory and checks the chain: the
    /// account key against the pin, each active device's `device` signature
    /// against that account key. Revoked devices are skipped.
    pub fn checked_contact(&mut self, ud: &UserDevices, now: u64) -> Contact {
        let note = self.pin(&ud.screen_name, &ud.account_key, now);
        if let Some(note) = note {
            self.said
                .insert(format!("pin:{}", sign::ident(&ud.screen_name)), note);
        }
        Contact {
            screen_name: ud.screen_name.clone(),
            devices: ud
                .devices
                .iter()
                .filter(|d| {
                    d.revoked_at.is_none() && device_signed_by(&ud.screen_name, &ud.account_key, d)
                })
                .cloned()
                .collect(),
        }
    }

    /// A note to show the user, once: the second time the same note is asked
    /// for it comes back empty.
    pub fn note_once(&mut self, key: &str, note: &str) -> Option<String> {
        if self.said.get(key) == Some(&note.to_string()) {
            return None;
        }
        self.said.insert(key.to_string(), note.to_string());
        Some(note.to_string())
    }

    /// A note the user has already been shown, if any, without making one.
    pub fn already_said(&self, key: &str) -> Option<&str> {
        self.said.get(key).map(String::as_str)
    }

    // --- outbound ----------------------------------------------------------

    /// Encrypts an outbound message for `contact`, building the session if
    /// this is the first message to it (CHECKLIST 2.1). The caller must have
    /// fetched the contact first, through [`fetch_contact`], so the message
    /// path itself never reaches the directory for a session.
    pub fn encrypt(
        &mut self,
        dir: &dyn DirectoryApi,
        bearer: &str,
        out: &Outgoing,
        contact: &Contact,
    ) -> DirResult<Outbound> {
        let control = out.text.is_empty();
        self.encrypt_as(dir, bearer, out, contact, control)
    }

    /// A control message carrying `out.text` as a payload for the other
    /// add-on (a call key exchange): flagged and enveloped as a control
    /// message, so an add-on that does not know the payload takes it as an
    /// ordinary one and shows nothing.
    pub fn encrypt_control(
        &mut self,
        dir: &dyn DirectoryApi,
        bearer: &str,
        out: &Outgoing,
        contact: &Contact,
    ) -> DirResult<Outbound> {
        self.encrypt_as(dir, bearer, out, contact, true)
    }

    fn encrypt_as(
        &mut self,
        dir: &dyn DirectoryApi,
        bearer: &str,
        out: &Outgoing,
        contact: &Contact,
        control: bool,
    ) -> DirResult<Outbound> {
        let peer = sign::ident(&out.peer);
        if !contact.usable() {
            let note = format!(
                "[ICQ E2E] Messages to {peer} are sent unencrypted: no device of theirs is in the key directory."
            );
            return Ok(Outbound::Clear {
                text: lossy(&out.text),
                note,
            });
        }
        // One fresh key protects the payload (CHECKLIST 3.1), and that same key
        // is what every wrap carries, so the header the AEAD binds is final
        // before the payload is sealed.
        let payload_key = random_key();
        let mut wraps = Vec::new();
        for d in &contact.devices {
            match self.olm_outbound(dir, bearer, &peer, d, &payload_key) {
                Ok((olm_type, message)) => wraps.push(Wrap {
                    device: d.device_id,
                    olm_type,
                    message,
                }),
                Err(why) => {
                    // A contact who announces the add-on is never sent clear
                    // text: the frame is dropped and the user is told.
                    return Ok(Outbound::Refused(format!(
                        "[ICQ E2E] The message to {peer} was not sent: {why}."
                    )));
                }
            }
        }
        let mut c = Container {
            flags: if control { FLAG_CONTROL } else { 0 },
            sender_device: self.device_id,
            wraps,
            ciphertext: Vec::new(),
        };
        let envelope = Envelope {
            kind: if control {
                Kind::Control
            } else {
                Kind::Message
            },
            from: self.screen_name.clone(),
            to: peer.clone(),
            time: out.now,
            form: out.form,
            text: out.text.clone(),
        };
        let pad = vec![0u8; container::padding_len(out.text.len(), random_u32())];
        c.ciphertext = container::seal(&payload_key, &c.header(), &envelope.to_bytes(&pad));
        let wire = container::armor(&c.to_bytes());
        if wire.len() > crate::rewrite::MAX_TEXT {
            return Ok(Outbound::Refused(format!(
                "[ICQ E2E] The message to {peer} is too long to send encrypted ({} bytes on the wire).",
                wire.len()
            )));
        }
        Ok(Outbound::Encrypted(wire))
    }

    /// The Olm message that carries the one-off payload key to a peer device:
    /// the session, newly built if this is the first message (CHECKLIST 2.1).
    /// Returns the Olm message type and bytes.
    fn olm_outbound(
        &mut self,
        dir: &dyn DirectoryApi,
        bearer: &str,
        peer: &str,
        device: &Device,
        payload_key: &[u8; 32],
    ) -> Result<(u8, Vec<u8>), String> {
        let mut session = match self.session(peer, device.device_id) {
            Some(s) => s,
            None => {
                let claimed = dir.claim(bearer, peer, device.device_id).map_err(why)?;
                let claim = check_claim(peer, device, &claimed)?;
                let otk = claim
                    .one_time_key
                    .as_ref()
                    .or(claim.fallback_key.as_ref())
                    .ok_or("that device published no one-time or fallback key".to_string())?;
                let their_curve = curve_key(&device.curve25519_key)?;
                let otk_key = curve_key(&otk.public_key)?;
                let account = self.account().ok_or("this device has no usable keys")?;
                let s = HANDSHAKE
                    .start_outbound(&account, their_curve, otk_key)
                    .map_err(|e| format!("no session with {peer} could be started: {e}"))?;
                self.set_session(peer, device.device_id, &s);
                s
            }
        };
        let (kind, bytes) = session
            .encrypt(payload_key)
            .map_err(|e| format!("olm refused to encrypt: {e}"))?
            .to_parts();
        self.set_session(peer, device.device_id, &session);
        Ok((if kind == 0 { OLM_PRE_KEY } else { OLM_NORMAL }, bytes))
    }

    // --- inbound -----------------------------------------------------------

    /// Decrypts an inbound container that arrived from `peer`.
    ///
    /// Never starts a session for its own sake: an inbound pre-key message is
    /// matched against the sessions already held, and only a pre-key message -
    /// which carries the key - may make a new one (CHECKLIST 2.5, 2.6). A
    /// message that cannot be read becomes a note; nothing else happens.
    pub fn decrypt(
        &mut self,
        dir: &dyn DirectoryApi,
        peer: &str,
        container: &Container,
        now: u64,
    ) -> Inbound {
        let peer = sign::ident(peer);
        let Some(wrap) = container.wrap_for(self.device_id) else {
            return Inbound::Unreadable(format!(
                "[ICQ E2E] An encrypted message from {peer} was not addressed to this device."
            ));
        };
        let Ok(olm) = OlmMessage::from_parts(wrap.olm_type as usize, &wrap.message) else {
            return Inbound::Unreadable(unreadable(&peer));
        };

        // A pre-key message may be answered by the sessions we already hold;
        // only if none of them opens it is a new inbound session made, and that
        // needs the sender's identity key checked through the directory. A
        // directory that cannot be reached leaves the message unreadable for
        // now - the alternative is that an outage silently accepts an
        // unverified sender.
        let Some((payload, advanced)) =
            self.decrypt_olm(&peer, container.sender_device, &olm, dir, now)
        else {
            return Inbound::Unreadable(unreadable(&peer));
        };
        let device = container.sender_device;
        let key: [u8; 32] = match payload.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => return Inbound::Unreadable(unreadable(&peer)),
        };
        // The key came out of olm; what it opens decides everything. A payload
        // that does not open is a note, never an error and never a key
        // exchange (CHECKLIST 2.5, 2.6).
        let readable = container::open(&key, &container.header(), &container.ciphertext)
            .and_then(|b| Envelope::from_bytes(&b))
            .filter(|e| {
                // The envelope names who sent it and who it is for; both are
                // checked against what the server said, so it cannot
                // re-address a message (CHECKLIST 3.4, 3.6).
                sign::ident(&e.from) == peer
                    && sign::ident(&e.to) == self.screen_name
                    // An offline message is stamped when it was written, so it
                    // may be days old, but nothing may come from the future.
                    && now.abs_diff(e.time) <= TIME_SKEW_PAST
                    && e.time <= now + TIME_SKEW_FUTURE
            });
        let Some(envelope) = readable else {
            return Inbound::Unreadable(unreadable(&peer));
        };
        // Only now does the session move on: a container we could not read
        // leaves no ratchet step behind (CHECKLIST 2.5).
        self.sessions
            .entry(peer.clone())
            .or_default()
            .insert(device, pickle_json(&advanced));
        match envelope.kind {
            Kind::Control => Inbound::Control(envelope.text),
            Kind::Message => Inbound::Text {
                text: envelope.text,
                form: envelope.form,
                peer,
                unverified: false,
            },
        }
    }

    /// Tries the sessions held for `peer`, and for a pre-key message makes one
    /// when the sender's device checks out against the directory. Returns the
    /// wrapped payload key and the session's state as it stands after the
    /// message; the caller keeps that state only once the payload opened, so a
    /// container that is tampered with costs no ratchet step (CHECKLIST 2.5).
    fn decrypt_olm(
        &mut self,
        peer: &str,
        sender_device: u32,
        olm: &OlmMessage,
        dir: &dyn DirectoryApi,
        now: u64,
    ) -> Option<(Vec<u8>, SessionPickle)> {
        // First: any session we already hold for the sender, whichever device
        // it is for. A session that fails leaves its pickle untouched, so a
        // ratchet only advances when a message really opened.
        let devices: Vec<u32> = self
            .sessions
            .get(peer)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        for d in devices {
            let Some(json) = self.sessions.get(peer).and_then(|m| m.get(&d)) else {
                continue;
            };
            let Ok(pickle) = serde_json::from_str::<SessionPickle>(json) else {
                continue;
            };
            let mut session = Session::from_pickle(pickle);
            if let Ok(plain) = session.decrypt(olm) {
                return Some((plain, session.pickle()));
            }
        }
        // Then: a pre-key message may make a new session, but only once the
        // sender's identity key has been checked through the directory, and
        // only for the device the message names.
        let OlmMessage::PreKey(pre) = olm else {
            return None;
        };
        let ud = dir.user_devices(peer).ok()?;
        let device = ud
            .devices
            .iter()
            .find(|d| d.device_id == sender_device && d.revoked_at.is_none())?
            .clone();
        if !device_signed_by(&ud.screen_name, &ud.account_key, &device) {
            return None;
        }
        // Nothing is pinned and no one-time key spent for a sender whose keys
        // the key log does not show.
        if self.log_trusted && !self.log_shows(peer, &ud.account_key, &device) {
            return None;
        }
        let their_curve = curve_key(&device.curve25519_key).ok()?;
        let mut account = self.account()?;
        let (session, plaintext) = HANDSHAKE.start_inbound(&mut account, their_curve, pre)?;
        // The account dropped the private half of the one-time key the message
        // used (CHECKLIST 1.5); keep it so the pool is right after a restart.
        self.account = pickle_json(&account.pickle());
        let next = session.pickle();
        // Pin the sender's account key the first time it writes to us, and say
        // so if it changed.
        if let Some(note) = self.pin(peer, &ud.account_key, now) {
            self.said.insert(format!("pin:{}", sign::ident(peer)), note);
        }
        Some((plaintext, next))
    }

    /// Whether our copy of the key log has `peer` with this account key and
    /// this device, keys and signature alike.
    pub fn log_shows(&self, peer: &str, account_key: &str, d: &Device) -> bool {
        self.log
            .accounts
            .get(&sign::ident(peer))
            .filter(|a| a.key == account_key)
            .and_then(|a| a.devices.get(&d.device_id))
            .is_some_and(|l| {
                l.curve25519_key == d.curve25519_key
                    && l.ed25519_key == d.ed25519_key
                    && l.account_signature == d.account_signature
            })
    }

    // --- the directory -----------------------------------------------------

    /// Reads and checks a contact's devices, pinning their account key. The
    /// first time a contact is fetched after a key change the note is recorded
    /// under `pin:<uin>`; the caller shows it (see [`OwnKeys::note_once`]).
    pub fn contact(
        &mut self,
        dir: &dyn DirectoryApi,
        uin: &str,
        now: u64,
    ) -> Result<Contact, String> {
        let ud = dir.user_devices(uin).map_err(why)?;
        Ok(self.checked_contact(&ud, now))
    }

    /// Whether our own device is in the directory, and how many one-time keys
    /// its pool holds. `None` if it is not published, or was revoked.
    pub fn own_device_state(
        dir: &dyn DirectoryApi,
        bearer: &str,
        device_id: u32,
    ) -> Option<DeviceState> {
        dir.get_device(bearer, device_id).ok()
    }
}

/// Reads and checks a contact's devices without touching our pins. Used when a
/// message is on its way out and we only need to know whether a session is
/// possible.
pub fn fetch_contact(dir: &dyn DirectoryApi, uin: &str) -> Result<Contact, String> {
    let ud = dir.user_devices(uin).map_err(why)?;
    Ok(Contact {
        screen_name: ud.screen_name.clone(),
        devices: ud
            .devices
            .iter()
            .filter(|d| {
                d.revoked_at.is_none() && device_signed_by(&ud.screen_name, &ud.account_key, d)
            })
            .cloned()
            .collect(),
    })
}

/// Whether a device's `device` message verifies under an account key: the
/// chain a contact's keys must pass (KEY-DIRECTORY-API.md 5).
pub fn device_signed_by(screen_name: &str, account_key: &str, d: &Device) -> bool {
    let Some(account_pk) = Ed25519PublicKey::from_base64(account_key).ok() else {
        return false;
    };
    let Some(sig) = Ed25519Signature::from_base64(&d.account_signature).ok() else {
        return false;
    };
    let (Some(curve), Some(ed)) = (
        Curve25519PublicKey::from_base64(&d.curve25519_key).ok(),
        Ed25519PublicKey::from_base64(&d.ed25519_key).ok(),
    ) else {
        return false;
    };
    let msg = sign::device(screen_name, d.device_id, curve.as_bytes(), ed.as_bytes());
    account_pk.verify(&msg, &sig).is_ok()
}

/// Checks the chain of a claim: the device's signature under the account key
/// the claim carries, and the claimed key's own signature by the device. The
/// account key itself is checked by the caller against its pin.
fn check_claim(peer: &str, device: &Device, claim: &Claim) -> Result<Claim, String> {
    if sign::ident(&claim.screen_name) != sign::ident(peer) {
        return Err("the claim names another account".into());
    }
    if !device_signed_by(peer, &claim.account_key, device) {
        return Err("the device is not signed by that account key".into());
    }
    let Some(ed) = Ed25519PublicKey::from_base64(&device.ed25519_key).ok() else {
        return Err("the device's Ed25519 key is not base64".into());
    };
    let check = |k: &SignedKey, one_time: bool| -> bool {
        let (Some(curve), Some(sig)) = (
            Curve25519PublicKey::from_base64(&k.public_key).ok(),
            Ed25519Signature::from_base64(&k.signature).ok(),
        ) else {
            return false;
        };
        let msg = if one_time {
            sign::one_time_key(peer, device.device_id, &k.key_id, curve.as_bytes())
        } else {
            sign::fallback_key(peer, device.device_id, &k.key_id, curve.as_bytes())
        };
        ed.verify(&msg, &sig).is_ok()
    };
    if let Some(k) = &claim.one_time_key {
        if !check(k, true) {
            return Err("the one-time key is not signed by the device".into());
        }
    }
    if let Some(k) = &claim.fallback_key {
        if !check(k, false) {
            return Err("the fallback key is not signed by the device".into());
        }
    }
    if claim.one_time_key.is_none() && claim.fallback_key.is_none() {
        return Err("the device published neither a one-time nor a fallback key".into());
    }
    Ok(claim.clone())
}

fn why(e: DirError) -> String {
    match e {
        DirError::Api { code, .. } => format!("the key directory said {code}"),
        DirError::Net(w) => format!("the key directory could not be reached: {w}"),
    }
}

fn raw32(b64: &str) -> Option<[u8; 32]> {
    vodozemac::base64_decode(b64).ok()?.try_into().ok()
}

/// The JSON of a vodozemac pickle. A vodozemac object that cannot serialise is
/// a programming error, not a runtime condition.
fn pickle_json<T: Serialize>(pickle: &T) -> String {
    serde_json::to_string(pickle).expect("a vodozemac pickle serialises")
}

fn curve_key(b64: &str) -> Result<Curve25519PublicKey, String> {
    let raw = raw32(b64).ok_or(format!("{b64} is not a 32-byte key"))?;
    Curve25519PublicKey::from_slice(&raw).map_err(|e| format!("{b64} is not a curve key: {e}"))
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn unreadable(peer: &str) -> String {
    format!("[ICQ E2E] An encrypted message from {peer} could not be read on this device.")
}

/// The note for a container this build cannot read at all: a version or
/// scheme of a newer add-on (CHECKLIST 9.8).
pub fn unsupported(peer: &str, version: u8, scheme: u8) -> String {
    format!(
        "[ICQ E2E] An encrypted message from {peer} could not be read: it uses a newer format (version {version}, scheme {scheme}). Update the ICQ E2E add-on to read it."
    )
}

fn random_device_id() -> u32 {
    loop {
        let id = random_u32();
        if id != 0 {
            return id;
        }
    }
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).expect("the OS random source");
    u32::from_le_bytes(b)
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).expect("the OS random source");
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::MemoryDirectory;
    use crate::token::Token;

    const NOW: u64 = 1_790_000_000;

    fn token(dir: &MemoryDirectory, who: &str) -> String {
        Token::parse(&dir.token(who)).unwrap().bearer
    }

    /// Publishes `k`'s account, device and a full pool of one-time keys.
    fn publish(dir: &MemoryDirectory, k: &mut OwnKeys) -> String {
        let t = token(dir, &k.screen_name);
        let (key, sig) = k.account_object();
        dir.announce(&k.screen_name, &raw32(&key).unwrap());
        dir.put_account(&t, &key, &sig).unwrap();
        let (curve, ed, dsig) = k.device_object().expect("a fresh account is readable");
        dir.put_device(&t, k.device_id, &curve, &ed, &dsig).unwrap();
        let keys = k.new_one_time_keys(0);
        dir.upload_one_time_keys(&t, k.device_id, &keys).unwrap();
        t
    }

    fn outgoing(peer: &str, text: &[u8]) -> Outgoing {
        Outgoing {
            peer: peer.into(),
            form: Form::Fragment {
                charset: 2,
                language: 0,
            },
            text: text.to_vec(),
            now: NOW,
        }
    }

    /// A message encrypted by `a`, ready to hand to `b`.
    fn sealed(a: &mut OwnKeys, dir: &MemoryDirectory, peer: &str, text: &[u8]) -> Container {
        seal_envelope(
            a,
            dir,
            peer,
            envelope_for(a, peer, Kind::Message, text, NOW),
        )
    }

    /// The envelope a message to `peer` normally carries.
    fn envelope_for(a: &OwnKeys, peer: &str, kind: Kind, text: &[u8], time: u64) -> Envelope {
        Envelope {
            kind,
            from: a.screen_name.clone(),
            to: peer.into(),
            time,
            form: Form::Fragment {
                charset: 2,
                language: 0,
            },
            text: text.to_vec(),
        }
    }

    /// An envelope sealed under a real session, so the checks that read it run
    /// exactly as they do for a message that came over the wire.
    fn seal_envelope(
        a: &mut OwnKeys,
        dir: &MemoryDirectory,
        peer: &str,
        envelope: Envelope,
    ) -> Container {
        let contact = fetch_contact(dir, peer).unwrap();
        let mut out = outgoing(peer, &envelope.text);
        out.form = envelope.form;
        let key = random_key();
        let mut wraps = Vec::new();
        for d in &contact.devices {
            let (t, m) = a
                .olm_outbound(dir, &token(dir, &a.screen_name), peer, d, &key)
                .unwrap();
            wraps.push(Wrap {
                device: d.device_id,
                olm_type: t,
                message: m,
            });
        }
        let mut c = Container {
            flags: if envelope.kind == Kind::Control {
                FLAG_CONTROL
            } else {
                0
            },
            sender_device: a.device_id,
            wraps,
            ciphertext: Vec::new(),
        };
        let pad = vec![0u8; container::padding_len(envelope.text.len(), random_u32())];
        c.ciphertext = container::seal(&key, &c.header(), &envelope.to_bytes(&pad));
        c
    }

    /// `b` answers `a`, which is what makes `a`'s session established: until
    /// olm has heard from the peer it sends every message as a pre-key one.
    fn reply(b: &mut OwnKeys, dir: &MemoryDirectory, peer: &str, text: &[u8]) -> Container {
        let contact = fetch_contact(dir, peer).unwrap();
        let wire = match b
            .encrypt(
                dir,
                &token(dir, &b.screen_name),
                &outgoing(peer, text),
                &contact,
            )
            .unwrap()
        {
            Outbound::Encrypted(w) => w,
            other => panic!("expected an encrypted message, got {other:?}"),
        };
        Container::from_bytes(&container::find_armor(&wire).unwrap()).unwrap()
    }

    /// The size budget a post-quantum first message needs (CHECKLIST 9.8):
    /// the longest text a first message to one device can carry, with the
    /// most padding it can get, now and with the ML-KEM-768 ciphertext
    /// (1088 bytes) plus its key id and framing (64 bytes, generous) added
    /// to that device's wrap.
    #[test]
    fn a_first_message_leaves_room_for_a_post_quantum_key_exchange() {
        const PQ_EXTRA: usize = 1088 + 64;
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        publish(&dir, &mut a);
        publish(&dir, &mut b);
        assert_eq!(HANDSHAKE.scheme(), container::SCHEME_OLM);

        // A first message of 100 bytes with the most padding a text over the
        // minimum gets; everything else in it does not depend on the text.
        let text = vec![b'x'; 100];
        let mut c = sealed(&mut a, &dir, "100002", &text);
        assert_eq!(c.wraps[0].olm_type, OLM_PRE_KEY, "a first message");
        let env = envelope_for(&a, "100002", Kind::Message, &text, NOW);
        let pad = vec![0u8; container::PAD_RANDOM_MAX];
        c.ciphertext = container::seal(&[1; 32], &c.header(), &env.to_bytes(&pad));
        let fixed = c.to_bytes().len() - text.len();
        let wire =
            |raw: usize| container::HINT.len() + container::ARMOR_TAG.len() + raw.div_ceil(3) * 4;
        let longest = |extra: usize| {
            (0..crate::rewrite::MAX_TEXT)
                .take_while(|t| wire(fixed + extra + t) <= crate::rewrite::MAX_TEXT)
                .last()
                .unwrap()
        };
        let (now, pq) = (longest(0), longest(PQ_EXTRA));
        println!("first message: {fixed} bytes besides the text; longest text {now} now, {pq} with PQXDH");
        // The post-quantum part costs about 1.5 KB of the 7000-byte wire
        // limit, and a text of 3000 bytes - 1500 UCS-2 characters with the
        // client's HTML around them - still fits in one first message.
        assert!(now - pq <= wire(PQ_EXTRA) && pq >= 3000, "{now} {pq}");
    }

    #[test]
    fn a_message_travels_both_ways_and_the_session_survives_a_restart() {
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        let _ta = publish(&dir, &mut a);
        let _tb = publish(&dir, &mut b);

        // First message: a pre-key message, which opens a session at b.
        let first = sealed(&mut a, &dir, "100002", b"first");
        assert_eq!(first.wraps[0].olm_type, OLM_PRE_KEY);
        match b.decrypt(&dir, "100001", &first, NOW) {
            Inbound::Text {
                text,
                peer,
                unverified,
                ..
            } => {
                assert_eq!(text, b"first");
                assert_eq!(peer, "100001");
                assert!(!unverified);
            }
            other => panic!("expected text, got {other:?}"),
        }
        // Once each side has heard from the other, messages are normal ones.
        assert!(matches!(
            a.decrypt(
                &dir,
                "100002",
                &reply(&mut b, &dir, "100001", b"hi back"),
                NOW
            ),
            Inbound::Text { .. }
        ));
        let second = sealed(&mut a, &dir, "100002", b"second");
        assert_eq!(second.wraps[0].olm_type, OLM_NORMAL);
        assert!(matches!(
            b.decrypt(&dir, "100001", &second, NOW),
            Inbound::Text { .. }
        ));

        // A restart: the state file gives both sides their sessions back, so no
        // new key exchange is needed.
        let a2 = serde_json::to_string(&a).unwrap();
        let mut a = serde_json::from_str::<OwnKeys>(&a2).unwrap();
        let b2 = serde_json::to_string(&b).unwrap();
        let mut b = serde_json::from_str::<OwnKeys>(&b2).unwrap();
        assert!(a
            .session("100002", contact_device(&dir, "100002"))
            .is_some());
        let third = sealed(&mut a, &dir, "100002", b"third");
        assert_eq!(third.wraps[0].olm_type, OLM_NORMAL);
        match b.decrypt(&dir, "100001", &third, NOW) {
            Inbound::Text { text, .. } => assert_eq!(text, b"third"),
            other => panic!("{other:?}"),
        }
    }

    fn contact_device(dir: &MemoryDirectory, uin: &str) -> u32 {
        dir.user_devices(uin).unwrap().devices[0].device_id
    }

    #[test]
    fn the_fallback_key_opens_a_session_when_the_pool_is_empty() {
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        publish(&dir, &mut a);
        publish(&dir, &mut b);
        // b has a fallback key but no one-time keys left.
        let tb = token(&dir, "100002");
        let fk = b.rotate_fallback_key(NOW).unwrap();
        dir.put_fallback_key(&tb, b.device_id, &fk).unwrap();
        let c = sealed(&mut a, &dir, "100002", b"over the fallback");
        assert_eq!(c.wraps[0].olm_type, OLM_PRE_KEY);
        assert!(matches!(
            b.decrypt(&dir, "100001", &c, NOW),
            Inbound::Text { .. }
        ));
    }

    #[test]
    fn a_contact_not_in_the_directory_gets_clear_text_and_a_note() {
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        publish(&dir, &mut a);
        let contact = Contact::default();
        match a
            .encrypt(
                &dir,
                &token(&dir, "100001"),
                &outgoing("100009", b"plain"),
                &contact,
            )
            .unwrap()
        {
            Outbound::Clear { text, note } => {
                assert_eq!(text, "plain");
                assert!(note.contains("unencrypted"), "{note}");
            }
            other => panic!("expected clear text, got {other:?}"),
        }
    }

    #[test]
    fn a_message_for_another_device_gets_a_note_and_opens_nothing() {
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        publish(&dir, &mut a);
        publish(&dir, &mut b);
        let c = sealed(&mut a, &dir, "100002", b"hi");
        let mut spoof = c.clone();
        spoof.wraps[0].device = 999;
        assert!(matches!(
            b.decrypt(&dir, "100001", &spoof, NOW),
            Inbound::Unreadable(_)
        ));
        assert!(b.sessions.is_empty());
    }

    #[test]
    fn a_tampered_container_gets_a_note_and_starts_no_session() {
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        publish(&dir, &mut a);
        publish(&dir, &mut b);
        let mut c = sealed(&mut a, &dir, "100002", b"hi");
        c.ciphertext = vec![0; c.ciphertext.len()];
        assert!(matches!(
            b.decrypt(&dir, "100001", &c, NOW),
            Inbound::Unreadable(_)
        ));
        assert!(
            b.sessions.is_empty(),
            "no session for a message we cannot read"
        );
    }

    #[test]
    fn an_envelope_that_names_someone_else_or_a_wrong_time_is_not_shown() {
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        publish(&dir, &mut a);
        publish(&dir, &mut b);

        // Each case is an envelope that is readable as far as olm and the AEAD
        // are concerned, and wrong only where the check under test looks.
        let cases = [
            ("names another sender", 1, "100001", NOW),
            ("is addressed elsewhere", 2, "100001", NOW),
            ("is too old", 0, "100001", NOW + TIME_SKEW_PAST + 60),
            (
                "is from the future",
                0,
                "100001",
                NOW - TIME_SKEW_FUTURE - 60,
            ),
        ];
        for (what, field, seen_from, now) in cases {
            let mut e = envelope_for(&a, "100002", Kind::Message, b"hi", NOW);
            match field {
                1 => e.from = "100009".into(),
                2 => e.to = "100009".into(),
                _ => {}
            }
            let c = seal_envelope(&mut a, &dir, "100002", e);
            let got = b.decrypt(&dir, seen_from, &c, now);
            assert!(
                matches!(got, Inbound::Unreadable(_)),
                "a message that {what} must not be shown, got {got:?}"
            );
        }
    }

    /// A time just inside the window is still delivered, and one just outside
    /// it is not - the bound is the whole of the rule.
    #[test]
    fn the_clock_window_admits_an_offline_message_but_nothing_beyond_it() {
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        publish(&dir, &mut a);
        publish(&dir, &mut b);

        let inside = envelope_for(
            &a,
            "100002",
            Kind::Message,
            b"hi",
            NOW - TIME_SKEW_PAST + 60,
        );
        let just_inside = seal_envelope(&mut a, &dir, "100002", inside);
        assert!(matches!(
            b.decrypt(&dir, "100001", &just_inside, NOW),
            Inbound::Text { .. }
        ));

        let outside = envelope_for(
            &a,
            "100002",
            Kind::Message,
            b"hi",
            NOW - TIME_SKEW_PAST - 60,
        );
        let just_outside = seal_envelope(&mut a, &dir, "100002", outside);
        assert!(matches!(
            b.decrypt(&dir, "100001", &just_outside, NOW),
            Inbound::Unreadable(_)
        ));
    }

    #[test]
    fn an_offline_message_replays_as_it_was_sent() {
        let dir = MemoryDirectory::new();
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        publish(&dir, &mut a);
        publish(&dir, &mut b);
        // A goes offline: the message is sealed and stored, and no session is
        // made at b yet.
        let stored = sealed(&mut a, &dir, "100002", b"while you were away");
        let days_later = NOW + 3 * 24 * 60 * 60;
        match b.decrypt(&dir, "100001", &stored, days_later) {
            Inbound::Text { text, .. } => assert_eq!(text, b"while you were away"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn one_time_keys_top_up_to_fifty_and_stop() {
        let mut k = OwnKeys::create("100001");
        assert_eq!(k.new_one_time_keys(0).len(), ONE_TIME_TARGET as usize);
        // A pool that is already full is left alone, whatever the directory
        // was last told: the gap is measured against the keys the account holds.
        assert!(k.new_one_time_keys(ONE_TIME_TARGET).is_empty());
        assert!(k.new_one_time_keys(0).is_empty());
    }

    #[test]
    fn the_fallback_key_is_replaced_after_a_week() {
        let mut k = OwnKeys::create("100001");
        assert!(k.rotate_fallback_key(NOW).is_some());
        assert!(k
            .rotate_fallback_key(NOW + FALLBACK_KEY_LIFETIME - 1)
            .is_none());
        assert!(k.rotate_fallback_key(NOW + FALLBACK_KEY_LIFETIME).is_some());
    }

    #[test]
    fn a_changed_account_key_is_noticed_once() {
        let mut k = OwnKeys::create("100001");
        assert!(k.pin("100002", "AAAA", NOW).is_none());
        assert!(k.pin("100002", "AAAA", NOW + 1).is_none());
        let note = k.pin("100002", "BBBB", NOW + 2).unwrap();
        assert!(
            note.contains("Your safety number with 100002 has changed"),
            "{note}"
        );
        assert!(note.contains("still encrypted"), "{note}");
        // Pinned to the new one now, so it is not reported twice.
        assert!(k.pin("100002", "BBBB", NOW + 3).is_none());
        // An unverified contact is never held for a change.
        assert!(!k.pinned("100002").unwrap().held);
    }

    #[test]
    fn verification_belongs_to_the_key_and_a_change_clears_it_and_holds() {
        let mut k = OwnKeys::create("100001");
        assert!(!k.verify("100002"), "nothing pinned, nothing to verify");
        assert!(
            k.pin("100002", "AAAA", NOW).is_none(),
            "first contact is silent"
        );
        assert!(k.verify("100002"));
        let p = k.pinned("100002").unwrap();
        assert!(p.is_verified() && !p.held);
        assert_eq!(p.verified.as_deref(), Some("AAAA"));

        let note = k.pin("100002", "BBBB", NOW + 1).unwrap();
        assert!(note.contains("verification is cleared"), "{note}");
        let p = k.pinned("100002").unwrap();
        assert!(!p.is_verified() && p.held);
        // A second change before the user answered keeps the hold.
        k.pin("100002", "CCCC", NOW + 2).unwrap();
        assert!(k.pinned("100002").unwrap().held);
        // Verifying releases it and binds to the key verified now.
        assert!(k.verify("100002"));
        let p = k.pinned("100002").unwrap();
        assert!(p.is_verified() && !p.held);
        assert_eq!(p.verified.as_deref(), Some("CCCC"));
        assert!(k.unverify("100002"));
        assert!(!k.pinned("100002").unwrap().is_verified());
        assert!(!k.unverify("100002"));
    }

    #[test]
    fn both_sides_compute_the_same_safety_number() {
        let mut a = OwnKeys::create("100001");
        let mut b = OwnKeys::create("100002");
        assert_eq!(a.safety_number("100002"), None, "no pin, no number");
        a.pin("100002", &b.account_key_b64(), NOW);
        b.pin("100001", &a.account_key_b64(), NOW);
        let n = a.safety_number("100002").unwrap();
        assert_eq!(n.len(), 60);
        assert_eq!(Some(n), b.safety_number("100001"));
    }

    #[test]
    fn notes_are_made_once() {
        let mut k = OwnKeys::create("100001");
        assert!(k.note_once("k", "hello").is_some());
        assert!(k.note_once("k", "hello").is_none());
        assert_eq!(k.already_said("k"), Some("hello"));
        assert_eq!(k.already_said("other"), None);
    }
}
