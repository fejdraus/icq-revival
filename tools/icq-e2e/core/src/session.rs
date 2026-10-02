//! One signed-on ICQ session's cryptography: the engine, its state on disk and
//! the key directory it publishes to, owned together and driven from the socket.
//!
//! The socket layer ([`stream`]) knows frames, not keys; this is what sits
//! between the two. It holds the one [`crypto::Engine`] for the connection,
//! loads the device's keys out of the state file on sign-on, hands the token it
//! found in the MOTD to the engine, saves the keys whenever the engine changed
//! them, and runs the publish and refill steps.
//!
//! The state file is the authority for "which device is this": a file that
//! cannot be opened is never replaced, because doing so would silently give the
//! account a new identity that no peer has ever seen.

use std::path::Path;
use std::sync::Arc;

use crate::config::Policy;
use crate::crypto::{Engine, Progress};
use crate::directory::{DirectoryApi, HttpDirectory};
use crate::icbm::Direction;
use crate::store::{StateLock, Store};
use crate::stream::StreamRewriter;

/// A signed-on session's cryptography.
pub struct Session {
    engine: Engine,
    store: Store,
    /// When the next publish or refill step is due. Zero means due now.
    retry_at: u64,
    /// Contacts whose capabilities have already been reported to the engine:
    /// they arrive again with every status change.
    told: Vec<String>,
    /// Set once the engine has changed the keys and they must reach the disk
    /// before anything else is done with them.
    unsaved: bool,
    /// Whether "no token yet" has already been said, so a client that never
    /// gets one is not told over and over.
    said_no_token: bool,
    /// The lock on the state file, held for the life of the session; `None`
    /// when another process holds it and this session is locked out.
    _lock: Option<StateLock>,
    /// Why this session never touches the state file: another process
    /// signed on as the same account holds it (audit 2026-10, finding 6).
    locked_out: Option<String>,
}

/// What an earlier build left for the lock button of the message window
/// (CHECKLIST 10.9), a button that was tried and dropped: a folder of one
/// file per contact, and the log its script wrote. Under the add-on's home.
const LOCK_LEFTOVERS: [&str; 2] = ["state", "lockbutton.log"];

/// Removes what the dropped lock button left in `home`. Best effort: what
/// cannot be removed now is tried again on the next sign-on, and nothing
/// depends on it being gone. Nothing else of the add-on lives under these
/// names - the keys are in `<account>.state` files next to them.
fn forget_lock_button(home: &Path) {
    for name in LOCK_LEFTOVERS {
        let path = home.join(name);
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else if path.is_file() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

impl Session {
    /// Opens the device's keys for `uin`, creating them on first sign-on.
    ///
    /// Returns the reason rather than a `Session` when the state file cannot be
    /// used: a file that is not ours, or one that cannot be unprotected, means
    /// this device cannot prove who it is, and going on without keys would
    /// quietly turn encryption off instead of saying so.
    ///
    /// The state file is locked for the life of the session (audit 2026-10,
    /// finding 6). When another process holds it - a second client signed on
    /// as the same account - the session is opened locked out: it never reads
    /// or writes the state, publishes nothing, and holds every message rather
    /// than sending it in clear, with a note that says why.
    pub fn open(dir: Arc<dyn DirectoryApi>, home: &Path, uin: &str) -> Result<Session, String> {
        let store = Store::new(home, uin);
        let Some(lock) = StateLock::take(home, uin)? else {
            let why = format!(
                "another ICQ signed on as {uin} on this computer is using its encryption keys"
            );
            let mut engine = Engine::new(dir, crate::keys::OwnKeys::create(uin));
            engine.lock_out(why.clone());
            return Ok(Session {
                engine,
                store,
                retry_at: 0,
                told: Vec::new(),
                unsaved: false,
                said_no_token: false,
                _lock: None,
                locked_out: Some(why),
            });
        };
        let keys = Store::open_or_create(home, uin)?;
        forget_lock_button(home);
        let mut engine = Engine::new(dir, keys);
        // A message whose ratchet moved on is let go only once this has
        // written the state (audit 2026-10, finding 5).
        let saver = Store::new(home, uin);
        engine.set_persist(Box::new(move |keys| saver.save(keys)));
        Ok(Session {
            engine,
            store,
            retry_at: 0,
            told: Vec::new(),
            unsaved: false,
            said_no_token: false,
            _lock: Some(lock),
            locked_out: None,
        })
    }

    /// Why this session is locked out of the state file, if it is.
    pub fn locked_out(&self) -> Option<&str> {
        self.locked_out.as_deref()
    }

    /// The engine, for the stream to drive.
    pub fn engine(&mut self) -> &mut Engine {
        &mut self.engine
    }

    /// Saves the keys if the engine changed them since the last save.
    ///
    /// Called after every frame: the keys advance the ratchet on every message,
    /// and a client that is closed without saving comes back with the same keys
    /// and cannot decrypt what it was sent in between.
    pub fn save(&mut self) -> Result<(), String> {
        // Never the state of a session locked out of it: it is another
        // process's, and what this one holds is a stand-in.
        if self.locked_out.is_some() {
            self.engine.take_changed();
            return Ok(());
        }
        // The engine's own flag covers what a message changes: a ratchet step,
        // a pinned key, a contact's setting. Without it only a publish was
        // ever written, and a restart lost every session advanced since.
        if self.engine.take_changed() {
            self.unsaved = true;
        }
        if !self.unsaved {
            return Ok(());
        }
        self.store.save(self.engine.keys())?;
        self.unsaved = false;
        Ok(())
    }

    /// Gives the engine the token out of the MOTD.
    ///
    /// `raw` is the token exactly as the server sent it; it is never written
    /// back into the stream, only read here.
    ///
    /// Does not publish. The MOTD arrives before the client's `LocateSetInfo`,
    /// so publishing here would spend a request the directory has to refuse
    /// for an account key that has not been announced on this connection yet,
    /// and it would refuse it as unauthorized rather than as `not_announced`.
    /// The publish happens when the announcement is seen.
    pub fn on_token(&mut self, raw: &[u8], _now: u64) -> Vec<String> {
        let mut lines = Vec::new();
        if self.engine.set_token(raw).is_none() {
            lines.push("[ICQ E2E] The key directory token could not be read.".to_string());
            return lines;
        }
        lines.push("[ICQ E2E] Key directory token accepted.".to_string());
        self.said_no_token = false;
        self.retry_at = 0;
        lines
    }

    /// Tells the engine which contacts announce the add-on - a hint only
    /// (CHECKLIST 10.6) - and remembers who has been reported.
    pub fn on_contacts(&mut self, contacts: &[(String, bool)]) {
        self.engine.note_contacts(contacts);
        for (screen_name, _has) in contacts {
            if !self.told.iter().any(|s| s == screen_name) {
                self.told.push(screen_name.clone());
            }
        }
    }

    /// Does the next publish or refill step if one is due.
    ///
    /// Called from the socket loop, so it must be cheap when nothing is due.
    pub fn poll(&mut self, now: u64) -> Vec<String> {
        if now < self.retry_at || self.locked_out.is_some() {
            return Vec::new();
        }
        let mut lines = self.publish(now);
        if let Err(why) = self.save() {
            lines.push(format!("[ICQ E2E] {why}"));
        }
        lines
    }

    /// When the next poll is due, so the socket loop need not wake up for it.
    pub fn retry_at(&self) -> u64 {
        self.retry_at
    }

    /// One publish step: account, device, one-time keys, fallback key, in the
    /// order the API expects, stopping at the first step it refuses.
    fn publish(&mut self, now: u64) -> Vec<String> {
        let mut lines = Vec::new();
        match self.engine.publish(now) {
            Progress::Done(p) => {
                self.unsaved = true;
                self.retry_at = now.saturating_add(crate::crypto::ANNOUNCE_EVERY.as_secs());
                lines.push(format!(
                    "[ICQ E2E] Keys published: {} one-time key(s) in the directory.",
                    p.one_time
                ));
            }
            Progress::Quiet(_) => {
                // Nothing was sent, so there is nothing to say. The next poll
                // is only there to top the pool up when it falls low, which is
                // exactly what `publish` checks before it sends anything.
                self.retry_at = now.saturating_add(crate::crypto::ANNOUNCE_EVERY.as_secs());
            }
            Progress::Wait { again, note } => {
                self.retry_at = now.saturating_add(again.as_secs());
                if let Some(note) = note {
                    lines.push(format!("[ICQ E2E] {note}"));
                }
            }
            Progress::Off { note } => {
                // Said once, not on every poll: with `retry_at` left at zero the
                // same two lines came out every two seconds for the whole life
                // of the client. There is nothing to retry either - a token that
                // has not arrived is not going to arrive sooner because we ask
                // again, and `on_token` runs the publish the moment one does.
                if !self.said_no_token {
                    self.said_no_token = true;
                    lines.push(format!("[ICQ E2E] {note}"));
                }
                self.retry_at = now.saturating_add(crate::crypto::ANNOUNCE_RETRY.as_secs());
            }
            Progress::Retry { note } => {
                self.retry_at = now.saturating_add(crate::crypto::ANNOUNCE_RETRY.as_secs());
                lines.push(format!("[ICQ E2E] {note}"));
            }
        }
        lines
    }
}

/// The key directory over HTTPS, as the loaders use it.
///
/// `None` when the policy names no directory: without one there is nothing to
/// publish to and no token will ever arrive, so the caller runs the add-on with
/// encryption off rather than with a directory that does not answer.
#[cfg(windows)]
pub fn linked(policy: &Policy) -> Option<HttpDirectory<crate::winhttp::WinHttp>> {
    let url = policy.directory.clone()?;
    Some(HttpDirectory::new(crate::winhttp::WinHttp::new(url)))
}

/// Feeds one direction of the socket through its rewriter and the session.
///
/// Kept next to the session so the two steps that must happen together - moving
/// bytes and saving the keys that move changed - are one call.
pub fn pump(
    rw: &mut StreamRewriter,
    dir: Direction,
    session: &mut Session,
    bytes: &[u8],
    now: u64,
    policy: &Policy,
    out: &mut Vec<u8>,
) -> Vec<String> {
    let _ = dir;
    let mut lines = rw.push_crypto(bytes, session.engine(), now, policy, out);
    if let Some(raw) = rw.take_token() {
        lines.extend(session.on_token(&raw, now));
    }
    if rw.take_announce().is_some() {
        // The account key has just gone out in the client's own SetInfo, which
        // is what the directory checks before it accepts a first publish.
        lines.extend(session.publish(now));
    }
    let contacts = rw.take_contacts();
    if !contacts.is_empty() {
        session.on_contacts(&contacts);
    }
    if let Err(why) = session.save() {
        lines.push(format!("[ICQ E2E] {why}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;
    use crate::config::Settings;
    use crate::crypto::Crypto;
    use crate::directory::MemoryDirectory;
    use std::path::PathBuf;

    const NOW: u64 = 1_790_000_000;

    /// A temporary directory that cleans itself up.
    struct Temp(PathBuf);

    impl Temp {
        fn new(tag: &str) -> Temp {
            let p = std::env::temp_dir().join(format!("icqe2e-session-{tag}"));
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

    /// A memory directory that has handed out a token for `100001`.
    fn announced(dir: &MemoryDirectory) {
        dir.announce("100001", &[7u8; 32]);
    }

    #[test]
    fn the_keys_survive_a_new_session() {
        let home = Temp::new("persist");
        let dir = Arc::new(MemoryDirectory::new());
        announced(&dir);
        let key = Session::open(dir.clone(), &home.0, "100001")
            .unwrap()
            .engine()
            .keys()
            .account_key_bytes();
        // A second session on the same home must find the same device.
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();
        assert_eq!(
            s.engine().keys().account_key_bytes(),
            key,
            "a reopened session is the same device"
        );
    }

    #[test]
    fn a_state_file_that_is_not_ours_is_an_error_and_is_left_alone() {
        let home = Temp::new("foreign");
        let path = home.0.join("100001.state");
        std::fs::write(&path, b"not our file at all").unwrap();
        let dir = Arc::new(MemoryDirectory::new());
        let why = match Session::open(dir.clone(), &home.0, "100001") {
            Ok(_) => panic!("a file that is not ours must not open as this device"),
            Err(why) => why,
        };
        assert!(!why.is_empty(), "the reason says why it cannot be used");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"not our file at all",
            "the file is left exactly as it was: this device keeps its identity"
        );
    }

    #[test]
    fn a_token_that_cannot_be_read_says_so_and_changes_nothing() {
        let home = Temp::new("badtok");
        let dir = Arc::new(MemoryDirectory::new());
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();
        let lines = s.on_token(b"not a token", NOW);
        assert!(
            lines.iter().any(|l| l.contains("could not be read")),
            "{lines:?}"
        );
        assert!(!s.engine().ready(), "and nothing became encryptable");
    }

    #[test]
    fn keys_are_only_written_when_they_changed() {
        let home = Temp::new("dirty");
        let dir = Arc::new(MemoryDirectory::new());
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();
        let path = Store::new(&home.0, "100001").path().to_path_buf();
        s.unsaved = false;
        s.save().unwrap();
        let before = std::fs::metadata(&path).unwrap().len();

        // Nothing changed, so nothing is written and nothing moves.
        s.save().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);

        // Something changed, so the new state reaches the disk and the flag
        // clears - a failed save must not look like a successful one.
        s.unsaved = true;
        s.save().unwrap();
        assert!(!s.unsaved);
    }

    /// An encrypting policy with no peer list, so every contact is encrypted.
    fn encrypting(peers: Option<&str>) -> Policy {
        Policy::from_settings(Settings {
            mode: Some("encrypt"),
            peers,
            ..Settings::default()
        })
    }

    /// A `LocateSetInfo` the client would send, carrying the account key.
    ///
    /// The directory only accepts a first publish for a key announced on the
    /// token's own BOS connection, so the session cannot publish until this has
    /// gone out.
    fn set_info(key: &[u8; 32]) -> Vec<u8> {
        let mut body = tlv(0x0001, b"text/aolrtf; charset=\"us-ascii\"");
        let with_key = match caps::announce_key(&body, key) {
            caps::KeyAnnounce::Added(b) => b,
            other => panic!("{other:?}"),
        };
        body.extend(tlv(0x0005, &with_key));
        let mut snac = vec![0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        snac.extend(body);
        // A SNAC reaches the stream inside a FLAP frame.
        let mut f = vec![crate::stream::FLAP_MARKER, crate::stream::FLAP_CHANNEL_SNAC];
        f.extend_from_slice(&2u16.to_be_bytes());
        f.extend_from_slice(&(snac.len() as u16).to_be_bytes());
        f.extend_from_slice(&snac);
        f
    }

    /// The sign-on frame that opens a FLAP connection.
    fn sign_on() -> Vec<u8> {
        let mut f = vec![
            crate::stream::FLAP_MARKER,
            crate::stream::FLAP_CHANNEL_SIGNON,
        ];
        f.extend_from_slice(&1u16.to_be_bytes());
        f.extend_from_slice(&4u16.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 1]);
        f
    }

    /// A TLV as the client writes it.
    fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut v = tag.to_be_bytes().to_vec();
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn a_token_alone_publishes_nothing() {
        let home = Temp::new("waits");
        let dir = Arc::new(MemoryDirectory::new());
        announced(&dir);
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();

        let lines = s.on_token(&dir.token("100001"), NOW);

        // The MOTD comes before the client's LocateSetInfo, so a publish here
        // would spend a request the directory refuses for an account key that
        // has not been announced on this connection yet.
        assert_eq!(
            lines,
            vec!["[ICQ E2E] Key directory token accepted.".to_string()],
            "the token is accepted and nothing else happens"
        );
        assert!(
            !s.unsaved,
            "and no key was spent, so nothing needs saving yet"
        );
    }

    #[test]
    fn publishing_goes_ahead_once_the_account_key_is_announced() {
        let home = Temp::new("publish");
        let dir = Arc::new(MemoryDirectory::new());
        announced(&dir);
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();
        s.on_token(&dir.token("100001"), NOW);

        let key = s.engine().account_key().unwrap();
        // The server reads the announcement off the connection; standing in for
        // that here is what makes the next publish accepted.
        dir.announce("100001", &key);
        let mut out = Vec::new();
        let mut rw = StreamRewriter::new(Direction::Outbound);
        // A stream is only FLAP once it has opened with a sign-on frame.
        pump(
            &mut rw,
            Direction::Outbound,
            &mut s,
            &sign_on(),
            NOW,
            &encrypting(None),
            &mut out,
        );
        let lines = pump(
            &mut rw,
            Direction::Outbound,
            &mut s,
            &set_info(&key),
            NOW,
            &encrypting(None),
            &mut out,
        );

        assert!(
            lines.iter().any(|l| l.contains("Keys published")),
            "the log says what went up: {lines:?}"
        );
        assert!(
            !s.unsaved,
            "publishing spends one-time keys, so they are saved"
        );
    }

    /// A client that never gets a token is told once, not on every poll: with
    /// nothing to retry, `retry_at` was left at zero and the same line came out
    /// every two seconds for the whole life of the client.
    #[test]
    fn no_token_is_said_once_and_not_every_two_seconds() {
        let home = Temp::new("said");
        let dir = Arc::new(MemoryDirectory::new());
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();

        let mut at = NOW;
        let first: Vec<String> = (0..5)
            .map(|_| {
                let l = s.poll(at);
                at += 10_000;
                l
            })
            .flatten()
            .collect();
        let said = first.iter().filter(|l| l.contains("no token yet")).count();
        assert_eq!(said, 1, "said once in all: {first:?}");
        assert!(
            s.retry_at() > NOW,
            "and something is scheduled, not an immediate repeat"
        );
    }

    /// A service connection's MOTD carries no token - the server sends one only
    /// on the BOS connection. That must not take the account's keys away: it
    /// used to reset the engine to "no token yet, encryption stays off", and
    /// messages went out in clear while the account sat there already
    /// published.
    #[test]
    fn a_motd_without_a_token_leaves_the_account_published() {
        let home = Temp::new("service");
        let dir = Arc::new(MemoryDirectory::new());
        announced(&dir);
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();
        s.on_token(&dir.token("100001"), NOW);

        let key = s.engine().account_key().unwrap();
        dir.announce("100001", &key);
        let mut out = Vec::new();
        let mut rw = StreamRewriter::new(Direction::Outbound);
        pump(
            &mut rw,
            Direction::Outbound,
            &mut s,
            &sign_on(),
            NOW,
            &encrypting(None),
            &mut out,
        );
        pump(
            &mut rw,
            Direction::Outbound,
            &mut s,
            &set_info(&key),
            NOW,
            &encrypting(None),
            &mut out,
        );
        assert!(s.engine().ready(), "the account published its keys");

        // Now the service connection: its own stream, its own MOTD, no token.
        let mut service = StreamRewriter::new(Direction::Inbound);
        let mut out = Vec::new();
        let mut motd_body = 0x0004u16.to_be_bytes().to_vec();
        motd_body.extend(tlv(0x000B, b"Welcome to the ICQ network"));
        let motd = {
            let mut snac = 0x0001u16.to_be_bytes().to_vec();
            snac.extend_from_slice(&0x0013u16.to_be_bytes());
            snac.extend_from_slice(&0u16.to_be_bytes());
            snac.extend_from_slice(&0u16.to_be_bytes());
            snac.extend_from_slice(&motd_body);
            let mut f = vec![
                crate::stream::FLAP_MARKER,
                crate::stream::FLAP_CHANNEL_SIGNON,
            ];
            f.extend_from_slice(&1u16.to_be_bytes());
            f.extend_from_slice(&(snac.len() as u16).to_be_bytes());
            f.extend_from_slice(&snac);
            f
        };
        let mut lines = pump(
            &mut service,
            Direction::Inbound,
            &mut s,
            &motd,
            NOW,
            &encrypting(None),
            &mut out,
        );
        // And on the next poll, which is where it actually went wrong: the
        // service connection's MOTD had no token, so the publish attempt found
        // none, said "off", and took the account's published keys with it.
        lines.extend(s.poll(NOW + 10));

        assert!(
            s.engine().ready(),
            "the account is still published: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("no token yet")),
            "and nothing says the account lost its directory: {lines:?}"
        );
    }

    #[test]
    fn a_poll_before_the_retry_time_does_nothing() {
        let home = Temp::new("poll");
        let dir = Arc::new(MemoryDirectory::new());
        announced(&dir);
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();
        s.on_token(&dir.token("100001"), NOW);
        s.publish(NOW);

        let due = s.retry_at();
        assert!(due > NOW, "a retry is scheduled: {due}");
        assert!(
            s.poll(due - 1).is_empty(),
            "nothing is attempted before the time"
        );
        assert!(!s.poll(due).is_empty(), "and something is at it when due");
    }

    /// What a message or a command changes reaches the state file: a contact's
    /// setting survives a restart (CHECKLIST 10.1). Only a publish used to mark
    /// the state for writing, so a setting - or a ratchet step - made between
    /// two publishes was lost when the client closed.
    #[test]
    fn a_contacts_setting_reaches_the_state_file() {
        let home = Temp::new("setting");
        let dir = Arc::new(MemoryDirectory::new());
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();
        assert!(s.engine().command("100002", "/e2e off", NOW));
        s.save().unwrap();
        // A restart: the first session lets go of the state first.
        drop(s);

        let mut again = Session::open(dir.clone(), &home.0, "100001").unwrap();
        assert_eq!(
            again.engine().remembered("100002").setting,
            crate::policy::Setting::Off
        );
    }

    /// What the dropped lock button of the message window left behind - a
    /// folder of state files and its script's log - is removed at sign-on;
    /// the keys next to it are not touched.
    #[test]
    fn the_lock_buttons_leftovers_go_at_sign_on() {
        let home = Temp::new("lock-leftovers");
        let state = home.0.join("state").join("100001");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("100002"), b"on").unwrap();
        std::fs::write(home.0.join("state").join("owner"), b"100001").unwrap();
        std::fs::write(home.0.join("lockbutton.log"), b"click").unwrap();
        let dir = Arc::new(MemoryDirectory::new());
        let key = Session::open(dir.clone(), &home.0, "100001")
            .unwrap()
            .engine()
            .keys()
            .account_key_bytes();
        assert!(!home.0.join("state").exists(), "the state folder is gone");
        assert!(!home.0.join("lockbutton.log").exists(), "the log is gone");
        assert!(home.0.join("100001.state").is_file(), "the keys stay");
        // Nothing left: a second sign-on is the same device, and quiet.
        let mut again = Session::open(dir.clone(), &home.0, "100001").unwrap();
        assert_eq!(again.engine().keys().account_key_bytes(), key);
    }

    /// `100002` in the directory with a full pool, as another add-on.
    fn peer_published(dir: &MemoryDirectory) -> crate::keys::OwnKeys {
        let mut b = crate::keys::OwnKeys::create("100002");
        let t = crate::token::Token::parse(&dir.token("100002"))
            .unwrap()
            .bearer;
        let (key, sig) = b.account_object();
        dir.announce("100002", &b.account_key_bytes());
        dir.put_account(&t, &key, &sig).unwrap();
        let (curve, ed, dsig) = b.device_object().unwrap();
        dir.put_device(&t, b.device_id, &curve, &ed, &dsig).unwrap();
        let pool = b.new_one_time_keys(0);
        dir.upload_one_time_keys(&t, b.device_id, &pool).unwrap();
        b
    }

    /// A session for `100001` with its keys published.
    fn published_session(dir: &Arc<MemoryDirectory>, home: &Path) -> Session {
        let mut s = Session::open(dir.clone(), home, "100001").unwrap();
        s.on_token(&dir.token("100001"), NOW);
        let key = s.engine().account_key().unwrap();
        dir.announce("100001", &key);
        s.publish(NOW);
        s.save().unwrap();
        assert!(s.engine().ready());
        s
    }

    fn form() -> crate::container::Form {
        crate::container::Form::Fragment {
            charset: 0,
            language: 0,
        }
    }

    /// Audit 2026-10, finding 5: a message whose ratchet moved on used to be
    /// let go - sent, or shown - whether or not the state it moved on had
    /// reached the disk. A restart after a failed save could then send
    /// another message under the same key, or lose what was shown.
    #[test]
    fn a_message_is_let_go_only_once_its_state_is_on_disk() {
        let home = Temp::new("persist-first");
        let dir = Arc::new(MemoryDirectory::new());
        let mut b = peer_published(&dir);
        let mut s = published_session(&dir, &home.0);
        let path = Store::new(&home.0, "100001").path().to_path_buf();

        // The state cannot be written: its temporary file is a folder.
        let tmp = path.with_extension("state.tmp");
        std::fs::create_dir(&tmp).unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        let out = s.engine().outbound("100002", form(), b"hi", NOW);
        match &out {
            crate::keys::Outbound::Refused(note) => {
                assert!(note.contains("could not be saved"), "{note}")
            }
            other => panic!("nothing may go out unsaved, got {other:?}"),
        }
        // And the next one waits too, without encrypting anything.
        assert!(matches!(
            s.engine().outbound("100002", form(), b"again", NOW),
            crate::keys::Outbound::Refused(_)
        ));

        // An incoming message is not shown either.
        let to_a = crate::keys::fetch_contact(&*dir, "100001").unwrap();
        let bearer = crate::token::Token::parse(&dir.token("100002"))
            .unwrap()
            .bearer;
        let wire = match b
            .encrypt(
                &*dir,
                &bearer,
                &crate::keys::Outgoing {
                    peer: "100001".into(),
                    form: form(),
                    text: b"hello a".to_vec(),
                    now: NOW,
                },
                &to_a,
            )
            .unwrap()
        {
            crate::keys::Outbound::Encrypted(w) => w,
            other => panic!("{other:?}"),
        };
        let c =
            crate::container::Container::from_bytes(&crate::container::find_armor(&wire).unwrap())
                .unwrap();
        match s.engine().inbound("100002", &c, NOW) {
            crate::keys::Inbound::Unreadable(note) => {
                assert!(note.contains("was not shown"), "{note}")
            }
            other => panic!("nothing may be shown unsaved, got {other:?}"),
        }
        assert_eq!(std::fs::read(&path).unwrap(), on_disk, "nothing written");

        // The disk takes it again: the same message, delivered again, opens,
        // and messages go out.
        std::fs::remove_dir(&tmp).unwrap();
        match s.engine().inbound("100002", &c, NOW) {
            crate::keys::Inbound::Text { text, .. } => assert_eq!(text, b"hello a"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            s.engine().outbound("100002", form(), b"now", NOW),
            crate::keys::Outbound::Encrypted(_)
        ));
        assert_ne!(std::fs::read(&path).unwrap(), on_disk, "and it is on disk");
    }

    /// Audit 2026-10, finding 6: two clients signed on as the same account
    /// used to load, advance and save one state file each, overwriting each
    /// other's ratchets. The second is locked out: it never touches the
    /// state, announces nothing, and holds messages rather than sending them
    /// in clear.
    #[test]
    fn a_second_session_of_the_same_account_is_locked_out_and_holds_messages() {
        let home = Temp::new("locked-out");
        let dir = Arc::new(MemoryDirectory::new());
        let _b = peer_published(&dir);
        let first = published_session(&dir, &home.0);
        assert!(first.locked_out().is_none());
        let path = Store::new(&home.0, "100001").path().to_path_buf();
        let on_disk = std::fs::read(&path).unwrap();

        let mut second = Session::open(dir.clone(), &home.0, "100001").unwrap();
        assert!(second.locked_out().is_some());
        assert!(second.engine().account_key().is_none(), "nothing announced");
        assert!(!second.engine().ready());
        second.on_token(&dir.token("100001"), NOW);
        let out = second.engine().outbound("100002", form(), b"hi", NOW);
        assert!(
            matches!(&out, crate::keys::Outbound::Refused(n) if n.contains("NOT sent")),
            "held, never clear: {out:?}"
        );
        assert!(second.poll(NOW).is_empty(), "nothing published");
        second.save().unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            on_disk,
            "the state untouched"
        );

        // Once the first lets go, a new session is the device again.
        drop(second);
        drop(first);
        let third = Session::open(dir.clone(), &home.0, "100001").unwrap();
        assert!(third.locked_out().is_none());
    }

    #[test]
    fn a_contacts_capability_is_taken_once() {
        let home = Temp::new("contacts");
        let dir = Arc::new(MemoryDirectory::new());
        let mut s = Session::open(dir.clone(), &home.0, "100001").unwrap();
        let contacts = vec![("100002".to_string(), true)];
        s.on_contacts(&contacts);
        s.on_contacts(&contacts);
        assert_eq!(
            s.told.len(),
            1,
            "the same contact arriving again with every status change is noted once"
        );
    }
}
