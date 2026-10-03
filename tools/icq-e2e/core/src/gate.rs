//! The protection gate (fourth review: bootstrap and interception).
//!
//! One place says what may cross the boundary between the client and the
//! network, so that no hook, no stream and no install path decides a
//! fallback of its own. Two states, asked per traffic class:
//!
//! - [`Bootstrap`]: whether the add-on is in place. `Starting` until the
//!   settings are read and the networking module is patched; then `Ready`
//!   with the hooks that went in, or `Fatal` with the reason (a hook the
//!   policy needs is missing, patching failed and was rolled back, the module
//!   never appeared). Before `Ready` nothing protected leaves: in a protecting
//!   policy every `connect`, `send` and `recv` the hooks see is refused.
//! - [`CryptoState`]: whether this account has its keys. `WaitingForIdentity`
//!   (the account is not known yet), `Ready` (a session), `Unavailable` (no
//!   key directory, a state file that cannot be read), `LockedOut` (another
//!   process holds the state; the engine holds every message itself).
//!
//! The classes ([`Class`]):
//!
//! - `Control`: OSCAR control frames - sign-on, service requests, presence.
//!   They pass once the bootstrap is `Ready`.
//! - `Message`: the text of a message. Encrypted or held by the engine per
//!   contact when the crypto state is `Ready`/`LockedOut`; otherwise held
//!   with a note in the chat ([`Withheld`]) - never sent in clear because of
//!   an internal failure. When the policy for a contact cannot be determined
//!   (no state), the payload counts as protected.
//! - `Media` and `File`: a call's signalling and a file transfer's
//!   rendezvous, with `calls_encrypt`/`files_encrypt` on. Encrypted per
//!   policy when the hooks they need are ready and the crypto state can tell
//!   the contact's policy; blocked when a contact's policy requires
//!   encryption and it cannot be had, or when the policy cannot be told.
//!
//! The decisions are pure functions of the policy and the two states, so the
//! fault matrix at the end of this file enumerates them without a client.
//! [`Gate`] holds the states for the process.

use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

use crate::config::{Mode, Policy, TlsPolicy};
use crate::container::{self, Form};
use crate::crypto::{Crypto, Note};
use crate::keys::{Inbound, Outbound};
use crate::policy;

/// The networking module's hooks, as a set.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct HookMask(pub u16);

impl HookMask {
    pub const NONE: HookMask = HookMask(0);
    pub const SEND: HookMask = HookMask(1);
    pub const RECV: HookMask = HookMask(1 << 1);
    pub const CONNECT: HookMask = HookMask(1 << 2);
    pub const CLOSE: HookMask = HookMask(1 << 3);
    pub const ASYNC_SELECT: HookMask = HookMask(1 << 4);
    pub const IOCTL: HookMask = HookMask(1 << 5);
    pub const GETPEERNAME: HookMask = HookMask(1 << 6);
    pub const ACCEPT: HookMask = HookMask(1 << 7);
    pub const ALL: HookMask = HookMask(0xFF);

    /// The Winsock names, in bit order.
    const NAMES: [&'static str; 8] = [
        "send",
        "recv",
        "connect",
        "closesocket",
        "WSAAsyncSelect",
        "ioctlsocket",
        "getpeername",
        "accept",
    ];

    /// The bit of a hooked Winsock function, by its export name.
    pub fn of(name: &str) -> HookMask {
        Self::NAMES
            .iter()
            .position(|n| *n == name)
            .map_or(HookMask::NONE, |i| HookMask(1 << i))
    }

    pub fn with(self, other: HookMask) -> HookMask {
        HookMask(self.0 | other.0)
    }

    pub fn contains(self, other: HookMask) -> bool {
        self.0 & other.0 == other.0
    }

    /// What of `required` is not in `self`.
    pub fn missing(self, required: HookMask) -> HookMask {
        HookMask(required.0 & !self.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn names(self) -> Vec<&'static str> {
        (0..8)
            .filter(|i| self.0 & (1 << i) != 0)
            .map(|i| Self::NAMES[i])
            .collect()
    }

    /// The hooks without which `policy` cannot keep its promise:
    ///
    /// - `send` and `recv` in every mode but observe: they carry the bytes;
    /// - `connect` with TLS (the mapping to the TLS port), with the guard
    ///   ports of `tls=off` (the mapping to the plain ports) and in encrypt
    ///   mode (the guard ports, and the connections of a file transfer);
    /// - `accept` with file transfers encrypted: the peer connection of the
    ///   side that listens.
    ///
    /// The others (`closesocket`, `WSAAsyncSelect`, `ioctlsocket`,
    /// `getpeername`) keep the client working smoothly; without them a
    /// connection may stall, but nothing leaves unprotected.
    pub fn required_for(p: &Policy) -> HookMask {
        if p.mode == Mode::Observe {
            return HookMask::NONE;
        }
        let mut m = HookMask::SEND.with(HookMask::RECV);
        let tls = matches!(
            p.tls,
            TlsPolicy::On { .. } | TlsPolicy::Invalid { .. } | TlsPolicy::Off { .. }
        );
        if tls || p.mode == Mode::Encrypt {
            m = m.with(HookMask::CONNECT);
        }
        if p.encrypts_files() {
            m = m.with(HookMask::ACCEPT);
        }
        m
    }
}

/// Whether `p` promises any protection: then a failure of the add-on itself
/// blocks traffic instead of letting it through. Observe mode only watches;
/// `e2e=off` with TLS off has nothing to protect.
pub fn protecting(p: &Policy) -> bool {
    match p.mode {
        Mode::Observe => false,
        Mode::Harness | Mode::Encrypt => true,
        Mode::Plain => matches!(p.tls, TlsPolicy::On { .. } | TlsPolicy::Invalid { .. }),
    }
}

/// Whether the add-on is in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bootstrap {
    /// The settings are not read or the networking module not patched yet.
    Starting,
    /// The hooks that went in.
    Ready(HookMask),
    /// Why the add-on cannot protect anything.
    Fatal(String),
}

/// The call modules' hooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaHooks {
    /// Not loaded and patched yet. With `calls_encrypt` the bootstrap loads
    /// and patches them before any call (fifth audit of 2026-10, finding 5);
    /// until then a call that must be encrypted is not let through.
    NotLoaded,
    Ready,
    /// The client has no such module (ICQ 6.5 has no `sipXmediaLib.dll`).
    Absent,
    Failed(String),
}

/// This account's cryptography. `S` is the session (the hooks keep an
/// `Arc<Mutex<Session>>`; the tests anything).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoState<S> {
    /// Not known yet which account this is.
    WaitingForIdentity,
    Ready(S),
    /// Why there are no keys: no key directory, a state file that cannot be
    /// read.
    Unavailable(String),
    /// Another process holds the state file; the session holds every message.
    LockedOut(S),
}

impl<S> CryptoState<S> {
    /// The session, when there is one.
    pub fn session(&self) -> Option<&S> {
        match self {
            CryptoState::Ready(s) | CryptoState::LockedOut(s) => Some(s),
            _ => None,
        }
    }

    /// Why messages are held, when there is no session.
    pub fn why_not(&self) -> Option<String> {
        match self {
            CryptoState::WaitingForIdentity => Some(
                "the add-on does not know yet which account this ICQ is signed on as".to_string(),
            ),
            CryptoState::Unavailable(why) => Some(why.clone()),
            _ => None,
        }
    }
}

/// What kind of traffic is asked about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Control,
    Message,
    Media,
    File,
}

/// What may cross.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// As it is: control traffic, or a class this policy does not protect.
    Pass,
    /// Through the engine, which encrypts it or holds it per contact.
    Protect,
    /// As it is, with this note (a call with a contact who does not require
    /// encryption, while the call hooks could not be installed).
    Plain(String),
    /// Held, with this note in the chat (a message).
    Hold(String),
    /// Refused or dropped, for this reason.
    Block(String),
}

impl Verdict {
    /// Whether the bytes may leave as the client wrote them.
    pub fn lets_plain_through(&self) -> bool {
        matches!(self, Verdict::Pass | Verdict::Plain(_))
    }
}

/// Control traffic, and the first question for every other class: whether
/// anything may cross at all.
pub fn admit(p: &Policy, boot: &Bootstrap) -> Verdict {
    if p.mode == Mode::Observe {
        return Verdict::Pass;
    }
    match boot {
        Bootstrap::Ready(_) => Verdict::Pass,
        Bootstrap::Starting => Verdict::Block("the add-on is still starting".to_string()),
        Bootstrap::Fatal(why) if protecting(p) => Verdict::Block(why.clone()),
        Bootstrap::Fatal(_) => Verdict::Pass,
    }
}

/// The text of a message.
pub fn message<S>(p: &Policy, boot: &Bootstrap, crypto: &CryptoState<S>) -> Verdict {
    match admit(p, boot) {
        Verdict::Pass => {}
        other => return other,
    }
    if p.mode != Mode::Encrypt {
        // Harness rewrites, `e2e=off` and observe never encrypt messages.
        return Verdict::Pass;
    }
    match crypto {
        CryptoState::Ready(_) | CryptoState::LockedOut(_) => Verdict::Protect,
        other => Verdict::Hold(other.why_not().unwrap_or_default()),
    }
}

/// A call's signalling with `calls_encrypt` on. `strict` is whether the
/// contact's policy requires encryption (`/e2e on`, verified), `None` when
/// it cannot be told (no session).
pub fn media(p: &Policy, boot: &Bootstrap, hooks: &MediaHooks, strict: Option<bool>) -> Verdict {
    match admit(p, boot) {
        Verdict::Pass => {}
        other => return other,
    }
    if !p.encrypts_calls() {
        return Verdict::Pass;
    }
    let Some(strict) = strict else {
        return Verdict::Block(
            "end-to-end encryption is not available in this ICQ, so the call cannot be encrypted"
                .to_string(),
        );
    };
    let required = strict || p.calls_required;
    match hooks {
        MediaHooks::Failed(why) if required => Verdict::Block(format!(
            "the add-on could not take over the call's media ({why})"
        )),
        MediaHooks::Failed(why) => Verdict::Plain(format!(
            "the add-on could not take over the call's media ({why}), so the call is not end-to-end encrypted"
        )),
        // The call modules are not patched yet: their first datagrams could
        // leave before the hooks are in (fifth audit of 2026-10, finding 5).
        MediaHooks::NotLoaded | MediaHooks::Absent if required => Verdict::Block(
            "the call modules are not loaded and patched yet, so the call's media could leave unencrypted".to_string(),
        ),
        MediaHooks::NotLoaded | MediaHooks::Absent => Verdict::Plain(
            "the call modules are not loaded and patched yet, so the call is not end-to-end encrypted".to_string(),
        ),
        MediaHooks::Ready => Verdict::Protect,
    }
}

/// A file transfer's rendezvous with `files_encrypt` on; `strict` as for
/// [`media`].
pub fn file(p: &Policy, boot: &Bootstrap, strict: Option<bool>) -> Verdict {
    match admit(p, boot) {
        Verdict::Pass => {}
        other => return other,
    }
    if !p.encrypts_files() {
        return Verdict::Pass;
    }
    let Some(strict) = strict else {
        return Verdict::Block(
            "end-to-end encryption is not available in this ICQ, so the file cannot be encrypted"
                .to_string(),
        );
    };
    let peer_hooks = HookMask::ACCEPT
        .with(HookMask::CONNECT)
        .with(HookMask::SEND)
        .with(HookMask::RECV);
    match boot {
        Bootstrap::Ready(mask) if !mask.contains(peer_hooks) => {
            let why = format!(
                "the add-on could not hook {} for the transfer's connection",
                mask.missing(peer_hooks).names().join(", ")
            );
            if strict || p.files_required {
                Verdict::Block(why)
            } else {
                Verdict::Plain(why)
            }
        }
        _ => Verdict::Protect,
    }
}

/// The gate's state for the process.
pub struct Gate {
    boot: Mutex<Bootstrap>,
    changed: Condvar,
    /// What the install of the networking module came to, until the policy
    /// is known and the two are settled into [`Bootstrap`].
    installed: Mutex<Option<Result<HookMask, String>>>,
    /// The two call modules (`hook_calls.rs`, `CALL_MODULES`).
    media: Mutex<[MediaHooks; 2]>,
    /// Notes for the chat from places that have no engine at hand.
    notes: Mutex<Vec<String>>,
    /// Keys already said, so a note is said once.
    said: Mutex<Vec<(String, u64)>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Default for Gate {
    fn default() -> Self {
        Gate::new()
    }
}

impl Gate {
    pub const fn new() -> Gate {
        Gate {
            boot: Mutex::new(Bootstrap::Starting),
            changed: Condvar::new(),
            installed: Mutex::new(None),
            media: Mutex::new([MediaHooks::NotLoaded, MediaHooks::NotLoaded]),
            notes: Mutex::new(Vec::new()),
            said: Mutex::new(Vec::new()),
        }
    }

    /// A gate that is ready with `mask`, its call modules patched (the tests
    /// and the test host).
    pub fn ready(mask: HookMask) -> Gate {
        let g = Gate::new();
        g.force(Bootstrap::Ready(mask));
        g.set_media(0, MediaHooks::Ready);
        g.set_media(1, MediaHooks::Ready);
        g
    }

    pub fn bootstrap(&self) -> Bootstrap {
        lock(&self.boot).clone()
    }

    /// Sets the bootstrap state as it is (the tests; and a Fatal reason).
    pub fn force(&self, b: Bootstrap) {
        *lock(&self.boot) = b;
        self.changed.notify_all();
    }

    /// Sets `Fatal` unless it is already.
    pub fn fail(&self, why: String) {
        let mut b = lock(&self.boot);
        if !matches!(*b, Bootstrap::Fatal(_)) {
            *b = Bootstrap::Fatal(why);
        }
        self.changed.notify_all();
    }

    /// Records what the install of the networking module came to: the hooks
    /// that went in, or why none did.
    pub fn installed(&self, r: Result<HookMask, String>) {
        *lock(&self.installed) = Some(r);
    }

    /// What the install came to, if it ended.
    pub fn install_outcome(&self) -> Option<Result<HookMask, String>> {
        lock(&self.installed).clone()
    }

    /// Turns the install's outcome into `Ready` or `Fatal` under `policy`,
    /// once both are known. A hook the policy needs that is missing is
    /// `Fatal`, with the hooks that are in place left to refuse. Returns
    /// the state now.
    pub fn settle(&self, policy: &Policy) -> Bootstrap {
        let outcome = lock(&self.installed).clone();
        let next = match outcome {
            None => return self.bootstrap(),
            Some(Err(why)) => Bootstrap::Fatal(why),
            Some(Ok(mask)) => {
                let missing = mask.missing(HookMask::required_for(policy));
                if missing.is_empty() {
                    Bootstrap::Ready(mask)
                } else {
                    Bootstrap::Fatal(format!(
                        "the client's networking module does not import {} through the hooks this setup needs",
                        missing.names().join(", ")
                    ))
                }
            }
        };
        let mut b = lock(&self.boot);
        if !matches!(*b, Bootstrap::Fatal(_)) {
            *b = next;
        }
        self.changed.notify_all();
        b.clone()
    }

    /// Waits up to `timeout` for the bootstrap to leave `Starting`.
    pub fn wait(&self, timeout: Duration) -> Bootstrap {
        let b = lock(&self.boot);
        let (b, _) = self
            .changed
            .wait_timeout_while(b, timeout, |b| *b == Bootstrap::Starting)
            .unwrap_or_else(|e| e.into_inner());
        b.clone()
    }

    pub fn set_media(&self, module: usize, state: MediaHooks) {
        if let Some(m) = lock(&self.media).get_mut(module) {
            *m = state;
        }
    }

    /// The call modules together: failed if one failed; not loaded while one
    /// the client has is not patched yet; ready once every module the
    /// client has is (fifth audit of 2026-10, finding 5: one patched module
    /// used to make both count as ready).
    pub fn media(&self) -> MediaHooks {
        combine(&lock(&self.media)[..])
    }

    /// Queues a note for the chat last used.
    pub fn say(&self, text: String) {
        lock(&self.notes).push(text);
    }

    pub fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut *lock(&self.notes))
    }

    /// Whether `key` was not said within `window` seconds before `now`;
    /// remembers it as said now.
    pub fn once(&self, key: &str, now: u64, window: u64) -> bool {
        let mut said = lock(&self.said);
        said.retain(|(_, at)| now.saturating_sub(*at) < window);
        if said.iter().any(|(k, _)| k == key) {
            return false;
        }
        said.push((key.to_string(), now));
        true
    }
}

/// The call modules' states as one: [`Gate::media`].
pub fn combine(m: &[MediaHooks]) -> MediaHooks {
    if let Some(f) = m.iter().find(|s| matches!(s, MediaHooks::Failed(_))) {
        return f.clone();
    }
    if m.contains(&MediaHooks::NotLoaded) {
        MediaHooks::NotLoaded
    } else if m.contains(&MediaHooks::Ready) {
        MediaHooks::Ready
    } else {
        MediaHooks::Absent
    }
}

/// The process's gate.
static GATE: Gate = Gate::new();

#[cfg(test)]
thread_local! {
    /// A gate for this thread only: the tests run many cases in one process,
    /// each with the gate it needs.
    static TEST_GATE: std::cell::RefCell<Option<&'static Gate>> =
        const { std::cell::RefCell::new(None) };
}

/// The gate the hooks and the stream ask.
///
/// Under test a thread without a gate of its own gets one that is ready with
/// every hook, so the tests of other modules run as before.
pub fn current() -> &'static Gate {
    #[cfg(test)]
    {
        static READY: std::sync::LazyLock<Gate> =
            std::sync::LazyLock::new(|| Gate::ready(HookMask::ALL));
        return TEST_GATE.with(|g| g.borrow().unwrap_or(&READY));
    }
    #[cfg(not(test))]
    &GATE
}

/// The process's gate, whatever the thread (the test host sets it ready).
pub fn global() -> &'static Gate {
    &GATE
}

/// Gives this thread a gate of its own (the tests).
#[cfg(test)]
pub fn use_for_this_thread(g: Option<&'static Gate>) {
    TEST_GATE.with(|t| *t.borrow_mut() = g);
}

// --- the engine of an account without keys ----------------------------------

/// What stands in for the engine in encrypt mode while [`CryptoState`] has
/// no session: every message is held with a note, never sent in clear;
/// every container is unreadable with a note; a `/e2e` command is answered
/// and never sent; nothing is announced or published. It holds the reason
/// and the notes, nothing else.
#[derive(Debug, Default)]
pub struct Withheld {
    why: String,
    notes: Vec<Note>,
    /// When a warning about an unencrypted message was last put in a chat.
    plain_said: std::collections::HashMap<String, u64>,
}

impl Withheld {
    pub fn new(why: String) -> Self {
        Withheld {
            why,
            ..Default::default()
        }
    }

    /// Changes the reason (the account became known, the state file stayed
    /// unreadable).
    pub fn set_reason(&mut self, why: String) {
        self.why = why;
    }

    /// A note about the add-on itself, for the chat last used.
    pub fn say(&mut self, text: String) {
        self.notes.push(Note { peer: None, text });
    }
}

impl Crypto for Withheld {
    fn bearer(&self) -> Option<String> {
        None
    }

    fn ready(&self) -> bool {
        false
    }

    /// None: nothing is announced without keys.
    fn account_key(&self) -> Option<[u8; 32]> {
        None
    }

    fn outbound(&mut self, peer: &str, _form: Form, _text: &[u8], _now: u64) -> Outbound {
        let note = format!(
            "{}The message to {peer} was NOT sent: {}. Nothing is sent unencrypted because of it; the message is held, send it again once encryption works.",
            policy::PREFIX,
            self.why
        );
        self.notes.push(Note::to(peer, note.clone()));
        Outbound::Refused(note)
    }

    fn inbound(&mut self, peer: &str, _c: &container::Container, _now: u64) -> Inbound {
        let note = format!(
            "{}An encrypted message from {peer} could not be read: {}.",
            policy::PREFIX,
            self.why
        );
        self.notes.push(Note::to(peer, note.clone()));
        Inbound::Unreadable(note)
    }

    fn unsupported(&mut self, peer: &str, version: u8, scheme: u8) -> Inbound {
        let note = keys_unsupported(peer, version, scheme);
        self.notes.push(Note::to(peer, note.clone()));
        Inbound::Unreadable(note)
    }

    fn take_note(&mut self) -> Option<Note> {
        (!self.notes.is_empty()).then(|| self.notes.remove(0))
    }

    fn command(&mut self, peer: &str, text: &str, _now: u64) -> bool {
        if policy::parse_command(text).is_none() {
            return false;
        }
        let note = format!(
            "{}Encryption is held in this ICQ: {}. Nothing is sent unencrypted because of it.",
            policy::PREFIX,
            self.why
        );
        self.notes.push(Note::to(peer, note));
        true
    }

    fn take_control(&mut self, _peer: &str) -> Option<Vec<u8>> {
        None
    }

    fn since_control(&self, _peer: &str) -> u32 {
        0
    }

    /// Unknown: there is no state to tell a contact's policy by.
    fn strictness(&self, _peer: &str) -> Option<bool> {
        None
    }

    /// Unknown, so protected (fifth audit of 2026-10, finding 1): no
    /// unencrypted message is shown while there are no keys, as no message
    /// is sent.
    fn plain_inbound(&mut self, peer: &str, now: u64) -> Option<String> {
        let why = format!(
            "the add-on cannot read its settings for {peer}: {}",
            self.why.trim_end_matches('.')
        );
        crate::crypto::plain_dropped(&mut self.plain_said, &mut self.notes, peer, &why, now);
        Some(why)
    }

    /// Unknown, so protected: there is no state to tell the contact's policy
    /// by, and no session to authenticate anything over.
    fn protected(&self, peer: &str) -> Option<String> {
        Some(format!(
            "the add-on cannot read its settings for {peer}: {}",
            self.why.trim_end_matches('.')
        ))
    }

    fn unauthenticated(&mut self, peer: &str, what: &str, note: String, now: u64) {
        crate::crypto::unauthenticated_note(
            &mut self.plain_said,
            &mut self.notes,
            peer,
            what,
            note,
            now,
        );
    }

    fn note(&mut self, peer: &str, text: String) {
        self.notes.push(Note::to(peer, text));
    }
}

fn keys_unsupported(peer: &str, version: u8, scheme: u8) -> String {
    crate::keys::unsupported(&crate::sign::ident(peer), version, scheme)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

    fn policy(f: impl FnOnce(&mut Policy)) -> Policy {
        let mut p = Policy::from_settings(Settings {
            mode: Some("encrypt"),
            directory: Some("https://example.invalid/e2e/v1/"),
            home: Some(" "),
            server: Some("icq.example.org"),
            tls: Some("on"),
            ..Default::default()
        });
        p.calls_encrypt = false;
        p.calls_required = false;
        p.files_encrypt = false;
        p.files_required = false;
        f(&mut p);
        p
    }

    #[test]
    fn the_required_hooks_follow_the_policy() {
        let enc = policy(|_| {});
        assert_eq!(
            HookMask::required_for(&enc),
            HookMask::SEND.with(HookMask::RECV).with(HookMask::CONNECT)
        );
        let files = policy(|p| p.files_encrypt = true);
        assert!(HookMask::required_for(&files).contains(HookMask::ACCEPT));
        let plain_no_tls = policy(|p| {
            p.mode = Mode::Plain;
            p.tls = TlsPolicy::NoServer;
        });
        assert_eq!(
            HookMask::required_for(&plain_no_tls),
            HookMask::SEND.with(HookMask::RECV)
        );
        let plain_tls = policy(|p| p.mode = Mode::Plain);
        assert!(HookMask::required_for(&plain_tls).contains(HookMask::CONNECT));
        assert_eq!(HookMask::required_for(&Policy::observe()), HookMask::NONE);
        assert_eq!(HookMask::of("accept"), HookMask::ACCEPT);
        assert_eq!(HookMask::of("sendto"), HookMask::NONE);
        assert_eq!(
            HookMask::ALL.missing(HookMask::SEND).names(),
            Vec::<&str>::new()
        );
        assert_eq!(
            HookMask::SEND
                .missing(HookMask::SEND.with(HookMask::ACCEPT))
                .names(),
            vec!["accept"]
        );
    }

    #[test]
    fn settling_a_missing_required_hook_is_fatal() {
        let g = Gate::new();
        let p = policy(|p| p.files_encrypt = true);
        assert_eq!(g.settle(&p), Bootstrap::Starting, "nothing installed yet");
        g.installed(Ok(HookMask::ALL.missing(HookMask::ACCEPT)));
        assert!(matches!(g.settle(&p), Bootstrap::Fatal(w) if w.contains("accept")));
        let g = Gate::new();
        g.installed(Ok(HookMask::ALL));
        assert_eq!(g.settle(&p), Bootstrap::Ready(HookMask::ALL));
        let g = Gate::new();
        g.installed(Err("rolled back".into()));
        assert_eq!(g.settle(&p), Bootstrap::Fatal("rolled back".into()));
        // Fatal stays Fatal.
        g.installed(Ok(HookMask::ALL));
        assert!(matches!(g.settle(&p), Bootstrap::Fatal(_)));
    }

    #[test]
    fn waiting_ends_when_the_bootstrap_is_settled_or_the_time_is_up() {
        let g: &'static Gate = Box::leak(Box::new(Gate::new()));
        assert_eq!(g.wait(Duration::from_millis(20)), Bootstrap::Starting);
        let t = std::thread::spawn(move || g.wait(Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(30));
        g.force(Bootstrap::Ready(HookMask::ALL));
        assert_eq!(t.join().unwrap(), Bootstrap::Ready(HookMask::ALL));
    }

    // --- the fault matrix --------------------------------------------------

    /// Every internal failure the fourth review names, as the gate sees it.
    #[derive(Clone, Debug)]
    enum Failure {
        Healthy,
        NoDirectory,
        NoUin,
        UnreadableState,
        CorruptState,
        LockedState,
        StillStarting,
        RequiredHookMissing(HookMask),
        RolledBack,
        NetworkingModuleNeverLoaded,
        CallHooksMissing,
        /// The call modules not loaded and patched yet (fifth audit of
        /// 2026-10, finding 5).
        CallModulesNotPatched,
        FileHooksMissing,
    }

    /// What a contact is.
    #[derive(Clone, Copy, Debug)]
    enum Contact {
        Auto,
        OnByCommand,
        Verified,
    }

    /// The modes of the matrix.
    fn modes() -> Vec<(&'static str, Policy)> {
        vec![
            ("encrypt, tls on", policy(|_| {})),
            (
                "encrypt, tls off",
                policy(|p| {
                    p.tls = TlsPolicy::Off {
                        server: "icq.example.org".into(),
                    }
                }),
            ),
            (
                "calls required",
                policy(|p| {
                    p.calls_encrypt = true;
                    p.calls_required = true;
                }),
            ),
            ("calls on", policy(|p| p.calls_encrypt = true)),
            (
                "files required",
                policy(|p| {
                    p.files_encrypt = true;
                    p.files_required = true;
                }),
            ),
            ("files on", policy(|p| p.files_encrypt = true)),
            ("e2e off, tls on", policy(|p| p.mode = Mode::Plain)),
        ]
    }

    /// The states a failure leaves behind, as the hooks would see them.
    fn states(f: &Failure, p: &Policy) -> (Bootstrap, CryptoState<()>, MediaHooks) {
        let ready = Bootstrap::Ready(HookMask::ALL);
        let ok = CryptoState::Ready(());
        let g = Gate::new();
        match f {
            Failure::Healthy => (ready, ok, MediaHooks::Ready),
            Failure::NoDirectory => (
                ready,
                CryptoState::Unavailable("no key directory".into()),
                MediaHooks::Ready,
            ),
            Failure::NoUin => (ready, CryptoState::WaitingForIdentity, MediaHooks::Ready),
            Failure::UnreadableState | Failure::CorruptState => (
                ready,
                CryptoState::Unavailable("the state file cannot be used".into()),
                MediaHooks::Ready,
            ),
            Failure::LockedState => (ready, CryptoState::LockedOut(()), MediaHooks::Ready),
            Failure::StillStarting => (Bootstrap::Starting, ok, MediaHooks::Ready),
            Failure::RequiredHookMissing(h) => {
                g.installed(Ok(HookMask::ALL.missing(*h)));
                (g.settle(p), ok, MediaHooks::Ready)
            }
            Failure::RolledBack => {
                g.installed(Err("VirtualProtect failed; every slot put back".into()));
                (g.settle(p), ok, MediaHooks::Ready)
            }
            Failure::NetworkingModuleNeverLoaded => {
                g.fail("no networking module appeared".into());
                (g.bootstrap(), ok, MediaHooks::Ready)
            }
            Failure::CallHooksMissing => (
                ready,
                ok,
                MediaHooks::Failed("sipXmediaLib.dll imports not patched".into()),
            ),
            Failure::CallModulesNotPatched => (ready, ok, MediaHooks::NotLoaded),
            Failure::FileHooksMissing => {
                g.installed(Ok(HookMask::ALL.missing(HookMask::ACCEPT)));
                (g.settle(p), ok, MediaHooks::Ready)
            }
        }
    }

    fn failures() -> Vec<Failure> {
        vec![
            Failure::Healthy,
            Failure::NoDirectory,
            Failure::NoUin,
            Failure::UnreadableState,
            Failure::CorruptState,
            Failure::LockedState,
            Failure::StillStarting,
            Failure::RequiredHookMissing(HookMask::SEND),
            Failure::RequiredHookMissing(HookMask::RECV),
            Failure::RequiredHookMissing(HookMask::CONNECT),
            Failure::RequiredHookMissing(HookMask::ACCEPT),
            Failure::RolledBack,
            Failure::NetworkingModuleNeverLoaded,
            Failure::CallHooksMissing,
            Failure::CallModulesNotPatched,
            Failure::FileHooksMissing,
        ]
    }

    /// The invariant, for every failure x mode x contact: whatever the policy
    /// requires to be protected never gets a verdict that lets it through as
    /// the client wrote it because of an internal failure; control traffic
    /// passes exactly when the add-on is in place; and when everything is
    /// healthy the compatibility paths still pass (a message goes to the
    /// engine, which sends an automatic contact without the add-on plain with
    /// a note; a call with a contact who does not require encryption goes as
    /// it is when the call hooks failed, with a note).
    #[test]
    fn no_internal_failure_lets_protected_traffic_through() {
        let mut cases = 0;
        for (mode, p) in modes() {
            for f in failures() {
                let (boot, crypto, hooks) = states(&f, &p);
                let installed = matches!(boot, Bootstrap::Ready(_));
                // Control: exactly when the add-on is in place (or nothing
                // is protected).
                let control = admit(&p, &boot);
                assert_eq!(
                    control.lets_plain_through(),
                    installed || !protecting(&p),
                    "{mode} / {f:?}: control {control:?}"
                );
                // Messages: never plain in encrypt mode unless the engine
                // has them.
                let m = message(&p, &boot, &crypto);
                if p.mode == Mode::Encrypt {
                    assert!(!m.lets_plain_through(), "{mode} / {f:?}: message {m:?}");
                    let engine_has_it = installed && crypto.session().is_some();
                    assert_eq!(m == Verdict::Protect, engine_has_it, "{mode} / {f:?}");
                }
                for contact in [Contact::Auto, Contact::OnByCommand, Contact::Verified] {
                    cases += 1;
                    let strict = match (&crypto, contact) {
                        (CryptoState::Ready(_), Contact::Auto) => Some(false),
                        (CryptoState::Ready(_), _) => Some(true),
                        // Locked out: the engine stands in and holds; its
                        // policy for the contact is not known.
                        _ => None,
                    };
                    let call = media(&p, &boot, &hooks, strict);
                    if p.encrypts_calls() {
                        let required = p.calls_required || strict != Some(false);
                        let hooks_ok = hooks == MediaHooks::Ready;
                        if required && !(installed && hooks_ok && strict.is_some()) {
                            assert!(
                                matches!(call, Verdict::Block(_)),
                                "{mode} / {f:?} / {contact:?}: call {call:?}"
                            );
                        }
                        if !installed {
                            assert!(!call.lets_plain_through(), "{mode} / {f:?}: call {call:?}");
                        }
                        if matches!(
                            f,
                            Failure::CallHooksMissing | Failure::CallModulesNotPatched
                        ) && !required
                            && strict.is_some()
                        {
                            assert!(
                                matches!(call, Verdict::Plain(_)),
                                "compatibility: a non-strict call goes plain with a note"
                            );
                        }
                        if matches!(f, Failure::Healthy) {
                            assert_eq!(call, Verdict::Protect);
                        }
                    }
                    let tr = file(&p, &boot, strict);
                    if p.encrypts_files() {
                        if !(installed && strict.is_some()) {
                            assert!(
                                matches!(tr, Verdict::Block(_)),
                                "{mode} / {f:?} / {contact:?}: file {tr:?}"
                            );
                        } else {
                            assert_eq!(tr, Verdict::Protect, "{mode} / {f:?}");
                        }
                    }
                }
                // Healthy: everything goes to the engine or passes.
                if matches!(f, Failure::Healthy) {
                    assert_eq!(control, Verdict::Pass);
                    assert!(matches!(m, Verdict::Pass | Verdict::Protect));
                }
            }
        }
        assert!(cases > 300, "{cases} cases");
    }

    /// The engine that stands in without keys never lets a message out and
    /// never shows a container, and says so in the chat.
    #[test]
    fn the_withheld_engine_holds_everything_with_a_note() {
        let mut w = Withheld::new("the state file cannot be read".into());
        match w.outbound("100002", Form::EightBit, b"secret", 1) {
            Outbound::Refused(n) => assert!(n.contains("NOT sent") && n.contains("state file")),
            other => panic!("{other:?}"),
        }
        assert!(w.take_note().unwrap().text.contains("NOT sent"));
        assert!(w.command("100002", "/e2e status", 1));
        assert!(w.take_note().unwrap().text.contains("held"));
        assert!(!w.command("100002", "hello", 1));
        assert_eq!(w.account_key(), None);
        assert_eq!(w.strictness("100002"), None);
        assert!(w.encrypts(), "messages go through it, so it can hold them");
        // Fifth audit of 2026-10, finding 1: no unencrypted message is
        // shown either, with one warning a minute in the chat.
        let why = w.plain_inbound("100002", 100).expect("refused");
        assert!(why.contains("state file"), "{why}");
        let n = w.take_note().unwrap();
        assert!(n.text.contains("was not shown"), "{}", n.text);
        assert!(w.plain_inbound("100002", 130).is_some());
        assert!(w.take_note().is_none(), "within the minute: not said again");
        assert!(w.plain_inbound("100002", 161).is_some());
        assert!(w.take_note().is_some());
    }

    /// Fifth audit of 2026-10, finding 5: the call modules count as ready
    /// only once every one the client has is patched; one patched module
    /// used to make both count.
    #[test]
    fn the_call_modules_are_ready_only_when_every_one_present_is() {
        use MediaHooks::*;
        let failed = Failed("x".into());
        for (m, want) in [
            ([Ready, Ready], Ready),
            ([Ready, Absent], Ready),
            ([Absent, Ready], Ready),
            ([Ready, NotLoaded], NotLoaded),
            ([NotLoaded, Ready], NotLoaded),
            ([NotLoaded, NotLoaded], NotLoaded),
            ([Absent, Absent], Absent),
            ([Ready, failed.clone()], failed.clone()),
            ([failed.clone(), NotLoaded], failed.clone()),
        ] {
            assert_eq!(combine(&m), want, "{m:?}");
        }
        let p = policy(|p| p.calls_encrypt = true);
        let boot = Bootstrap::Ready(HookMask::ALL);
        for hooks in [NotLoaded, Absent] {
            assert!(matches!(
                media(&p, &boot, &hooks, Some(true)),
                Verdict::Block(_)
            ));
            assert!(matches!(
                media(&p, &boot, &hooks, Some(false)),
                Verdict::Plain(_)
            ));
        }
        assert_eq!(media(&p, &boot, &Ready, Some(true)), Verdict::Protect);
    }
}
