//! The user's say over encryption, contact by contact (CHECKLIST section 10).
//!
//! What is remembered per contact, in the state file: the setting the user
//! chose (`/e2e on`, `/e2e off`, or nothing - automatic) and whether the
//! contact has ever been seen encrypting (signed devices in the key directory,
//! or an encrypted message exchanged). The second is what makes downgrade
//! protection sticky: once a contact has encrypted, a server that later shows
//! no keys for them cannot switch the conversation to clear text unnoticed
//! (10.7).
//!
//! This module is pure: the commands typed in the chat, the remembered state
//! and the words of the notes. [`crate::crypto::Engine`] applies it to the
//! messages.

use serde::{Deserialize, Serialize};

/// What the user chose for one contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Setting {
    /// Nothing chosen: encrypted whenever the contact can receive it (10.1),
    /// switched on by an incoming encrypted message (10.5).
    #[default]
    Auto,
    /// Switched on by hand: nothing ever goes to this contact in clear (10.8),
    /// whatever client they are signed in with now (10.6): a message that
    /// cannot be encrypted is held until the user types `/e2e auto` or
    /// `/e2e off`, and their unencrypted messages are not shown.
    On,
    /// Switched off by hand: messages go in clear, and an incoming encrypted
    /// message does not change that, it only gives a hint (10.5).
    Off,
}

/// What the state file keeps about one contact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remembered {
    #[serde(default)]
    pub setting: Setting,
    /// The contact has been seen with signed devices or has exchanged an
    /// encrypted message. Never cleared by what the server says later.
    #[serde(default)]
    pub seen_encrypting: bool,
}

impl Remembered {
    /// Whether a message to this contact may only go out in clear on the
    /// user's explicit word: switched on by hand, or seen encrypting before.
    pub fn strict(&self) -> bool {
        self.setting == Setting::On || self.seen_encrypting
    }
}

/// What the chat shows as the state of encryption with one contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Messages to this contact are encrypted.
    On,
    /// The user switched encryption off for this contact.
    Off,
    /// The contact cannot receive encrypted messages and was never seen
    /// encrypting, so messages go in clear (trust on first use).
    Unavailable,
    /// The contact is signed in with a client whose presence does not
    /// announce the add-on, so messages go in clear while it does (the
    /// owner's decision on the current client, CHECKLIST 10.6).
    OtherClient,
}

/// A command typed in the chat input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    On,
    Off,
    Status,
    /// Send the next message in clear, once.
    Plain,
    /// Back to the automatic rule: the manual on or off is forgotten, whether
    /// the contact was seen encrypting is not.
    Auto,
    /// Show the safety number with this contact (CHECKLIST 10.10).
    Safety,
    /// Mark the contact verified: the safety number was compared.
    Verify,
    /// Take the verification back.
    Unverify,
    /// Send on to a verified contact whose safety number changed, without
    /// verifying the new number: the contact is unverified from then on.
    Accept,
    /// Forget our copy of the key log and its key, and read it anew: after
    /// the server's operator restored it from a backup or started it afresh.
    ResetLog,
    /// `/e2e` with something it does not know: the list of commands.
    Help,
}

/// The word every command starts with.
pub const COMMAND: &str = "/e2e";

/// Reads a command out of the text the client sent, or `None` for an ordinary
/// message. The client wraps what was typed in HTML (`<HTML><BODY>...`), may
/// put `&nbsp;` for spaces and may change the case, so all of that is taken
/// off before looking.
pub fn parse_command(text: &str) -> Option<Command> {
    let plain = plain_text(text).to_lowercase();
    let mut words = plain.split_whitespace();
    if words.next()? != COMMAND {
        return None;
    }
    let what = words.next();
    if words.next().is_some() {
        return Some(Command::Help);
    }
    Some(match what {
        None | Some("status") => Command::Status,
        Some("on") => Command::On,
        Some("off") => Command::Off,
        Some("plain") => Command::Plain,
        Some("auto") => Command::Auto,
        Some("safety") => Command::Safety,
        Some("verify") => Command::Verify,
        Some("unverify") => Command::Unverify,
        Some("accept") => Command::Accept,
        Some("resetlog") => Command::ResetLog,
        Some(_) => Command::Help,
    })
}

/// The text of a message without its markup: tags removed, the common
/// entities turned back into characters.
pub fn plain_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match (in_tag, ch) {
            (false, '<') => in_tag = true,
            (true, '>') => {
                in_tag = false;
                // A tag separates words the way a line break does.
                out.push(' ');
            }
            (true, _) => {}
            (false, c) => out.push(c),
        }
    }
    let mut s = out;
    for (entity, ch) in [
        ("&nbsp;", " "),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#32;", " "),
        ("&#160;", " "),
        ("&amp;", "&"),
    ] {
        s = s.replace(entity, ch);
    }
    s.replace('\u{a0}', " ")
}

// --- the words of the notes ------------------------------------------------

/// The prefix every note carries, so it cannot be taken for the contact's own
/// words.
pub const PREFIX: &str = "[ICQ E2E] ";

/// The commands, for the end of a note.
pub const COMMANDS: &str = "/e2e on, /e2e off, /e2e auto, /e2e status, /e2e plain, /e2e safety, /e2e verify, /e2e unverify, /e2e accept, /e2e resetlog";

/// The note for a status the chat is now in.
pub fn status_note(peer: &str, status: Status) -> String {
    match status {
        Status::On => format!("{PREFIX}Encryption is on in this chat: messages to {peer} are end-to-end encrypted."),
        Status::Off => format!(
            "{PREFIX}Encryption is off in this chat (/e2e off): messages to {peer} are never encrypted, and their unencrypted messages are shown. Type /e2e auto to encrypt whenever their client can, or /e2e on to send only encrypted."
        ),
        Status::Unavailable => format!(
            "{PREFIX}Messages to {peer} are sent unencrypted: they do not have the add-on."
        ),
        Status::OtherClient => other_client_note(peer, None),
    }
}

// --- the contact's current client (owner's decision, CHECKLIST 10.6) ---------

/// The note when a message to `peer` went unencrypted because the client
/// `peer` is signed in with now does not announce the add-on. Once per
/// change of state per sign-on. `strict` is why the contact would otherwise
/// be held to encryption (`/e2e on`, verified), which makes it a warning.
pub fn other_client_note(peer: &str, strict: Option<&str>) -> String {
    match strict {
        None => format!(
            "{PREFIX}{peer} is signed in with a client without end-to-end encryption; this message went unencrypted, and so do the next ones while {peer} uses that client."
        ),
        Some(why) => format!(
            "{PREFIX}WARNING: {why}, but {peer} is now signed in with a client without end-to-end encryption; this message went unencrypted, and so do the next ones while {peer} uses that client. If {peer} did not switch clients, the server may be hiding their add-on to read the conversation: ask them another way, or type /e2e off only once you know."
        ),
    }
}

/// The note when something unencrypted from `peer` (`what`: "message",
/// "call", "file transfer", "tZer") was shown because the client `peer` is
/// signed in with now does not announce the add-on, though `peer` is
/// otherwise protected (`why`). `strong`: under `/e2e on` or verified.
pub fn arrived_unencrypted_note(peer: &str, what: &str, why: &str, strong: bool) -> String {
    let why = why.trim_end_matches('.');
    if strong {
        format!(
            "{PREFIX}WARNING: a {what} from {peer} arrived unencrypted and was shown: {why}, but {peer} is using a client without end-to-end encryption. If {peer} did not switch clients, the server may have written it in their name."
        )
    } else {
        format!(
            "{PREFIX}A {what} from {peer} arrived unencrypted: {peer} is using a client without end-to-end encryption ({why})."
        )
    }
}

/// The note for a publish that leaves encryption not working. `why` is the
/// publisher's own one-line reason.
pub fn publish_failed_note(why: &str) -> String {
    let why = why.trim_end_matches('.');
    format!("{PREFIX}Encryption is not working: this add-on's keys could not be put in the key directory ({why}). Until it works, messages go unencrypted, or are held for contacts that must not get them unencrypted.")
}

/// The note at every sign-on when the user turned TLS to the server off
/// (`tls=off` in `icq-e2e.ini`, STAGE-TLS 3.5).
pub fn tls_off_note(server: &str) -> String {
    format!("{PREFIX}The connection to the server ({server}) is not encrypted (tls=off in icq-e2e.ini): the contact list, presence and sign-in travel in clear. Messages to contacts with the add-on are still end-to-end encrypted.")
}

/// The same with `e2e=off` as well, where nothing at all is encrypted.
pub fn tls_off_plain_note(server: &str) -> String {
    format!("{PREFIX}The connection to the server ({server}) is not encrypted (tls=off in icq-e2e.ini), and end-to-end encryption is off on this install (e2e=off): nothing this client sends is encrypted.")
}

/// The answer to a `/e2e` command on an install with `e2e=off`. The command
/// itself never leaves.
pub fn e2e_off_note(peer: &str) -> String {
    format!("{PREFIX}End-to-end encryption is off on this install (e2e=off in icq-e2e.ini), so /e2e commands do nothing. This command was not sent to {peer}.")
}

/// The note once encryption works after a failure.
pub fn ready_note() -> String {
    format!("{PREFIX}Encryption is ready: this add-on's keys are in the key directory.")
}

/// The note when an incoming encrypted message switched encryption on.
pub fn switched_on_note(peer: &str) -> String {
    format!("{PREFIX}Encryption switched on in this chat: {peer} sent an encrypted message, so your replies are encrypted too.")
}

/// The hint when a contact encrypts and the user switched encryption off.
pub fn encrypts_while_off_note(peer: &str) -> String {
    format!(
        "{PREFIX}{peer} sends encrypted messages, but encryption is off in this chat (switched off by you), so your replies go unencrypted. Type /e2e on to answer encrypted."
    )
}

/// Why a message was held rather than sent in clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// Switched on by hand, and the contact has no keys (10.8).
    OnByHand,
    /// Seen encrypting before, and the server now shows no keys (10.7).
    Downgrade,
    /// The key directory could not be reached for a contact that must not get
    /// clear text.
    Unreachable(String),
    /// Our own keys are not in the directory yet.
    NotPublished,
    /// Switched on by hand, and the contact is signed in with a client that
    /// does not announce the add-on, so it could not read an encrypted
    /// message (10.6, the owner's decision: `/e2e on` stays strict).
    OtherClient,
    /// The contact was verified and their safety number has changed since:
    /// nothing goes to the new key until the user says so (CHECKLIST 10.10).
    SafetyChanged,
    /// The directory gives the contact an account key that is not theirs in
    /// the key log (docs/e2e/KEY-TRANSPARENCY.md).
    NotInLog(String),
    /// The contact's keys are new to this add-on, and the key log cannot
    /// vouch for them right now: it cannot be read, no auditor has vouched
    /// for it lately, or its auditors have not reached them yet (second
    /// audit of 2026-10, findings 2 and 3). Not an attack in itself; the
    /// message waits for the log.
    NotYet(String),
}

/// What a held message's note ends with in a chat under `/e2e on`: only
/// the user's own switch lets messages go unencrypted (`/e2e plain` does
/// not, 10.8).
fn on_hold_way_out(peer: &str) -> String {
    format!("Encryption is on in this chat (/e2e on), so messages to {peer} only ever go encrypted and are held otherwise: type /e2e auto to send unencrypted whenever {peer} cannot receive encrypted messages, or /e2e off to switch encryption off in this chat.")
}

/// The note for a message that was held. `on`: the chat is under `/e2e on`,
/// where `/e2e plain` does nothing and the way out is `/e2e auto` or
/// `/e2e off`.
pub fn held_note(peer: &str, why: &Held, on: bool) -> String {
    match why {
        Held::OnByHand => format!(
            "{PREFIX}The message to {peer} was NOT sent: {peer} has no encryption keys in the key directory. {}",
            on_hold_way_out(peer)
        ),
        Held::OtherClient => format!(
            "{PREFIX}The message to {peer} was NOT sent: {peer} is signed in with a client without end-to-end encryption, which could not read it. {} If {peer} did not switch clients, the server may be hiding their add-on.",
            on_hold_way_out(peer)
        ),
        Held::Unreachable(e) if on => format!(
            "{PREFIX}The message to {peer} was NOT sent: the key directory could not be reached ({e}). Send it again later. {}",
            on_hold_way_out(peer)
        ),
        Held::NotPublished if on => format!(
            "{PREFIX}The message to {peer} was NOT sent: this add-on's keys are not in the key directory yet. Send it again in a moment. {}",
            on_hold_way_out(peer)
        ),
        Held::Downgrade => format!(
            "{PREFIX}The message to {peer} was NOT sent: {peer} used encryption before, but the server now shows no encryption keys for them. This can be a server or network attack, or {peer} removed the add-on - ask them another way. Type /e2e plain to send the next message unencrypted once, or /e2e off to switch encryption off."
        ),
        Held::Unreachable(e) => format!(
            "{PREFIX}The message to {peer} was NOT sent: the key directory could not be reached ({e}), and messages to {peer} must not go unencrypted. Send it again later, or type /e2e plain to send the next message unencrypted once."
        ),
        Held::NotPublished => format!(
            "{PREFIX}The message to {peer} was NOT sent: this add-on's keys are not in the key directory yet, and messages to {peer} must not go unencrypted. Send it again in a moment."
        ),
        Held::SafetyChanged => format!(
            "{PREFIX}The message to {peer} was NOT sent: your safety number with {peer} has changed, and {peer} was verified (or, after keys replaced by the server's operator, is under /e2e on), so nothing goes to the new key until you check it. Type /e2e safety and compare the new number with {peer} in person or by phone - not through this chat - then /e2e verify, and send the message again. To send without verifying, type /e2e accept."
        ),
        Held::NotYet(why) => format!(
            "{PREFIX}The message to {peer} was NOT sent: {why}. Nothing goes to keys the key log has not vouched for; send it again in a minute or two."
        ),
        Held::NotInLog(why) => format!(
            "{PREFIX}The message to {peer} was NOT sent: {why}. The key directory is handing out a key that the server's public key log does not show, which is what an attack on the server looks like. Ask {peer} another way whether they reset their keys. Type /e2e plain to send the next message unencrypted once."
        ),
    }
}

// --- the key log (docs/e2e/KEY-TRANSPARENCY.md) -------------------------------

/// The note when the key log cannot be trusted any more: rewritten, gone, or
/// signed by another key. Once per sign-on.
pub fn log_broken_note(why: &str) -> String {
    format!("{PREFIX}WARNING: {why}. The key log lets this add-on check that everyone gets the same keys; a log that changes its past is what an attack on the server looks like. Until it is sorted out, only contacts and devices checked before it broke are used; nothing new is taken. If the server's operator says the log was restored from a backup or started afresh, type /e2e resetlog.")
}

/// The note when the key log's auditor has not vouched for it lately, once
/// per sign-on.
pub fn audit_stale_note(why: &str) -> String {
    format!("{PREFIX}Warning: {why}. The auditor is the independent party that checks the server shows everyone the same key log; without its recent word, a server showing you a log of its own would not be noticed. Messages to contacts and devices already in use are still encrypted; new contacts, new devices and changed keys are held until an auditor vouches for the log again.")
}

/// The note when the key log shows our account with an account key that is
/// not ours.
pub fn log_own_key_note() -> String {
    format!("{PREFIX}WARNING: the server's key log shows your account with an account key that is not this add-on's. If you did not reset your keys on another computer, someone may be posing as you to your contacts: change your password and tell the server's operator.")
}

/// The note when the key log shows a device of our account that we have not
/// been told about.
pub fn log_own_device_note(device_id: u32) -> String {
    format!("{PREFIX}A device was added to your account in the key directory (device {device_id}). If you linked another computer, nothing needs doing. If not, someone can read the messages sent to you on it: change your password and tell the server's operator.")
}

/// The note when one of a contact's devices is in the directory but not in
/// the key log, so nothing is encrypted for it.
pub fn log_device_left_out_note(peer: &str, device_id: u32) -> String {
    format!("{PREFIX}One of {peer}'s devices (device {device_id}) is in the key directory but not in the server's key log, so messages are not encrypted for it. That device may not be theirs.")
}

/// The note when one of a contact's devices is in the key log but newer than
/// what its auditors have vouched for, so nothing is encrypted for it yet.
pub fn log_device_unvouched_note(peer: &str, device_id: u32) -> String {
    format!("{PREFIX}One of {peer}'s devices (device {device_id}) is new and not yet vouched for by the key log's auditor (or the log cannot be checked right now), so messages are not encrypted for it until it is.")
}

/// The note when a contact's account key was replaced without the
/// contact's own key: the operator revoked or deleted it (a recovery), or it
/// was reset (second audit of 2026-10, finding 1). Said every time it
/// happens. `held`: the contact is verified or under `/e2e on`, so messages
/// wait for `/e2e verify` or `/e2e accept`.
pub fn recovery_key_note(peer: &str, why: &str, held: bool, was_verified: bool) -> String {
    let mut base = format!(
        "{PREFIX}WARNING: the server replaced {peer}'s keys without {peer}'s key (operator recovery: {why}). Your safety number with {peer} has changed. Treat this as a new contact: it may be {peer} after losing their keys, or someone else."
    );
    if was_verified {
        base.push_str(&format!(
            " You had verified {peer}, so that verification is cleared."
        ));
    }
    if held {
        format!("{base} Messages to {peer} are held until you type /e2e safety, compare the number with {peer} in person or by phone and type /e2e verify (or /e2e accept to send without verifying).")
    } else {
        format!("{base} Messages are still encrypted, to the new key. Type /e2e safety to compare the number with {peer}.")
    }
}

/// The note when a contact's safety number changed (CHECKLIST 10.10), once
/// per change. Nothing is said the first time a contact is seen: like Signal,
/// the first key is trusted on first use.
pub fn safety_changed_note(peer: &str, was_verified: bool) -> String {
    let base = format!(
        "{PREFIX}Your safety number with {peer} has changed. This can mean that {peer} reinstalled the add-on or reset its keys, or that someone is trying to intercept the conversation."
    );
    if was_verified {
        format!("{base} You had verified {peer}, so that verification is cleared, and messages to {peer} are held until you type /e2e safety, compare the new number with them and type /e2e verify (or /e2e accept to send without verifying).")
    } else {
        format!("{base} Messages are still encrypted, to the new key. Type /e2e safety to compare the new number with {peer}.")
    }
}

/// The answer to `/e2e safety`: the 60 digits as Signal groups them, whether
/// the contact is verified, and how to compare.
pub fn safety_note(peer: &str, grouped: &str, verified: bool) -> String {
    let state = if verified {
        format!("{peer} is verified (with this number).")
    } else {
        format!("{peer} is not verified.")
    };
    format!("{PREFIX}Your safety number with {peer}:
{grouped}
{state} Compare it with the number {peer} sees in their chat with you (/e2e safety there), in person or by phone - not through this chat, which the server carries. If it matches, type /e2e verify; /e2e unverify takes it back.")
}

/// The note for a voice or video call whose media both add-ons encrypt
/// (`calls_encrypt=on`, docs/e2e/CALLS-RESEARCH.md stage C3).
pub fn call_encrypted_note(peer: &str, verified: bool) -> String {
    let trust = if verified {
        format!("{peer} is verified.")
    } else {
        "Type /e2e safety to compare the safety number.".to_string()
    };
    format!("{PREFIX}This call with {peer} is end-to-end encrypted: the voice and video are encrypted with keys agreed through your encrypted chat. {trust}")
}

/// The note for a call that goes unencrypted, with the reason. A call is
/// never blocked (the owner's rule: calls must work as they always did with a
/// contact without the add-on); for a contact under `/e2e on` or verified the
/// note says so in stronger words.
pub fn call_plain_note(peer: &str, why: &str, strict: bool) -> String {
    let why = why.trim_end_matches('.');
    let mut s = format!("{PREFIX}This call with {peer} is not end-to-end encrypted: {why}.");
    if strict {
        s.push_str(&format!(" Encryption is on for {peer} in this chat, but calls are never blocked: the server and the network can listen to this one. Hang up if it must stay private."));
    }
    s
}

/// The note for a file transfer whose data connection both add-ons encrypt
/// (`files_encrypt=on`, docs/e2e/FILES-RESEARCH.md stage F4).
pub fn file_encrypted_note(peer: &str, verified: bool) -> String {
    let trust = if verified {
        format!("{peer} is verified.")
    } else {
        "Type /e2e safety to compare the safety number.".to_string()
    };
    format!("{PREFIX}This file transfer with {peer} is end-to-end encrypted: the files and their names travel encrypted with keys agreed through your encrypted chat. {trust}")
}

/// The note for a file transfer that goes unencrypted, with the reason: a
/// contact that is not strict (neither under `/e2e on` nor verified, and no
/// `files_encrypt = required`), whose transfer goes as it always did.
pub fn file_plain_note(peer: &str, why: &str) -> String {
    let why = why.trim_end_matches('.');
    format!("{PREFIX}This file transfer with {peer} is not end-to-end encrypted: {why}.")
}

/// The note for a file transfer that is not let through because it is not
/// end-to-end encrypted: `required` says the ini lets no unencrypted
/// transfer through; otherwise encryption is on for the contact (`/e2e on`,
/// or verified), for file transfers as for messages and calls (second audit
/// of 2026-10, finding 4).
pub fn file_blocked_note(peer: &str, why: &str, required: bool, verified: bool) -> String {
    let why = why.trim_end_matches('.');
    let rule = if required {
        "files_encrypt = required in icq-e2e.ini lets no other file transfer through".to_string()
    } else if verified {
        format!("{peer} is verified, so a file transfer with them is encrypted or not sent, as messages are")
    } else {
        format!("encryption is on for {peer} in this chat (/e2e on), for file transfers as for messages")
    };
    format!("{PREFIX}This file transfer with {peer} was not sent: it is not end-to-end encrypted ({why}), and {rule}. Nothing of it went over the network unencrypted; cancel it.")
}

/// The note for an encrypted file transfer whose connection was closed
/// because something on it did not check out (fail closed).
pub fn file_failed_note(peer: &str, why: &str) -> String {
    let why = why.trim_end_matches('.');
    format!("{PREFIX}The encrypted file transfer with {peer} was stopped: {why}. Nothing of it was passed on unencrypted; send the file again.")
}

/// Whether `/e2e plain` may open a message held for this reason. A contact
/// switched on by hand never gets clear text (10.8).
pub fn plain_allowed(setting: Setting) -> bool {
    setting != Setting::On
}

// --- unencrypted messages in a contact's name (fifth audit of 2026-10) --------

/// Why a contact's unencrypted message is not shown, or `None` when it may
/// be: the second half of the central invariant - if a contact is
/// protected, the client never shows a message in their name that did not
/// pass end-to-end authentication (finding 1).
///
/// - switched off by hand (`/e2e off`): shown;
/// - automatic, never seen encrypting and not verified: shown (a contact
///   without the add-on);
/// - switched on by hand, seen encrypting, or verified: not shown.
///
/// `rem` is `None` when the contact's settings cannot be read (no state, a
/// locked-out or stand-in engine): not shown, as the gate does with a call
/// or a file it cannot decide. `/e2e plain` is about sending and does not
/// apply here.
pub fn plain_inbound_refusal(
    peer: &str,
    rem: Option<Remembered>,
    verified: bool,
) -> Option<String> {
    let Some(rem) = rem else {
        return Some(format!(
            "the add-on cannot read its settings for {peer} in this ICQ"
        ));
    };
    if rem.setting == Setting::Off {
        return None;
    }
    if verified {
        Some(format!("{peer} is verified"))
    } else if rem.setting == Setting::On {
        Some(format!(
            "encryption is on for {peer} in this chat (/e2e on)"
        ))
    } else if rem.seen_encrypting {
        Some(format!("{peer} has used encryption before"))
    } else {
        None
    }
}

/// The note for an unencrypted message in `peer`'s name that was not shown.
pub fn plain_dropped_note(peer: &str, why: &str) -> String {
    let why = why.trim_end_matches('.');
    format!(
        "{PREFIX}WARNING: a message that was not end-to-end encrypted arrived in {peer}'s name and was not shown ({why}). The server or the network can write such a message; {peer}'s own add-on encrypts what it sends. If {peer} really wrote without encryption (another client, or encryption off on their side), ask them to switch it on. Typing /e2e off here shows their unencrypted messages again, and sends yours unencrypted too."
    )
}

/// The text an authorization event in a protected contact's name carries in
/// place of the contact's (sixth audit of 2026-10, finding 2): the event
/// itself stays, so the client's request or reply flow still works, but
/// nothing in it is shown as the contact's words. ASCII, so it reads the
/// same in every charset; one sentence, since ICQ 5 drops a request with
/// more than one period in its text.
pub fn auth_local_text(peer: &str, request: bool) -> String {
    let peer: String = peer.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    format!(
        "{PREFIX}Authorization {} attributed to {peer} was not end-to-end authenticated, its text is not shown.",
        if request { "request" } else { "reply" }
    )
}

/// The warning for a call, a file proposal or a tZer in `peer`'s name that
/// came without the announcement `peer`'s add-on sends before it, and was
/// not let through (sixth audit of 2026-10, findings 3 and 4).
pub fn unauthenticated_action_note(peer: &str, what: &str, why: &str) -> String {
    let why = why.trim_end_matches('.');
    let (a, done) = match what {
        "call" => ("A call", "was not put through"),
        "call answer" => ("An answer to your call", "was not put through"),
        "file transfer" => ("A file transfer", "was not shown"),
        _ => ("A tZer", "was not shown"),
    };
    format!(
        "{PREFIX}WARNING: {a} in {peer}'s name {done}: it came without the announcement {peer}'s add-on sends over the encrypted session first, or not as announced, or too late, so it is not end-to-end authenticated ({why}). The server or the network can make such a {what}. If {peer} really sent it, their add-on is missing, older, or has this switched off; typing /e2e off here lets such things through again."
    )
}

/// What a message from the network that starts like a note gets in front of
/// it, so that only the add-on can put a real-looking note in the chat
/// (finding 2).
pub fn from_peer_prefix(peer: &str) -> String {
    let peer: String = peer
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | '&' | '"'))
        .collect();
    format!("(from {peer}) ")
}

/// The marker, folded the way [`looks_like_note`] folds text.
const MARKER_FOLDED: &str = "[icqe2e]";

/// A character as [`looks_like_note`] compares it: case folded, full-width
/// forms and the Cyrillic and Greek look-alikes of the marker's letters
/// taken as the Latin ones (also as Latin-1 shows the CP1251 bytes of the
/// Cyrillic ones, since 8-bit text is decoded as Latin-1 here). `None` for a
/// character that does not show: whitespace, zero-width and format
/// characters.
fn fold(c: char) -> Option<char> {
    if c.is_whitespace()
        || matches!(
            c,
            '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}'
        )
    {
        return None;
    }
    let c = match c as u32 {
        // Full-width ASCII.
        0xFF01..=0xFF5E => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
        _ => c,
    };
    Some(match c {
        'І' | 'і' | 'Ι' | 'ι' | 'Ӏ' | '²' | '³' | 'ı' | 'l' | '|' | '1' => 'i',
        'С' | 'с' | 'Ϲ' | 'ϲ' | 'Ñ' | 'ñ' => 'c',
        'Е' | 'е' | 'Ε' | 'ε' | 'Å' | 'å' => 'e',
        '［' => '[',
        '］' => ']',
        c => c.to_ascii_lowercase(),
    })
}

/// `&#NN;` and `&#xNN;` turned into their characters.
fn numeric_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("&#") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let (hex, digits) = match after.strip_prefix(['x', 'X']) {
            Some(h) => (true, h),
            None => (false, after),
        };
        let end = digits.find(';');
        let parsed = end.and_then(|e| {
            let n = &digits[..e];
            (!n.is_empty() && n.len() <= 8)
                .then(|| u32::from_str_radix(n, if hex { 16 } else { 10 }).ok())
                .flatten()
                .and_then(char::from_u32)
                .map(|c| (c, e))
        });
        match parsed {
            Some((c, e)) => {
                out.push(c);
                rest = &digits[e + 1..];
            }
            None => {
                out.push_str("&#");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether `text`, as a client shows it, starts with something that reads
/// as the note marker `[ICQ E2E]`: in any case, with any whitespace or
/// invisible characters in it, wrapped in HTML, written with entities, or
/// with look-alike letters.
pub fn looks_like_note(text: &str) -> bool {
    let shown = numeric_entities(&plain_text(&numeric_entities(text)));
    let folded: String = shown
        .chars()
        .filter_map(fold)
        .take(MARKER_FOLDED.chars().count())
        .collect();
    folded == MARKER_FOLDED
}

/// Where the text a client shows first starts in `units` (bytes of an 8-bit
/// charset, or UCS-2 code units): after the leading whitespace, tags and
/// `&nbsp;`.
fn shown_start(units: &[u16]) -> usize {
    let is = |i: usize, c: char| units.get(i) == Some(&(c as u16));
    let mut i = 0;
    loop {
        while units
            .get(i)
            .is_some_and(|&u| matches!(u, 0x20 | 0x09 | 0x0A | 0x0D | 0xA0))
        {
            i += 1;
        }
        if is(i, '<') {
            match units[i..].iter().position(|&u| u == '>' as u16) {
                Some(p) => i += p + 1,
                None => return i,
            }
            continue;
        }
        let nbsp: Vec<u16> = "&nbsp;".encode_utf16().collect();
        if units[i..].len() >= nbsp.len()
            && units[i..i + nbsp.len()]
                .iter()
                .zip(&nbsp)
                .all(|(a, b)| (*a as u8 as char).to_ascii_lowercase() as u16 == *b && *a < 0x80)
        {
            i += nbsp.len();
            continue;
        }
        return i;
    }
}

/// A message text from the network (unencrypted, or as decrypted) in
/// `charset`, made unable to pass for a note of the add-on's (finding 2):
/// when it starts like one ([`looks_like_note`]), "(from <peer>) " is put in
/// front of what shows first, in the same charset. `None` when it does not
/// start like a note, and is left as it is.
pub fn unmark(peer: &str, charset: u16, raw: &[u8]) -> Option<Vec<u8>> {
    if !looks_like_note(&crate::text::decode(charset, raw)) {
        return None;
    }
    let prefix = from_peer_prefix(peer);
    let out = if charset == crate::text::CHARSET_UNICODE {
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let at = shown_start(&units);
        let mut v: Vec<u16> = units[..at].to_vec();
        v.extend(prefix.encode_utf16());
        v.extend_from_slice(&units[at..]);
        let mut b: Vec<u8> = v.iter().flat_map(|u| u.to_be_bytes()).collect();
        // An odd trailing byte stays where it was.
        if raw.len() % 2 == 1 {
            b.push(raw[raw.len() - 1]);
        }
        b
    } else {
        let units: Vec<u16> = raw.iter().map(|&b| b as u16).collect();
        let at = shown_start(&units);
        [&raw[..at], prefix.as_bytes(), &raw[at..]].concat()
    };
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_read_through_the_clients_markup() {
        assert_eq!(parse_command("/e2e on"), Some(Command::On));
        assert_eq!(parse_command("/E2E OFF"), Some(Command::Off));
        assert_eq!(parse_command("  /e2e   status "), Some(Command::Status));
        assert_eq!(parse_command("/e2e"), Some(Command::Status));
        assert_eq!(parse_command("/e2e plain"), Some(Command::Plain));
        assert_eq!(parse_command("/e2e AUTO"), Some(Command::Auto));
        assert_eq!(parse_command("/e2e safety"), Some(Command::Safety));
        assert_eq!(parse_command("/e2e verify"), Some(Command::Verify));
        assert_eq!(parse_command("/e2e unverify"), Some(Command::Unverify));
        assert_eq!(parse_command("/e2e accept"), Some(Command::Accept));
        assert_eq!(parse_command("/e2e what"), Some(Command::Help));
        assert_eq!(parse_command("/e2e on now"), Some(Command::Help));
        // ICQ 7.2 and 6.5 send HTML.
        assert_eq!(
            parse_command("<HTML><BODY dir=\"ltr\"><FONT face=\"Arial\" color=\"#000000\" size=\"2\">/e2e&nbsp;on</FONT></BODY></HTML>"),
            Some(Command::On)
        );
        assert_eq!(parse_command("/e2e\u{a0}off"), Some(Command::Off));
    }

    #[test]
    fn ordinary_messages_are_not_commands() {
        assert_eq!(parse_command("hello"), None);
        assert_eq!(parse_command("see /e2e on"), None);
        assert_eq!(parse_command("/e2eon"), None);
        assert_eq!(parse_command(""), None);
        assert_eq!(parse_command("<HTML><BODY></BODY></HTML>"), None);
    }

    #[test]
    fn strict_means_on_by_hand_or_seen_encrypting() {
        let mut r = Remembered::default();
        assert!(!r.strict(), "a new contact is trust on first use");
        r.seen_encrypting = true;
        assert!(r.strict());
        r = Remembered {
            setting: Setting::On,
            seen_encrypting: false,
        };
        assert!(r.strict());
        r.setting = Setting::Off;
        assert!(!r.strict());
    }

    #[test]
    fn plain_is_refused_only_when_switched_on_by_hand() {
        assert!(plain_allowed(Setting::Auto));
        assert!(plain_allowed(Setting::Off));
        assert!(!plain_allowed(Setting::On));
    }

    #[test]
    fn the_state_reads_back_from_json_and_from_nothing() {
        let r = Remembered {
            setting: Setting::Off,
            seen_encrypting: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#"{"setting":"off","seen_encrypting":true}"#);
        assert_eq!(serde_json::from_str::<Remembered>(&json).unwrap(), r);
        assert_eq!(
            serde_json::from_str::<Remembered>("{}").unwrap(),
            Remembered::default()
        );
    }

    #[test]
    fn notes_are_plain_ascii() {
        // A note is put into the chat as an ASCII message.
        for n in [
            status_note("100002", Status::On),
            status_note("100002", Status::Off),
            status_note("100002", Status::Unavailable),
            switched_on_note("100002"),
            encrypts_while_off_note("100002"),
            held_note("100002", &Held::OnByHand, true),
            held_note("100002", &Held::OtherClient, true),
            held_note("100002", &Held::Downgrade, false),
            held_note("100002", &Held::Unreachable("x".into()), false),
            held_note("100002", &Held::Unreachable("x".into()), true),
            held_note("100002", &Held::NotPublished, false),
            held_note("100002", &Held::NotPublished, true),
            held_note("100002", &Held::SafetyChanged, false),
            safety_changed_note("100002", true),
            safety_changed_note("100002", false),
            safety_note("100002", "12345 12345", true),
            safety_note("100002", "12345 12345", false),
            publish_failed_note("the key directory could not be reached: timeout."),
            ready_note(),
            plain_dropped_note("100002", "100002 is verified"),
        ] {
            assert!(n.is_ascii(), "{n}");
            assert!(n.starts_with(PREFIX), "{n}");
        }
    }

    /// Fifth audit of 2026-10, finding 1: the rule, as a table.
    #[test]
    fn an_unencrypted_message_is_refused_exactly_for_a_protected_contact() {
        let r = |setting, seen| Remembered {
            setting,
            seen_encrypting: seen,
        };
        let cases = [
            (Some(r(Setting::Auto, false)), false, false),
            (Some(r(Setting::Auto, true)), false, true),
            (Some(r(Setting::Auto, false)), true, true),
            (Some(r(Setting::On, false)), false, true),
            (Some(r(Setting::On, true)), true, true),
            (Some(r(Setting::Off, true)), false, false),
            (Some(r(Setting::Off, true)), true, false),
            (None, false, true),
        ];
        for (rem, verified, refused) in cases {
            assert_eq!(
                plain_inbound_refusal("100002", rem, verified).is_some(),
                refused,
                "{rem:?} verified={verified}"
            );
        }
    }

    /// Finding 2: text from the network that starts like a note, in any of
    /// the ways a client would show the same thing.
    #[test]
    fn the_note_marker_is_recognised_in_every_disguise() {
        for t in [
            "[ICQ E2E] Encryption is on",
            "[icq e2e] x",
            "  [ I C Q   E 2 E ]x",
            "<HTML><BODY dir=\"ltr\"><FONT face=\"Arial\">[ICQ E2E] hi</FONT></BODY></HTML>",
            "&nbsp;[ICQ&nbsp;E2E]",
            "&#91;ICQ E2E&#93; spoofed",
            "&#x5B;ICQ E2E&#x5D;",
            "\u{200B}[ICQ\u{200D} E2E]",
            "\u{FF3B}ICQ E2E\u{FF3D}",
            "[\u{0406}\u{0421}Q \u{0415}2\u{0415}]",
            "[ICQ\u{a0}E2E]",
        ] {
            assert!(looks_like_note(t), "{t:?}");
        }
        for t in [
            "",
            "hello [ICQ E2E]",
            "(from 100002) [ICQ E2E] x",
            "[ICQ] E2E",
            "[ICQ E2",
            "<HTML><BODY>ICQ E2E</BODY></HTML>",
        ] {
            assert!(!looks_like_note(t), "{t:?}");
        }
    }

    #[test]
    fn a_marker_from_the_network_is_shown_as_the_contacts_in_every_charset() {
        let peer = "100002";
        // 8-bit, plain.
        let got = unmark(peer, crate::text::CHARSET_ASCII, b"[ICQ E2E] fake").unwrap();
        assert_eq!(got, b"(from 100002) [ICQ E2E] fake");
        // 8-bit, HTML: after the leading tags, so the client renders it.
        let html = b"<HTML><BODY><FONT size=2> [icq e2e] fake</FONT></BODY></HTML>";
        let got = unmark(peer, crate::text::CHARSET_LATIN1, html).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "<HTML><BODY><FONT size=2> (from 100002) [icq e2e] fake</FONT></BODY></HTML>"
        );
        // UCS-2.
        let ucs: Vec<u8> = "<HTML><BODY>&nbsp;[ICQ E2E] x</BODY></HTML>"
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        let got = unmark(peer, crate::text::CHARSET_UNICODE, &ucs).unwrap();
        let shown = crate::text::decode(crate::text::CHARSET_UNICODE, &got);
        assert_eq!(
            shown,
            "<HTML><BODY>&nbsp;(from 100002) [ICQ E2E] x</BODY></HTML>"
        );
        // Whatever the disguise, the result no longer reads as a note.
        for t in [
            "&#91;ICQ E2E&#93; x",
            "\u{200B}[ICQ E2E]",
            "<b></b>[ICQ E2E]",
        ] {
            let got = unmark(peer, crate::text::CHARSET_ASCII, t.as_bytes()).unwrap();
            let s = String::from_utf8(got).unwrap();
            assert!(!looks_like_note(&s), "{s:?}");
            assert!(plain_text(&s).contains("(from 100002)"), "{s:?}");
        }
        // Ordinary text is left alone.
        assert_eq!(
            unmark(peer, crate::text::CHARSET_ASCII, b"hi [ICQ E2E]"),
            None
        );
    }
}
