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
    /// Switched on by hand: nothing ever goes to this contact in clear (10.8).
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
pub const COMMANDS: &str = "/e2e on, /e2e off, /e2e auto, /e2e status, /e2e plain, /e2e safety, /e2e verify, /e2e unverify, /e2e accept";

/// The note for a status the chat is now in.
pub fn status_note(peer: &str, status: Status) -> String {
    match status {
        Status::On => format!("{PREFIX}Encryption is on in this chat: messages to {peer} are end-to-end encrypted."),
        Status::Off => format!(
            "{PREFIX}Encryption is off in this chat (switched off by you): messages to {peer} are sent unencrypted. Type /e2e on to switch it on."
        ),
        Status::Unavailable => format!(
            "{PREFIX}Messages to {peer} are sent unencrypted: they do not have the add-on."
        ),
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
    /// The contact was verified and their safety number has changed since:
    /// nothing goes to the new key until the user says so (CHECKLIST 10.10).
    SafetyChanged,
}

/// The note for a message that was held.
pub fn held_note(peer: &str, why: &Held) -> String {
    match why {
        Held::OnByHand => format!(
            "{PREFIX}The message to {peer} was NOT sent: encryption is on in this chat (switched on by you) and {peer} has no encryption keys in the key directory. Type /e2e off to send unencrypted."
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
            "{PREFIX}The message to {peer} was NOT sent: you had verified {peer}, and your safety number with them has changed. Type /e2e safety and compare the new number with {peer} in person or by phone - not through this chat - then /e2e verify, and send the message again. To send without verifying, type /e2e accept."
        ),
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

/// Whether `/e2e plain` may open a message held for this reason. A contact
/// switched on by hand never gets clear text (10.8).
pub fn plain_allowed(setting: Setting) -> bool {
    setting != Setting::On
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
            held_note("100002", &Held::OnByHand),
            held_note("100002", &Held::Downgrade),
            held_note("100002", &Held::Unreachable("x".into())),
            held_note("100002", &Held::NotPublished),
            held_note("100002", &Held::SafetyChanged),
            safety_changed_note("100002", true),
            safety_changed_note("100002", false),
            safety_note("100002", "12345 12345", true),
            safety_note("100002", "12345 12345", false),
            publish_failed_note("the key directory could not be reached: timeout."),
            ready_note(),
        ] {
            assert!(n.is_ascii(), "{n}");
            assert!(n.starts_with(PREFIX), "{n}");
        }
    }
}
