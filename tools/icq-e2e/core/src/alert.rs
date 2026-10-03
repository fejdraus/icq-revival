//! Security alerts shown outside the chat (fifth audit of 2026-10, finding 2).
//!
//! A note in the chat is an incoming message in the contact's name: the
//! server, or anyone who can make it relay a message, can write one that
//! looks the same. The events a user must be able to trust are therefore
//! also shown where the network cannot reach: a Windows message box of the
//! add-on's own. They are
//!
//! - the answers to `/e2e safety`, `/e2e verify`, `/e2e unverify` and
//!   `/e2e accept`;
//! - a verified contact's keys changing (messages to them are held);
//! - the key log breaking, or going without an auditor's word;
//! - a message that was not end-to-end encrypted arriving in a protected
//!   contact's name, and not being shown.
//!
//! Never blocking: each box comes from a thread of its own, never from a
//! hook or the client's UI thread. Rate-limited: one key is shown at most
//! once per [`WINDOW_SECS`], and at most [`MAX_OPEN`] boxes are open at a
//! time - a flood of forged messages cannot bury the screen in boxes. The
//! log always gets the line. Switched by `security_popups = on|off` in
//! `icq-e2e.ini` (on by default); off, only the chat note and the log
//! remain.
//!
//! Off until [`enable`] is called: only the add-on's bootstrap turns it on,
//! so a test or the test host never opens a box. The unit tests collect what
//! would have been shown instead ([`take_shown`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// One key is shown at most once in this many seconds.
pub const WINDOW_SECS: u64 = 60;
/// At most this many boxes are open at once.
pub const MAX_OPEN: usize = 3;

static ENABLED: AtomicBool = AtomicBool::new(false);
#[cfg_attr(test, allow(dead_code))]
static OPEN: AtomicUsize = AtomicUsize::new(0);

#[cfg_attr(test, allow(dead_code))]
fn shown_at() -> &'static Mutex<HashMap<String, u64>> {
    static S: std::sync::LazyLock<Mutex<HashMap<String, u64>>> =
        std::sync::LazyLock::new(Default::default);
    &S
}

#[cfg(test)]
thread_local! {
    /// What this test thread would have shown.
    static SHOWN: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    /// Whether this test thread has alerts on (they are by default here, so
    /// the engine's tests see them; a test turns them off to check the
    /// switch).
    static TEST_ON: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
    /// The rate limit, per test thread.
    static TEST_AT: std::cell::RefCell<HashMap<String, u64>> = std::cell::RefCell::new(HashMap::new());
}

/// Turns the boxes on or off for the process (`security_popups`).
pub fn enable(on: bool) {
    ENABLED.store(on, Ordering::Release);
}

/// Turns alerts on or off for this test thread.
#[cfg(test)]
pub fn enable_for_this_thread(on: bool) {
    TEST_ON.with(|t| t.set(on));
}

/// What this test thread would have shown since the last call.
#[cfg(test)]
pub fn take_shown() -> Vec<String> {
    SHOWN.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// Whether `key` may be shown at `now`: not within [`WINDOW_SECS`] of its
/// last showing. Remembers it as shown now.
fn due(at: &mut HashMap<String, u64>, key: &str, now: u64) -> bool {
    at.retain(|_, t| now.saturating_sub(*t) < WINDOW_SECS);
    if at.contains_key(key) {
        return false;
    }
    at.insert(key.to_string(), now);
    true
}

/// Shows `text` in a box of the add-on's own, unless `key` was shown within
/// the last [`WINDOW_SECS`], too many boxes are open, or the boxes are off.
/// Returns whether it was shown (or, under test, collected).
pub fn raise(key: &str, text: &str, now: u64) -> bool {
    #[cfg(test)]
    {
        if !TEST_ON.with(|t| t.get()) {
            return false;
        }
        if !TEST_AT.with(|a| due(&mut a.borrow_mut(), key, now)) {
            return false;
        }
        SHOWN.with(|s| s.borrow_mut().push(text.to_string()));
        true
    }
    #[cfg(not(test))]
    {
        if !ENABLED.load(Ordering::Acquire) {
            return false;
        }
        let ok = match shown_at().lock() {
            Ok(mut at) => due(&mut at, key, now),
            Err(e) => due(&mut e.into_inner(), key, now),
        };
        if !ok {
            return false;
        }
        show(text.to_string())
    }
}

/// Opens the box from a thread of its own.
#[cfg(all(windows, not(test)))]
fn show(text: String) -> bool {
    if OPEN.fetch_add(1, Ordering::AcqRel) >= MAX_OPEN {
        OPEN.fetch_sub(1, Ordering::AcqRel);
        crate::log::line(&format!(
            "security alert not shown ({MAX_OPEN} already open): {text}"
        ));
        return false;
    }
    crate::log::line(&format!("security alert shown: {text}"));
    let spawned = std::thread::Builder::new()
        .name("icq-e2e alert".into())
        .spawn(move || {
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                MessageBoxW, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MB_TOPMOST,
            };
            let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
            let body = wide(&text);
            let title = wide("ICQ E2E - security");
            // SAFETY: NUL-terminated strings that outlive the call; no owner.
            unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    body.as_ptr(),
                    title.as_ptr(),
                    MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
                );
            }
            OPEN.fetch_sub(1, Ordering::AcqRel);
        });
    if spawned.is_err() {
        OPEN.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    true
}

#[cfg(all(not(windows), not(test)))]
fn show(_text: String) -> bool {
    let _ = &OPEN;
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_key_is_shown_once_a_minute_and_the_switch_holds_all() {
        enable_for_this_thread(true);
        let _ = take_shown();
        assert!(raise("k", "first", 100));
        assert!(!raise("k", "again", 130), "within the minute");
        assert!(raise("other", "another key", 130));
        assert!(raise("k", "a minute on", 160));
        assert_eq!(take_shown(), ["first", "another key", "a minute on"]);
        enable_for_this_thread(false);
        assert!(!raise("off", "nothing", 500));
        assert!(take_shown().is_empty());
        enable_for_this_thread(true);
    }
}
