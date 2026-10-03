//! Logging for the add-on.
//!
//! A line always goes to `OutputDebugStringA` (visible in DebugView). The file
//! it is also appended to is, in order: whatever `ICQE2E_LOG` names, else
//! `icqe2e.log` in a per-user folder under the local application data. There is
//! no case where the add-on runs and leaves nothing behind - a silent add-on
//! and one that is not loaded at all look exactly the same from the outside,
//! which is what made an ICQ 6.5 client that never reached the directory
//! impossible to tell apart from one that had nothing to report.
//! Every entry point that writes is guarded so a logging failure can never take
//! the host down.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringA;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

struct Logger {
    file: Option<File>,
}

/// The one file the log goes to, opened the first time a line is written.
///
/// Under test it is always a file of its own in the temp folder, never the one
/// `ICQE2E_LOG` names: that variable is set for the whole user, and a test run
/// appending to the owner's real log would bury the real client's entries
/// under a library's test output.
static LOGGER: std::sync::LazyLock<Mutex<Logger>> =
    std::sync::LazyLock::new(|| Mutex::new(Logger { file: open_log() }));

fn logger() -> &'static Mutex<Logger> {
    &LOGGER
}

fn open_log() -> Option<File> {
    let path = log_path(
        &std::env::var("ICQE2E_LOG")
            .ok()
            .map(std::path::PathBuf::from),
        cfg!(test) || use_temp_file(),
    );
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    OpenOptions::new().create(true).append(true).open(path).ok()
}

/// The file this run appends to.
///
/// A test - the library's own unit tests, or an integration test that called
/// `own_file` - never reaches the owner's, because `ICQE2E_LOG` is set for the
/// whole user and the real client is writing to it while the tests run.
fn log_path(configured: &Option<std::path::PathBuf>, own: bool) -> std::path::PathBuf {
    if own {
        return temp_log_path();
    }
    configured.clone().unwrap_or_else(default_log_path)
}

/// Where the log goes when `ICQE2E_LOG` is not set: a folder of the user's own,
/// so two clients on one machine do not append to each other's file.
fn default_log_path() -> std::path::PathBuf {
    ["LOCALAPPDATA", "APPDATA"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok())
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from)
        .join("icqe2e")
        .join("icqe2e.log")
}

fn use_temp_file() -> bool {
    OWN_LOG.load(Ordering::Relaxed)
}

/// Points this run's log at a file of its own instead of the one `ICQE2E_LOG`
/// names.
///
/// `cfg!(test)` only covers a library's own unit tests: the integration tests
/// in `tests/` link the library as an ordinary dependency, where it is false.
/// Those tests inherit `ICQE2E_LOG` from the environment, which the owner has
/// set for the whole machine, so without this a `cargo test` run appends its
/// output to the live client's log. Must be called before the first line is
/// written.
pub fn own_file() {
    OWN_LOG.store(true, Ordering::Relaxed);
}

static OWN_LOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A file of this test run's own, so two runs do not append to each other and
/// neither writes to the owner's log.
fn temp_log_path() -> std::path::PathBuf {
    static DIR: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
        let dir = std::env::temp_dir().join("icqe2e-tests");
        let _ = std::fs::create_dir_all(&dir);
        dir
    });
    DIR.join("icqe2e.log")
}

fn local_stamp() -> String {
    // SAFETY: GetLocalTime fills a caller-owned struct; no invariants to hold.
    let mut st = unsafe { std::mem::zeroed::<windows_sys::Win32::Foundation::SYSTEMTIME>() };
    unsafe { GetLocalTime(&mut st) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
    )
}

/// Lines said under the loader lock, waiting for a thread that may open the
/// log file (fourth review, finding H).
static DEFERRED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Keeps a line for later: what runs under the loader lock (the loader
/// stub's `DllMain`, the loader notification) must not open or write a file.
/// Only `OutputDebugStringA` is called now; the file gets the line, with the
/// time it is written, from the next [`line`] or [`flush_deferred`].
pub fn defer(msg: String) {
    if let Ok(c) = CString::new(format!("[icq-e2e] {msg}")) {
        // SAFETY: a valid NUL-terminated pointer for the duration of the call.
        unsafe { OutputDebugStringA(c.as_ptr() as *const u8) };
    }
    if let Ok(mut d) = DEFERRED.lock() {
        d.push(msg);
    }
}

/// Writes the deferred lines to the file. Never call it under the loader
/// lock.
pub fn flush_deferred() {
    let lines = match DEFERRED.lock() {
        Ok(mut d) if !d.is_empty() => std::mem::take(&mut *d),
        _ => return,
    };
    if let Ok(mut guard) = logger().lock() {
        if let Some(file) = guard.file.as_mut() {
            for msg in lines {
                let _ = writeln!(file, "{} (deferred) {}", local_stamp(), msg);
            }
            let _ = file.flush();
        }
    }
}

/// Writes one line to OutputDebugString and, when configured, to the file.
/// Lines deferred before it are written first.
pub fn line(msg: &str) {
    flush_deferred();
    // OutputDebugString first, so it works even if the file is unavailable.
    if let Ok(c) = CString::new(format!("[icq-e2e] {msg}")) {
        // SAFETY: a valid NUL-terminated pointer for the duration of the call.
        unsafe { OutputDebugStringA(c.as_ptr() as *const u8) };
    }
    if let Ok(mut guard) = logger().lock() {
        if let Some(file) = guard.file.as_mut() {
            let _ = writeln!(file, "{} {}", local_stamp(), msg);
            let _ = file.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_is_always_a_file_to_log_to() {
        // The point of the fallback: with nothing configured the add-on still
        // lands somewhere, because "the log is silent" and "the add-on never
        // loaded" are indistinguishable from the outside - which is exactly how
        // an ICQ 6.5 client that never reached the directory looked like one
        // with nothing to report.
        let path = log_path(&None, false);
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("icqe2e.log"),
            "the log is a file, not a directory: {}",
            path.display()
        );
        assert!(
            path.components().count() > 1,
            "a bare name would be relative to the working directory: {}",
            path.display()
        );
    }

    #[test]
    fn a_configured_log_wins_over_the_fallback() {
        let configured = std::path::PathBuf::from("C:\\IcqLogs\\icqe2e.log");
        assert_eq!(
            log_path(&Some(configured.clone()), false),
            configured,
            "the variable is what the owner sets to keep both clients in one file"
        );
    }

    #[test]
    fn a_test_run_never_reaches_the_owners_log() {
        // `ICQE2E_LOG` points at the live client's file for the whole user, and
        // a test appending to it would bury the real client's entries under a
        // library's output. This is the case `own_file` exists for.
        let owners = std::path::PathBuf::from("C:\\IcqLogs\\icqe2e.log");
        assert_eq!(
            log_path(&Some(owners.clone()), true),
            temp_log_path(),
            "a test would append to the owner's log: {}",
            owners.display()
        );
    }
}
