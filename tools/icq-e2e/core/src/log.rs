//! Logging for the add-on.
//!
//! A line always goes to `OutputDebugStringA` (visible in DebugView). If the
//! `ICQE2E_LOG` environment variable names a file, the line is also appended
//! there with a local-time stamp. With no such variable, no file is opened.
//! Every entry point that writes is guarded so a logging failure can never take
//! the host down.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringA;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

struct Logger {
    file: Option<File>,
}

fn logger() -> &'static Mutex<Logger> {
    static LOG: OnceLock<Mutex<Logger>> = OnceLock::new();
    LOG.get_or_init(|| {
        let file = std::env::var("ICQE2E_LOG").ok().and_then(|path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()
        });
        Mutex::new(Logger { file })
    })
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

/// Writes one line to OutputDebugString and, when configured, to the file.
pub fn line(msg: &str) {
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
