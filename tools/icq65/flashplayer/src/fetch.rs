//! Reads a movie from a local path, a file: URL or an http(s) URL (WinINet).
//! Runs on a background thread.

use std::ffi::c_void;
use std::ptr::null;

use windows_sys::Win32::Networking::WinInet::{
    HTTP_QUERY_FLAG_NUMBER, HTTP_QUERY_STATUS_CODE, HttpQueryInfoW, INTERNET_FLAG_NO_UI,
    INTERNET_FLAG_RELOAD, INTERNET_OPEN_TYPE_PRECONFIG, InternetCloseHandle, InternetOpenUrlW,
    InternetOpenW, InternetReadFile,
};

const MAX_MOVIE: usize = 64 << 20;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn is_http(url: &str) -> bool {
    let l = url.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

/// A local path for a file: URL or a plain path.
fn local_path(url: &str) -> String {
    let l = url.to_ascii_lowercase();
    if l.starts_with("file:") {
        let rest = url[5..].trim_start_matches('/');
        let mut out = Vec::new();
        let bytes = rest.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Some(v) = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).replace('/', "\\")
    } else {
        url.to_owned()
    }
}

/// The URL Ruffle is told the movie came from.
pub fn movie_url(url: &str) -> String {
    if is_http(url) || url.to_ascii_lowercase().starts_with("file:") {
        url.to_owned()
    } else {
        format!("file:///{}", url.replace('\\', "/"))
    }
}

pub fn fetch(url: &str) -> Result<Vec<u8>, String> {
    if is_http(url) {
        http(url)
    } else {
        std::fs::read(local_path(url)).map_err(|e| e.to_string())
    }
}

fn http(url: &str) -> Result<Vec<u8>, String> {
    struct Handle(*mut c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { InternetCloseHandle(self.0) };
            }
        }
    }
    let agent = wide("Shockwave Flash");
    let session = Handle(unsafe {
        InternetOpenW(
            agent.as_ptr(),
            INTERNET_OPEN_TYPE_PRECONFIG,
            null(),
            null(),
            0,
        )
    });
    if session.0.is_null() {
        return Err("InternetOpen failed".into());
    }
    let w = wide(url);
    let req = Handle(unsafe {
        InternetOpenUrlW(
            session.0,
            w.as_ptr(),
            null(),
            0,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI,
            0,
        )
    });
    if req.0.is_null() {
        return Err(format!(
            "InternetOpenUrl failed ({})",
            std::io::Error::last_os_error()
        ));
    }
    let mut status: u32 = 0;
    let mut len = size_of::<u32>() as u32;
    let ok = unsafe {
        HttpQueryInfoW(
            req.0,
            HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            (&mut status as *mut u32).cast(),
            &mut len,
            std::ptr::null_mut(),
        )
    };
    if ok != 0 && !(200..300).contains(&status) {
        return Err(format!("HTTP {status}"));
    }
    let mut data = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut read = 0u32;
        let ok = unsafe {
            InternetReadFile(req.0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read)
        };
        if ok == 0 {
            return Err(format!("read failed ({})", std::io::Error::last_os_error()));
        }
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buf[..read as usize]);
        if data.len() > MAX_MOVIE {
            return Err("movie too large".into());
        }
    }
    Ok(data)
}
