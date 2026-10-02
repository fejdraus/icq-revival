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

/// The plain HTTP port the server's pages and movies are served on, and the
/// port nginx serves the same paths on over HTTPS.
const PAGES_PORT: &str = "8101";
const PAGES_PORT_TLS: &str = "8102";

/// The HTTPS address of the same file, for an `http://<host>:8101/...`
/// address on the server's pages port; `None` for any other address.
///
/// The animated avatars' addresses stay plain HTTP in the BART item every
/// contact downloads: the clients that set them, and other players, may not
/// speak HTTPS. This player does, so it reads them over TLS on 8102.
pub(crate) fn secure_twin(url: &str) -> Option<String> {
    let scheme = url.get(..7)?;
    if !scheme.eq_ignore_ascii_case("http://") {
        return None;
    }
    let rest = &url[7..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let host = authority.strip_suffix(PAGES_PORT)?.strip_suffix(':')?;
    if host.is_empty() || (host.contains(['@', ':']) && !host.starts_with('[')) {
        return None;
    }
    Some(format!("https://{host}:{PAGES_PORT_TLS}{path}"))
}

pub fn fetch(url: &str) -> Result<Vec<u8>, String> {
    if is_http(url) {
        // A movie on the server's pages port is read over HTTPS only, never
        // over the plain address as well: falling back would let anyone on
        // the path block 8102 and hand the player a movie of their own.
        let target = secure_twin(url).unwrap_or_else(|| url.to_owned());
        http(&target).map_err(HttpError::into_message)
    } else {
        std::fs::read(local_path(url)).map_err(|e| e.to_string())
    }
}

/// Reads a movie. An ICQ extras document instead of a SWF
/// (`<DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>...</URL></RESSET></DOCUMENT>`,
/// what a Flash avatar's BART item holds) is followed once to the movie it
/// names. Returns the movie and the URL it came from.
pub fn fetch_movie(url: &str) -> Result<(Vec<u8>, String), String> {
    let data = fetch(url)?;
    if is_swf(&data) {
        return Ok((data, url.to_owned()));
    }
    match extras_url(&data) {
        Some(inner) => {
            crate::log(&format!("{url} is an ICQ extras document for {inner}"));
            let data = fetch(&inner)?;
            Ok((data, inner))
        }
        None => Ok((data, url.to_owned())),
    }
}

fn is_swf(data: &[u8]) -> bool {
    data.len() >= 3 && matches!(&data[1..3], b"WS") && matches!(data[0], b'F' | b'C' | b'Z')
}

/// The `<URL>` of an ICQ extras document (UTF-8 or UTF-16), if `data` is one.
pub(crate) fn extras_url(data: &[u8]) -> Option<String> {
    let text = if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        let units: Vec<u16> = data[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(data).into_owned()
    };
    let text = text.trim_start_matches('\u{feff}').trim_start();
    if !text.starts_with('<') {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if !lower.contains("<document") {
        return None;
    }
    let start = lower.find("<url>")? + "<url>".len();
    let end = start + lower[start..].find("</url>")?;
    let mut inner = text[start..end].trim();
    if let Some(s) = inner.strip_prefix("<![CDATA[") {
        inner = s.strip_suffix("]]>").unwrap_or(s).trim();
    }
    let url = inner
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&");
    (!url.is_empty()).then_some(url)
}

/// Why a download failed: the server could not be reached (no connection, no
/// TLS), or it answered and the answer was not the file.
enum HttpError {
    Unreachable(String),
    Status(String),
}

impl HttpError {
    fn into_message(self) -> String {
        match self {
            HttpError::Unreachable(e) | HttpError::Status(e) => e,
        }
    }
}

fn http(url: &str) -> Result<Vec<u8>, HttpError> {
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
        return Err(HttpError::Unreachable("InternetOpen failed".into()));
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
        return Err(HttpError::Unreachable(format!(
            "InternetOpenUrl failed ({})",
            std::io::Error::last_os_error()
        )));
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
        return Err(HttpError::Status(format!("HTTP {status}")));
    }
    let mut data = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut read = 0u32;
        let ok = unsafe {
            InternetReadFile(req.0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read)
        };
        if ok == 0 {
            return Err(HttpError::Status(format!(
                "read failed ({})",
                std::io::Error::last_os_error()
            )));
        }
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buf[..read as usize]);
        if data.len() > MAX_MOVIE {
            return Err(HttpError::Status("movie too large".into()));
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_port_is_read_over_tls() {
        assert_eq!(
            secure_twin("http://icq.example.org:8101/icq/avatars/pirate.swf?emotion=stam")
                .as_deref(),
            Some("https://icq.example.org:8102/icq/avatars/pirate.swf?emotion=stam")
        );
        assert_eq!(
            secure_twin("HTTP://h:8101").as_deref(),
            Some("https://h:8102")
        );
        assert_eq!(
            secure_twin("http://[::1]:8101/x.swf").as_deref(),
            Some("https://[::1]:8102/x.swf")
        );
        assert_eq!(secure_twin("https://h:8101/x.swf"), None);
        assert_eq!(secure_twin("http://h/x.swf"), None);
        assert_eq!(secure_twin("http://h:81010/x.swf"), None);
        assert_eq!(secure_twin("http://h:18101/x.swf"), None);
        assert_eq!(secure_twin("http://u@h:8101/x.swf"), None);
        assert_eq!(secure_twin("http://:8101/x.swf"), None);
        assert_eq!(secure_twin("http://example.com/devil.swf"), None);
        assert_eq!(secure_twin(r"C:\movies\x.swf"), None);
    }

    #[test]
    fn extras_document_names_its_movie() {
        let doc = br#"<?xml version="1.0" encoding="UTF-8"?><DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>http://h:8101/icq/avatars/smile.swf?a=1&amp;b=2</URL></RESSET></DOCUMENT>"#;
        assert_eq!(
            extras_url(doc).as_deref(),
            Some("http://h:8101/icq/avatars/smile.swf?a=1&b=2")
        );
        let wide: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                "<DOCUMENT><RESSET><URL> <![CDATA[x.swf]]> </URL></RESSET></DOCUMENT>"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes()),
            )
            .collect();
        assert_eq!(extras_url(&wide).as_deref(), Some("x.swf"));
        assert_eq!(extras_url(b"FWS\x06rest"), None);
        assert_eq!(extras_url(b"<html><URL>x</URL></html>"), None);
        assert!(is_swf(b"CWS\x08") && is_swf(b"FWS\x06") && !is_swf(b"<DOC"));
    }
}
