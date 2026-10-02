//! The key directory over HTTPS, through WinHTTP.
//!
//! WinHTTP shares the machine's proxy and certificate stores, which is what
//! makes the directory's certificate check the ordinary one: a certificate the
//! system does not trust is refused here exactly as it would be in a browser,
//! so nothing in this file turns encryption off. The check is left on
//! (`WINHTTP_FLAG_SECURE`) and no code path relaxes it.
//!
//! The base URL is `https://<domain>:8102/e2e/v1/`, as
//! `docs/e2e/STAGE-3-CLIENT-CRYPTO.md` records; the patch writes the domain it
//! configured into `icq-e2e.ini` and `ICQE2E_DIRECTORY` overrides it.
//!
//! Handles are opened per request rather than kept: publishing happens on a
//! worker thread a few times per sign-on, and a session opened under one
//! sign-on must not be reused after the next.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryDataAvailable,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WinHttpWriteData, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE,
};

use crate::directory::Transport;

/// The most a reply may be. The API's largest answer is one device with its key
/// pool; this leaves room for several and refuses anything larger.
const MAX_REPLY: usize = 512 * 1024;

/// How much is read at a time.
const CHUNK: usize = 16 * 1024;

/// HTTPS over WinHTTP.
pub struct WinHttp {
    base: String,
}

impl WinHttp {
    /// A transport for the API at `base`, e.g. `https://aim.example:8102/e2e/v1/`.
    pub fn new(base: impl Into<String>) -> WinHttp {
        let mut base = base.into();
        if !base.ends_with('/') {
            base.push('/');
        }
        WinHttp { base }
    }

    /// The base URL requests are made against.
    pub fn base(&self) -> &str {
        &self.base
    }
}

impl Transport for WinHttp {
    fn call(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), String> {
        let url = format!("{}{}", self.base, path.trim_start_matches('/'));
        let (host, port, target) = crack(&url)?;
        unsafe { exchange(&host, port, &target, method, bearer, body) }
    }
}

/// Splits a URL into the host, port and request target WinHTTP wants. The URL
/// is built from the configured base and the API's own paths, so anything odd
/// in it is a configuration error and is reported as one.
fn crack(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("{url} is not an https:// url"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| format!("{url} has no usable port"))?,
        ),
        None => (authority.to_string(), 443),
    };
    if host.is_empty() {
        return Err(format!("{url} has no host"));
    }
    Ok((host, port, path.to_string()))
}

/// A WinHTTP session, connection or request handle, closed however the
/// function leaves. All three are the same `*mut c_void` closed the same way.
struct Handle(*mut c_void);

impl Handle {
    /// # Safety
    /// `raw` must be a handle one of the WinHTTP functions just returned.
    unsafe fn new(raw: *mut c_void, what: &str) -> Result<Handle, String> {
        if raw.is_null() {
            Err(format!("{what} failed: {}", GetLastError()))
        } else {
            Ok(Handle(raw))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

/// A UTF-16, null-terminated string for the wide WinHTTP API.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The last WinHTTP error, as a message.
unsafe fn last(what: &str) -> String {
    format!("{what} failed: {}", GetLastError())
}

/// One request and its reply.
unsafe fn exchange(
    host: &str,
    port: u16,
    target: &str,
    method: &str,
    bearer: Option<&str>,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let session = Handle::new(
        WinHttpOpen(
            wide("ICQ E2E/0.3").as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        ),
        "WinHttpOpen",
    )?;
    let connection = Handle::new(
        WinHttpConnect(session.0, wide(host).as_ptr(), port, 0),
        "WinHttpConnect",
    )?;
    let request = Handle::new(
        WinHttpOpenRequest(
            connection.0,
            wide(method).as_ptr(),
            wide(target).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ),
        "WinHttpOpenRequest",
    )?;

    let headers = match bearer {
        Some(t) => format!("Authorization: Bearer {t}\r\nContent-Type: application/json\r\n"),
        None => "Content-Type: application/json\r\n".to_string(),
    };
    let length = body.map_or(0, <[u8]>::len) as u32;
    // dwcontext 0: the reply needs nothing from the caller's context.
    let context = if body.is_some() { length as usize } else { 0 };
    if WinHttpSendRequest(
        request.0,
        wide(&headers).as_ptr(),
        headers.len() as u32,
        std::ptr::null(),
        0,
        length,
        context,
    ) == 0
    {
        return Err(last("WinHttpSendRequest"));
    }
    if let Some(b) = body.filter(|b| !b.is_empty()) {
        let mut done = 0usize;
        while done < b.len() {
            let mut written = 0u32;
            if WinHttpWriteData(
                request.0,
                b[done..].as_ptr() as *const c_void,
                (b.len() - done) as u32,
                &mut written,
            ) == 0
                || written == 0
            {
                return Err(last("WinHttpWriteData"));
            }
            done += written as usize;
        }
    }
    if WinHttpReceiveResponse(request.0, std::ptr::null_mut()) == 0 {
        return Err(format!("RECEIVE: {}", GetLastError()));
    }

    let status = status_of(request.0)?;
    let mut reply = Vec::new();
    let mut chunk = [0u8; CHUNK];
    loop {
        let mut available = 0u32;
        if WinHttpQueryDataAvailable(request.0, &mut available) == 0 {
            return Err(last("WinHttpQueryDataAvailable"));
        }
        if available == 0 {
            break;
        }
        if reply.len() + available as usize > MAX_REPLY {
            return Err(format!("the directory's reply is over {MAX_REPLY} bytes"));
        }
        let mut read = 0u32;
        if WinHttpReadData(
            request.0,
            chunk.as_mut_ptr() as *mut c_void,
            available.min(CHUNK as u32),
            &mut read,
        ) == 0
        {
            return Err(last("WinHttpReadData"));
        }
        if read == 0 {
            break;
        }
        reply.extend_from_slice(&chunk[..read as usize]);
    }
    Ok((status, reply))
}

/// The reply's status code.
///
/// Asked for as a number with `WINHTTP_QUERY_FLAG_NUMBER`, not as the status
/// line: the string form depends on the reason phrase and on the length coming
/// back in bytes rather than characters, and taking the second word of that
/// line is how a `401 unauthorized` from the directory was logged as
/// `1 unauthorized` - a status no server sends, which sent the whole
/// investigation after the wrong fault.
///
/// The buffer is not sized first. A number is a fixed four bytes, and asking
/// for the size of one is not a question WinHTTP answers: with a null buffer it
/// fails with `ERROR_WINHTTP_INVALID_QUERY_REQUEST` (12154) rather than
/// `ERROR_INSUFFICIENT_BUFFER`, which read as "the TLS handshake failed" and
/// sent the search after a certificate that was never the problem.
unsafe fn status_of(request: *mut c_void) -> Result<u16, String> {
    /// `WINHTTP_QUERY_STATUS_CODE`, which is **19** (`0x13`).
    ///
    /// Not 9. `9` is `WINHTTP_QUERY_DATE`, so that constant asked for the
    /// `Date` header and came back with `Thu, 01 Oct 2026 ...` - which is why
    /// the second word of it was a number of the day, and why a `401
    /// unauthorized` from the directory was logged as `1 unauthorized`.
    const STATUS_CODE: u32 = 0x0000_0013;
    /// `WINHTTP_QUERY_FLAG_NUMBER`: answer as a number, not as text.
    const FLAG_NUMBER: u32 = 0x2000_0000;
    /// `WINHTTP_HEADER_NAME_BY_INDEX`, `((LPWSTR)(LONG_PTR)-1)`, which the
    /// documentation requires whenever the level is not `WINHTTP_QUERY_CUSTOM`.
    const BY_INDEX: *const u16 = usize::MAX as *const u16;

    let mut status = 0u32;
    let mut len = std::mem::size_of::<u32>() as u32;
    if WinHttpQueryHeaders(
        request,
        STATUS_CODE | FLAG_NUMBER,
        BY_INDEX,
        (&mut status as *mut u32).cast(),
        &mut len,
        std::ptr::null_mut(),
    ) == 0
    {
        return Err(last("WinHttpQueryHeaders"));
    }
    u16::try_from(status).map_err(|_| format!("the directory sent status {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_base_url_is_built_from_what_the_patch_wrote() {
        let t = WinHttp::new("https://aim.example:8102/e2e/v1");
        assert_eq!(t.base(), "https://aim.example:8102/e2e/v1/");
        // The API's path is appended to the base; the host never is.
        let (host, port, target) =
            crack(&format!("{}{}", t.base(), "users/100001/devices")).unwrap();
        assert_eq!(
            (host.as_str(), port, target.as_str()),
            ("aim.example", 8102, "/e2e/v1/users/100001/devices")
        );
    }

    #[test]
    fn a_url_that_is_not_https_is_a_configuration_error() {
        assert!(crack("http://aim.example:8102/e2e/v1/").is_err());
        assert!(crack("https://:8102/e2e/v1/").is_err());
        assert!(crack("https://aim.example:not-a-port/e2e/v1/").is_err());
    }

    /// The status a real directory answers with, read through the same WinHTTP
    /// path the add-on uses. It was read as a wide string whose length is
    /// reported in bytes, which turned a `401 unauthorized` into
    /// `1 unauthorized`; only a real reply shows that.
    ///
    /// Skipped unless `ICQE2E_TEST_DIRECTORY` names a directory to talk to.
    /// It does not skip on a transport failure: that is the failure this test
    /// exists to catch, and a test that skips when it should fail is worse
    /// than no test.
    #[test]
    fn a_real_reply_status_is_read_as_it_is() {
        let Ok(base) = std::env::var("ICQE2E_TEST_DIRECTORY") else {
            return;
        };
        let t = WinHttp::new(&base);
        let (status, body) = t
            .call(
            "PUT",
            "account",
            Some("this is not a token"),
            Some(br#"{"account_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","self_signature":"x"}"#),
            )
            .expect("the directory answered, with a status this reads as a number");

        assert_eq!(
            status,
            401,
            "the status is 401, not 1: {status}, {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            String::from_utf8_lossy(&body).contains("unauthorized"),
            "and the body says why: {}",
            String::from_utf8_lossy(&body)
        );
    }

    #[test]
    fn a_url_without_a_port_uses_the_https_default() {
        let (host, port, target) = crack("https://aim.example/e2e/v1/token").unwrap();
        assert_eq!(
            (host.as_str(), port, target.as_str()),
            ("aim.example", 443, "/e2e/v1/token")
        );
    }
}
