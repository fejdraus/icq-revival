//! Per-user (HKCU) registration of the ShockwaveFlash control class, next to
//! the type library registration (typelib.rs). HKLM is never written.
//!
//! Keys, under HKCU\Software\Classes (a 32-bit process such as regsvr32 from
//! SysWOW64 gets the CLSID key redirected to the 32-bit view, which is where
//! the 32-bit ICQ looks):
//!
//!   CLSID\{D27CDB6E-...}                    "Shockwave Flash Object"
//!     InprocServer32 = <this DLL>, ThreadingModel = Apartment
//!     ProgID, VersionIndependentProgID, TypeLib, Version, Control, MiscStatus\1
//!   ShockwaveFlash.ShockwaveFlash[.9|.10]\CLSID = {D27CDB6E-...}
//!
//! FLASHPLAYERCONTROL_TEST_REGROOT (tests only) replaces "Software\Classes"
//! with another HKCU subkey and leaves the type library alone, so a test never
//! touches the user's real registration.

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, S_OK};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows_sys::core::HRESULT;

const CLSID: &str = "{D27CDB6E-AE6D-11cf-96B8-444553540000}";
const LIBID: &str = "{D27CDB6B-AE6D-11CF-96B8-444553540000}";
const PROGID: &str = "ShockwaveFlash.ShockwaveFlash";
const PROGID_CUR: &str = "ShockwaveFlash.ShockwaveFlash.10";
const PROGIDS: [&str; 3] = [PROGID, "ShockwaveFlash.ShockwaveFlash.9", PROGID_CUR];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn hr(e: u32) -> HRESULT {
    if e == ERROR_SUCCESS {
        S_OK
    } else {
        (0x8007_0000 | (e & 0xFFFF)) as HRESULT
    }
}

/// The classes root and whether it is the real one.
pub fn root() -> (String, bool) {
    match std::env::var("FLASHPLAYERCONTROL_TEST_REGROOT") {
        Ok(r) if !r.trim().is_empty() => (r.trim().trim_matches('\\').to_owned(), false),
        _ => ("Software\\Classes".to_owned(), true),
    }
}

fn set(path: &str, name: Option<&str>, value: &str) -> HRESULT {
    let p = wide(path);
    let mut key: HKEY = null_mut();
    let e = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            p.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            null(),
            &mut key,
            null_mut(),
        )
    };
    if e != ERROR_SUCCESS {
        return hr(e);
    }
    let n = name.map(wide);
    let v = wide(value);
    let e = unsafe {
        RegSetValueExW(
            key,
            n.as_ref().map_or(null(), |n| n.as_ptr()),
            0,
            REG_SZ,
            v.as_ptr().cast(),
            (v.len() * 2) as u32,
        )
    };
    unsafe { RegCloseKey(key) };
    hr(e)
}

fn get(path: &str, name: Option<&str>) -> Option<String> {
    let p = wide(path);
    let mut key: HKEY = null_mut();
    if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, p.as_ptr(), 0, KEY_READ, &mut key) }
        != ERROR_SUCCESS
    {
        return None;
    }
    let n = name.map(wide);
    let mut buf = vec![0u16; 1024];
    let mut len = (buf.len() * 2) as u32;
    let mut ty = 0u32;
    let e = unsafe {
        RegQueryValueExW(
            key,
            n.as_ref().map_or(null(), |n| n.as_ptr()),
            null(),
            &mut ty,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    unsafe { RegCloseKey(key) };
    if e != ERROR_SUCCESS || ty != REG_SZ {
        return None;
    }
    let chars = (len as usize / 2).min(buf.len());
    Some(
        String::from_utf16_lossy(&buf[..chars])
            .trim_end_matches('\0')
            .to_owned(),
    )
}

fn delete(path: &str) -> HRESULT {
    let p = wide(path);
    let e = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, p.as_ptr()) };
    if e == ERROR_FILE_NOT_FOUND {
        S_OK
    } else {
        hr(e)
    }
}

/// Registers the control class and ProgIDs for the current user.
pub fn register(dll: &str) -> HRESULT {
    let (root, _) = root();
    let c = format!("{root}\\CLSID\\{CLSID}");
    let mut writes: Vec<(String, Option<&str>, String)> = vec![
        (c.clone(), None, "Shockwave Flash Object".into()),
        (format!("{c}\\InprocServer32"), None, dll.into()),
        (
            format!("{c}\\InprocServer32"),
            Some("ThreadingModel"),
            "Apartment".into(),
        ),
        (format!("{c}\\ProgID"), None, PROGID_CUR.into()),
        (
            format!("{c}\\VersionIndependentProgID"),
            None,
            PROGID.into(),
        ),
        (format!("{c}\\TypeLib"), None, LIBID.into()),
        (format!("{c}\\Version"), None, "1.0".into()),
        (format!("{c}\\Control"), None, String::new()),
        (format!("{c}\\MiscStatus"), None, "0".into()),
        (format!("{c}\\MiscStatus\\1"), None, "131473".into()),
    ];
    for p in PROGIDS {
        writes.push((
            format!("{root}\\{p}"),
            None,
            "Shockwave Flash Object".into(),
        ));
        writes.push((format!("{root}\\{p}\\CLSID"), None, CLSID.into()));
    }
    writes.push((format!("{root}\\{PROGID}\\CurVer"), None, PROGID_CUR.into()));
    for (path, name, value) in &writes {
        let r = set(path, *name, value);
        if r < 0 {
            crate::log(&format!("register: cannot write HKCU\\{path}: {r:#x}"));
            return r;
        }
    }
    crate::log(&format!(
        "registered the ShockwaveFlash control for this user under HKCU\\{root}"
    ));
    S_OK
}

/// Removes the class registration, if it is this DLL's. ProgIDs are removed
/// only when they point at the class and the class was ours.
pub fn unregister(dll: &str) -> HRESULT {
    let (root, _) = root();
    let c = format!("{root}\\CLSID\\{CLSID}");
    match get(&format!("{c}\\InprocServer32"), None) {
        None => return S_OK, // not registered for this user
        Some(server) if !server.eq_ignore_ascii_case(dll) => {
            crate::log(&format!(
                "unregister: the Flash class is registered to {server}, not this DLL; left alone"
            ));
            return S_OK;
        }
        Some(_) => {}
    }
    let mut result = delete(&c);
    for p in PROGIDS {
        let key = format!("{root}\\{p}");
        if get(&format!("{key}\\CLSID"), None).is_some_and(|v| v.eq_ignore_ascii_case(CLSID)) {
            let r = delete(&key);
            if r < 0 {
                result = r;
            }
        }
    }
    result
}
