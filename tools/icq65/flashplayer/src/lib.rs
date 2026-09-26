//! FlashPlayerControl.dll for ICQ 6.5, playing movies with Ruffle instead of
//! the Adobe Flash ActiveX control. See README.md for the contract.

#![allow(non_snake_case)]

mod audio;
mod com;
mod fetch;
mod gpu;
mod instance;
mod movie;
mod typelib;

use std::ffi::c_void;
use std::io::Write;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{E_POINTER, HMODULE, HWND, LPARAM, S_OK};
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CS_DBLCLKS, CS_GLOBALCLASS, GetClassInfoExW, IDC_ARROW, LoadCursorW, RegisterClassExW,
    UnregisterClassW, WNDCLASSEXW,
};
use windows_sys::core::{BOOL, HRESULT};

use instance::Listener;

const CLASS_NAME: &str = "FlashPlayerControl";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// This DLL's module handle.
fn module() -> HMODULE {
    let mut h: HMODULE = null_mut();
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            module as *const c_void as *const u16,
            &mut h,
        )
    };
    h
}

/// Full path of this DLL.
fn module_path() -> String {
    let mut buf = vec![0u16; 1024];
    let n = unsafe { GetModuleFileNameW(module(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
    String::from_utf16_lossy(&buf[..n])
}

/// Runs `f`, turning a panic into `default`. Every entry point from the client
/// (exports, COM methods, the window procedure) and every thread of the DLL
/// goes through this or `catch_unwind`: a panic must never reach the client,
/// where an unwinding `extern "system"` function aborts the process.
pub(crate) fn ffi_guard<T>(what: &str, default: T, f: impl FnOnce() -> T) -> T {
    install_panic_hook();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            log(&format!("panic in {what}; returning an error"));
            default
        }
    }
}

/// Logs every panic (message and source location) instead of printing it to
/// a stderr that ICQ does not have.
pub(crate) fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let thread = std::thread::current();
            log(&format!(
                "panic on thread {:?}: {info}",
                thread.name().unwrap_or("?")
            ));
        }));
    });
}

/// Writes to the debugger, and to the file named by FLASHPLAYERCONTROL_LOG.
pub(crate) fn log(msg: &str) {
    let line = format!("FlashPlayerControl: {msg}\n");
    let w = wide(&line);
    unsafe { OutputDebugStringW(w.as_ptr()) };
    if let Some(path) = std::env::var_os("FLASHPLAYERCONTROL_LOG") {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

fn with_instance(hwnd: HWND, f: impl FnOnce(&instance::Instance) -> HRESULT) -> HRESULT {
    match instance::lookup(hwnd) {
        Ok(i) => {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&i))).unwrap_or_else(|_| {
                log("panic in export");
                windows_sys::Win32::Foundation::E_FAIL
            })
        }
        Err(hr) => hr,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn FPCIsFlashInstalled() -> BOOL {
    crate::ffi_guard("FPCIsFlashInstalled", 0, || {
        // Called on the client's UI thread: waits at most a moment for the
        // renderer probe (see gpu::available for the reasoning).
        gpu::available() as BOOL
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn RegisterFlashWindowClass() -> BOOL {
    crate::ffi_guard("RegisterFlashWindowClass", 0, || {
        let name = wide(CLASS_NAME);
        let hinst = module();
        let mut existing: WNDCLASSEXW = unsafe { std::mem::zeroed() };
        existing.cbSize = size_of::<WNDCLASSEXW>() as u32;
        if unsafe { GetClassInfoExW(hinst, name.as_ptr(), &mut existing) } != 0 {
            return 1;
        }
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_GLOBALCLASS | CS_DBLCLKS,
            lpfnWndProc: Some(instance::wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: null_mut(),
            hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
            hbrBackground: null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: name.as_ptr(),
            hIconSm: null_mut(),
        };
        (unsafe { RegisterClassExW(&class) } != 0) as BOOL
    })
}

/// Fails (harmlessly) while windows of the class still exist.
#[unsafe(no_mangle)]
pub extern "system" fn UnregisterFlashWindowClass() -> BOOL {
    crate::ffi_guard("UnregisterFlashWindowClass", 0, || {
        let name = wide(CLASS_NAME);
        unsafe { UnregisterClassW(name.as_ptr(), module()) }
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn FPC_LoadMovieW(hwnd: HWND, _layer: i32, url: *const u16) -> HRESULT {
    crate::ffi_guard(
        "FPC_LoadMovieW",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if url.is_null() {
                return E_POINTER;
            }
            let len = (0..).take_while(|&i| unsafe { *url.add(i) } != 0).count();
            let url = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(url, len) });
            with_instance(hwnd, |i| i.load(&url))
        },
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn FPC_Play(hwnd: HWND) -> HRESULT {
    crate::ffi_guard("FPC_Play", windows_sys::Win32::Foundation::E_FAIL, || {
        with_instance(hwnd, |i| i.play())
    })
}

/// Stops and rewinds (also called before any movie is loaded).
#[unsafe(no_mangle)]
pub extern "system" fn FPC_Stop(hwnd: HWND) -> HRESULT {
    crate::ffi_guard("FPC_Stop", windows_sys::Win32::Foundation::E_FAIL, || {
        with_instance(hwnd, |i| i.stop())
    })
}

/// Pauses.
#[unsafe(no_mangle)]
pub extern "system" fn FPC_StopPlay(hwnd: HWND) -> HRESULT {
    crate::ffi_guard(
        "FPC_StopPlay",
        windows_sys::Win32::Foundation::E_FAIL,
        || with_instance(hwnd, |i| i.stop_play()),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn FPC_IsPlaying(hwnd: HWND, out: *mut i16) -> HRESULT {
    crate::ffi_guard(
        "FPC_IsPlaying",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            with_instance(hwnd, |i| {
                unsafe { *out = if i.is_playing() { -1 } else { 0 } };
                S_OK
            })
        },
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn FPC_UpdateWindow(hwnd: HWND) -> HRESULT {
    crate::ffi_guard(
        "FPC_UpdateWindow",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            with_instance(hwnd, |i| {
                i.present();
                S_OK
            })
        },
    )
}

/// Stores the listener; no notifications are sent to it.
#[unsafe(no_mangle)]
pub extern "system" fn FPCSetEventListener(
    hwnd: HWND,
    listener: Option<Listener>,
    param: LPARAM,
) -> BOOL {
    crate::ffi_guard("FPCSetEventListener", 0, || match instance::lookup(hwnd) {
        Ok(i) => {
            i.listener.set(listener.map(|l| (l, param)));
            1
        }
        Err(_) => 0,
    })
}

/// Registers the type library for the current user (HKCU\Software\Classes).
#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    crate::ffi_guard(
        "DllRegisterServer",
        windows_sys::Win32::Foundation::E_FAIL,
        || typelib::register(),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
    crate::ffi_guard(
        "DllUnregisterServer",
        windows_sys::Win32::Foundation::E_FAIL,
        || typelib::unregister(),
    )
}
