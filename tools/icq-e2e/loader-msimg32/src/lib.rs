//! ICQ 6.5 loader stub, shipped as `msimg32.dll`.
//!
//! `msimg32.dll` is not a KnownDLL, and `MUtils.dll` (loaded at process init by
//! `ICQ.exe`) statically imports it, so a copy in the ICQ folder is loaded
//! before any BOS connection. This proxy forwards the five real msimg32 exports
//! to the genuine `system32\msimg32.dll` and, in `DllMain(DLL_PROCESS_ATTACH)`,
//! starts the E2E observer. GDI calls pass straight through.
//!
//! Forwarding is done with naked thunks that `jmp` to the real function pointers
//! resolved at attach time, rather than PE export forwarders, because a
//! forwarder to `msimg32.<name>` would resolve back to this same app-directory
//! module and loop.

use core::ffi::c_void;
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{HINSTANCE, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, GetModuleHandleExW, GetProcAddress, LoadLibraryW,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

const DLL_PROCESS_ATTACH: u32 = 1;

// Resolved addresses of the genuine msimg32 exports. Written once in DllMain,
// before any of our thunks can be called (MUtils imports us statically, so our
// attach runs before its own code calls AlphaBlend).
static mut REAL_ALPHABLEND: usize = 0;
static mut REAL_DLLINITIALIZE: usize = 0;
static mut REAL_GRADIENTFILL: usize = 0;
static mut REAL_TRANSPARENTBLT: usize = 0;
static mut REAL_VSETDDRAWFLAG: usize = 0;

#[no_mangle]
pub extern "system" fn DllMain(hinst: HINSTANCE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        // SAFETY: standard DllMain-time calls.
        unsafe {
            DisableThreadLibraryCalls(hinst as HMODULE);
            if !resolve_real() {
                // Without the real exports the client's GDI calls would fault,
                // so fail the load rather than proxy nothing.
                return 0;
            }
            pin_self();
        }
        icqe2e_core::install();
    }
    1
}

/// Loads the genuine system32\msimg32.dll and resolves its exports. Returns
/// false if any required export is missing.
unsafe fn resolve_real() -> bool {
    let mut dir = [0u16; 260];
    let n = GetSystemDirectoryW(dir.as_mut_ptr(), dir.len() as u32) as usize;
    if n == 0 || n >= dir.len() {
        return false;
    }
    let mut path: Vec<u16> = dir[..n].to_vec();
    path.extend("\\msimg32.dll\0".encode_utf16());
    let h: HMODULE = LoadLibraryW(path.as_ptr() as PCWSTR);
    if h.is_null() {
        return false;
    }
    REAL_ALPHABLEND = proc(h, b"AlphaBlend\0");
    REAL_DLLINITIALIZE = proc(h, b"DllInitialize\0");
    REAL_GRADIENTFILL = proc(h, b"GradientFill\0");
    REAL_TRANSPARENTBLT = proc(h, b"TransparentBlt\0");
    REAL_VSETDDRAWFLAG = proc(h, b"vSetDdrawflag\0");
    REAL_ALPHABLEND != 0
        && REAL_GRADIENTFILL != 0
        && REAL_TRANSPARENTBLT != 0
        && REAL_VSETDDRAWFLAG != 0
}

unsafe fn proc(h: HMODULE, name: &[u8]) -> usize {
    match GetProcAddress(h, name.as_ptr()) {
        Some(p) => p as usize,
        None => 0,
    }
}

unsafe fn pin_self() {
    let mut h: HMODULE = core::ptr::null_mut();
    let addr = DllMain as *const () as *const u16;
    let _ = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        addr,
        &mut h,
    );
}

// --- forwarding thunks ------------------------------------------------------
//
// Each exported name is a naked function that tail-jumps to the real pointer,
// leaving the caller's stack and arguments exactly in place. The real function
// returns straight to our caller.

macro_rules! forward {
    ($name:ident, $target:ident) => {
        #[no_mangle]
        #[unsafe(naked)]
        pub extern "system" fn $name() {
            // A jmp through a resolved function pointer; no Rust state.
            core::arch::naked_asm!(
                "jmp dword ptr [{t}]",
                t = sym $target,
            );
        }
    };
}

forward!(AlphaBlend, REAL_ALPHABLEND);
forward!(DllInitialize, REAL_DLLINITIALIZE);
forward!(GradientFill, REAL_GRADIENTFILL);
forward!(TransparentBlt, REAL_TRANSPARENTBLT);
forward!(vSetDdrawflag, REAL_VSETDDRAWFLAG);
