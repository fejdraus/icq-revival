//! ICQ 6.5 loader stub, shipped as `msimg32.dll`.
//!
//! `msimg32.dll` is not a KnownDLL, and `MUtils.dll` (loaded at process init by
//! `ICQ.exe`) statically imports it, so a copy in the ICQ folder is loaded
//! before any BOS connection. This proxy forwards the five real msimg32 exports
//! to the genuine `system32\msimg32.dll` and, in `DllMain(DLL_PROCESS_ATTACH)`,
//! starts the E2E add-on. GDI calls pass straight through.
//!
//! Forwarding is done with naked thunks that `jmp` through a pointer, rather
//! than PE export forwarders, because a forwarder to `msimg32.<name>` would
//! resolve back to this same app-directory module and loop.
//!
//! Nothing is loaded in `DllMain` (fourth review, finding H): loading a
//! library under the loader lock is what `DllMain` must not do. Each
//! pointer starts at a stub of ours that resolves all five exports once
//! ([`resolve_all`], thread-safe) and then jumps on; the bootstrap thread of
//! the add-on resolves them too as soon as the loader lock is released, so
//! in practice the first GDI call already finds them. Should the genuine DLL
//! be missing, each export answers as a failed call (`FALSE`, its arguments
//! popped) instead of the process failing to start.

use core::ffi::c_void;
use std::sync::Once;
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{HINSTANCE, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryW,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

const DLL_PROCESS_ATTACH: u32 = 1;

type Thunk = unsafe extern "system" fn();

// Where each forwarding thunk jumps: first our resolving stub, then the
// genuine export (or the failing stub). Written only inside `RESOLVED`'s
// `call_once`, each in one aligned store, so a thread that reads one sees a
// whole pointer.
static mut REAL_ALPHABLEND: Thunk = lazy_alphablend;
static mut REAL_DLLINITIALIZE: Thunk = lazy_dllinitialize;
static mut REAL_GRADIENTFILL: Thunk = lazy_gradientfill;
static mut REAL_TRANSPARENTBLT: Thunk = lazy_transparentblt;
static mut REAL_VSETDDRAWFLAG: Thunk = lazy_vsetddrawflag;

static RESOLVED: Once = Once::new();

#[no_mangle]
pub extern "system" fn DllMain(hinst: HINSTANCE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        // SAFETY: standard DllMain-time calls; nothing is loaded here.
        unsafe {
            DisableThreadLibraryCalls(hinst as HMODULE);
            pin_self();
        }
        icqe2e_core::install_with(prewarm);
    }
    1
}

/// Run by the add-on's bootstrap thread, outside the loader lock.
fn prewarm() {
    resolve_all();
}

/// Resolves the five exports once. Called by the first stub that runs, and
/// by the bootstrap thread; every other caller waits for the first.
extern "C" fn resolve_all() {
    RESOLVED.call_once(|| {
        // SAFETY: loader calls with valid NUL-terminated names, and writes of
        // our own pointers inside the one-time block.
        unsafe {
            let h = real_module();
            let pick = |name: &[u8], fail: Thunk| -> Thunk {
                if h.is_null() {
                    return fail;
                }
                match GetProcAddress(h, name.as_ptr()) {
                    Some(p) => {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, Thunk>(p)
                    }
                    None => fail,
                }
            };
            core::ptr::write_volatile(&raw mut REAL_ALPHABLEND, pick(b"AlphaBlend\0", fail_44));
            core::ptr::write_volatile(
                &raw mut REAL_DLLINITIALIZE,
                pick(b"DllInitialize\0", fail_12),
            );
            core::ptr::write_volatile(&raw mut REAL_GRADIENTFILL, pick(b"GradientFill\0", fail_24));
            core::ptr::write_volatile(
                &raw mut REAL_TRANSPARENTBLT,
                pick(b"TransparentBlt\0", fail_44),
            );
            core::ptr::write_volatile(
                &raw mut REAL_VSETDDRAWFLAG,
                pick(b"vSetDdrawflag\0", fail_0),
            );
        }
    });
}

/// The genuine `system32\msimg32.dll`: the one already loaded by its full
/// path if there is one, else loaded now (never under the loader lock in
/// practice: see the module docs).
unsafe fn real_module() -> HMODULE {
    let mut dir = [0u16; 260];
    let n = GetSystemDirectoryW(dir.as_mut_ptr(), dir.len() as u32) as usize;
    if n == 0 || n >= dir.len() {
        return core::ptr::null_mut();
    }
    let mut path: Vec<u16> = dir[..n].to_vec();
    path.extend("\\msimg32.dll\0".encode_utf16());
    let loaded = GetModuleHandleW(path.as_ptr() as PCWSTR);
    if !loaded.is_null() {
        return loaded;
    }
    LoadLibraryW(path.as_ptr() as PCWSTR)
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
// Each exported name is a naked function that tail-jumps through its
// pointer, leaving the caller's stack and arguments exactly in place. The
// real function returns straight to our caller.

macro_rules! forward {
    ($name:ident, $target:ident) => {
        #[no_mangle]
        #[unsafe(naked)]
        pub extern "system" fn $name() {
            // A jmp through a pointer; no Rust state.
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

// The resolving stubs: the caller's arguments stay where they are on the
// stack; `resolve_all` is a call of our own below them (cdecl, no
// arguments, so the stack is as it was when it returns), and the jump then
// goes through the pointer it has written. eax, ecx and edx are the
// callee's to use under stdcall, so the caller expects nothing of them.
macro_rules! lazy {
    ($name:ident, $target:ident) => {
        #[unsafe(naked)]
        unsafe extern "system" fn $name() {
            core::arch::naked_asm!(
                "call {r}",
                "jmp dword ptr [{t}]",
                r = sym resolve_all,
                t = sym $target,
            );
        }
    };
}

lazy!(lazy_alphablend, REAL_ALPHABLEND);
lazy!(lazy_dllinitialize, REAL_DLLINITIALIZE);
lazy!(lazy_gradientfill, REAL_GRADIENTFILL);
lazy!(lazy_transparentblt, REAL_TRANSPARENTBLT);
lazy!(lazy_vsetddrawflag, REAL_VSETDDRAWFLAG);

// The failing stubs, for a genuine DLL that cannot be had: `FALSE`, with the
// stdcall arguments popped (AlphaBlend and TransparentBlt take 11, GradientFill
// 6, DllInitialize 3, vSetDdrawflag none).
macro_rules! fail {
    ($name:ident, $bytes:literal) => {
        #[unsafe(naked)]
        unsafe extern "system" fn $name() {
            core::arch::naked_asm!("xor eax, eax", concat!("ret ", $bytes));
        }
    };
}

fail!(fail_44, "44");
fail!(fail_24, "24");
fail!(fail_12, "12");

#[unsafe(naked)]
unsafe extern "system" fn fail_0() {
    core::arch::naked_asm!("xor eax, eax", "ret");
}
