//! ICQ 7.2 loader stub, shipped as `tbdiag.dll`.
//!
//! ICQ.exe (build 3525) loads `tbdiag.dll` from its own folder very early, when
//! `aolload.exe` is present, with `LoadLibraryExA` (verified by disassembly of
//! the 3525 ICQ.exe startup path). It then resolves the AOL "feature counter"
//! (`FC*`) telemetry exports with `GetProcAddress` and calls them **cdecl**
//! (the caller cleans the stack). The stock module crashes ICQ 7, which is why
//! the patch renames it aside; this replacement takes its slot.
//!
//! We do two things in `DllMain(DLL_PROCESS_ATTACH)`:
//!   1. pin our own module so the client's later `FreeLibrary` cannot unload the
//!      code the installed hooks and the worker thread live in;
//!   2. start the E2E add-on (icqe2e_core::install), which under the loader
//!      lock only registers its loader notification, patches a networking
//!      module that is already mapped and creates its bootstrap thread; the
//!      settings, the log and everything else wait for that thread, which
//!      runs once the lock is released (fourth review, finding H).
//!
//! We also export the `FC*` names as harmless cdecl stubs so the client's probe
//! succeeds (FCLibraryVersion reports a recent version, init returns success)
//! and never takes its "diagnostics unavailable" cleanup path.

use windows_sys::Win32::Foundation::{HINSTANCE, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_PIN,
};

const DLL_PROCESS_ATTACH: u32 = 1;

#[no_mangle]
pub extern "system" fn DllMain(
    hinst: HINSTANCE,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        // SAFETY: standard DllMain calls; the address handed to
        // GetModuleHandleExW lies inside this module.
        unsafe {
            DisableThreadLibraryCalls(hinst as HMODULE);
            pin_self();
        }
        icqe2e_core::install();
    }
    1
}

/// Pins this module in memory so the client's reference-counted FreeLibrary of
/// tbdiag.dll cannot unload it while our hooks are live.
unsafe fn pin_self() {
    let mut h: HMODULE = core::ptr::null_mut();
    let addr = DllMain as *const () as *const u16;
    let _ = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        addr,
        &mut h,
    );
}

// --- FC* telemetry stubs (cdecl; caller cleans the stack) -------------------
//
// The client calls these with varying argument counts, but cdecl means the
// caller restores the stack, so a zero-argument stub is safe for any of them.
// FCLibraryVersion must report >= 6 or the client tears the module down; the
// initialise functions must return 0 (success). All others return 0.

macro_rules! fc_ok {
    ($name:ident) => {
        #[no_mangle]
        pub extern "C" fn $name() -> u32 {
            0
        }
    };
}

#[no_mangle]
pub extern "C" fn FCLibraryVersion() -> u32 {
    8
}

fc_ok!(FCInitializeWithManifestInternal);
fc_ok!(FCInitializeWithManifestInternalEx);
fc_ok!(FCCreateKey);
fc_ok!(FCSetKeyOptions);
fc_ok!(FCCreatePersistentKey);
fc_ok!(FCCreateCounter);
fc_ok!(FCCreatePersistentCounter);
fc_ok!(FCFlushNonSharedPersistentKeys);
fc_ok!(FCAddDataToKey);
fc_ok!(FCDeleteDataFromKey);
fc_ok!(FCAddIntToKey);
fc_ok!(FCDeleteIntFromKey);
fc_ok!(FCAddStringToKey);
fc_ok!(FCDeleteStringFromKey);
fc_ok!(FCRegisterMemory);
fc_ok!(FCUnregisterMemory);
fc_ok!(FCAddDateToKey);
fc_ok!(FCDeleteDateFromKey);
fc_ok!(FCSetCounter);
fc_ok!(FCIncrementCounter);
fc_ok!(FCDecrementCounter);
fc_ok!(FCGetCounter);
fc_ok!(FCCreateSupportIncidentInternal);
fc_ok!(FCTraceInternal);
fc_ok!(FCTraceParamInternal);
fc_ok!(FCCleanup);
fc_ok!(FCOrphanLoadCount);
fc_ok!(FCSetMiniDump);
fc_ok!(FCExceptionHandler);
fc_ok!(FCSetUIState);
fc_ok!(FCClearKeys);
fc_ok!(FCClearCounters);
fc_ok!(FCClearKey);
fc_ok!(FCDeleteKey);
fc_ok!(FCStartTimer);
fc_ok!(FCHeartbeatTimer);
fc_ok!(FCEndTimer);
fc_ok!(FCGetSessionUniqueID);
fc_ok!(FCSetLocale);
fc_ok!(FCRunMemTest);
fc_ok!(FCAssertInternal1);
fc_ok!(FCAssertParamInternal1);
fc_ok!(FCTriggerInternal1);
