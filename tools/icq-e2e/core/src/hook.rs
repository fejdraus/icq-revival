//! Winsock interception, installed by IAT-patching the client's own networking
//! module (coolcore59.dll on 7.2, coolcore49.dll on 6.5). We swap that module's
//! import thunks for `wsock32.dll!send/recv/connect/closesocket`, observe the
//! bytes, and always call the original with the data unchanged, returning its
//! result verbatim. Observation runs inside `catch_unwind`, so a parsing bug can
//! never reach the host.

use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetModuleHandleW};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
use windows_sys::Win32::System::Threading::{CreateThread, GetCurrentProcess, Sleep};

use crate::engine::Engine;
use crate::log;

type Socket = usize;

// Original function pointers, kept as raw addresses and transmuted on call.
static ORIG_SEND: AtomicUsize = AtomicUsize::new(0);
static ORIG_RECV: AtomicUsize = AtomicUsize::new(0);
static ORIG_CONNECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_CLOSE: AtomicUsize = AtomicUsize::new(0);

static INSTALLED: AtomicBool = AtomicBool::new(false);

// Log the first observed bytes in each direction once, so the log confirms the
// hooks are live even before any instant message is exchanged.
static FIRST_SEND: AtomicBool = AtomicBool::new(false);
static FIRST_RECV: AtomicBool = AtomicBool::new(false);

fn engine() -> &'static Mutex<Engine> {
    static E: OnceLock<Mutex<Engine>> = OnceLock::new();
    E.get_or_init(|| Mutex::new(Engine::new()))
}

// --- Winsock function types (all __stdcall on x86) --------------------------

type SendFn = unsafe extern "system" fn(Socket, *const u8, i32, i32) -> i32;
type RecvFn = unsafe extern "system" fn(Socket, *mut u8, i32, i32) -> i32;
type ConnectFn = unsafe extern "system" fn(Socket, *const u8, i32) -> i32;
type CloseFn = unsafe extern "system" fn(Socket) -> i32;

// --- hook bodies ------------------------------------------------------------

unsafe extern "system" fn hook_send(s: Socket, buf: *const u8, len: i32, flags: i32) -> i32 {
    let orig: SendFn = std::mem::transmute(ORIG_SEND.load(Ordering::Acquire));
    let n = orig(s, buf, len, flags);
    if n > 0 && !buf.is_null() {
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            let slice = std::slice::from_raw_parts(buf, n as usize);
            observe(s, slice, true);
        }));
    }
    n
}

unsafe extern "system" fn hook_recv(s: Socket, buf: *mut u8, len: i32, flags: i32) -> i32 {
    let orig: RecvFn = std::mem::transmute(ORIG_RECV.load(Ordering::Acquire));
    let n = orig(s, buf, len, flags);
    if n > 0 && !buf.is_null() {
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            let slice = std::slice::from_raw_parts(buf, n as usize);
            observe(s, slice, false);
        }));
    }
    n
}

unsafe extern "system" fn hook_connect(s: Socket, name: *const u8, namelen: i32) -> i32 {
    let orig: ConnectFn = std::mem::transmute(ORIG_CONNECT.load(Ordering::Acquire));
    let r = orig(s, name, namelen);
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let peer = parse_sockaddr(name, namelen);
        if let Ok(mut e) = engine().lock() {
            e.on_connect(s as u64, peer);
        }
    }));
    r
}

unsafe extern "system" fn hook_closesocket(s: Socket) -> i32 {
    let orig: CloseFn = std::mem::transmute(ORIG_CLOSE.load(Ordering::Acquire));
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        if let Ok(mut e) = engine().lock() {
            e.on_close(s as u64);
        }
    }));
    orig(s)
}

/// Feeds observed bytes to the engine and logs any decoded messages. Uses
/// `try_lock` so a re-entrant call (unlikely, but cheap to guard) is skipped
/// rather than deadlocking.
fn observe(s: Socket, bytes: &[u8], outbound: bool) {
    let first = if outbound { &FIRST_SEND } else { &FIRST_RECV };
    if !first.swap(true, Ordering::AcqRel) {
        log::line(&format!(
            "hook live: first {} bytes on socket {} (n={})",
            if outbound { "outbound" } else { "inbound" },
            s,
            bytes.len()
        ));
    }
    let lines = match engine().try_lock() {
        Ok(mut e) => {
            if outbound {
                e.on_send(s as u64, bytes)
            } else {
                e.on_recv(s as u64, bytes)
            }
        }
        Err(_) => return,
    };
    for line in lines {
        log::line(&line);
    }
}

/// Parses a sockaddr_in into "a.b.c.d:port" for log context. Returns None for
/// anything that is not a 4-byte IPv4 address.
unsafe fn parse_sockaddr(name: *const u8, namelen: i32) -> Option<String> {
    if name.is_null() || namelen < 8 {
        return None;
    }
    let sa = std::slice::from_raw_parts(name, namelen as usize);
    let family = u16::from_le_bytes([sa[0], sa[1]]);
    if family != 2 {
        // AF_INET only.
        return None;
    }
    let port = u16::from_be_bytes([sa[2], sa[3]]);
    Some(format!("{}.{}.{}.{}:{}", sa[4], sa[5], sa[6], sa[7], port))
}

// --- installation -----------------------------------------------------------

/// Starts a background thread that waits for the networking module to load and
/// then installs the hooks. Safe to call more than once; only the first install
/// takes effect. Called from each loader's DllMain.
pub fn start() {
    // SAFETY: CreateThread with a plain function; no captured state.
    unsafe {
        let h = CreateThread(
            ptr::null(),
            0,
            Some(install_thread),
            ptr::null(),
            0,
            ptr::null_mut(),
        );
        if !h.is_null() {
            windows_sys::Win32::Foundation::CloseHandle(h);
        }
    }
}

unsafe extern "system" fn install_thread(_: *mut core::ffi::c_void) -> u32 {
    log::line("install worker running; searching for the networking module (coolcore5x/4x)");
    // A quick sanity line comparing name-based lookups, since a wrong name/case
    // or ANSI-vs-wide lookup would explain a module that is loaded but not found.
    log_named_lookups();

    // The networking module may not be loaded yet (load order). Poll for it,
    // logging what happens at each stage.
    let mut warned_not_loaded = false;
    for attempt in 0..600u32 {
        if INSTALLED.load(Ordering::Acquire) {
            return 0;
        }
        match find_networking_module(attempt == 0) {
            Some((name, base)) => {
                log::line(&format!(
                    "networking module found: {name} at base {base:#010x}"
                ));
                match patch_iat(
                    base,
                    "wsock32.dll",
                    &[
                        // (name, wsock32 ordinal, hook, original-pointer slot).
                        // coolcore59.dll and coolcore49.dll import WSOCK32.dll by
                        // ordinal only, so the ordinal is what identifies a slot.
                        ("send", 19u16, hook_send as SendFn as usize, &ORIG_SEND),
                        ("recv", 16u16, hook_recv as RecvFn as usize, &ORIG_RECV),
                        (
                            "connect",
                            4u16,
                            hook_connect as ConnectFn as usize,
                            &ORIG_CONNECT,
                        ),
                        (
                            "closesocket",
                            3u16,
                            hook_closesocket as CloseFn as usize,
                            &ORIG_CLOSE,
                        ),
                    ],
                ) {
                    Ok(report) => {
                        if ORIG_SEND.load(Ordering::Acquire) != 0
                            && ORIG_RECV.load(Ordering::Acquire) != 0
                        {
                            INSTALLED.store(true, Ordering::Release);
                            log::line(&format!(
                                "hooks installed in {name}: {report}; observing BOS traffic"
                            ));
                        } else {
                            log::line(&format!(
                                "giving up: {name} parsed but send/recv thunks were not patched ({report})"
                            ));
                        }
                        return 0;
                    }
                    Err(reason) => {
                        log::line(&format!("giving up: could not patch {name}: {reason}"));
                        return 0;
                    }
                }
            }
            None => {
                if !warned_not_loaded {
                    log::line("networking module not loaded yet; waiting for it");
                    warned_not_loaded = true;
                } else if attempt % 100 == 0 && attempt > 0 {
                    log::line(&format!(
                        "still waiting for the networking module ({}s)",
                        attempt / 10
                    ));
                }
            }
        }
        Sleep(100);
    }
    log::line("gave up after 60s: no coolcore5x/4x module appeared among the loaded modules");
    0
}

/// Logs what name-based module lookups return, to catch a name/case or
/// ANSI-vs-wide mismatch directly.
fn log_named_lookups() {
    for name in [
        "coolcore59.dll",
        "coolcore49.dll",
        "coolcore59",
        "coolcore49",
    ] {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: valid NUL-terminated pointers for the duration of the calls.
        let hw = unsafe { GetModuleHandleW(w.as_ptr()) } as usize;
        let ha = match std::ffi::CString::new(name) {
            Ok(c) => (unsafe { GetModuleHandleA(c.as_ptr() as *const u8) }) as usize,
            Err(_) => 0,
        };
        log::line(&format!(
            "lookup {name:<16} GetModuleHandleW={hw:#010x} GetModuleHandleA={ha:#010x}"
        ));
    }
}

/// Enumerates the current process's loaded modules and returns the first whose
/// base name starts with "coolcore", together with its base address. When
/// `verbose` is set, logs the coolcore modules seen and the total module count,
/// so a wrong name never hides a module that is actually present.
fn find_networking_module(verbose: bool) -> Option<(String, usize)> {
    // SAFETY: standard psapi enumeration of our own process.
    unsafe {
        let proc = GetCurrentProcess();
        let mut mods = [core::ptr::null_mut::<core::ffi::c_void>(); 1024];
        let mut needed: u32 = 0;
        let cb = (mods.len() * core::mem::size_of::<HMODULE>()) as u32;
        if EnumProcessModules(proc, mods.as_mut_ptr() as *mut HMODULE, cb, &mut needed) == 0 {
            if verbose {
                log::line("EnumProcessModules failed; cannot enumerate loaded modules");
            }
            return None;
        }
        let count = ((needed as usize) / core::mem::size_of::<HMODULE>()).min(mods.len());
        let mut coolcore: Vec<String> = Vec::new();
        let mut hit: Option<(String, usize)> = None;
        for &h in mods.iter().take(count) {
            let mut buf = [0u16; 260];
            let n = GetModuleBaseNameW(proc, h as HMODULE, buf.as_mut_ptr(), buf.len() as u32);
            if n == 0 {
                continue;
            }
            let name = String::from_utf16_lossy(&buf[..n as usize]);
            if name.to_ascii_lowercase().starts_with("coolcore") {
                coolcore.push(name.clone());
                if hit.is_none() {
                    hit = Some((name.clone(), h as usize));
                }
            }
        }
        if verbose {
            log::line(&format!(
                "loaded modules: {count}; coolcore modules: [{}]",
                if coolcore.is_empty() {
                    "none".to_string()
                } else {
                    coolcore.join(", ")
                }
            ));
        }
        hit
    }
}

/// Patches the named module's import thunks for the given functions of `dll`.
/// Returns a report string of what was patched, or an error reason. Logs the
/// intermediate findings so a partial or failed patch is explained.
fn patch_iat(
    base: usize,
    dll: &str,
    funcs: &[(&str, u16, usize, &AtomicUsize)],
) -> Result<String, String> {
    // SAFETY: base is a loaded module; all reads are bounds-guarded by the PE
    // structure and stay within the mapped image.
    unsafe {
        let rd32 = |off: usize| ptr::read_unaligned((base + off) as *const u32);
        if rd32(0) & 0xFFFF != 0x5A4D {
            return Err("no MZ signature".to_string());
        }
        let e_lfanew = ptr::read_unaligned((base + 0x3C) as *const u32) as usize;
        if rd32(e_lfanew) != 0x0000_4550 {
            return Err("no PE signature".to_string());
        }
        let magic = ptr::read_unaligned((base + e_lfanew + 0x18) as *const u16);
        if magic != 0x010B {
            return Err(format!("not PE32 (optional header magic {magic:#06x})"));
        }
        let import_rva = rd32(e_lfanew + 0x80) as usize;
        if import_rva == 0 {
            return Err("no import directory".to_string());
        }
        let mut imported_dlls: Vec<String> = Vec::new();
        let mut dll_found = false;
        let mut matched: Vec<&str> = Vec::new();
        let mut desc = base + import_rva;
        loop {
            let name_rva = ptr::read_unaligned((desc + 12) as *const u32) as usize;
            let first_thunk = ptr::read_unaligned((desc + 16) as *const u32) as usize;
            if name_rva == 0 && first_thunk == 0 {
                break;
            }
            let dll_name = read_cstr(base + name_rva);
            imported_dlls.push(dll_name.clone());
            if dll_name.eq_ignore_ascii_case(dll) {
                dll_found = true;
                let orig_thunk = ptr::read_unaligned(desc as *const u32) as usize;
                let int_rva = if orig_thunk != 0 {
                    orig_thunk
                } else {
                    first_thunk
                };
                let by_int = orig_thunk != 0; // names come from the INT (unbound)
                let mut i = 0usize;
                loop {
                    let int_entry = ptr::read_unaligned((base + int_rva + i * 4) as *const u32);
                    if int_entry == 0 {
                        break;
                    }
                    // The INT is present for every wsock32 import in these
                    // clients, but the entries are ordinal imports (high bit
                    // set), not names - so match on the ordinal number.
                    if by_int {
                        let (fname, hook, orig_slot) = if int_entry & 0x8000_0000 == 0 {
                            let name_ptr = base + int_entry as usize + 2;
                            match funcs
                                .iter()
                                .find(|(fname, _, _, _)| cstr_eq_ci(name_ptr, fname))
                            {
                                Some(f) => (f.0, f.2, f.3),
                                None => {
                                    i += 1;
                                    continue;
                                }
                            }
                        } else {
                            let ordinal = (int_entry & 0x7FFF_FFFF) as u16;
                            match funcs.iter().find(|(_, want, _, _)| *want == ordinal) {
                                Some(f) => (f.0, f.2, f.3),
                                None => {
                                    i += 1;
                                    continue;
                                }
                            }
                        };
                        let slot = base + first_thunk + i * 4;
                        if write_thunk(slot, hook, orig_slot) {
                            matched.push(fname);
                        }
                    }
                    i += 1;
                }
            }
            desc += 20;
        }
        if !dll_found {
            return Err(format!(
                "{dll} not among imports of the module; imports seen: [{}]",
                imported_dlls.join(", ")
            ));
        }
        if matched.is_empty() {
            return Err(format!(
                "{dll} imported but no send/recv/connect/closesocket thunk matched (bound or ordinal imports?)"
            ));
        }
        Ok(format!("patched [{}]", matched.join(", ")))
    }
}

/// Reads a NUL-terminated ASCII C string at `ptr` into a String.
unsafe fn read_cstr(ptr: usize) -> String {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        let c = ptr::read_unaligned((ptr + i) as *const u8);
        if c == 0 || i > 260 {
            break;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Saves the current thunk value into `orig_slot` and writes `hook` in its
/// place. Returns true on success.
unsafe fn write_thunk(slot: usize, hook: usize, orig_slot: &AtomicUsize) -> bool {
    let current = ptr::read_unaligned(slot as *const u32) as usize;
    if current == hook {
        return true; // already ours
    }
    let addr = slot as *const core::ffi::c_void;
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    if VirtualProtect(addr, 4, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return false;
    }
    orig_slot.store(current, Ordering::Release);
    ptr::write_unaligned(slot as *mut u32, hook as u32);
    let mut tmp: PAGE_PROTECTION_FLAGS = 0;
    let _ = VirtualProtect(addr, 4, old, &mut tmp);
    true
}

/// Case-insensitive comparison of a NUL-terminated C string at `ptr` with `s`.
unsafe fn cstr_eq_ci(ptr: usize, s: &str) -> bool {
    let bytes = s.as_bytes();
    for (i, &want) in bytes.iter().enumerate() {
        let c = ptr::read_unaligned((ptr + i) as *const u8);
        if c == 0 {
            return false;
        }
        if c.to_ascii_lowercase() != want.to_ascii_lowercase() {
            return false;
        }
    }
    ptr::read_unaligned((ptr + bytes.len()) as *const u8) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// wsock32.dll exports the Winsock 1.1 entry points by these ordinals; both
    /// coolcore59.dll and coolcore49.dll import them that way (no names).
    const ORD_SEND: u16 = 19;
    const ORD_RECV: u16 = 16;
    const ORD_CONNECT: u16 = 4;
    const ORD_CLOSE: u16 = 3;

    /// An entry in an import lookup table: a name is an RVA to a hint/name
    /// struct; an ordinal import has the high bit set with the ordinal below.
    fn named_entry(rva: usize) -> u32 {
        rva as u32
    }

    fn ordinal_entry(ordinal: u16) -> u32 {
        0x8000_0000 | ordinal as u32
    }

    /// Builds a minimal PE32 image whose single import descriptor points at
    /// `dll_name` with `entries` in both the INT and the IAT, and returns the
    /// image bytes plus the RVA the image is mapped at.
    fn synthetic_pe(dll_name: &str, entries: &[u32]) -> Vec<u8> {
        const IMAGE_BASE_RVA: usize = 0x1000;
        let mut img = vec![0u8; 0x4000];

        // DOS header: MZ, e_lfanew -> 0x80.
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature + COFF header (i386).
        img[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        img[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        // Optional header magic PE32.
        img[0x80 + 0x18..0x80 + 0x1A].copy_from_slice(&0x010Bu16.to_le_bytes());
        // Import directory RVA -> data directory entry 1.
        let import_rva = IMAGE_BASE_RVA;
        img[0x80 + 0x80..0x80 + 0x84].copy_from_slice(&(import_rva as u32).to_le_bytes());

        // Import descriptor: name, INT, IAT, all at known RVAs.
        let name_rva = IMAGE_BASE_RVA + 0x40;
        let int_rva = IMAGE_BASE_RVA + 0x80;
        let iat_rva = IMAGE_BASE_RVA + 0x100;
        img[import_rva + 12..import_rva + 16].copy_from_slice(&(name_rva as u32).to_le_bytes());
        img[import_rva + 16..import_rva + 20].copy_from_slice(&(iat_rva as u32).to_le_bytes());
        img[import_rva..import_rva + 4].copy_from_slice(&(int_rva as u32).to_le_bytes());

        img[name_rva..name_rva + dll_name.len()].copy_from_slice(dll_name.as_bytes());
        img[name_rva + dll_name.len()] = 0;

        for (i, e) in entries.iter().enumerate() {
            img[int_rva + i * 4..int_rva + i * 4 + 4].copy_from_slice(&e.to_le_bytes());
            // IAT is pre-filled with a recognisable fake address; write_thunk
            // must overwrite it.
            img[iat_rva + i * 4..iat_rva + i * 4 + 4]
                .copy_from_slice(&(0x7FFF_0000u32 + i as u32).to_le_bytes());
        }
        // Both tables are NUL-terminated.
        let n = entries.len();
        img[int_rva + n * 4..int_rva + n * 4 + 4].copy_from_slice(&0u32.to_le_bytes());
        img[iat_rva + n * 4..iat_rva + n * 4 + 4].copy_from_slice(&0u32.to_le_bytes());

        img
    }

    fn funcs_table() -> Vec<(&'static str, u16, usize, &'static AtomicUsize)> {
        // Hook addresses are arbitrary distinct non-zero values; only that they
        // differ from the IAT contents matters.
        vec![
            ("send", ORD_SEND, 0x1000_1000, &ORIG_SEND),
            ("recv", ORD_RECV, 0x1000_2000, &ORIG_RECV),
            ("connect", ORD_CONNECT, 0x1000_3000, &ORIG_CONNECT),
            ("closesocket", ORD_CLOSE, 0x1000_4000, &ORIG_CLOSE),
        ]
    }

    /// The real shape of coolcore59.dll: every wsock32 import is by ordinal, so
    /// name matching must not be required and every slot must be found.
    #[test]
    fn ordinal_imports_are_patched() {
        let img = synthetic_pe(
            "WSOCK32.dll",
            &[
                ordinal_entry(ORD_CONNECT),
                ordinal_entry(ORD_CLOSE),
                ordinal_entry(11), // inet_addr - not hooked
                ordinal_entry(ORD_RECV),
                ordinal_entry(ORD_SEND),
            ],
        );
        let funcs = funcs_table();
        let report = patch_iat(img.as_ptr() as usize, "wsock32.dll", &funcs)
            .expect("ordinal imports should be patched");
        assert_eq!(report, "patched [connect, closesocket, recv, send]");

        // The IAT now holds the hook addresses; the pre-patch addresses were
        // saved into the ORIG_* slots (asserted below).
        let iat = 0x1000 + 0x100;
        let slot = |i: usize| iat + i * 4;

        assert_eq!(ORIG_SEND.load(Ordering::Acquire), 0x7FFF_0004);
        assert_eq!(ORIG_RECV.load(Ordering::Acquire), 0x7FFF_0003);
        assert_eq!(ORIG_CONNECT.load(Ordering::Acquire), 0x7FFF_0000);
        assert_eq!(ORIG_CLOSE.load(Ordering::Acquire), 0x7FFF_0001);

        // The IAT itself now holds the hook addresses.
        let patched =
            |i: usize| u32::from_le_bytes(img[slot(i)..slot(i) + 4].try_into().unwrap()) as usize;
        assert_eq!(patched(0), 0x1000_3000);
        assert_eq!(patched(1), 0x1000_4000);
        assert_eq!(patched(3), 0x1000_2000);
        assert_eq!(patched(4), 0x1000_1000);

        ORIG_SEND.store(0, Ordering::Release);
        ORIG_RECV.store(0, Ordering::Release);
        ORIG_CONNECT.store(0, Ordering::Release);
        ORIG_CLOSE.store(0, Ordering::Release);
    }

    /// A named import (the shape some modules use) must still be matched by
    /// name, so the ordinal path did not regress the existing behaviour.
    #[test]
    fn named_imports_are_still_patched() {
        let mut img = synthetic_pe("WSOCK32.dll", &[named_entry(0x200), named_entry(0x240)]);
        // Write the two hint/name structs the INT points at.
        let put = |img: &mut Vec<u8>, rva: usize, name: &str| {
            img[rva..rva + 2].copy_from_slice(&0u16.to_le_bytes());
            img[rva + 2..rva + 2 + name.len()].copy_from_slice(name.as_bytes());
            img[rva + 2 + name.len()] = 0;
        };
        put(&mut img, 0x200, "send");
        put(&mut img, 0x240, "recv");

        let funcs = funcs_table();
        let report = patch_iat(img.as_ptr() as usize, "wsock32.dll", &funcs)
            .expect("named imports should be patched");
        assert_eq!(report, "patched [send, recv]");

        ORIG_SEND.store(0, Ordering::Release);
        ORIG_RECV.store(0, Ordering::Release);
        ORIG_CONNECT.store(0, Ordering::Release);
        ORIG_CLOSE.store(0, Ordering::Release);
    }

    /// A wsock32 import that contains none of the hooked ordinals must be
    /// reported as unmatched rather than silently "succeeding".
    #[test]
    fn unrelated_ordinals_do_not_patch() {
        let img = synthetic_pe("WSOCK32.dll", &[ordinal_entry(11), ordinal_entry(12)]);
        let funcs = funcs_table();
        let err = patch_iat(img.as_ptr() as usize, "wsock32.dll", &funcs)
            .expect_err("no hooked ordinal is present");
        assert!(
            err.contains("no send/recv/connect/closesocket thunk matched"),
            "{err}"
        );
    }
}
