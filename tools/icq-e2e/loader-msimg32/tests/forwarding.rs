//! The built `msimg32.dll`, loaded by its full path into this process, as
//! ICQ 6.5 loads it: its exports reach the genuine `system32\msimg32.dll`
//! through the lazy stubs (fourth review, finding H: nothing is loaded in
//! `DllMain` any more), with the caller's stack intact.

use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

type AlphaBlendFn =
    unsafe extern "system" fn(usize, i32, i32, i32, i32, usize, i32, i32, i32, i32, u32) -> i32;
type GradientFillFn = unsafe extern "system" fn(usize, *const u8, u32, *const u8, u32, u32) -> i32;

#[test]
fn the_exports_reach_the_genuine_dll_with_the_stack_intact() {
    // Observe mode: the add-on this DLL starts only watches, and with no
    // client's networking module in this process it never blocks anything.
    // SAFETY: set before the DLL (and any other thread of this test) reads it.
    unsafe { std::env::set_var("ICQE2E_MODE", "observe") };
    let dll = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("msimg32.dll");
    assert!(dll.is_file(), "{} is built", dll.display());
    let wide: Vec<u16> = dll.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: loading our own DLL by its full path, and calling its exports
    // with the documented signatures and null device contexts, which the
    // genuine functions refuse with FALSE.
    unsafe {
        let h = LoadLibraryW(wide.as_ptr());
        assert!(!h.is_null(), "the proxy loads");
        let ab: AlphaBlendFn =
            std::mem::transmute(GetProcAddress(h, c"AlphaBlend".as_ptr().cast()).unwrap());
        let gf: GradientFillFn =
            std::mem::transmute(GetProcAddress(h, c"GradientFill".as_ptr().cast()).unwrap());
        // Many calls, before and after the bootstrap thread resolved the
        // exports: a stub that popped the wrong number of bytes would have
        // crashed by the end.
        let marker = [0x5Au8; 64];
        for i in 0..2000 {
            assert_eq!(ab(0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0x00FF_0000), 0);
            assert_eq!(gf(0, std::ptr::null(), 0, std::ptr::null(), 0, 0), 0);
            if i == 10 {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        assert!(
            marker.iter().all(|&b| b == 0x5A),
            "the caller's stack is intact"
        );
    }
}
