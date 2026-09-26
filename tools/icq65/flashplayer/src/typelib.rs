//! The embedded type library (resource TYPELIB #1, built from typelib\flash.idl)
//! and its per-user registration.

use std::cell::Cell;
use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{E_FAIL, S_OK};
use windows_sys::Win32::System::Com::SYS_WIN32;
use windows_sys::Win32::System::Ole::{
    LoadTypeLibEx, REGKIND_NONE, RegisterTypeLibForUser, UnRegisterTypeLibForUser,
};
use windows_sys::core::{GUID, HRESULT};

use crate::com::{IID_ISHOCKWAVEFLASH, LIBID_SHOCKWAVEFLASHOBJECTS, com_release, vcall};

type Unk = *mut c_void;

thread_local! {
    static INFOS: Cell<Option<(Unk, Unk)>> = const { Cell::new(None) };
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Loads the type library from `path` (a .tlb, or a module with a TYPELIB resource).
pub fn load(path: &str) -> Result<Unk, HRESULT> {
    let mut lib: Unk = null_mut();
    let w = wide(path);
    let hr = unsafe { LoadTypeLibEx(w.as_ptr(), REGKIND_NONE, (&mut lib as *mut Unk).cast()) };
    if hr < 0 || lib.is_null() {
        Err(hr)
    } else {
        Ok(lib)
    }
}

/// (dispatch view, interface view) of IShockwaveFlash from a type library.
unsafe fn shockwave_infos(lib: Unk) -> Result<(Unk, Unk), HRESULT> {
    unsafe {
        let mut disp: Unk = null_mut();
        let hr = vcall!(
            lib,
            6,
            fn(*const GUID, *mut Unk) -> HRESULT,
            &IID_ISHOCKWAVEFLASH,
            &mut disp
        );
        if hr < 0 {
            return Err(hr);
        }
        let mut href: u32 = 0;
        let hr = vcall!(disp, 8, fn(u32, *mut u32) -> HRESULT, u32::MAX, &mut href);
        if hr < 0 {
            return Ok((disp, null_mut()));
        }
        let mut iface: Unk = null_mut();
        let hr = vcall!(disp, 14, fn(u32, *mut Unk) -> HRESULT, href, &mut iface);
        Ok((disp, if hr < 0 { null_mut() } else { iface }))
    }
}

fn infos() -> (Unk, Unk) {
    if let Some(v) = INFOS.with(|c| c.get()) {
        return v;
    }
    let v = load(&crate::module_path())
        .ok()
        .and_then(|lib| {
            let r = unsafe { shockwave_infos(lib) }.ok();
            unsafe { com_release(lib) };
            r
        })
        .unwrap_or((null_mut(), null_mut()));
    INFOS.with(|c| c.set(Some(v)));
    v
}

/// ITypeInfo of IShockwaveFlash as a dispinterface (for GetTypeInfo).
pub fn dispatch_info() -> Unk {
    infos().0
}

/// ITypeInfo of IShockwaveFlash as a vtable interface (for DispInvoke).
pub fn interface_info() -> Unk {
    infos().1
}

/// Registers the embedded type library for the current user (HKCU only).
pub fn register() -> HRESULT {
    let path = crate::module_path();
    let lib = match load(&path) {
        Ok(l) => l,
        Err(hr) => return hr,
    };
    let w = wide(&path);
    let hr = unsafe { RegisterTypeLibForUser(lib.cast(), w.as_ptr(), std::ptr::null()) };
    unsafe { com_release(lib) };
    hr
}

pub fn unregister() -> HRESULT {
    let hr = unsafe { UnRegisterTypeLibForUser(&LIBID_SHOCKWAVEFLASHOBJECTS, 1, 0, 0, SYS_WIN32) };
    // Already gone counts as success.
    if hr == 0x8002801Cu32 as i32 || hr == 0x80029C4Au32 as i32 || hr == E_FAIL {
        S_OK
    } else {
        hr
    }
}

/// For the unit test: (name, 32-bit argument count) of every vtable slot of
/// IShockwaveFlash as the type library describes it.
#[cfg(test)]
pub fn tests_slot_arg_dwords(tlb: &str) -> Vec<(String, u32)> {
    use windows_sys::Win32::System::Com::{FUNCDESC, TYPEATTR};
    let lib = load(tlb).expect("load tlb");
    let (disp, iface) = unsafe { shockwave_infos(lib) }.expect("IShockwaveFlash");
    assert!(!iface.is_null());
    let mut slots: Vec<(String, u32)> = (0..7).map(|_| (String::from("<IDispatch>"), 0)).collect();
    unsafe {
        let mut attr: *mut TYPEATTR = null_mut();
        assert!(vcall!(iface, 3, fn(*mut *mut TYPEATTR) -> HRESULT, &mut attr) >= 0);
        let n = (*attr).cFuncs as u32;
        vcall!(iface, 19, fn(*mut TYPEATTR) -> (), attr);
        for i in 0..n {
            let mut fd: *mut FUNCDESC = null_mut();
            assert!(vcall!(iface, 5, fn(u32, *mut *mut FUNCDESC) -> HRESULT, i, &mut fd) >= 0);
            let f = &*fd;
            let mut name: *const u16 = std::ptr::null();
            vcall!(
                iface,
                12,
                fn(i32, *mut *const u16, *mut c_void, *mut c_void, *mut c_void) -> HRESULT,
                f.memid,
                &mut name,
                null_mut(),
                null_mut(),
                null_mut()
            );
            let name = crate::com::bstr_to_string(name);
            let mut dwords = 0;
            for p in 0..f.cParams as usize {
                let vt = (*f.lprgelemdescParam.add(p)).tdesc.vt;
                dwords += match vt {
                    5 | 6 | 7 | 20 | 21 => 2, // R8, CY, DATE, I8, UI8
                    12 => 4,                  // VARIANT by value
                    _ => 1,
                };
            }
            let slot = f.oVft as usize / size_of::<usize>();
            if slots.len() <= slot {
                slots.resize(slot + 1, (String::new(), 0));
            }
            slots[slot] = (name, dwords);
            vcall!(iface, 20, fn(*mut FUNCDESC) -> (), fd);
        }
        com_release(iface);
        com_release(disp);
        com_release(lib);
    }
    slots
}
