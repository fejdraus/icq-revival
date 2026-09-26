//! The COM object the client gets through message 0x1401: IShockwaveFlash
//! (dual) plus IConnectionPointContainer / IConnectionPoint for
//! _IShockwaveFlashEvents.
//!
//! The object is written by hand: three vtable pointers at the start of one
//! allocation, one per interface. Methods that ICQ does not need return
//! E_NOTIMPL, but every slot takes the right number of stack arguments, since
//! a __stdcall callee pops its own arguments.

use std::cell::Cell;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{
    E_INVALIDARG, E_NOINTERFACE, E_NOTIMPL, E_POINTER, HWND, S_OK, SysAllocString, SysStringLen,
};
use windows_sys::core::{GUID, HRESULT};

use crate::instance;

pub const IID_ISHOCKWAVEFLASH: GUID = GUID::from_u128(0xD27CDB6C_AE6D_11cf_96B8_444553540000);
pub const DIID_ISHOCKWAVEFLASHEVENTS: GUID =
    GUID::from_u128(0xD27CDB6D_AE6D_11cf_96B8_444553540000);
pub const LIBID_SHOCKWAVEFLASHOBJECTS: GUID =
    GUID::from_u128(0xD27CDB6B_AE6D_11cf_96B8_444553540000);
const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_C000_000000000046);
const IID_IDISPATCH: GUID = GUID::from_u128(0x00020400_0000_0000_C000_000000000046);
const IID_ICONNECTIONPOINTCONTAINER: GUID = GUID::from_u128(0xB196B284_BAB4_101A_B69C_00AA00341D07);
const IID_ICONNECTIONPOINT: GUID = GUID::from_u128(0xB196B286_BAB4_101A_B69C_00AA00341D07);
const IID_NULL: GUID = GUID::from_u128(0);

const CONNECT_E_NOCONNECTION: HRESULT = 0x80040200u32 as i32;
const CONNECT_E_ADVISELIMIT: HRESULT = 0x80040201u32 as i32;
const CONNECT_E_CANNOTCONNECT: HRESULT = 0x80040202u32 as i32;

pub const DISPID_READYSTATECHANGE: i32 = -609;
pub const DISPID_FSCOMMAND: i32 = 0x96;

const VARIANT_TRUE: i16 = -1;
const VARIANT_FALSE: i16 = 0;

pub const VT_I4: u16 = 3;
pub const VT_BSTR: u16 = 8;

/// A VARIANT as laid out on x86 (16 bytes).
#[repr(C)]
pub struct Variant {
    pub vt: u16,
    pub reserved: [u16; 3],
    pub value: u64,
}

#[repr(C)]
struct DispParams {
    rgvarg: *mut Variant,
    rgdispid_named_args: *mut i32,
    c_args: u32,
    c_named_args: u32,
}

type Unk = *mut c_void;

/// Calls method `slot` of COM interface `p`.
macro_rules! vcall {
    ($p:expr, $slot:expr, fn($($t:ty),* $(,)?) -> $r:ty $(, $a:expr)* $(,)?) => {{
        let p: *mut c_void = $p;
        let vtbl = *(p as *const *const usize);
        let f: unsafe extern "system" fn(*mut c_void $(, $t)*) -> $r =
            std::mem::transmute(*vtbl.add($slot));
        f(p $(, $a)*)
    }};
}
pub(crate) use vcall;

pub unsafe fn com_release(p: Unk) {
    if !p.is_null() {
        unsafe { vcall!(p, 2, fn() -> u32,) };
    }
}

unsafe fn com_addref(p: Unk) {
    if !p.is_null() {
        unsafe { vcall!(p, 1, fn() -> u32,) };
    }
}

#[repr(C)]
pub struct FlashObject {
    sf_vtbl: *const usize,
    cpc_vtbl: *const CpcVtbl,
    cp_vtbl: *const CpVtbl,
    refs: AtomicU32,
    /// The window this object controls; null once the window is gone.
    pub hwnd: Cell<HWND>,
    /// The advised event sink (an AddRef'd IDispatch), or null.
    sink: Cell<Unk>,
    cookie: Cell<u32>,
    loop_: Cell<bool>,
}

const PTR: usize = size_of::<usize>();

impl FlashObject {
    /// A new object with one reference, owned by the caller.
    pub fn create(hwnd: HWND) -> *mut FlashObject {
        Box::into_raw(Box::new(FlashObject {
            sf_vtbl: sf_vtbl(),
            cpc_vtbl: &CPC_VTBL,
            cp_vtbl: &CP_VTBL,
            refs: AtomicU32::new(1),
            hwnd: Cell::new(hwnd),
            sink: Cell::new(null_mut()),
            cookie: Cell::new(0),
            loop_: Cell::new(true),
        }))
    }

    unsafe fn from_sf<'a>(this: *mut c_void) -> &'a FlashObject {
        unsafe { &*(this as *const FlashObject) }
    }
    unsafe fn from_cpc<'a>(this: *mut c_void) -> &'a FlashObject {
        unsafe { &*((this as *const u8).sub(PTR) as *const FlashObject) }
    }
    unsafe fn from_cp<'a>(this: *mut c_void) -> &'a FlashObject {
        unsafe { &*((this as *const u8).sub(2 * PTR) as *const FlashObject) }
    }

    fn base(&self) -> *mut c_void {
        self as *const _ as *mut c_void
    }

    pub unsafe fn query(&self, iid: &GUID, out: *mut Unk) -> HRESULT {
        if out.is_null() {
            return E_POINTER;
        }
        let base = self.base() as *mut u8;
        let p = if guid_eq(iid, &IID_IUNKNOWN)
            || guid_eq(iid, &IID_IDISPATCH)
            || guid_eq(iid, &IID_ISHOCKWAVEFLASH)
        {
            base
        } else if guid_eq(iid, &IID_ICONNECTIONPOINTCONTAINER) {
            unsafe { base.add(PTR) }
        } else if guid_eq(iid, &IID_ICONNECTIONPOINT) {
            unsafe { base.add(2 * PTR) }
        } else {
            unsafe { *out = null_mut() };
            return E_NOINTERFACE;
        };
        self.refs.fetch_add(1, Ordering::Relaxed);
        unsafe { *out = p as Unk };
        S_OK
    }

    fn add_ref(&self) -> u32 {
        self.refs.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Drops one reference; frees the object at zero.
    pub unsafe fn release(this: *const FlashObject) -> u32 {
        let left = unsafe { (*this).refs.fetch_sub(1, Ordering::AcqRel) } - 1;
        if left == 0 {
            let obj = unsafe { Box::from_raw(this as *mut FlashObject) };
            unsafe { com_release(obj.sink.replace(null_mut())) };
        }
        left
    }

    /// Releases the event sink (window destroyed).
    pub fn drop_sink(&self) {
        unsafe { com_release(self.sink.replace(null_mut())) };
    }

    /// Calls the sink's IDispatch::Invoke with `args` (last argument first).
    pub fn fire(&self, dispid: i32, args: &mut [Variant]) {
        let sink = self.sink.get();
        if sink.is_null() {
            return;
        }
        unsafe {
            com_addref(sink);
            let mut params = DispParams {
                rgvarg: args.as_mut_ptr(),
                rgdispid_named_args: null_mut(),
                c_args: args.len() as u32,
                c_named_args: 0,
            };
            let hr = vcall!(
                sink,
                6,
                fn(
                    i32,
                    *const GUID,
                    u32,
                    u16,
                    *mut DispParams,
                    *mut Variant,
                    *mut c_void,
                    *mut u32,
                ) -> HRESULT,
                dispid,
                &IID_NULL,
                0x0400,
                1,
                &mut params,
                null_mut(),
                null_mut(),
                null_mut()
            );
            if hr < 0 {
                crate::log(&format!("event {dispid} Invoke failed: {hr:#x}"));
            }
            com_release(sink);
        }
    }

    pub fn fire_ready_state(&self, state: i32) {
        let mut args = [Variant {
            vt: VT_I4,
            reserved: [0; 3],
            value: state as u32 as u64,
        }];
        self.fire(DISPID_READYSTATECHANGE, &mut args);
    }

    pub fn fire_fscommand(&self, command: &str, args: &str) {
        let mut v = [bstr_variant(args), bstr_variant(command)];
        self.fire(DISPID_FSCOMMAND, &mut v);
        for x in &mut v {
            unsafe { free_bstr(x.value as usize as *const u16) };
        }
    }
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

pub fn bstr(s: &str) -> *const u16 {
    let w: Vec<u16> = s.encode_utf16().chain(Some(0)).collect();
    unsafe { SysAllocString(w.as_ptr()) }
}

unsafe fn free_bstr(b: *const u16) {
    unsafe { windows_sys::Win32::Foundation::SysFreeString(b) };
}

fn bstr_variant(s: &str) -> Variant {
    Variant {
        vt: VT_BSTR,
        reserved: [0; 3],
        value: bstr(s) as usize as u64,
    }
}

pub unsafe fn bstr_to_string(b: *const u16) -> String {
    if b.is_null() {
        return String::new();
    }
    let len = unsafe { SysStringLen(b) } as usize;
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(b, len) })
}

// ---------------------------------------------------------------------------
// IUnknown / IDispatch for the IShockwaveFlash pointer

unsafe extern "system" fn sf_query(this: Unk, iid: *const GUID, out: *mut Unk) -> HRESULT {
    crate::ffi_guard("sf_query", windows_sys::Win32::Foundation::E_FAIL, || {
        if iid.is_null() {
            return E_POINTER;
        }
        unsafe { FlashObject::from_sf(this).query(&*iid, out) }
    })
}
unsafe extern "system" fn sf_addref(this: Unk) -> u32 {
    crate::ffi_guard("sf_addref", 0, || unsafe {
        FlashObject::from_sf(this).add_ref()
    })
}
unsafe extern "system" fn sf_release(this: Unk) -> u32 {
    crate::ffi_guard("sf_release", 0, || unsafe {
        FlashObject::release(FlashObject::from_sf(this))
    })
}

unsafe extern "system" fn sf_get_type_info_count(_this: Unk, n: *mut u32) -> HRESULT {
    crate::ffi_guard(
        "sf_get_type_info_count",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if n.is_null() {
                return E_POINTER;
            }
            unsafe {
                *n = if crate::typelib::interface_info().is_null() {
                    0
                } else {
                    1
                }
            };
            S_OK
        },
    )
}
unsafe extern "system" fn sf_get_type_info(
    _this: Unk,
    index: u32,
    _lcid: u32,
    out: *mut Unk,
) -> HRESULT {
    crate::ffi_guard(
        "sf_get_type_info",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            unsafe { *out = null_mut() };
            let ti = crate::typelib::dispatch_info();
            if index != 0 || ti.is_null() {
                return 0x8002000Bu32 as i32; // DISP_E_BADINDEX
            }
            unsafe {
                com_addref(ti);
                *out = ti;
            }
            S_OK
        },
    )
}
unsafe extern "system" fn sf_get_ids_of_names(
    _this: Unk,
    _riid: *const GUID,
    names: *const *const u16,
    count: u32,
    _lcid: u32,
    ids: *mut i32,
) -> HRESULT {
    crate::ffi_guard(
        "sf_get_ids_of_names",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            let ti = crate::typelib::interface_info();
            if ti.is_null() {
                return E_NOTIMPL;
            }
            unsafe {
                windows_sys::Win32::System::Ole::DispGetIDsOfNames(ti.cast(), names, count, ids)
            }
        },
    )
}
unsafe extern "system" fn sf_invoke(
    this: Unk,
    dispid: i32,
    _riid: *const GUID,
    _lcid: u32,
    flags: u16,
    params: *mut c_void,
    result: *mut c_void,
    excep: *mut c_void,
    arg_err: *mut u32,
) -> HRESULT {
    crate::ffi_guard("sf_invoke", windows_sys::Win32::Foundation::E_FAIL, || {
        let ti = crate::typelib::interface_info();
        if ti.is_null() {
            return E_NOTIMPL;
        }
        unsafe {
            windows_sys::Win32::System::Ole::DispInvoke(
                this,
                ti.cast(),
                dispid,
                flags,
                params.cast(),
                result.cast(),
                excep.cast(),
                arg_err,
            )
        }
    })
}

// ---------------------------------------------------------------------------
// IShockwaveFlash methods

fn inst(this: Unk) -> Option<std::rc::Rc<instance::Instance>> {
    let hwnd = unsafe { FlashObject::from_sf(this) }.hwnd.get();
    instance::get(hwnd)
}

macro_rules! guard {
    ($body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(hr) => hr,
            Err(_) => {
                crate::log("panic in IShockwaveFlash method");
                windows_sys::Win32::Foundation::E_FAIL
            }
        }
    };
}

unsafe extern "system" fn get_ready_state(this: Unk, out: *mut i32) -> HRESULT {
    crate::ffi_guard(
        "get_ready_state",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            let v = inst(this).map_or(0, |i| i.ready_state.get());
            unsafe { *out = v };
            S_OK
        },
    )
}
unsafe extern "system" fn get_total_frames(this: Unk, out: *mut i32) -> HRESULT {
    crate::ffi_guard(
        "get_total_frames",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            let v = inst(this).map_or(0, |i| i.total_frames());
            unsafe { *out = v };
            S_OK
        },
    )
}
unsafe extern "system" fn get_playing(this: Unk, out: *mut i16) -> HRESULT {
    crate::ffi_guard(
        "get_playing",
        windows_sys::Win32::Foundation::E_FAIL,
        || unsafe { is_playing(this, out) },
    )
}
unsafe extern "system" fn put_playing(this: Unk, v: usize) -> HRESULT {
    crate::ffi_guard(
        "put_playing",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if v as i16 != VARIANT_FALSE {
                play(this)
            } else {
                stop_play(this)
            }
        },
    )
}
unsafe extern "system" fn get_loop(this: Unk, out: *mut i16) -> HRESULT {
    crate::ffi_guard("get_loop", windows_sys::Win32::Foundation::E_FAIL, || {
        if out.is_null() {
            return E_POINTER;
        }
        let l = unsafe { FlashObject::from_sf(this) }.loop_.get();
        unsafe { *out = if l { VARIANT_TRUE } else { VARIANT_FALSE } };
        S_OK
    })
}
unsafe extern "system" fn put_loop(this: Unk, v: usize) -> HRESULT {
    crate::ffi_guard("put_loop", windows_sys::Win32::Foundation::E_FAIL, || {
        unsafe { FlashObject::from_sf(this) }
            .loop_
            .set(v as i16 != 0);
        S_OK
    })
}
unsafe extern "system" fn get_movie(this: Unk, out: *mut *const u16) -> HRESULT {
    crate::ffi_guard("get_movie", windows_sys::Win32::Foundation::E_FAIL, || {
        if out.is_null() {
            return E_POINTER;
        }
        let url = inst(this)
            .map(|i| i.url.borrow().clone())
            .unwrap_or_default();
        unsafe { *out = bstr(&url) };
        S_OK
    })
}
unsafe extern "system" fn put_movie(this: Unk, url: *const u16) -> HRESULT {
    crate::ffi_guard(
        "put_movie",
        windows_sys::Win32::Foundation::E_FAIL,
        || unsafe { load_movie(this, 0, url) },
    )
}
unsafe extern "system" fn get_frame_num(this: Unk, out: *mut i32) -> HRESULT {
    crate::ffi_guard(
        "get_frame_num",
        windows_sys::Win32::Foundation::E_FAIL,
        || unsafe { current_frame(this, out) },
    )
}
unsafe extern "system" fn put_frame_num(this: Unk, frame: i32) -> HRESULT {
    crate::ffi_guard(
        "put_frame_num",
        windows_sys::Win32::Foundation::E_FAIL,
        || goto_frame(this, frame),
    )
}
extern "system" fn play(this: Unk) -> HRESULT {
    crate::ffi_guard("play", windows_sys::Win32::Foundation::E_FAIL, || {
        guard!(inst(this).map_or(E_INVALIDARG, |i| i.play()))
    })
}
extern "system" fn stop(this: Unk) -> HRESULT {
    crate::ffi_guard("stop", windows_sys::Win32::Foundation::E_FAIL, || {
        guard!(inst(this).map_or(E_INVALIDARG, |i| i.stop()))
    })
}
extern "system" fn rewind(this: Unk) -> HRESULT {
    crate::ffi_guard("rewind", windows_sys::Win32::Foundation::E_FAIL, || {
        guard!(inst(this).map_or(E_INVALIDARG, |i| i.goto_frame(0)))
    })
}
extern "system" fn stop_play(this: Unk) -> HRESULT {
    crate::ffi_guard("stop_play", windows_sys::Win32::Foundation::E_FAIL, || {
        guard!(inst(this).map_or(E_INVALIDARG, |i| i.stop_play()))
    })
}
extern "system" fn goto_frame(this: Unk, frame: i32) -> HRESULT {
    crate::ffi_guard("goto_frame", windows_sys::Win32::Foundation::E_FAIL, || {
        guard!(inst(this).map_or(E_INVALIDARG, |i| i.goto_frame(frame)))
    })
}
extern "system" fn back(this: Unk) -> HRESULT {
    crate::ffi_guard("back", windows_sys::Win32::Foundation::E_FAIL, || {
        guard!(inst(this).map_or(E_INVALIDARG, |i| {
            let f = i.current_frame();
            i.goto_frame((f - 1).max(0))
        }))
    })
}
extern "system" fn forward(this: Unk) -> HRESULT {
    crate::ffi_guard("forward", windows_sys::Win32::Foundation::E_FAIL, || {
        guard!(inst(this).map_or(E_INVALIDARG, |i| {
            let f = i.current_frame();
            i.goto_frame(f + 1)
        }))
    })
}
unsafe extern "system" fn current_frame(this: Unk, out: *mut i32) -> HRESULT {
    crate::ffi_guard(
        "current_frame",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            let v = inst(this).map_or(0, |i| i.current_frame());
            unsafe { *out = v };
            S_OK
        },
    )
}
unsafe extern "system" fn is_playing(this: Unk, out: *mut i16) -> HRESULT {
    crate::ffi_guard("is_playing", windows_sys::Win32::Foundation::E_FAIL, || {
        if out.is_null() {
            return E_POINTER;
        }
        let v = inst(this).is_some_and(|i| i.is_playing());
        unsafe { *out = if v { VARIANT_TRUE } else { VARIANT_FALSE } };
        S_OK
    })
}
unsafe extern "system" fn percent_loaded(this: Unk, out: *mut i32) -> HRESULT {
    crate::ffi_guard(
        "percent_loaded",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            let v = inst(this).map_or(0, |i| if i.ready_state.get() == 4 { 100 } else { 0 });
            unsafe { *out = v };
            S_OK
        },
    )
}
unsafe extern "system" fn frame_loaded(this: Unk, frame: i32, out: *mut i16) -> HRESULT {
    crate::ffi_guard(
        "frame_loaded",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            let v = inst(this).is_some_and(|i| {
                i.ready_state.get() == 4 && frame >= 0 && frame < i.total_frames()
            });
            unsafe { *out = if v { VARIANT_TRUE } else { VARIANT_FALSE } };
            S_OK
        },
    )
}
unsafe extern "system" fn flash_version(_this: Unk, out: *mut i32) -> HRESULT {
    crate::ffi_guard(
        "flash_version",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            unsafe { *out = 0x000A0000 }; // reports Flash 10
            S_OK
        },
    )
}
unsafe extern "system" fn get_wmode(_this: Unk, out: *mut *const u16) -> HRESULT {
    crate::ffi_guard("get_wmode", windows_sys::Win32::Foundation::E_FAIL, || {
        if out.is_null() {
            return E_POINTER;
        }
        unsafe { *out = bstr("transparent") };
        S_OK
    })
}
unsafe extern "system" fn load_movie(this: Unk, _layer: i32, url: *const u16) -> HRESULT {
    crate::ffi_guard("load_movie", windows_sys::Win32::Foundation::E_FAIL, || {
        let url = unsafe { bstr_to_string(url) };
        guard!(inst(this).map_or(E_INVALIDARG, |i| i.load(&url)))
    })
}

// Stubs for everything else, by number of 32-bit stack arguments.
extern "system" fn stub0(_: Unk) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn stub1(_: Unk, _: usize) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn stub2(_: Unk, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn stub3(_: Unk, _: usize, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn stub4(_: Unk, _: usize, _: usize, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}

/// Number of 32-bit stack arguments of each IShockwaveFlash method, in
/// vtable order starting at slot 7 (after IUnknown and IDispatch). Checked
/// against typelib\flash.tlb by the unit test below.
pub const ARG_DWORDS: [u8; 93] = [
    1, 1, // ReadyState, TotalFrames
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // Playing .. FrameNum (get/put pairs)
    4, 1, 3, // SetZoomRect, Zoom, Pan
    0, 0, 0, 0, 0, 0, // Play, Stop, Back, Forward, Rewind, StopPlay
    1, 1, 1, 1, 2,
    1, // GotoFrame, CurrentFrame, IsPlaying, PercentLoaded, FrameLoaded, FlashVersion
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // WMode .. Quality2
    2, 2, 2, 2, 2, 1,
    1, // LoadMovie, TGotoFrame, TGotoLabel, TCurrentFrame, TCurrentLabel, TPlay, TStopPlay
    2, 2, 3, 3, 2, 2, 4, 3, 3, // SetVariable .. TGetPropertyAsNumber
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // SWRemote .. SeamlessTabbing
    0, // EnforceLocalSecurity
    1, 1, 1, 1, 1, 1, // Profile, ProfileAddress, ProfilePort
    2, 1, 0, // CallFunction, SetReturnValue, DisableLocalSecurity
    1, 1, 1, 1, // AllowNetworking, AllowFullScreen
];

fn sf_vtbl() -> *const usize {
    static VTBL: OnceLock<Vec<usize>> = OnceLock::new();
    VTBL.get_or_init(|| {
        let mut v: Vec<usize> = vec![
            sf_query as *const () as usize,
            sf_addref as *const () as usize,
            sf_release as *const () as usize,
            sf_get_type_info_count as *const () as usize,
            sf_get_type_info as *const () as usize,
            sf_get_ids_of_names as *const () as usize,
            sf_invoke as *const () as usize,
        ];
        for n in ARG_DWORDS {
            v.push(match n {
                0 => stub0 as *const () as usize,
                1 => stub1 as *const () as usize,
                2 => stub2 as *const () as usize,
                3 => stub3 as *const () as usize,
                _ => stub4 as *const () as usize,
            });
        }
        let mut set = |slot: usize, f: usize| v[slot] = f;
        set(7, get_ready_state as *const () as usize);
        set(8, get_total_frames as *const () as usize); // +0x20
        set(9, get_playing as *const () as usize);
        set(10, put_playing as *const () as usize);
        set(19, get_loop as *const () as usize);
        set(20, put_loop as *const () as usize);
        set(21, get_movie as *const () as usize);
        set(22, put_movie as *const () as usize);
        set(23, get_frame_num as *const () as usize);
        set(24, put_frame_num as *const () as usize);
        set(28, play as *const () as usize);
        set(29, stop as *const () as usize);
        set(30, back as *const () as usize);
        set(31, forward as *const () as usize);
        set(32, rewind as *const () as usize);
        set(33, stop_play as *const () as usize);
        set(34, goto_frame as *const () as usize); // +0x88
        set(35, current_frame as *const () as usize);
        set(36, is_playing as *const () as usize);
        set(37, percent_loaded as *const () as usize);
        set(38, frame_loaded as *const () as usize);
        set(39, flash_version as *const () as usize);
        set(40, get_wmode as *const () as usize);
        set(58, load_movie as *const () as usize);
        v
    })
    .as_ptr()
}

// ---------------------------------------------------------------------------
// IConnectionPointContainer

#[repr(C)]
struct CpcVtbl {
    query: unsafe extern "system" fn(Unk, *const GUID, *mut Unk) -> HRESULT,
    add_ref: unsafe extern "system" fn(Unk) -> u32,
    release: unsafe extern "system" fn(Unk) -> u32,
    enum_connection_points: unsafe extern "system" fn(Unk, *mut Unk) -> HRESULT,
    find_connection_point: unsafe extern "system" fn(Unk, *const GUID, *mut Unk) -> HRESULT,
}

static CPC_VTBL: CpcVtbl = CpcVtbl {
    query: cpc_query,
    add_ref: cpc_addref,
    release: cpc_release,
    enum_connection_points: cpc_enum,
    find_connection_point: cpc_find,
};

unsafe extern "system" fn cpc_query(this: Unk, iid: *const GUID, out: *mut Unk) -> HRESULT {
    crate::ffi_guard("cpc_query", windows_sys::Win32::Foundation::E_FAIL, || {
        if iid.is_null() {
            return E_POINTER;
        }
        unsafe { FlashObject::from_cpc(this).query(&*iid, out) }
    })
}
unsafe extern "system" fn cpc_addref(this: Unk) -> u32 {
    crate::ffi_guard("cpc_addref", 0, || unsafe {
        FlashObject::from_cpc(this).add_ref()
    })
}
unsafe extern "system" fn cpc_release(this: Unk) -> u32 {
    crate::ffi_guard("cpc_release", 0, || unsafe {
        FlashObject::release(FlashObject::from_cpc(this))
    })
}
unsafe extern "system" fn cpc_enum(_this: Unk, out: *mut Unk) -> HRESULT {
    crate::ffi_guard("cpc_enum", windows_sys::Win32::Foundation::E_FAIL, || {
        if !out.is_null() {
            unsafe { *out = null_mut() };
        }
        E_NOTIMPL
    })
}
unsafe extern "system" fn cpc_find(this: Unk, iid: *const GUID, out: *mut Unk) -> HRESULT {
    crate::ffi_guard("cpc_find", windows_sys::Win32::Foundation::E_FAIL, || {
        if iid.is_null() || out.is_null() {
            return E_POINTER;
        }
        unsafe { *out = null_mut() };
        if !guid_eq(unsafe { &*iid }, &DIID_ISHOCKWAVEFLASHEVENTS) {
            return CONNECT_E_NOCONNECTION;
        }
        unsafe { FlashObject::from_cpc(this).query(&IID_ICONNECTIONPOINT, out) }
    })
}

// ---------------------------------------------------------------------------
// IConnectionPoint (one sink)

#[repr(C)]
struct CpVtbl {
    query: unsafe extern "system" fn(Unk, *const GUID, *mut Unk) -> HRESULT,
    add_ref: unsafe extern "system" fn(Unk) -> u32,
    release: unsafe extern "system" fn(Unk) -> u32,
    get_connection_interface: unsafe extern "system" fn(Unk, *mut GUID) -> HRESULT,
    get_connection_point_container: unsafe extern "system" fn(Unk, *mut Unk) -> HRESULT,
    advise: unsafe extern "system" fn(Unk, Unk, *mut u32) -> HRESULT,
    unadvise: unsafe extern "system" fn(Unk, u32) -> HRESULT,
    enum_connections: unsafe extern "system" fn(Unk, *mut Unk) -> HRESULT,
}

static CP_VTBL: CpVtbl = CpVtbl {
    query: cp_query,
    add_ref: cp_addref,
    release: cp_release,
    get_connection_interface: cp_get_interface,
    get_connection_point_container: cp_get_container,
    advise: cp_advise,
    unadvise: cp_unadvise,
    enum_connections: cp_enum,
};

unsafe extern "system" fn cp_query(this: Unk, iid: *const GUID, out: *mut Unk) -> HRESULT {
    crate::ffi_guard("cp_query", windows_sys::Win32::Foundation::E_FAIL, || {
        if iid.is_null() {
            return E_POINTER;
        }
        unsafe { FlashObject::from_cp(this).query(&*iid, out) }
    })
}
unsafe extern "system" fn cp_addref(this: Unk) -> u32 {
    crate::ffi_guard("cp_addref", 0, || unsafe {
        FlashObject::from_cp(this).add_ref()
    })
}
unsafe extern "system" fn cp_release(this: Unk) -> u32 {
    crate::ffi_guard("cp_release", 0, || unsafe {
        FlashObject::release(FlashObject::from_cp(this))
    })
}
unsafe extern "system" fn cp_get_interface(_this: Unk, out: *mut GUID) -> HRESULT {
    crate::ffi_guard(
        "cp_get_interface",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            if out.is_null() {
                return E_POINTER;
            }
            unsafe { *out = DIID_ISHOCKWAVEFLASHEVENTS };
            S_OK
        },
    )
}
unsafe extern "system" fn cp_get_container(this: Unk, out: *mut Unk) -> HRESULT {
    crate::ffi_guard(
        "cp_get_container",
        windows_sys::Win32::Foundation::E_FAIL,
        || unsafe { FlashObject::from_cp(this).query(&IID_ICONNECTIONPOINTCONTAINER, out) },
    )
}
unsafe extern "system" fn cp_advise(this: Unk, sink: Unk, cookie: *mut u32) -> HRESULT {
    crate::ffi_guard("cp_advise", windows_sys::Win32::Foundation::E_FAIL, || {
        if sink.is_null() || cookie.is_null() {
            return E_POINTER;
        }
        let obj = unsafe { FlashObject::from_cp(this) };
        if !obj.sink.get().is_null() {
            return CONNECT_E_ADVISELIMIT;
        }
        // Prefer the event interface itself, then plain IDispatch.
        let mut disp: Unk = null_mut();
        let mut hr = unsafe {
            vcall!(
                sink,
                0,
                fn(*const GUID, *mut Unk) -> HRESULT,
                &DIID_ISHOCKWAVEFLASHEVENTS,
                &mut disp
            )
        };
        if hr < 0 || disp.is_null() {
            hr = unsafe {
                vcall!(
                    sink,
                    0,
                    fn(*const GUID, *mut Unk) -> HRESULT,
                    &IID_IDISPATCH,
                    &mut disp
                )
            };
        }
        if hr < 0 || disp.is_null() {
            return CONNECT_E_CANNOTCONNECT;
        }
        obj.sink.set(disp);
        let c = obj.cookie.get().wrapping_add(1).max(1);
        obj.cookie.set(c);
        unsafe { *cookie = c };
        S_OK
    })
}
unsafe extern "system" fn cp_unadvise(this: Unk, cookie: u32) -> HRESULT {
    crate::ffi_guard(
        "cp_unadvise",
        windows_sys::Win32::Foundation::E_FAIL,
        || {
            let obj = unsafe { FlashObject::from_cp(this) };
            if obj.sink.get().is_null() || cookie != obj.cookie.get() {
                return CONNECT_E_NOCONNECTION;
            }
            obj.drop_sink();
            S_OK
        },
    )
}
unsafe extern "system" fn cp_enum(_this: Unk, out: *mut Unk) -> HRESULT {
    crate::ffi_guard("cp_enum", windows_sys::Win32::Foundation::E_FAIL, || {
        if !out.is_null() {
            unsafe { *out = null_mut() };
        }
        E_NOTIMPL
    })
}

#[cfg(test)]
mod tests {
    /// Every slot of the hand-written vtable takes as many stack bytes as the
    /// type library says, and the two slots ICQ calls are where it calls them.
    #[test]
    fn vtable_matches_typelib() {
        let slots = crate::typelib::tests_slot_arg_dwords(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "\\typelib\\flash.tlb"
        ));
        assert_eq!(slots.len(), 7 + super::ARG_DWORDS.len());
        for (i, (name, dwords)) in slots.iter().enumerate().skip(7) {
            assert_eq!(
                *dwords,
                super::ARG_DWORDS[i - 7] as u32,
                "slot {i} ({name}) argument size"
            );
        }
        assert_eq!(slots[0x20 / 4].0, "TotalFrames");
        assert_eq!(slots[0x88 / 4].0, "GotoFrame");
    }
}
