//! A windowless ActiveX container for the ShockwaveFlash control, the way
//! ICQ 6.5's Boxely renderer hosts Flash avatars (boxelyRenderer.dll), plus
//! the same control inside Windows' own ATL host (atl.dll, AtlAxAttachControl).
//!
//!   host <dll> axreg                          registration under a test root
//!   host <dll> ax <base dir|url> <out> <names...>   avatars x emotions
//!
//! The control is created through COM (CoRegisterClassObject with the DLL's
//! class factory, then CoCreateInstance by CLSID), never from the user's real
//! registry.

use std::cell::Cell;
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::Com::*;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{GUID, HRESULT};

use crate::{Unk, bstr_str, guid_eq, pump_for, wide};

const CLSID_FLASH: GUID = GUID::from_u128(0xD27CDB6E_AE6D_11cf_96B8_444553540000);
const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_C000_000000000046);
const IID_ICLASSFACTORY: GUID = GUID::from_u128(0x00000001_0000_0000_C000_000000000046);
const IID_IOLEOBJECT: GUID = GUID::from_u128(0x00000112_0000_0000_C000_000000000046);
const IID_IPERSISTPROPERTYBAG: GUID = GUID::from_u128(0x37D84F60_42CB_11CE_8135_00AA004BB851);
const IID_IPERSISTSTREAMINIT: GUID = GUID::from_u128(0x7FD52380_4E07_101B_AE2D_08002B2EC713);
const IID_IVIEWOBJECTEX: GUID = GUID::from_u128(0x3AF24292_0C96_11CE_A0CF_00AA00600AB8);
const IID_IVIEWOBJECT2: GUID = GUID::from_u128(0x00000127_0000_0000_C000_000000000046);
const IID_IVIEWOBJECT: GUID = GUID::from_u128(0x0000010D_0000_0000_C000_000000000046);
const IID_IOBJECTWITHSITE: GUID = GUID::from_u128(0xFC4801A3_2BA9_11CF_A229_00AA003D7352);
const IID_IOLEINPLACEOBJECTWINDOWLESS: GUID =
    GUID::from_u128(0x1C2056CC_5EF4_101B_8BC8_00AA003E3B29);
const IID_IOLECLIENTSITE: GUID = GUID::from_u128(0x00000118_0000_0000_C000_000000000046);
const IID_IOLEWINDOW: GUID = GUID::from_u128(0x00000114_0000_0000_C000_000000000046);
const IID_IOLEINPLACESITE: GUID = GUID::from_u128(0x00000119_0000_0000_C000_000000000046);
const IID_IOLEINPLACESITEEX: GUID = GUID::from_u128(0x9C2CAD80_3424_11CF_B670_00AA004CD6D8);
const IID_IOLEINPLACESITEWINDOWLESS: GUID = GUID::from_u128(0x922EADA0_3424_11CF_B670_00AA004CD6D8);
const IID_IADVISESINK: GUID = GUID::from_u128(0x0000010F_0000_0000_C000_000000000046);
const IID_IPROPERTYBAG: GUID = GUID::from_u128(0x55272A00_42CB_11CE_8135_00AA004BB851);
const IID_IDISPATCH: GUID = GUID::from_u128(0x00020400_0000_0000_C000_000000000046);

pub const EMOTIONS: [&str; 9] = [
    "stam", "smile", "sad", "laugh", "mad", "cry", "love", "offline", "busy",
];

// ---------------------------------------------------------------------------
// Site: IOleClientSite + IOleInPlaceSiteWindowless + IAdviseSink

#[repr(C)]
struct Site {
    vtbls: [*const usize; 3],
    hwnd: HWND,
    pos: Cell<RECT>,
    invalidations: Cell<u32>,
    view_changes: Cell<u32>,
    activate_flags: Cell<i64>,
}

unsafe fn site<'a>(this: Unk, i: usize) -> &'a Site {
    unsafe { &*((this as *const u8).sub(i * size_of::<usize>()) as *const Site) }
}

unsafe extern "system" fn s_qi<const I: usize>(
    this: Unk,
    iid: *const GUID,
    out: *mut Unk,
) -> HRESULT {
    let s = unsafe { site(this, I) };
    let iid = unsafe { &*iid };
    let base = s as *const Site as *mut u8;
    let p = if guid_eq(iid, &IID_IUNKNOWN) || guid_eq(iid, &IID_IOLECLIENTSITE) {
        base
    } else if guid_eq(iid, &IID_IOLEWINDOW)
        || guid_eq(iid, &IID_IOLEINPLACESITE)
        || guid_eq(iid, &IID_IOLEINPLACESITEEX)
        || guid_eq(iid, &IID_IOLEINPLACESITEWINDOWLESS)
    {
        unsafe { base.add(size_of::<usize>()) }
    } else if guid_eq(iid, &IID_IADVISESINK) {
        unsafe { base.add(2 * size_of::<usize>()) }
    } else {
        unsafe { *out = null_mut() };
        return E_NOINTERFACE;
    };
    unsafe { *out = p as Unk };
    S_OK
}
extern "system" fn s_ref(_: Unk) -> u32 {
    2
}
extern "system" fn r0(_: Unk) -> HRESULT {
    S_OK
}
extern "system" fn r1(_: Unk, _: usize) -> HRESULT {
    S_OK
}
extern "system" fn n0(_: Unk) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn n1(_: Unk, _: usize) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn n2(_: Unk, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn n3(_: Unk, _: usize, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn n4(_: Unk, _: usize, _: usize, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn sfalse0(_: Unk) -> HRESULT {
    S_FALSE
}
unsafe extern "system" fn cs_get_container(_: Unk, out: *mut Unk) -> HRESULT {
    unsafe { *out = null_mut() };
    E_NOINTERFACE
}
unsafe extern "system" fn ip_get_window(this: Unk, out: *mut HWND) -> HRESULT {
    unsafe { *out = site(this, 1).hwnd };
    S_OK
}
unsafe extern "system" fn ip_get_window_context(
    this: Unk,
    frame: *mut Unk,
    doc: *mut Unk,
    pos: *mut RECT,
    clip: *mut RECT,
    _info: *mut u32,
) -> HRESULT {
    let s = unsafe { site(this, 1) };
    unsafe {
        *frame = null_mut();
        *doc = null_mut();
        *pos = s.pos.get();
        *clip = s.pos.get();
    }
    S_OK
}
unsafe extern "system" fn ip_on_activate_ex(this: Unk, no_redraw: *mut i32, flags: u32) -> HRESULT {
    let s = unsafe { site(this, 1) };
    s.activate_flags.set(flags as i64);
    if !no_redraw.is_null() {
        unsafe { *no_redraw = 0 };
    }
    S_OK
}
unsafe extern "system" fn ip_invalidate_rect(this: Unk, rect: *const RECT, erase: i32) -> HRESULT {
    let s = unsafe { site(this, 1) };
    s.invalidations.set(s.invalidations.get() + 1);
    let r = if rect.is_null() {
        s.pos.get()
    } else {
        unsafe { *rect }
    };
    unsafe { InvalidateRect(s.hwnd, &r, erase) };
    S_OK
}
unsafe extern "system" fn ip_invalidate_rgn(this: Unk, _rgn: usize, erase: i32) -> HRESULT {
    unsafe { ip_invalidate_rect(this, null(), erase) }
}
unsafe extern "system" fn ip_def_window_message(
    _: Unk,
    _: u32,
    _: usize,
    _: isize,
    res: *mut isize,
) -> HRESULT {
    if !res.is_null() {
        unsafe { *res = 0 };
    }
    S_OK
}
unsafe extern "system" fn as_view_change(this: Unk, _aspect: u32, _lindex: i32) {
    let s = unsafe { site(this, 2) };
    s.view_changes.set(s.view_changes.get() + 1);
}
extern "system" fn av0(_: Unk) {}
extern "system" fn av1(_: Unk, _: usize) {}
extern "system" fn av2(_: Unk, _: usize, _: usize) {}

fn site_vtbls() -> [*const usize; 3] {
    static V: OnceLock<[Vec<usize>; 3]> = OnceLock::new();
    let v = V.get_or_init(|| {
        let u = |i: usize| -> Vec<usize> {
            vec![
                match i {
                    0 => s_qi::<0> as *const () as usize,
                    1 => s_qi::<1> as *const () as usize,
                    _ => s_qi::<2> as *const () as usize,
                },
                s_ref as *const () as usize,
                s_ref as *const () as usize,
            ]
        };
        let f = |p: *const ()| p as usize;
        let mut cs = u(0);
        cs.extend([
            f(n0 as *const ()),               // SaveObject
            f(n3 as *const ()),               // GetMoniker
            f(cs_get_container as *const ()), // GetContainer
            f(r0 as *const ()),               // ShowObject
            f(r1 as *const ()),               // OnShowWindow
            f(n0 as *const ()),               // RequestNewObjectLayout
        ]);
        let mut ip = u(1);
        ip.extend([
            f(ip_get_window as *const ()),         // GetWindow
            f(n1 as *const ()),                    // ContextSensitiveHelp
            f(r0 as *const ()),                    // CanInPlaceActivate
            f(r0 as *const ()),                    // OnInPlaceActivate
            f(r0 as *const ()),                    // OnUIActivate
            f(ip_get_window_context as *const ()), // GetWindowContext
            f(n2 as *const ()),                    // Scroll(SIZE)
            f(r1 as *const ()),                    // OnUIDeactivate
            f(r0 as *const ()),                    // OnInPlaceDeactivate
            f(r0 as *const ()),                    // DiscardUndoState
            f(r0 as *const ()),                    // DeactivateAndUndo
            f(r1 as *const ()),                    // OnPosRectChange
            f(ip_on_activate_ex as *const ()),     // OnInPlaceActivateEx
            f(r1 as *const ()),                    // OnInPlaceDeactivateEx
            f(r0 as *const ()),                    // RequestUIActivate
            f(r0 as *const ()),                    // CanWindowlessActivate
            f(sfalse0 as *const ()),               // GetCapture
            f(r1 as *const ()),                    // SetCapture
            f(sfalse0 as *const ()),               // GetFocus
            f(r1 as *const ()),                    // SetFocus
            f(n3 as *const ()),                    // GetDC
            f(n1 as *const ()),                    // ReleaseDC
            f(ip_invalidate_rect as *const ()),    // InvalidateRect
            f(ip_invalidate_rgn as *const ()),     // InvalidateRgn
            f(n4 as *const ()),                    // ScrollRect
            f(r1 as *const ()),                    // AdjustRect
            f(ip_def_window_message as *const ()), // OnDefWindowMessage
        ]);
        let mut av = u(2);
        av.extend([
            f(av2 as *const ()),            // OnDataChange
            f(as_view_change as *const ()), // OnViewChange
            f(av1 as *const ()),            // OnRename
            f(av0 as *const ()),            // OnSave
            f(av0 as *const ()),            // OnClose
        ]);
        [cs, ip, av]
    });
    [v[0].as_ptr(), v[1].as_ptr(), v[2].as_ptr()]
}

// ---------------------------------------------------------------------------
// IPropertyBag with the <param>s

#[repr(C)]
struct Bag {
    vtbl: *const usize,
    params: Vec<(String, String)>,
    reads: std::cell::RefCell<Vec<String>>,
}

unsafe extern "system" fn bag_qi(this: Unk, iid: *const GUID, out: *mut Unk) -> HRESULT {
    let iid = unsafe { &*iid };
    if guid_eq(iid, &IID_IUNKNOWN) || guid_eq(iid, &IID_IPROPERTYBAG) {
        unsafe { *out = this };
        S_OK
    } else {
        unsafe { *out = null_mut() };
        E_NOINTERFACE
    }
}
#[repr(C)]
struct Var {
    vt: u16,
    r: [u16; 3],
    value: u64,
}
unsafe extern "system" fn bag_read(
    this: Unk,
    name: *const u16,
    var: *mut Var,
    _log: Unk,
) -> HRESULT {
    let bag = unsafe { &*(this as *const Bag) };
    let n = (0..).take_while(|&i| unsafe { *name.add(i) } != 0).count();
    let name = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(name, n) });
    bag.reads.borrow_mut().push(name.clone());
    match bag
        .params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&name))
    {
        Some((_, v)) => {
            let w = wide(v);
            unsafe {
                (*var).vt = 8;
                (*var).value = SysAllocString(w.as_ptr()) as usize as u64;
            }
            S_OK
        }
        None => E_INVALIDARG,
    }
}
fn bag_vtbl() -> *const usize {
    static V: OnceLock<Vec<usize>> = OnceLock::new();
    V.get_or_init(|| {
        vec![
            bag_qi as *const () as usize,
            s_ref as *const () as usize,
            s_ref as *const () as usize,
            bag_read as *const () as usize,
            n3 as *const () as usize, // Write
        ]
    })
    .as_ptr()
}

// ---------------------------------------------------------------------------

pub struct Hosted {
    pub unk: Unk,
    pub ole: Unk,
    pub view: Unk,
    pub flash: Unk,
    site: Box<Site>,
    pub name: String,
}

pub fn qi(p: Unk, iid: &GUID) -> Unk {
    let mut out: Unk = null_mut();
    let hr = unsafe { vcall!(p, 0, fn(*const GUID, *mut Unk) -> HRESULT, iid, &mut out) };
    if hr < 0 { null_mut() } else { out }
}

/// Creates the control and activates it windowless in `hwnd` at `rect`, in the
/// order boxelyRenderer uses. Movie is set afterwards through IDispatch.
pub fn host_control(
    hwnd: HWND,
    rect: RECT,
    params: &[(&str, &str)],
    name: &str,
    log: bool,
) -> Result<Hosted, String> {
    unsafe {
        let mut unk: Unk = null_mut();
        let hr = CoCreateInstance(
            &CLSID_FLASH,
            null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_IUNKNOWN,
            &mut unk,
        );
        if hr < 0 {
            return Err(format!("CoCreateInstance {hr:#x}"));
        }
        let site = Box::new(Site {
            vtbls: site_vtbls(),
            hwnd,
            pos: Cell::new(rect),
            invalidations: Cell::new(0),
            view_changes: Cell::new(0),
            activate_flags: Cell::new(-1),
        });
        let site_unk = &*site as *const Site as Unk;
        let sink = (site_unk as *mut u8).add(2 * size_of::<usize>()) as Unk;
        let ole = qi(unk, &IID_IOLEOBJECT);
        if ole.is_null() {
            return Err("no IOleObject".into());
        }
        let mut misc = 0u32;
        vcall!(ole, 22, fn(u32, *mut u32) -> HRESULT, 1, &mut misc);
        let first = misc & 0x20000 != 0;
        if first {
            vcall!(ole, 3, fn(Unk) -> HRESULT, site_unk);
        }
        let pb = qi(unk, &IID_IPERSISTPROPERTYBAG);
        let bag = Box::new(Bag {
            vtbl: bag_vtbl(),
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            reads: Default::default(),
        });
        let load_hr = if !pb.is_null() {
            let hr = vcall!(
                pb,
                5,
                fn(Unk, Unk) -> HRESULT,
                &*bag as *const Bag as Unk,
                null_mut()
            );
            vcall!(pb, 2, fn() -> u32);
            hr
        } else {
            let psi = qi(unk, &IID_IPERSISTSTREAMINIT);
            let hr = vcall!(psi, 8, fn() -> HRESULT);
            vcall!(psi, 2, fn() -> u32);
            hr
        };
        if !first {
            vcall!(ole, 3, fn(Unk) -> HRESULT, site_unk);
        }
        let mut view = qi(unk, &IID_IVIEWOBJECTEX);
        let mut which = "IViewObjectEx";
        if view.is_null() {
            view = qi(unk, &IID_IVIEWOBJECT2);
            which = "IViewObject2";
        }
        if view.is_null() {
            view = qi(unk, &IID_IVIEWOBJECT);
            which = "IViewObject";
        }
        let mut cookie = 0u32;
        let adv_hr = vcall!(ole, 19, fn(Unk, *mut u32) -> HRESULT, sink, &mut cookie);
        let sadv_hr = vcall!(view, 7, fn(u32, u32, Unk) -> HRESULT, 1, 0, sink);
        let app = wide("AXWIN");
        vcall!(
            ole,
            5,
            fn(*const u16, *const u16) -> HRESULT,
            app.as_ptr(),
            null()
        );
        let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);
        let ext = SIZE {
            cx: w * 2540 / 96,
            cy: h * 2540 / 96,
        };
        let ext_hr = vcall!(ole, 17, fn(u32, *const SIZE) -> HRESULT, 1, &ext);
        let mut got = SIZE { cx: 0, cy: 0 };
        vcall!(ole, 18, fn(u32, *mut SIZE) -> HRESULT, 1, &mut got);
        let verb_hr = vcall!(
            ole,
            11,
            fn(i32, Unk, Unk, i32, HWND, *const RECT) -> HRESULT,
            -5,
            null_mut(),
            site_unk,
            0,
            hwnd,
            &rect
        );
        let ows = qi(unk, &IID_IOBJECTWITHSITE);
        let ows_hr = if ows.is_null() {
            E_NOINTERFACE
        } else {
            let hr = vcall!(ows, 3, fn(Unk) -> HRESULT, site_unk);
            vcall!(ows, 2, fn() -> u32);
            hr
        };
        let ipw = qi(unk, &IID_IOLEINPLACEOBJECTWINDOWLESS);
        let rects_hr = vcall!(
            ipw,
            7,
            fn(*const RECT, *const RECT) -> HRESULT,
            &rect,
            &rect
        );
        vcall!(ipw, 2, fn() -> u32);
        let flash = qi(unk, &crate::IID_ISHOCKWAVEFLASH);
        if log {
            say!(
                "[{name}] misc {misc:#x} (SETCLIENTSITEFIRST {first}); PropertyBag Load {load_hr:#x} read {:?}; {which}; \
                 Advise {adv_hr:#x}, SetAdvise {sadv_hr:#x}; SetExtent {ext_hr:#x} -> GetExtent {}x{}; \
                 DoVerb(INPLACEACTIVATE) {verb_hr:#x}, site saw OnInPlaceActivateEx flags {}; SetSite {ows_hr:#x}; \
                 SetObjectRects {rects_hr:#x}; IShockwaveFlash {}",
                bag.reads.borrow(),
                got.cx,
                got.cy,
                site.activate_flags.get(),
                !flash.is_null()
            );
        }
        if flash.is_null() {
            return Err("no IShockwaveFlash".into());
        }
        Ok(Hosted {
            unk,
            ole,
            view,
            flash,
            site,
            name: name.to_string(),
        })
    }
}

impl Hosted {
    /// The Movie property through IDispatch (PROPERTYPUT), as the box sets it.
    pub fn put_movie_dispatch(&self, url: &str) -> HRESULT {
        unsafe {
            let disp = qi(self.unk, &IID_IDISPATCH);
            let name = wide("Movie");
            let names = [name.as_ptr()];
            let mut id = 0i32;
            let hr = vcall!(
                disp,
                5,
                fn(*const GUID, *const *const u16, u32, u32, *mut i32) -> HRESULT,
                &GUID::from_u128(0),
                names.as_ptr(),
                1,
                0x400,
                &mut id
            );
            if hr < 0 {
                return hr;
            }
            let w = wide(url);
            let mut arg = Var {
                vt: 8,
                r: [0; 3],
                value: SysAllocString(w.as_ptr()) as usize as u64,
            };
            let mut named = -3i32; // DISPID_PROPERTYPUT
            #[repr(C)]
            struct Dp {
                args: *mut Var,
                named: *mut i32,
                c: u32,
                cn: u32,
            }
            let dp = Dp {
                args: &mut arg,
                named: &mut named,
                c: 1,
                cn: 1,
            };
            let hr = vcall!(
                disp,
                6,
                fn(i32, *const GUID, u32, u16, *const Dp, Unk, Unk, *mut u32) -> HRESULT,
                id,
                &GUID::from_u128(0),
                0x400,
                4, /* DISPATCH_PROPERTYPUT */
                &dp,
                null_mut(),
                null_mut(),
                null_mut()
            );
            SysFreeString(arg.value as usize as *const u16);
            vcall!(disp, 2, fn() -> u32);
            hr
        }
    }

    /// IShockwaveFlash::put_Scale (+0xC4).
    pub fn put_scale(&self, scale: &str) -> HRESULT {
        unsafe {
            let w = wide(scale);
            let b = SysAllocString(w.as_ptr());
            let hr = vcall!(self.flash, 49, fn(*const u16) -> HRESULT, b);
            SysFreeString(b);
            hr
        }
    }

    /// IOleInPlaceObject::SetObjectRects, as a host does on a move or resize.
    pub fn set_object_rects(&self, r: RECT) -> HRESULT {
        unsafe {
            let ipw = qi(self.unk, &IID_IOLEINPLACEOBJECTWINDOWLESS);
            let hr = vcall!(ipw, 7, fn(*const RECT, *const RECT) -> HRESULT, &r, &r);
            vcall!(ipw, 2, fn() -> u32);
            self.site.pos.set(r);
            hr
        }
    }

    /// IShockwaveFlash::StopPlay (+0x84): pause.
    pub fn stop_play(&self) -> HRESULT {
        unsafe { vcall!(self.flash, 33, fn() -> HRESULT) }
    }

    pub fn play(&self) -> HRESULT {
        unsafe { vcall!(self.flash, 28, fn() -> HRESULT) } // +0x70
    }
    pub fn stop(&self) -> HRESULT {
        unsafe { vcall!(self.flash, 29, fn() -> HRESULT) } // +0x74
    }
    pub fn set_variable(&self, name: &str, value: &str) -> HRESULT {
        unsafe {
            let (n, v) = (wide(name), wide(value));
            let (bn, bv) = (SysAllocString(n.as_ptr()), SysAllocString(v.as_ptr()));
            let hr = vcall!(
                self.flash,
                65,
                fn(*const u16, *const u16) -> HRESULT,
                bn,
                bv
            ); // +0x104
            SysFreeString(bn);
            SysFreeString(bv);
            hr
        }
    }
    pub fn get_variable(&self, name: &str) -> (HRESULT, String) {
        unsafe {
            let n = wide(name);
            let bn = SysAllocString(n.as_ptr());
            let mut out: *const u16 = null();
            let hr = vcall!(
                self.flash,
                66,
                fn(*const u16, *mut *const u16) -> HRESULT,
                bn,
                &mut out
            );
            SysFreeString(bn);
            let s = bstr_str(out);
            if !out.is_null() {
                SysFreeString(out);
            }
            (hr, s)
        }
    }
    pub fn t_goto_label(&self, target: &str, label: &str) -> HRESULT {
        unsafe {
            let (t, l) = (wide(target), wide(label));
            let (bt, bl) = (SysAllocString(t.as_ptr()), SysAllocString(l.as_ptr()));
            let hr = vcall!(
                self.flash,
                60,
                fn(*const u16, *const u16) -> HRESULT,
                bt,
                bl
            ); // +0xF0
            SysFreeString(bt);
            SysFreeString(bl);
            hr
        }
    }
    pub fn ready_state(&self) -> i32 {
        let mut v = 0i32;
        unsafe { vcall!(self.flash, 7, fn(*mut i32) -> HRESULT, &mut v) };
        v
    }
    pub fn invalidations(&self) -> u32 {
        self.site.invalidations.get()
    }
    pub fn view_changes(&self) -> u32 {
        self.site.view_changes.get()
    }

    /// IViewObject::Draw into a memory DC (the path with a rectangle), onto a
    /// fully transparent 32bpp surface: premultiplied BGRA pixels.
    pub fn capture(&self, w: i32, h: i32) -> (HRESULT, Vec<u8>) {
        unsafe {
            let mut bi: BITMAPINFO = std::mem::zeroed();
            bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
            bi.bmiHeader.biWidth = w;
            bi.bmiHeader.biHeight = -h;
            bi.bmiHeader.biPlanes = 1;
            bi.bmiHeader.biBitCount = 32;
            let mut bits: *mut c_void = null_mut();
            let bmp = CreateDIBSection(null_mut(), &bi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
            let dc = CreateCompatibleDC(null_mut());
            let old = SelectObject(dc, bmp);
            let r = RECT {
                left: 0,
                top: 0,
                right: w,
                bottom: h,
            };
            let hr = vcall!(
                self.view,
                3,
                fn(u32, i32, Unk, Unk, HDC, HDC, *const RECT, *const RECT, usize, usize) -> HRESULT,
                1,
                -1,
                null_mut(),
                null_mut(),
                null_mut(),
                dc,
                &r,
                null(),
                0,
                0
            );
            GdiFlush();
            let px = std::slice::from_raw_parts(bits as *const u8, (w * h * 4) as usize).to_vec();
            SelectObject(dc, old);
            DeleteDC(dc);
            DeleteObject(bmp);
            (hr, px)
        }
    }

    pub fn close(self) {
        unsafe {
            vcall!(self.ole, 6, fn(u32) -> HRESULT, 1); // Close(OLECLOSE_NOSAVE)
            vcall!(self.ole, 3, fn(Unk) -> HRESULT, null_mut()); // SetClientSite(NULL)
            vcall!(self.view, 7, fn(u32, u32, Unk) -> HRESULT, 1, 0, null_mut());
            vcall!(self.flash, 2, fn() -> u32);
            vcall!(self.view, 2, fn() -> u32);
            vcall!(self.ole, 2, fn() -> u32);
            let left = vcall!(self.unk, 2, fn() -> u32);
            say!("[{}] closed, last Release -> {left}", self.name);
        }
    }
}

// ---------------------------------------------------------------------------
// The container window: paints every hosted control windowless (Draw with no
// rectangle is not used by us; we pass the control's position like ATL does).

/// One control as the container paints it.
pub struct PaintItem {
    pub view: Unk,
    pub rect: RECT,
    /// The host paints this element (boxelyRenderer skips an element whose
    /// state flag is not set; a hidden or not-yet-shown box).
    pub ready: bool,
    /// Paint like boxelyRenderer's second path: a memory DC with the
    /// viewport origin moved, Draw with the element's rectangle.
    pub path_a: bool,
}

thread_local! {
    pub static PAINT: std::cell::RefCell<Vec<PaintItem>> = const { std::cell::RefCell::new(Vec::new()) };
    /// Draw calls the container made with a frame on screen afterwards is not
    /// known here; this counts Draw calls per item index.
    pub static DRAWS: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
}

unsafe fn draw_view(view: Unk, dc: HDC, r: &RECT) -> HRESULT {
    unsafe {
        vcall!(
            view,
            3,
            fn(u32, i32, Unk, Unk, HDC, HDC, *const RECT, *const RECT, usize, usize) -> HRESULT,
            1,
            -1,
            null_mut(),
            null_mut(),
            null_mut(),
            dc,
            r,
            null(),
            0,
            0
        )
    }
}

/// boxelyRenderer's memory-DC path: copy the background under the element
/// into a memory DC, move its viewport origin to (-left, -top), Draw with the
/// element's rectangle, copy the result back.
unsafe fn draw_path_a(view: Unk, dc: HDC, r: &RECT) {
    unsafe {
        let (w, h) = (r.right - r.left, r.bottom - r.top);
        let mem = CreateCompatibleDC(dc);
        let bmp = CreateCompatibleBitmap(dc, w, h);
        let old = SelectObject(mem, bmp);
        BitBlt(mem, 0, 0, w, h, dc, r.left, r.top, SRCCOPY);
        let mut prev = POINT { x: 0, y: 0 };
        OffsetViewportOrgEx(mem, -r.left, -r.top, &mut prev);
        draw_view(view, mem, r);
        SetViewportOrgEx(mem, prev.x, prev.y, null_mut());
        BitBlt(dc, r.left, r.top, w, h, mem, 0, 0, SRCCOPY);
        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
    }
}

thread_local! {
    /// Checkerboard background, drawn once per window size.
    static BACKGROUND: std::cell::Cell<(HDC, i32, i32)> = const { std::cell::Cell::new((std::ptr::null_mut(), 0, 0)) };
    /// Time spent in WM_PAINT, microseconds, and number of paints.
    pub static PAINT_US: std::cell::Cell<(u128, u32)> = const { std::cell::Cell::new((0, 0)) };
}

unsafe fn background(dc: HDC, w: i32, h: i32) -> HDC {
    let (bg, bw, bh) = BACKGROUND.with(|b| b.get());
    if !bg.is_null() && bw == w && bh == h {
        return bg;
    }
    unsafe {
        let mem = CreateCompatibleDC(dc);
        let bmp = CreateCompatibleBitmap(dc, w, h);
        SelectObject(mem, bmp);
        // Checkerboard, so transparency shows.
        let a = CreateSolidBrush(0x00C06020);
        let b = CreateSolidBrush(0x00A0A0A0);
        let mut y = 0;
        while y < h {
            let mut x = 0;
            while x < w {
                let r = RECT {
                    left: x,
                    top: y,
                    right: x + 16,
                    bottom: y + 16,
                };
                FillRect(mem, &r, if ((x + y) / 16) % 2 == 0 { a } else { b });
                x += 16;
            }
            y += 16;
        }
        DeleteObject(a);
        DeleteObject(b);
        BACKGROUND.with(|b| b.set((mem, w, h)));
        mem
    }
}

unsafe extern "system" fn container_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_PAINT {
        let t = Instant::now();
        unsafe {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let dc = BeginPaint(hwnd, &mut ps);
            let mut rc: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rc);
            let bg = background(dc, rc.right, rc.bottom);
            let p = ps.rcPaint;
            // Paint only what was invalidated: background, then the
            // controls that overlap it, windowless (IViewObject::Draw into
            // the window's DC at the control's position, as ATL does).
            BitBlt(
                dc,
                p.left,
                p.top,
                p.right - p.left,
                p.bottom - p.top,
                bg,
                p.left,
                p.top,
                SRCCOPY,
            );
            PAINT.with(|list| {
                for (i, item) in list.borrow().iter().enumerate() {
                    let r = &item.rect;
                    let overlaps = r.left < p.right
                        && r.right > p.left
                        && r.top < p.bottom
                        && r.bottom > p.top;
                    if !overlaps || !item.ready {
                        continue;
                    }
                    if item.path_a {
                        draw_path_a(item.view, dc, r);
                    } else {
                        draw_view(item.view, dc, r);
                    }
                    DRAWS.with(|d| {
                        let mut d = d.borrow_mut();
                        if d.len() <= i {
                            d.resize(i + 1, 0);
                        }
                        d[i] += 1;
                    });
                }
            });
            EndPaint(hwnd, &ps);
        }
        PAINT_US.with(|c| {
            let (us, n) = c.get();
            c.set((us + t.elapsed().as_micros(), n + 1));
        });
        return 0;
    }
    unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
}

pub fn container_window(w: i32, h: i32, title: &str) -> HWND {
    let cls = wide("FpcAxContainer");
    unsafe {
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(container_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: GetModuleHandleW(null()),
            hIcon: null_mut(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: null_mut(),
            lpszMenuName: null(),
            lpszClassName: cls.as_ptr(),
        };
        RegisterClassW(&wc);
        let t = wide(title);
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            cls.as_ptr(),
            t.as_ptr(),
            WS_POPUP | WS_VISIBLE,
            40,
            40,
            w,
            h,
            null_mut(),
            null_mut(),
            GetModuleHandleW(null()),
            null(),
        );
        UpdateWindow(hwnd);
        hwnd
    }
}

pub fn save_png(path: &str, w: u32, h: u32, bgra_premul: &[u8]) {
    let rgba: Vec<u8> = bgra_premul
        .chunks_exact(4)
        .flat_map(|p| {
            let a = p[3] as u32;
            let un = |c: u8| {
                if a == 0 {
                    0
                } else {
                    ((c as u32 * 255 + a / 2) / a).min(255) as u8
                }
            };
            [un(p[2]), un(p[1]), un(p[0]), p[3]]
        })
        .collect();
    image::RgbaImage::from_raw(w, h, rgba)
        .unwrap()
        .save(path)
        .unwrap();
}

/// The window's pixels as they are on screen (BGRA, alpha 255).
pub fn grab(hwnd: HWND) -> (i32, i32, Vec<u8>) {
    unsafe {
        let mut rc: RECT = std::mem::zeroed();
        GetWindowRect(hwnd, &mut rc);
        let (w, h) = (rc.right - rc.left, rc.bottom - rc.top);
        let screen = GetDC(null_mut());
        let mem = CreateCompatibleDC(screen);
        let bmp = CreateCompatibleBitmap(screen, w, h);
        let old = SelectObject(mem, bmp);
        BitBlt(
            mem,
            0,
            0,
            w,
            h,
            screen,
            rc.left,
            rc.top,
            SRCCOPY | CAPTUREBLT,
        );
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        let mut buf = vec![0u8; (w * h * 4) as usize];
        GetDIBits(
            mem,
            bmp,
            0,
            h as u32,
            buf.as_mut_ptr().cast(),
            &mut bi,
            DIB_RGB_COLORS,
        );
        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        ReleaseDC(null_mut(), screen);
        for p in buf.chunks_exact_mut(4) {
            p[3] = 255;
        }
        (w, h, buf)
    }
}

pub fn screenshot(hwnd: HWND, path: &str) {
    unsafe {
        let mut rc: RECT = std::mem::zeroed();
        GetWindowRect(hwnd, &mut rc);
        let (w, h) = (rc.right - rc.left, rc.bottom - rc.top);
        let screen = GetDC(null_mut());
        let mem = CreateCompatibleDC(screen);
        let bmp = CreateCompatibleBitmap(screen, w, h);
        let old = SelectObject(mem, bmp);
        BitBlt(
            mem,
            0,
            0,
            w,
            h,
            screen,
            rc.left,
            rc.top,
            SRCCOPY | CAPTUREBLT,
        );
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        let mut buf = vec![0u8; (w * h * 4) as usize];
        GetDIBits(
            mem,
            bmp,
            0,
            h as u32,
            buf.as_mut_ptr().cast(),
            &mut bi,
            DIB_RGB_COLORS,
        );
        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        ReleaseDC(null_mut(), screen);
        for p in buf.chunks_exact_mut(4) {
            p[3] = 255;
        }
        save_png(path, w as u32, h as u32, &buf);
    }
    say!("screenshot -> {path}");
}

/// Registers the DLL's class factory for this process (CoRegisterClassObject),
/// so CoCreateInstance(CLSID) reaches it without the registry.
pub fn register_class(dll_path: &str) -> u32 {
    unsafe {
        let w = wide(dll_path);
        let h = LoadLibraryW(w.as_ptr());
        let get =
            GetProcAddress(h, c"DllGetClassObject".as_ptr().cast()).expect("DllGetClassObject");
        let get: unsafe extern "system" fn(*const GUID, *const GUID, *mut Unk) -> HRESULT =
            std::mem::transmute(get);
        let mut cf: Unk = null_mut();
        let hr = get(&CLSID_FLASH, &IID_ICLASSFACTORY, &mut cf);
        say!("DllGetClassObject(CLSID ShockwaveFlash, IClassFactory) -> {hr:#x}");
        let mut cookie = 0u32;
        let hr = CoRegisterClassObject(
            &CLSID_FLASH,
            cf,
            CLSCTX_INPROC_SERVER,
            REGCLS_MULTIPLEUSE as u32,
            &mut cookie,
        );
        say!("CoRegisterClassObject -> {hr:#x}");
        let s = wide("{D27CDB6E-AE6D-11cf-96B8-444553540000}");
        let mut clsid: GUID = std::mem::zeroed();
        let hr = CLSIDFromString(s.as_ptr(), &mut clsid);
        say!(
            "CLSIDFromString -> {hr:#x}, same CLSID {}",
            guid_eq(&clsid, &CLSID_FLASH)
        );
        cookie
    }
}

pub struct Report {
    pub ok: bool,
}

/// All avatars at once in one container, every emotion in turn.
pub fn avatars_emotions(base: &str, out: &str, names: &[String]) -> Report {
    let _ = std::fs::create_dir_all(out);
    let (cw, ch) = (87, 109);
    let cols = 8;
    let rows = names.len().div_ceil(cols) as i32;
    let win = container_window(
        cols as i32 * (cw + 4) + 4,
        rows * (ch + 4) + 4,
        "ShockwaveFlash container",
    );
    let params = [
        ("WMode", "transparent"),
        ("Scale", "NoBorder"),
        ("Quality", "High"),
    ];
    let mut hosted = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let x = 4 + (i % cols) as i32 * (cw + 4);
        let y = 4 + (i / cols) as i32 * (ch + 4);
        let rect = RECT {
            left: x,
            top: y,
            right: x + cw,
            bottom: y + ch,
        };
        match host_control(win, rect, &params, n, i == 0) {
            Ok(h) => {
                PAINT.with(|p| {
                    p.borrow_mut().push(PaintItem {
                        view: h.view,
                        rect,
                        ready: true,
                        path_a: false,
                    })
                });
                hosted.push(h)
            }
            Err(e) => {
                say!("[{n}] cannot host: {e}");
                return Report { ok: false };
            }
        }
    }
    let sep = if base.starts_with("http") { "/" } else { "\\" };
    for h in &hosted {
        let url = format!("{base}{sep}{}", h.name);
        let hr = h.put_movie_dispatch(&url);
        let p = h.play();
        if hr < 0 {
            say!("[{}] put Movie {hr:#x}", h.name);
        }
        let _ = p;
    }
    // Wait for all loads.
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) && hosted.iter().any(|h| h.ready_state() != 4) {
        pump_for(Duration::from_millis(50));
    }
    say!(
        "{} controls loaded in {} ms ({} not ready)",
        hosted.len(),
        t.elapsed().as_millis(),
        hosted.iter().filter(|h| h.ready_state() != 4).count()
    );
    pump_for(Duration::from_millis(800));
    screenshot(win, &format!("{out}\\container-start.png"));

    // Cost with every avatar animating: frames rendered, UI thread busy.
    let inv0: u32 = hosted.iter().map(|h| h.invalidations()).sum();
    let busy0 = crate::busy_us();
    let paint0 = PAINT_US.with(|c| c.get());
    let t0 = Instant::now();
    pump_for(Duration::from_secs(5));
    let secs = t0.elapsed().as_secs_f64();
    let frames = hosted.iter().map(|h| h.invalidations()).sum::<u32>() - inv0;
    let busy = (crate::busy_us() - busy0) as f64 / 1e6;
    let paint = PAINT_US.with(|c| c.get());
    say!(
        "load: {} controls animating: {:.0} frames/s in total ({:.1} per control), UI thread busy {:.0}% (painting the container {:.0}%, {} paints)",
        hosted.len(),
        frames as f64 / secs,
        frames as f64 / secs / hosted.len() as f64,
        busy / secs * 100.0,
        (paint.0 - paint0.0) as f64 / 1e6 / secs * 100.0,
        paint.1 - paint0.1
    );

    // Sheet: one row per avatar, columns = initial + each emotion.
    let cols_sheet = 1 + EMOTIONS.len();
    let (sw, sh) = (cols_sheet * cw as usize, names.len() * ch as usize);
    let mut sheet = vec![0u8; sw * sh * 4];
    let put = |sheet: &mut Vec<u8>, row: usize, col: usize, px: &[u8]| {
        for y in 0..ch as usize {
            let dst = ((row * ch as usize + y) * sw + col * cw as usize) * 4;
            let src = y * cw as usize * 4;
            sheet[dst..dst + cw as usize * 4].copy_from_slice(&px[src..src + cw as usize * 4]);
        }
    };
    let mut blank = 0;
    for (r, h) in hosted.iter().enumerate() {
        let (_, px) = h.capture(cw, ch);
        put(&mut sheet, r, 0, &px);
    }
    let mut changed_total = 0;
    for (c, e) in EMOTIONS.iter().enumerate() {
        for h in &hosted {
            // What MCDevilImpl does: reset to "stam", then the emotion.
            h.set_variable("face.emotion", "stam");
            let hr = h.set_variable("face.emotion", e);
            if hr < 0 {
                say!("[{}] SetVariable(face.emotion, {e}) {hr:#x}", h.name);
            }
        }
        pump_for(Duration::from_millis(900));
        let mut changed = 0;
        for (r, h) in hosted.iter().enumerate() {
            let (hr, px) = h.capture(cw, ch);
            if hr < 0 {
                say!("[{}] Draw {hr:#x}", h.name);
            }
            if px.chunks_exact(4).all(|p| p[3] == 0) {
                blank += 1;
            }
            // Compare with the previous column.
            let prev_col = c; // column index of previous capture
            let mut differs = false;
            for y in 0..ch as usize {
                let a = ((r * ch as usize + y) * sw + prev_col * cw as usize) * 4;
                if sheet[a..a + cw as usize * 4]
                    != px[y * cw as usize * 4..(y + 1) * cw as usize * 4]
                {
                    differs = true;
                    break;
                }
            }
            if differs {
                changed += 1;
            }
            put(&mut sheet, r, c + 1, &px);
        }
        let (_, v) = hosted[0].get_variable("face.emotion");
        say!(
            "emotion {e:8}: {changed}/{} avatars changed picture; GetVariable(face.emotion) on {} -> {v:?}",
            hosted.len(),
            hosted[0].name
        );
        changed_total += changed;
        if *e == "love" {
            screenshot(win, &format!("{out}\\container-love.png"));
        }
    }
    save_png(
        &format!("{out}\\sheet-avatars-x-emotions.png"),
        sw as u32,
        sh as u32,
        &sheet,
    );
    say!(
        "sheet -> {out}\\sheet-avatars-x-emotions.png ({} rows x {} columns: start, {})",
        names.len(),
        cols_sheet,
        EMOTIONS.join(", ")
    );

    // TGotoLabel, Stop, Play on the first avatar.
    let h = &hosted[0];
    let (_, f0) = h.get_variable("face._currentframe");
    let hr = h.t_goto_label("face", "smile");
    pump_for(Duration::from_millis(100));
    let (_, f1) = h.get_variable("face._currentframe");
    say!(
        "[{}] TGotoLabel(face, smile) {hr:#x}: face._currentframe {f0} -> {f1}",
        h.name
    );
    let hr_root = h.t_goto_label("_root", "nosuchlabel");
    say!(
        "[{}] TGotoLabel(_root, nosuchlabel) {hr_root:#x} (runs; Flash ignores unknown labels)",
        h.name
    );
    let inv0 = h.invalidations();
    let s = h.stop();
    pump_for(Duration::from_millis(600));
    let inv1 = h.invalidations();
    let p = h.play();
    pump_for(Duration::from_millis(600));
    let inv2 = h.invalidations();
    say!(
        "[{}] Stop {s:#x}: InvalidateRect calls in 600 ms {}; Play {p:#x}: {} in 600 ms",
        h.name,
        inv1 - inv0,
        inv2 - inv1
    );
    let total_inv: u32 = hosted.iter().map(|h| h.invalidations()).sum();
    let total_vc: u32 = hosted.iter().map(|h| h.view_changes()).sum();
    say!("site InvalidateRect calls {total_inv}, IAdviseSink::OnViewChange {total_vc}");

    PAINT.with(|p| p.borrow_mut().clear());
    for h in hosted {
        h.close();
    }
    unsafe { DestroyWindow(win) };
    say!(
        "summary: {} emotion captures changed the picture, {blank} blank captures",
        changed_total
    );
    Report {
        ok: blank == 0 && changed_total > 0,
    }
}

// ---------------------------------------------------------------------------
// Windows' own ATL host (atl.dll): AtlAxAttachControl on an existing control.

pub fn atl_host(base: &str, out: &str, names: &[String]) -> bool {
    unsafe {
        let w = wide("atl.dll");
        let atl = LoadLibraryW(w.as_ptr());
        if atl.is_null() {
            say!("atl.dll not found");
            return false;
        }
        let init: unsafe extern "system" fn() -> i32 =
            std::mem::transmute(GetProcAddress(atl, c"AtlAxWinInit".as_ptr().cast()).unwrap());
        let attach: unsafe extern "system" fn(Unk, HWND, *mut Unk) -> HRESULT = std::mem::transmute(
            GetProcAddress(atl, c"AtlAxAttachControl".as_ptr().cast()).unwrap(),
        );
        init();
        let (cw, ch) = (87 * 2, 109 * 2);
        let win = container_window(names.len() as i32 * (cw + 8) + 8, ch + 16, "ATL host");
        let cls = wide("AtlAxWin");
        let mut ok = true;
        let mut kept = Vec::new();
        for (i, n) in names.iter().enumerate() {
            let child = CreateWindowExW(
                0,
                cls.as_ptr(),
                null(),
                WS_CHILD | WS_VISIBLE,
                8 + i as i32 * (cw + 8),
                8,
                cw,
                ch,
                win,
                null_mut(),
                GetModuleHandleW(null()),
                null(),
            );
            let mut unk: Unk = null_mut();
            let hr = CoCreateInstance(
                &CLSID_FLASH,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_IUNKNOWN,
                &mut unk,
            );
            if hr < 0 {
                say!("ATL [{n}] CoCreateInstance {hr:#x}");
                ok = false;
                continue;
            }
            // Parameters first (as a page's <param>s would), then ATL activates it.
            let bag = Box::new(Bag {
                vtbl: bag_vtbl(),
                params: vec![
                    ("WMode".into(), "transparent".into()),
                    ("Scale".into(), "NoBorder".into()),
                ],
                reads: Default::default(),
            });
            let pb = qi(unk, &IID_IPERSISTPROPERTYBAG);
            vcall!(
                pb,
                5,
                fn(Unk, Unk) -> HRESULT,
                &*bag as *const Bag as Unk,
                null_mut()
            );
            vcall!(pb, 2, fn() -> u32);
            let mut container: Unk = null_mut();
            let hr = attach(unk, child, &mut container);
            let flash = qi(unk, &crate::IID_ISHOCKWAVEFLASH);
            let sep = if base.starts_with("http") { "/" } else { "\\" };
            let url = wide(&format!("{base}{sep}{n}"));
            let b = SysAllocString(url.as_ptr());
            let mh = vcall!(flash, 22, fn(*const u16) -> HRESULT, b); // put_Movie +0x58
            SysFreeString(b);
            say!("ATL [{n}] AtlAxAttachControl {hr:#x}, put_Movie {mh:#x}");
            if hr < 0 {
                ok = false;
            }
            kept.push((unk, flash, container, child));
        }
        pump_for(Duration::from_millis(2500));
        for (_, flash, _, _) in &kept {
            let (n, v) = (wide("face.emotion"), wide("love"));
            let (bn, bv) = (SysAllocString(n.as_ptr()), SysAllocString(v.as_ptr()));
            vcall!(*flash, 65, fn(*const u16, *const u16) -> HRESULT, bn, bv);
            SysFreeString(bn);
            SysFreeString(bv);
        }
        pump_for(Duration::from_millis(1200));
        screenshot(win, &format!("{out}\\atl-host.png"));
        for (unk, flash, container, child) in kept {
            vcall!(flash, 2, fn() -> u32);
            DestroyWindow(child);
            if !container.is_null() {
                vcall!(container, 2, fn() -> u32);
            }
            let left = vcall!(unk, 2, fn() -> u32);
            say!("ATL control released -> {left}");
        }
        DestroyWindow(win);
        ok
    }
}

// ---------------------------------------------------------------------------
// Registration under a test root.

fn reg_get(path: &str, name: Option<&str>) -> Option<String> {
    unsafe {
        let p = wide(path);
        let n = name.map(wide);
        let mut buf = vec![0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        let e = RegGetValueW(
            HKEY_CURRENT_USER,
            p.as_ptr(),
            n.as_ref().map_or(null(), |n| n.as_ptr()),
            RRF_RT_REG_SZ,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        );
        if e != 0 {
            return None;
        }
        Some(
            String::from_utf16_lossy(&buf[..len as usize / 2])
                .trim_end_matches('\0')
                .to_string(),
        )
    }
}

pub fn registration(fpc: &crate::Fpc) -> bool {
    let root = "Software\\FlashPlayerControlTest\\Classes";
    unsafe { std::env::set_var("FLASHPLAYERCONTROL_TEST_REGROOT", root) };
    let tl = "Software\\Classes\\TypeLib\\{D27CDB6B-AE6D-11CF-96B8-444553540000}\\1.0\\0\\win32";
    let before = reg_get(tl, None);
    say!("user's type library registration before: {before:?}");
    say!(
        "DllRegisterServer (test root) -> {:#x}",
        (fpc.DllRegisterServer)()
    );
    let c = format!("{root}\\CLSID\\{{D27CDB6E-AE6D-11cf-96B8-444553540000}}");
    let mut ok = true;
    for (k, n) in [
        (c.clone(), None),
        (format!("{c}\\InprocServer32"), None),
        (format!("{c}\\InprocServer32"), Some("ThreadingModel")),
        (format!("{c}\\ProgID"), None),
        (format!("{c}\\VersionIndependentProgID"), None),
        (format!("{c}\\TypeLib"), None),
        (format!("{c}\\MiscStatus\\1"), None),
        (
            format!("{root}\\ShockwaveFlash.ShockwaveFlash\\CLSID"),
            None,
        ),
        (
            format!("{root}\\ShockwaveFlash.ShockwaveFlash\\CurVer"),
            None,
        ),
        (
            format!("{root}\\ShockwaveFlash.ShockwaveFlash.9\\CLSID"),
            None,
        ),
        (
            format!("{root}\\ShockwaveFlash.ShockwaveFlash.10\\CLSID"),
            None,
        ),
    ] {
        let v = reg_get(&k, n);
        ok &= v.is_some();
        say!(
            "  HKCU\\{k}{} = {v:?}",
            n.map(|n| format!(" [{n}]")).unwrap_or_default()
        );
    }
    say!(
        "DllUnregisterServer (test root) -> {:#x}",
        (fpc.DllUnregisterServer)()
    );
    let gone = reg_get(&format!("{c}\\InprocServer32"), None).is_none()
        && reg_get(
            &format!("{root}\\ShockwaveFlash.ShockwaveFlash\\CLSID"),
            None,
        )
        .is_none();
    say!("class keys removed: {gone}");
    unsafe {
        let p = wide("Software\\FlashPlayerControlTest");
        let e = RegDeleteTreeW(HKEY_CURRENT_USER, p.as_ptr());
        let p2 = wide("Software\\FlashPlayerControlTest");
        RegDeleteKeyW(HKEY_CURRENT_USER, p2.as_ptr());
        say!("test root deleted ({e})");
    }
    let after = reg_get(tl, None);
    say!(
        "user's type library registration after: {after:?} (unchanged: {})",
        before == after
    );
    ok && gone && before == after
}

/// face <base dir|url> <name>: the return to the status face after a smiley
/// (src/face.rs), with the faces sent the way ICQ 6.5's MCDevilImpl sends
/// them: "stam", then the face. Run with FLASHPLAYERCONTROL_FACE_RETURN=2.
pub fn face_return(dll_path: &str, base: &str, name: &str) -> bool {
    let wait = Duration::from_secs(2);
    let win = container_window(95, 117, "face return");
    let rect = RECT {
        left: 4,
        top: 4,
        right: 91,
        bottom: 113,
    };
    let params = [("WMode", "transparent"), ("Scale", "NoBorder")];
    let h = match host_control(win, rect, &params, name, true) {
        Ok(h) => h,
        Err(e) => {
            say!("[{name}] cannot host: {e}");
            return false;
        }
    };
    let sep = if base.starts_with("http") { "/" } else { "\\" };
    h.put_movie_dispatch(&format!("{base}{sep}{name}"));
    h.play();
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) && h.ready_state() != 4 {
        pump_for(Duration::from_millis(50));
    }
    pump_for(Duration::from_millis(300));

    let pair = |e: &str| {
        h.set_variable("face.emotion", "stam");
        h.set_variable("face.emotion", e);
    };
    let face = || h.get_variable("face.emotion").1;
    let mut ok = true;
    let mut check = |what: &str, want: &str| {
        let got = face();
        say!("{what}: face {got:?} (want {want:?})");
        ok &= got == want;
    };

    pair("busy");
    check("status busy", "busy");
    pair("smile");
    check("smiley while busy", "smile");
    pump_for(wait - Duration::from_millis(500));
    check("just before the return", "smile");
    pump_for(Duration::from_millis(1000));
    check("after the return", "busy");

    pair("stam");
    pair("laugh");
    pump_for(wait - Duration::from_millis(700));
    pair("sad");
    pump_for(Duration::from_millis(1200));
    check("a second smiley restarted the wait", "sad");
    pump_for(Duration::from_millis(1300));
    check("after the second return", "stam");

    pair("mad");
    pump_for(Duration::from_millis(300));
    pair("offline");
    check("status change during a smiley", "offline");
    pump_for(wait + Duration::from_millis(500));
    check("the status stays", "offline");

    // A host that times the faces itself.
    unsafe {
        let w = wide(dll_path);
        let m = LoadLibraryW(w.as_ptr());
        let set = GetProcAddress(m, c"FPCSetFaceReturn".as_ptr().cast()).expect("FPCSetFaceReturn");
        let set: unsafe extern "system" fn(u32) -> HRESULT = std::mem::transmute(set);
        say!("FPCSetFaceReturn(0) -> {:#x}", set(0));
    }
    pair("stam");
    h.set_variable("face.emotion", "love");
    pump_for(wait + Duration::from_millis(500));
    check("return off", "love");

    say!("result: face return ok {ok}");
    ok
}
