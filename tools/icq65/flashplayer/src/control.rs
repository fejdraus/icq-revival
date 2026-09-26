//! The ShockwaveFlash ActiveX control, CLSID {D27CDB6E-AE6D-11cf-96B8-444553540000}.
//!
//! ICQ 6.5's Boxely UI (boxelyRenderer.dll, the "devil" avatar gadget) hosts
//! Flash as a windowless ActiveX control, not through FlashPlayerControl's
//! window. This object provides that on the same Ruffle engine: each control
//! owns a hidden message-only window of class "FlashPlayerControl" (so it gets
//! the same player, timer, loading and IShockwaveFlash as a tZer window, see
//! instance.rs), and adds the OLE control interfaces a host needs:
//!
//! - IOleObject, IPersistPropertyBag, IPersistStreamInit (creation, the
//!   `<param>`s: Movie, WMode, Scale, Play, Loop)
//! - IViewObjectEx / IViewObject2 / IViewObject (Draw: the last frame,
//!   premultiplied, AlphaBlend'ed into the host's DC)
//! - IOleInPlaceObjectWindowless / IOleInPlaceObject / IOleWindow
//!   (windowless in-place activation, SetObjectRects)
//! - IObjectWithSite, IOleControl
//! - IShockwaveFlash / IDispatch / IConnectionPointContainer from the
//!   window's FlashObject, which delegates its IUnknown to this control.
//!
//! When the movie shows a new frame, the host is told through
//! IOleInPlaceSiteWindowless::InvalidateRect (or IAdviseSink::OnViewChange)
//! and paints it with Draw. Everything runs on the thread that created the
//! control (apartment threaded).

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{
    E_FAIL, E_NOINTERFACE, E_NOTIMPL, E_POINTER, E_UNEXPECTED, HWND, POINT, RECT, S_FALSE, S_OK,
    SIZE,
};
use windows_sys::Win32::Graphics::Gdi::{
    AC_SRC_ALPHA, AC_SRC_OVER, AlphaBlend, BLENDFUNCTION, CreateCompatibleDC, DeleteDC,
    DeleteObject, HBITMAP, HDC, SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, HWND_MESSAGE};
use windows_sys::core::{GUID, HRESULT};

use crate::com::{FlashObject, bstr_to_string, com_release, vcall};
use crate::instance::{self, Instance};
use crate::log;
use crate::movie::Frame;

type Unk = *mut c_void;

pub const CLSID_SHOCKWAVEFLASH: GUID = GUID::from_u128(0xD27CDB6E_AE6D_11cf_96B8_444553540000);

const fn iid(v: u128) -> GUID {
    GUID::from_u128(v)
}
const IID_IUNKNOWN: GUID = iid(0x00000000_0000_0000_C000_000000000046);
const IID_ICLASSFACTORY: GUID = iid(0x00000001_0000_0000_C000_000000000046);
const IID_ICLASSFACTORY2: GUID = iid(0xB196B28F_BAB4_101A_B69C_00AA00341D07);
const IID_IOLEOBJECT: GUID = iid(0x00000112_0000_0000_C000_000000000046);
const IID_IPERSIST: GUID = iid(0x0000010C_0000_0000_C000_000000000046);
const IID_IPERSISTPROPERTYBAG: GUID = iid(0x37D84F60_42CB_11CE_8135_00AA004BB851);
const IID_IPERSISTSTREAMINIT: GUID = iid(0x7FD52380_4E07_101B_AE2D_08002B2EC713);
const IID_IVIEWOBJECT: GUID = iid(0x0000010D_0000_0000_C000_000000000046);
const IID_IVIEWOBJECT2: GUID = iid(0x00000127_0000_0000_C000_000000000046);
const IID_IVIEWOBJECTEX: GUID = iid(0x3AF24292_0C96_11CE_A0CF_00AA00600AB8);
const IID_IOLEWINDOW: GUID = iid(0x00000114_0000_0000_C000_000000000046);
const IID_IOLEINPLACEOBJECT: GUID = iid(0x00000113_0000_0000_C000_000000000046);
const IID_IOLEINPLACEOBJECTWINDOWLESS: GUID = iid(0x1C2056CC_5EF4_101B_8BC8_00AA003E3B29);
const IID_IOBJECTWITHSITE: GUID = iid(0xFC4801A3_2BA9_11CF_A229_00AA003D7352);
const IID_IOLECONTROL: GUID = iid(0xB196B288_BAB4_101A_B69C_00AA00341D07);
const IID_IOLEINPLACESITE: GUID = iid(0x00000119_0000_0000_C000_000000000046);
const IID_IOLEINPLACESITEEX: GUID = iid(0x9C2CAD80_3424_11CF_B670_00AA004CD6D8);
const IID_IOLEINPLACESITEWINDOWLESS: GUID = iid(0x922EADA0_3424_11CF_B670_00AA004CD6D8);
const IID_IDISPATCH: GUID = iid(0x00020400_0000_0000_C000_000000000046);
const IID_ISHOCKWAVEFLASH: GUID = crate::com::IID_ISHOCKWAVEFLASH;
const IID_ICONNECTIONPOINTCONTAINER: GUID = iid(0xB196B284_BAB4_101A_B69C_00AA00341D07);

const CLASS_E_NOAGGREGATION: HRESULT = 0x80040110u32 as i32;
const CLASS_E_CLASSNOTAVAILABLE: HRESULT = 0x80040111u32 as i32;
const OLE_S_USEREG: HRESULT = 0x00040000;
const OLEOBJ_S_INVALIDVERB: HRESULT = 0x00040180;
const OLE_E_NOTRUNNING: HRESULT = 0x80040005u32 as i32;

const OLEIVERB_PRIMARY: i32 = 0;
const OLEIVERB_SHOW: i32 = -1;
const OLEIVERB_HIDE: i32 = -3;
const OLEIVERB_UIACTIVATE: i32 = -4;
const OLEIVERB_INPLACEACTIVATE: i32 = -5;

/// Flash's registered MiscStatus: RECOMPOSEONRESIZE | CANTLINKINSIDE |
/// INSIDEOUT | ACTIVATEWHENVISIBLE | SETCLIENTSITEFIRST.
const MISC_STATUS: u32 = 0x0002_0191;
const ACTIVATE_WINDOWLESS: u32 = 1;
const DVASPECT_CONTENT: u32 = 1;
const VIEWSTATUS_OPAQUE: u32 = 1;
const HITRESULT_OUTSIDE: u32 = 0;
const HITRESULT_HIT: u32 = 3;

const PTR: usize = size_of::<usize>();

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

fn px_from_himetric(v: i32) -> i32 {
    (v as i64 * 96 / 2540) as i32
}
fn himetric_from_px(v: i32) -> i32 {
    (v as i64 * 2540 / 96) as i32
}

/// Interface slots of the control: index i is at offset i * PTR.
const I_UNKNOWN: usize = 0;
const I_OLEOBJECT: usize = 1;
const I_PROPBAG: usize = 2;
const I_STREAMINIT: usize = 3;
const I_VIEW: usize = 4;
const I_INPLACE: usize = 5;
const I_WITHSITE: usize = 6;
const I_CONTROL: usize = 7;
const INTERFACES: usize = 8;

#[repr(C)]
pub struct Control {
    vtbls: [*const usize; INTERFACES],
    refs: AtomicU32,
    /// The hidden window whose Instance plays the movie.
    hwnd: Cell<HWND>,
    flash: Cell<*mut FlashObject>,
    client_site: Cell<Unk>,
    site: Cell<Unk>,
    inplace_site: Cell<Unk>,
    /// Kind of `inplace_site`: 0 plain, 1 Ex, 2 windowless.
    site_kind: Cell<u8>,
    active: Cell<bool>,
    pos: Cell<RECT>,
    extent: Cell<SIZE>, // HIMETRIC
    view_sink: Cell<Unk>,
    view_aspects: Cell<u32>,
    view_advf: Cell<u32>,
    advise_holder: Cell<Unk>,
    in_draw: Cell<bool>,
    /// GDI copy of the last frame drawn: (frame, memory DC, bitmap, old bitmap).
    cache: RefCell<Option<(Rc<Frame>, HDC, HBITMAP, *mut c_void)>>,
}

unsafe fn ctl<'a>(this: Unk, index: usize) -> &'a Control {
    unsafe { &*((this as *const u8).sub(index * PTR) as *const Control) }
}

impl Control {
    fn ptr(&self, index: usize) -> Unk {
        unsafe { (self as *const Control as *const u8).add(index * PTR) as Unk }
    }

    fn inst(&self) -> Option<Rc<Instance>> {
        instance::get(self.hwnd.get())
    }

    /// A new control with one reference, or an error.
    fn create() -> Result<*mut Control, HRESULT> {
        crate::RegisterFlashWindowClass();
        let c = Box::into_raw(Box::new(Control {
            vtbls: vtables(),
            refs: AtomicU32::new(1),
            hwnd: Cell::new(null_mut()),
            flash: Cell::new(null_mut()),
            client_site: Cell::new(null_mut()),
            site: Cell::new(null_mut()),
            inplace_site: Cell::new(null_mut()),
            site_kind: Cell::new(0),
            active: Cell::new(false),
            pos: Cell::new(RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            }),
            extent: Cell::new(SIZE {
                cx: himetric_from_px(100),
                cy: himetric_from_px(100),
            }),
            view_sink: Cell::new(null_mut()),
            view_aspects: Cell::new(0),
            view_advf: Cell::new(0),
            advise_holder: Cell::new(null_mut()),
            in_draw: Cell::new(false),
            cache: RefCell::new(None),
        }));
        let control = unsafe { &*c };
        let class: Vec<u16> = "FlashPlayerControl".encode_utf16().chain(Some(0)).collect();
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                null(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                null_mut(),
                crate::module(),
                null(),
            )
        };
        let Some(inst) = instance::get(hwnd) else {
            log("control: cannot create its window");
            unsafe { drop(Box::from_raw(c)) };
            return Err(E_FAIL);
        };
        control.hwnd.set(hwnd);
        inst.set_control_mode();
        let flash = inst.com;
        unsafe { (*flash).set_outer(control.ptr(I_UNKNOWN)) };
        control.flash.set(flash);
        let me = c as usize;
        *inst.on_frame.borrow_mut() = Some(Box::new(move || unsafe {
            (*(me as *const Control)).frame_changed()
        }));
        Ok(c)
    }

    fn query(&self, iid: &GUID, out: *mut Unk) -> HRESULT {
        if out.is_null() {
            return E_POINTER;
        }
        let index = if guid_eq(iid, &IID_IUNKNOWN) {
            Some(I_UNKNOWN)
        } else if guid_eq(iid, &IID_IOLEOBJECT) {
            Some(I_OLEOBJECT)
        } else if guid_eq(iid, &IID_IPERSISTPROPERTYBAG) {
            Some(I_PROPBAG)
        } else if guid_eq(iid, &IID_IPERSISTSTREAMINIT) || guid_eq(iid, &IID_IPERSIST) {
            Some(I_STREAMINIT)
        } else if guid_eq(iid, &IID_IVIEWOBJECT)
            || guid_eq(iid, &IID_IVIEWOBJECT2)
            || guid_eq(iid, &IID_IVIEWOBJECTEX)
        {
            Some(I_VIEW)
        } else if guid_eq(iid, &IID_IOLEWINDOW)
            || guid_eq(iid, &IID_IOLEINPLACEOBJECT)
            || guid_eq(iid, &IID_IOLEINPLACEOBJECTWINDOWLESS)
        {
            Some(I_INPLACE)
        } else if guid_eq(iid, &IID_IOBJECTWITHSITE) {
            Some(I_WITHSITE)
        } else if guid_eq(iid, &IID_IOLECONTROL) {
            Some(I_CONTROL)
        } else {
            None
        };
        if let Some(i) = index {
            self.refs.fetch_add(1, Ordering::Relaxed);
            unsafe { *out = self.ptr(i) };
            return S_OK;
        }
        let flash = self.flash.get();
        if !flash.is_null()
            && (guid_eq(iid, &IID_IDISPATCH)
                || guid_eq(iid, &IID_ISHOCKWAVEFLASH)
                || guid_eq(iid, &IID_ICONNECTIONPOINTCONTAINER))
        {
            return unsafe { (*flash).own_query(iid, out) };
        }
        unsafe { *out = null_mut() };
        E_NOINTERFACE
    }

    fn add_ref(&self) -> u32 {
        self.refs.fetch_add(1, Ordering::Relaxed) + 1
    }

    unsafe fn release(this: *const Control) -> u32 {
        let left = unsafe { (*this).refs.fetch_sub(1, Ordering::AcqRel) } - 1;
        if left == 0 {
            // Keep the object alive while tearing down (callbacks may AddRef).
            unsafe { (*this).refs.store(1, Ordering::Relaxed) };
            unsafe { (*this).teardown() };
            unsafe { drop(Box::from_raw(this as *mut Control)) };
        }
        left
    }

    fn teardown(&self) {
        self.deactivate();
        if let Some(inst) = self.inst() {
            inst.on_frame.borrow_mut().take();
        }
        let flash = self.flash.replace(null_mut());
        if !flash.is_null() {
            unsafe { (*flash).set_outer(null_mut()) };
        }
        let hwnd = self.hwnd.replace(null_mut());
        if !hwnd.is_null() {
            // Destroys the Instance: stops the movie, releases the FlashObject.
            unsafe { DestroyWindow(hwnd) };
        }
        for cell in [
            &self.client_site,
            &self.site,
            &self.view_sink,
            &self.advise_holder,
        ] {
            unsafe { com_release(cell.replace(null_mut())) };
        }
        self.drop_cache();
    }

    fn drop_cache(&self) {
        if let Some((_, dc, bmp, old)) = self.cache.borrow_mut().take() {
            unsafe {
                SelectObject(dc, old);
                DeleteObject(bmp);
                DeleteDC(dc);
            }
        }
    }

    /// The movie showed a new frame: ask the host to repaint us.
    fn frame_changed(&self) {
        if self.in_draw.get() {
            return;
        }
        let site = self.inplace_site.get();
        if self.active.get() && !site.is_null() && self.site_kind.get() == 2 {
            // IOleInPlaceSiteWindowless::InvalidateRect(NULL, FALSE)
            unsafe { vcall!(site, 25, fn(*const RECT, i32) -> HRESULT, null(), 0) };
            return;
        }
        let sink = self.view_sink.get();
        if !sink.is_null() {
            // IAdviseSink::OnViewChange(DVASPECT_CONTENT, -1)
            unsafe { vcall!(sink, 4, fn(u32, i32) -> (), DVASPECT_CONTENT, -1) };
        }
    }

    fn pixel_size(&self) -> (u32, u32) {
        let r = self.pos.get();
        if self.active.get() && r.right > r.left && r.bottom > r.top {
            ((r.right - r.left) as u32, (r.bottom - r.top) as u32)
        } else {
            let e = self.extent.get();
            (
                px_from_himetric(e.cx).max(1) as u32,
                px_from_himetric(e.cy).max(1) as u32,
            )
        }
    }

    fn resize(&self) {
        let (w, h) = self.pixel_size();
        if let Some(inst) = self.inst() {
            inst.set_size(w, h);
        }
    }

    fn activate(&self, rect: *const RECT) -> HRESULT {
        let client = self.client_site.get();
        if client.is_null() {
            return E_UNEXPECTED;
        }
        if self.active.get() {
            if !rect.is_null() {
                self.pos.set(unsafe { *rect });
                self.resize();
            }
            return S_OK;
        }
        unsafe {
            let mut site: Unk = null_mut();
            let mut kind = 0u8;
            let q = |iid: &GUID, out: &mut Unk| {
                vcall!(client, 0, fn(*const GUID, *mut Unk) -> HRESULT, iid, out) >= 0
                    && !out.is_null()
            };
            let mut s: Unk = null_mut();
            if q(&IID_IOLEINPLACESITEWINDOWLESS, &mut s) {
                if vcall!(s, 18, fn() -> HRESULT) == S_OK {
                    site = s;
                    kind = 2;
                } else {
                    com_release(s);
                }
            }
            if site.is_null() {
                let mut s: Unk = null_mut();
                if q(&IID_IOLEINPLACESITEEX, &mut s) {
                    site = s;
                    kind = 1;
                }
            }
            if site.is_null() {
                let mut s: Unk = null_mut();
                if q(&IID_IOLEINPLACESITE, &mut s) {
                    site = s;
                }
            }
            if site.is_null() {
                return E_NOINTERFACE;
            }
            let hr = match kind {
                2 | 1 => {
                    let mut no_redraw = 0i32;
                    let flags = if kind == 2 { ACTIVATE_WINDOWLESS } else { 0 };
                    vcall!(
                        site,
                        15,
                        fn(*mut i32, u32) -> HRESULT,
                        &mut no_redraw,
                        flags
                    )
                }
                _ => {
                    if vcall!(site, 5, fn() -> HRESULT) != S_OK {
                        com_release(site);
                        return E_FAIL;
                    }
                    vcall!(site, 6, fn() -> HRESULT)
                }
            };
            if hr < 0 {
                com_release(site);
                return hr;
            }
            if kind != 2 {
                log(
                    "control: host has no windowless site; frames reach it only through IAdviseSink::OnViewChange",
                );
            }
            // GetWindowContext for the position rectangle.
            let mut frame: Unk = null_mut();
            let mut doc: Unk = null_mut();
            let mut pos: RECT = std::mem::zeroed();
            let mut clip: RECT = std::mem::zeroed();
            let mut info = [0u32; 5];
            info[0] = 20; // OLEINPLACEFRAMEINFO.cb
            let hr = vcall!(
                site,
                8,
                fn(*mut Unk, *mut Unk, *mut RECT, *mut RECT, *mut u32) -> HRESULT,
                &mut frame,
                &mut doc,
                &mut pos,
                &mut clip,
                info.as_mut_ptr()
            );
            com_release(frame);
            com_release(doc);
            if !rect.is_null() {
                self.pos.set(*rect);
            } else if hr >= 0 {
                self.pos.set(pos);
            }
            self.inplace_site.set(site);
            self.site_kind.set(kind);
            self.active.set(true);
            // IOleClientSite::ShowObject
            vcall!(client, 6, fn() -> HRESULT);
        }
        self.resize();
        self.frame_changed();
        S_OK
    }

    fn deactivate(&self) {
        if !self.active.replace(false) {
            return;
        }
        let site = self.inplace_site.replace(null_mut());
        if site.is_null() {
            return;
        }
        unsafe {
            if self.site_kind.get() >= 1 {
                vcall!(site, 16, fn(i32) -> HRESULT, 1);
            } else {
                vcall!(site, 11, fn() -> HRESULT);
            }
            com_release(site);
        }
    }

    /// Reads the `<param>`s Flash understands and applies them.
    fn load_params(&self, bag: Unk) -> HRESULT {
        let read = |name: &str| -> Option<String> {
            let w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let mut var = crate::com::Variant {
                vt: crate::com::VT_BSTR,
                reserved: [0; 3],
                value: 0,
            };
            let hr = unsafe {
                vcall!(
                    bag,
                    3,
                    fn(*const u16, *mut crate::com::Variant, Unk) -> HRESULT,
                    w.as_ptr(),
                    &mut var,
                    null_mut()
                )
            };
            if hr < 0 {
                return None;
            }
            if var.vt != crate::com::VT_BSTR {
                unsafe {
                    windows_sys::Win32::System::Variant::VariantClear(
                        (&mut var as *mut crate::com::Variant).cast(),
                    )
                };
                return None;
            }
            let b = var.value as usize as *const u16;
            let s = unsafe { bstr_to_string(b) };
            unsafe { windows_sys::Win32::Foundation::SysFreeString(b) };
            Some(s)
        };
        let Some(inst) = self.inst() else {
            return E_UNEXPECTED;
        };
        let mut d = inst.display.get();
        if let Some(w) = read("WMode") {
            d.transparent = w.trim().eq_ignore_ascii_case("transparent");
        }
        if let Some(s) = read("Scale").and_then(|s| crate::movie::scale_mode(&s)) {
            d.scale = s;
        }
        inst.set_display(d);
        let movie = read("Movie")
            .or_else(|| read("Src"))
            .filter(|m| !m.trim().is_empty());
        let play = read("Play").is_none_or(|p| !p.trim().eq_ignore_ascii_case("false"));
        log(&format!(
            "control params: movie {movie:?}, transparent {}, scale {:?}, play {play}",
            d.transparent, d.scale
        ));
        if let Some(m) = movie {
            inst.load(&m);
            if !play {
                inst.stop_play();
            }
        }
        S_OK
    }

    /// GDI bitmap of the frame (cached until the next frame).
    fn frame_dc(&self, frame: &Rc<Frame>) -> Option<HDC> {
        if let Some((f, dc, _, _)) = self.cache.borrow().as_ref() {
            if Rc::ptr_eq(f, frame) {
                return Some(*dc);
            }
        }
        self.drop_cache();
        let (bmp, bits) = crate::instance::new_dib(frame.width, frame.height)?;
        unsafe {
            std::ptr::copy_nonoverlapping(frame.pixels.as_ptr(), bits, frame.pixels.len());
            let dc = CreateCompatibleDC(null_mut());
            let old = SelectObject(dc, bmp);
            *self.cache.borrow_mut() = Some((frame.clone(), dc, bmp, old));
            Some(dc)
        }
    }

    fn draw(&self, hdc: HDC, bounds: *const RECT) -> HRESULT {
        if hdc.is_null() {
            return E_POINTER;
        }
        let r = if bounds.is_null() {
            self.pos.get()
        } else {
            unsafe { *bounds }
        };
        let (w, h) = (r.right - r.left, r.bottom - r.top);
        if w <= 0 || h <= 0 {
            return S_OK;
        }
        let Some(inst) = self.inst() else { return S_OK };
        self.in_draw.set(true);
        if inst
            .frame
            .borrow()
            .as_ref()
            .is_none_or(|f| f.width != w as u32 || f.height != h as u32)
        {
            // A size the movie has not been rendered at yet (a Draw into a
            // memory DC, or before activation): render at it now.
            inst.set_size(w as u32, h as u32);
        }
        self.in_draw.set(false);
        let frame = inst.frame.borrow().clone();
        let Some(frame) = frame else { return S_OK }; // nothing to show yet
        let Some(src) = self.frame_dc(&frame) else {
            return S_OK;
        };
        let blend = BLENDFUNCTION {
            BlendOp: AC_SRC_OVER as u8,
            BlendFlags: 0,
            SourceConstantAlpha: 255,
            AlphaFormat: AC_SRC_ALPHA as u8,
        };
        unsafe {
            AlphaBlend(
                hdc,
                r.left,
                r.top,
                w,
                h,
                src,
                0,
                0,
                frame.width as i32,
                frame.height as i32,
                blend,
            );
        }
        S_OK
    }

    fn hit(&self, bounds: *const RECT, x: i32, y: i32) -> u32 {
        let r = if bounds.is_null() {
            self.pos.get()
        } else {
            unsafe { *bounds }
        };
        if x < r.left || y < r.top || x >= r.right || y >= r.bottom {
            return HITRESULT_OUTSIDE;
        }
        let Some(inst) = self.inst() else {
            return HITRESULT_OUTSIDE;
        };
        let frame = inst.frame.borrow().clone();
        let Some(f) = frame else {
            return HITRESULT_OUTSIDE;
        };
        let fx = ((x - r.left) as i64 * f.width as i64 / (r.right - r.left).max(1) as i64) as usize;
        let fy = ((y - r.top) as i64 * f.height as i64 / (r.bottom - r.top).max(1) as i64) as usize;
        let i = (fy * f.width as usize + fx) * 4 + 3;
        if f.pixels.get(i).copied().unwrap_or(0) != 0 {
            HITRESULT_HIT
        } else {
            HITRESULT_OUTSIDE
        }
    }
}

// ---------------------------------------------------------------------------
// Vtables. `this` points at one of the control's vtable pointers; the
// const parameter says which one.

macro_rules! g {
    ($what:expr, $default:expr, $body:expr) => {
        crate::ffi_guard($what, $default, || $body)
    };
}

unsafe extern "system" fn qi<const I: usize>(
    this: Unk,
    iid: *const GUID,
    out: *mut Unk,
) -> HRESULT {
    if iid.is_null() {
        return E_POINTER;
    }
    g!("control QueryInterface", E_FAIL, unsafe {
        ctl(this, I).query(&*iid, out)
    })
}
unsafe extern "system" fn addref<const I: usize>(this: Unk) -> u32 {
    unsafe { ctl(this, I).add_ref() }
}
unsafe extern "system" fn release<const I: usize>(this: Unk) -> u32 {
    g!("control Release", 0, unsafe {
        Control::release(ctl(this, I))
    })
}

fn unk<const I: usize>() -> Vec<usize> {
    vec![
        qi::<I> as *const () as usize,
        addref::<I> as *const () as usize,
        release::<I> as *const () as usize,
    ]
}

// --- IOleObject -------------------------------------------------------------

unsafe extern "system" fn ole_set_client_site(this: Unk, site: Unk) -> HRESULT {
    g!("SetClientSite", E_FAIL, {
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        if site.is_null() {
            c.deactivate();
        } else {
            unsafe { vcall!(site, 1, fn() -> u32) };
        }
        unsafe { com_release(c.client_site.replace(site)) };
        S_OK
    })
}
unsafe extern "system" fn ole_get_client_site(this: Unk, out: *mut Unk) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let c = unsafe { ctl(this, I_OLEOBJECT) };
    let s = c.client_site.get();
    if !s.is_null() {
        unsafe { vcall!(s, 1, fn() -> u32) };
    }
    unsafe { *out = s };
    S_OK
}
extern "system" fn ok2(_: Unk, _: usize, _: usize) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ole_close(this: Unk, _save: u32) -> HRESULT {
    g!("Close", E_FAIL, {
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        c.deactivate();
        let h = c.advise_holder.get();
        if !h.is_null() {
            unsafe { vcall!(h, 8, fn() -> HRESULT) }; // SendOnClose
        }
        S_OK
    })
}
extern "system" fn notimpl2(_: Unk, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}
unsafe extern "system" fn notimpl_out3(_: Unk, _: usize, _: usize, out: *mut Unk) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = null_mut() };
    }
    E_NOTIMPL
}
extern "system" fn notimpl3(_: Unk, _: usize, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}
unsafe extern "system" fn ole_do_verb(
    this: Unk,
    verb: i32,
    _msg: Unk,
    _site: Unk,
    _lindex: i32,
    _parent: HWND,
    rect: *const RECT,
) -> HRESULT {
    g!("DoVerb", E_FAIL, {
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        match verb {
            OLEIVERB_PRIMARY | OLEIVERB_SHOW | OLEIVERB_INPLACEACTIVATE | OLEIVERB_UIACTIVATE => {
                c.activate(rect)
            }
            OLEIVERB_HIDE => {
                c.deactivate();
                S_OK
            }
            _ => OLEOBJ_S_INVALIDVERB,
        }
    })
}
unsafe extern "system" fn ole_use_reg1(_: Unk, out: *mut Unk) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = null_mut() };
    }
    OLE_S_USEREG
}
extern "system" fn ok0(_: Unk) -> HRESULT {
    S_OK
}
unsafe extern "system" fn get_class_id(_: Unk, out: *mut GUID) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { *out = CLSID_SHOCKWAVEFLASH };
    S_OK
}
unsafe extern "system" fn ole_get_user_type(_: Unk, _form: u32, out: *mut Unk) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = null_mut() };
    }
    OLE_S_USEREG
}
unsafe extern "system" fn ole_set_extent(this: Unk, aspect: u32, size: *const SIZE) -> HRESULT {
    g!("SetExtent", E_FAIL, {
        if size.is_null() {
            return E_POINTER;
        }
        if aspect != DVASPECT_CONTENT {
            return E_FAIL;
        }
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        c.extent.set(unsafe { *size });
        if !c.active.get() {
            c.resize();
        }
        S_OK
    })
}
unsafe extern "system" fn ole_get_extent(this: Unk, _aspect: u32, size: *mut SIZE) -> HRESULT {
    if size.is_null() {
        return E_POINTER;
    }
    unsafe { *size = ctl(this, I_OLEOBJECT).extent.get() };
    S_OK
}
unsafe extern "system" fn ole_advise(this: Unk, sink: Unk, cookie: *mut u32) -> HRESULT {
    g!("IOleObject::Advise", E_FAIL, {
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        if c.advise_holder.get().is_null() {
            let mut h: Unk = null_mut();
            let hr = unsafe {
                windows_sys::Win32::System::Ole::CreateOleAdviseHolder((&mut h as *mut Unk).cast())
            };
            if hr < 0 {
                return hr;
            }
            c.advise_holder.set(h);
        }
        let h = c.advise_holder.get();
        unsafe { vcall!(h, 3, fn(Unk, *mut u32) -> HRESULT, sink, cookie) }
    })
}
unsafe extern "system" fn ole_unadvise(this: Unk, cookie: u32) -> HRESULT {
    g!("IOleObject::Unadvise", E_FAIL, {
        let h = unsafe { ctl(this, I_OLEOBJECT) }.advise_holder.get();
        if h.is_null() {
            return E_FAIL;
        }
        unsafe { vcall!(h, 4, fn(u32) -> HRESULT, cookie) }
    })
}
unsafe extern "system" fn ole_enum_advise(this: Unk, out: *mut Unk) -> HRESULT {
    g!("IOleObject::EnumAdvise", E_FAIL, {
        let h = unsafe { ctl(this, I_OLEOBJECT) }.advise_holder.get();
        if h.is_null() {
            if !out.is_null() {
                unsafe { *out = null_mut() };
            }
            return E_FAIL;
        }
        unsafe { vcall!(h, 5, fn(*mut Unk) -> HRESULT, out) }
    })
}
unsafe extern "system" fn ole_get_misc_status(_: Unk, _aspect: u32, out: *mut u32) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { *out = MISC_STATUS };
    S_OK
}
extern "system" fn notimpl1(_: Unk, _: usize) -> HRESULT {
    E_NOTIMPL
}

fn oleobject_vtbl() -> Vec<usize> {
    let mut v = unk::<I_OLEOBJECT>();
    v.extend([
        ole_set_client_site as *const () as usize, // SetClientSite
        ole_get_client_site as *const () as usize, // GetClientSite
        ok2 as *const () as usize,                 // SetHostNames(app, obj)
        ole_close as *const () as usize,           // Close
        notimpl2 as *const () as usize,            // SetMoniker(which, pmk)
        notimpl_out3 as *const () as usize,        // GetMoniker(assign, which, ppmk)
        notimpl3 as *const () as usize,            // InitFromData(obj, creation, reserved)
        notimpl_out_2 as *const () as usize,       // GetClipboardData(reserved, ppobj)
        ole_do_verb as *const () as usize,         // DoVerb
        ole_use_reg1 as *const () as usize,        // EnumVerbs
        ok0 as *const () as usize,                 // Update
        ok0 as *const () as usize,                 // IsUpToDate
        get_class_id as *const () as usize,        // GetUserClassID
        ole_get_user_type as *const () as usize,   // GetUserType
        ole_set_extent as *const () as usize,      // SetExtent
        ole_get_extent as *const () as usize,      // GetExtent
        ole_advise as *const () as usize,          // Advise
        ole_unadvise as *const () as usize,        // Unadvise
        ole_enum_advise as *const () as usize,     // EnumAdvise
        ole_get_misc_status as *const () as usize, // GetMiscStatus
        notimpl1 as *const () as usize,            // SetColorScheme
    ]);
    v
}
unsafe extern "system" fn notimpl_out_2(_: Unk, _: usize, out: *mut Unk) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = null_mut() };
    }
    E_NOTIMPL
}

// --- IPersistPropertyBag / IPersistStreamInit --------------------------------

unsafe extern "system" fn pb_load(this: Unk, bag: Unk, _log: Unk) -> HRESULT {
    g!("IPersistPropertyBag::Load", E_FAIL, {
        if bag.is_null() {
            return E_POINTER;
        }
        unsafe { ctl(this, I_PROPBAG) }.load_params(bag)
    })
}
fn propbag_vtbl() -> Vec<usize> {
    let mut v = unk::<I_PROPBAG>();
    v.extend([
        get_class_id as *const () as usize, // GetClassID
        ok0 as *const () as usize,          // InitNew
        pb_load as *const () as usize,      // Load(bag, errorlog)
        notimpl3 as *const () as usize,     // Save(bag, clearDirty, saveAll)
    ]);
    v
}
extern "system" fn s_false0(_: Unk) -> HRESULT {
    S_FALSE
}
unsafe extern "system" fn psi_get_size_max(_: Unk, out: *mut u64) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    S_OK
}
fn streaminit_vtbl() -> Vec<usize> {
    let mut v = unk::<I_STREAMINIT>();
    v.extend([
        get_class_id as *const () as usize,     // GetClassID
        s_false0 as *const () as usize,         // IsDirty
        notimpl1 as *const () as usize,         // Load(stream)
        notimpl2 as *const () as usize,         // Save(stream, clearDirty)
        psi_get_size_max as *const () as usize, // GetSizeMax
        ok0 as *const () as usize,              // InitNew
    ]);
    v
}

// --- IViewObjectEx ------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn view_draw(
    this: Unk,
    _aspect: u32,
    _lindex: i32,
    _pv: Unk,
    _ptd: Unk,
    _hdc_target: HDC,
    hdc: HDC,
    bounds: *const RECT,
    _wbounds: *const RECT,
    _cont: usize,
    _cont_arg: usize,
) -> HRESULT {
    g!(
        "IViewObject::Draw",
        E_FAIL,
        unsafe { ctl(this, I_VIEW) }.draw(hdc, bounds)
    )
}
unsafe extern "system" fn view_get_color_set(
    _: Unk,
    _: u32,
    _: i32,
    _: Unk,
    _: Unk,
    _: HDC,
    out: *mut Unk,
) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = null_mut() };
    }
    S_FALSE
}
unsafe extern "system" fn view_freeze(_: Unk, _: u32, _: i32, _: Unk, out: *mut u32) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    S_OK
}
unsafe extern "system" fn view_set_advise(
    this: Unk,
    aspects: u32,
    advf: u32,
    sink: Unk,
) -> HRESULT {
    g!("SetAdvise", E_FAIL, {
        let c = unsafe { ctl(this, I_VIEW) };
        if !sink.is_null() {
            unsafe { vcall!(sink, 1, fn() -> u32) };
        }
        unsafe { com_release(c.view_sink.replace(sink)) };
        c.view_aspects.set(aspects);
        c.view_advf.set(advf);
        S_OK
    })
}
unsafe extern "system" fn view_get_advise(
    this: Unk,
    aspects: *mut u32,
    advf: *mut u32,
    sink: *mut Unk,
) -> HRESULT {
    let c = unsafe { ctl(this, I_VIEW) };
    unsafe {
        if !aspects.is_null() {
            *aspects = c.view_aspects.get();
        }
        if !advf.is_null() {
            *advf = c.view_advf.get();
        }
        if !sink.is_null() {
            let s = c.view_sink.get();
            if !s.is_null() {
                vcall!(s, 1, fn() -> u32);
            }
            *sink = s;
        }
    }
    S_OK
}
unsafe extern "system" fn view_get_extent(
    this: Unk,
    _aspect: u32,
    _lindex: i32,
    _ptd: Unk,
    size: *mut SIZE,
) -> HRESULT {
    if size.is_null() {
        return E_POINTER;
    }
    unsafe { *size = ctl(this, I_VIEW).extent.get() };
    S_OK
}
unsafe extern "system" fn view_get_rect(this: Unk, aspect: u32, out: *mut RECT) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if aspect != DVASPECT_CONTENT {
        return E_NOTIMPL;
    }
    unsafe { *out = ctl(this, I_VIEW).pos.get() };
    S_OK
}
unsafe extern "system" fn view_get_view_status(this: Unk, out: *mut u32) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let c = unsafe { ctl(this, I_VIEW) };
    let transparent = c.inst().is_none_or(|i| i.display.get().transparent);
    unsafe { *out = if transparent { 0 } else { VIEWSTATUS_OPAQUE } };
    S_OK
}
unsafe extern "system" fn view_query_hit_point(
    this: Unk,
    _aspect: u32,
    bounds: *const RECT,
    x: i32,
    y: i32,
    _hint: i32,
    out: *mut u32,
) -> HRESULT {
    g!("QueryHitPoint", E_FAIL, {
        if out.is_null() {
            return E_POINTER;
        }
        unsafe { *out = ctl(this, I_VIEW).hit(bounds, x, y) };
        S_OK
    })
}
unsafe extern "system" fn view_query_hit_rect(
    this: Unk,
    _aspect: u32,
    bounds: *const RECT,
    loc: *const RECT,
    _hint: i32,
    out: *mut u32,
) -> HRESULT {
    if out.is_null() || loc.is_null() {
        return E_POINTER;
    }
    let c = unsafe { ctl(this, I_VIEW) };
    let b = if bounds.is_null() {
        c.pos.get()
    } else {
        unsafe { *bounds }
    };
    let l = unsafe { *loc };
    let overlap = l.left < b.right && l.right > b.left && l.top < b.bottom && l.bottom > b.top;
    unsafe {
        *out = if overlap {
            HITRESULT_HIT
        } else {
            HITRESULT_OUTSIDE
        }
    };
    S_OK
}
unsafe extern "system" fn view_get_natural_extent(
    _: Unk,
    _: u32,
    _: i32,
    _: Unk,
    _: HDC,
    _: Unk,
    _: *mut SIZE,
) -> HRESULT {
    E_NOTIMPL
}
extern "system" fn ok1(_: Unk, _: usize) -> HRESULT {
    S_OK
}
fn view_vtbl() -> Vec<usize> {
    let mut v = unk::<I_VIEW>();
    v.extend([
        view_draw as *const () as usize,
        view_get_color_set as *const () as usize,
        view_freeze as *const () as usize,
        ok1 as *const () as usize, // Unfreeze
        view_set_advise as *const () as usize,
        view_get_advise as *const () as usize,
        view_get_extent as *const () as usize, // IViewObject2
        view_get_rect as *const () as usize,   // IViewObjectEx
        view_get_view_status as *const () as usize,
        view_query_hit_point as *const () as usize,
        view_query_hit_rect as *const () as usize,
        view_get_natural_extent as *const () as usize,
    ]);
    v
}

// --- IOleInPlaceObjectWindowless ------------------------------------------------

unsafe extern "system" fn ipo_get_window(_: Unk, out: *mut HWND) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = null_mut() };
    }
    E_FAIL // windowless
}
unsafe extern "system" fn ipo_deactivate(this: Unk) -> HRESULT {
    g!("InPlaceDeactivate", E_FAIL, {
        unsafe { ctl(this, I_INPLACE) }.deactivate();
        S_OK
    })
}
unsafe extern "system" fn ipo_set_object_rects(
    this: Unk,
    pos: *const RECT,
    _clip: *const RECT,
) -> HRESULT {
    g!("SetObjectRects", E_FAIL, {
        if pos.is_null() {
            return E_POINTER;
        }
        let c = unsafe { ctl(this, I_INPLACE) };
        c.pos.set(unsafe { *pos });
        c.resize();
        S_OK
    })
}
unsafe extern "system" fn ipo_on_window_message(
    _: Unk,
    _msg: u32,
    _wp: usize,
    _lp: isize,
    result: *mut isize,
) -> HRESULT {
    if !result.is_null() {
        unsafe { *result = 0 };
    }
    S_FALSE // input is not forwarded to the movie
}
fn inplace_vtbl() -> Vec<usize> {
    let mut v = unk::<I_INPLACE>();
    v.extend([
        ipo_get_window as *const () as usize,        // GetWindow
        notimpl1 as *const () as usize,              // ContextSensitiveHelp
        ipo_deactivate as *const () as usize,        // InPlaceDeactivate
        ok0 as *const () as usize,                   // UIDeactivate
        ipo_set_object_rects as *const () as usize,  // SetObjectRects
        notimpl_0 as *const () as usize,             // ReactivateAndUndo
        ipo_on_window_message as *const () as usize, // OnWindowMessage
        ole_use_reg_notimpl1 as *const () as usize,  // GetDropTarget
    ]);
    v
}
extern "system" fn notimpl_0(_: Unk) -> HRESULT {
    E_NOTIMPL
}
unsafe extern "system" fn ole_use_reg_notimpl1(_: Unk, out: *mut Unk) -> HRESULT {
    if !out.is_null() {
        unsafe { *out = null_mut() };
    }
    E_NOTIMPL
}

// --- IObjectWithSite / IOleControl ------------------------------------------------

unsafe extern "system" fn ows_set_site(this: Unk, site: Unk) -> HRESULT {
    g!("SetSite", E_FAIL, {
        let c = unsafe { ctl(this, I_WITHSITE) };
        if !site.is_null() {
            unsafe { vcall!(site, 1, fn() -> u32) };
        }
        unsafe { com_release(c.site.replace(site)) };
        S_OK
    })
}
unsafe extern "system" fn ows_get_site(this: Unk, iid: *const GUID, out: *mut Unk) -> HRESULT {
    g!("GetSite", E_FAIL, {
        if out.is_null() || iid.is_null() {
            return E_POINTER;
        }
        unsafe { *out = null_mut() };
        let s = unsafe { ctl(this, I_WITHSITE) }.site.get();
        if s.is_null() {
            return E_FAIL;
        }
        unsafe { vcall!(s, 0, fn(*const GUID, *mut Unk) -> HRESULT, iid, out) }
    })
}
fn withsite_vtbl() -> Vec<usize> {
    let mut v = unk::<I_WITHSITE>();
    v.extend([
        ows_set_site as *const () as usize,
        ows_get_site as *const () as usize,
    ]);
    v
}
fn control_vtbl() -> Vec<usize> {
    let mut v = unk::<I_CONTROL>();
    v.extend([
        notimpl1 as *const () as usize, // GetControlInfo
        notimpl1 as *const () as usize, // OnMnemonic
        ok1 as *const () as usize,      // OnAmbientPropertyChange
        ok1 as *const () as usize,      // FreezeEvents
    ]);
    v
}

fn vtables() -> [*const usize; INTERFACES] {
    static V: OnceLock<Vec<Vec<usize>>> = OnceLock::new();
    let v = V.get_or_init(|| {
        let mut unknown = unk::<I_UNKNOWN>();
        unknown.truncate(3);
        vec![
            unknown,
            oleobject_vtbl(),
            propbag_vtbl(),
            streaminit_vtbl(),
            view_vtbl(),
            inplace_vtbl(),
            withsite_vtbl(),
            control_vtbl(),
        ]
    });
    std::array::from_fn(|i| v[i].as_ptr())
}

// ---------------------------------------------------------------------------
// Class factory (IClassFactory2, so hosts that check the license get "verified").

#[repr(C)]
struct Factory {
    vtbl: *const usize,
}
unsafe impl Sync for Factory {}
unsafe impl Send for Factory {}

static FACTORY: OnceLock<Factory> = OnceLock::new();

fn factory() -> &'static Factory {
    FACTORY.get_or_init(|| {
        static VT: OnceLock<Vec<usize>> = OnceLock::new();
        let vt = VT.get_or_init(|| {
            vec![
                cf_query as *const () as usize,
                cf_addref as *const () as usize,
                cf_release as *const () as usize,
                cf_create as *const () as usize,
                ok1 as *const () as usize, // LockServer (the DLL never unloads)
                cf_get_lic_info as *const () as usize,
                cf_request_lic_key as *const () as usize,
                cf_create_lic as *const () as usize,
            ]
        });
        Factory { vtbl: vt.as_ptr() }
    })
}

unsafe extern "system" fn cf_query(this: Unk, iid: *const GUID, out: *mut Unk) -> HRESULT {
    if iid.is_null() || out.is_null() {
        return E_POINTER;
    }
    let iid = unsafe { &*iid };
    if guid_eq(iid, &IID_IUNKNOWN)
        || guid_eq(iid, &IID_ICLASSFACTORY)
        || guid_eq(iid, &IID_ICLASSFACTORY2)
    {
        unsafe { *out = this };
        S_OK
    } else {
        unsafe { *out = null_mut() };
        E_NOINTERFACE
    }
}
extern "system" fn cf_addref(_: Unk) -> u32 {
    2
}
extern "system" fn cf_release(_: Unk) -> u32 {
    1
}
unsafe extern "system" fn cf_create(
    _this: Unk,
    outer: Unk,
    iid: *const GUID,
    out: *mut Unk,
) -> HRESULT {
    g!("CreateInstance", E_FAIL, {
        if out.is_null() || iid.is_null() {
            return E_POINTER;
        }
        unsafe { *out = null_mut() };
        if !outer.is_null() {
            return CLASS_E_NOAGGREGATION;
        }
        if !crate::gpu::available() {
            log("CreateInstance: no renderer, no Flash control");
            return E_FAIL;
        }
        let c = match Control::create() {
            Ok(c) => c,
            Err(hr) => return hr,
        };
        let hr = unsafe { (*c).query(&*iid, out) };
        unsafe { Control::release(c) };
        log(&format!("CreateInstance -> {hr:#x}"));
        hr
    })
}
#[repr(C)]
struct LicInfo {
    cb: i32,
    runtime_key_avail: i32,
    lic_verified: i32,
}
unsafe extern "system" fn cf_get_lic_info(_: Unk, info: *mut LicInfo) -> HRESULT {
    if info.is_null() {
        return E_POINTER;
    }
    unsafe {
        *info = LicInfo {
            cb: size_of::<LicInfo>() as i32,
            runtime_key_avail: 1,
            lic_verified: 1,
        }
    };
    S_OK
}
unsafe extern "system" fn cf_request_lic_key(
    _: Unk,
    _reserved: u32,
    key: *mut *const u16,
) -> HRESULT {
    if key.is_null() {
        return E_POINTER;
    }
    unsafe { *key = crate::com::bstr("") };
    S_OK
}
unsafe extern "system" fn cf_create_lic(
    this: Unk,
    outer: Unk,
    _reserved: Unk,
    iid: *const GUID,
    _key: Unk,
    out: *mut Unk,
) -> HRESULT {
    unsafe { cf_create(this, outer, iid, out) }
}

/// DllGetClassObject for the ShockwaveFlash control.
pub fn get_class_object(clsid: &GUID, iid: &GUID, out: *mut Unk) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { *out = null_mut() };
    if !guid_eq(clsid, &CLSID_SHOCKWAVEFLASH) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    let f = factory() as *const Factory as Unk;
    unsafe { cf_query(f, iid, out) }
}

#[allow(dead_code)]
fn _unused() -> (HRESULT, POINT) {
    (OLE_E_NOTRUNNING, POINT { x: 0, y: 0 })
}
