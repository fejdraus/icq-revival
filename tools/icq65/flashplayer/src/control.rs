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
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, HWND_MESSAGE, KillTimer, SetTimer,
};
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

/// Screen DPI (x, y), for HIMETRIC <-> pixels.
fn screen_dpi() -> (i32, i32) {
    use windows_sys::Win32::Graphics::Gdi::{
        GetDC, GetDeviceCaps, LOGPIXELSX, LOGPIXELSY, ReleaseDC,
    };
    unsafe {
        let dc = GetDC(null_mut());
        if dc.is_null() {
            return (96, 96);
        }
        let x = GetDeviceCaps(dc, LOGPIXELSX as i32);
        let y = GetDeviceCaps(dc, LOGPIXELSY as i32);
        ReleaseDC(null_mut(), dc);
        (if x > 0 { x } else { 96 }, if y > 0 { y } else { 96 })
    }
}

fn px_from_himetric(v: i32, dpi: i32) -> i32 {
    ((v as i64 * dpi as i64 + 1270) / 2540) as i32
}
fn himetric_from_px(v: i32, dpi: i32) -> i32 {
    ((v as i64 * 2540 + dpi as i64 / 2) / dpi as i64) as i32
}

fn rect_str(r: &RECT) -> String {
    format!(
        "({},{})-({},{}) {}x{}",
        r.left,
        r.top,
        r.right,
        r.bottom,
        r.right - r.left,
        r.bottom - r.top
    )
}

fn opt_rect_str(r: *const RECT) -> String {
    if r.is_null() {
        "NULL".into()
    } else {
        rect_str(unsafe { &*r })
    }
}

/// Class, visibility, rectangle and styles of a window and its ancestors,
/// for the log: where a host's InvalidateRect ends up.
fn describe_window(hwnd: HWND) -> String {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GA_PARENT, GWL_EXSTYLE, GWL_STYLE, GetAncestor, GetClassNameW, GetWindowLongW,
        GetWindowRect, IsWindowVisible,
    };
    if hwnd.is_null() {
        return "NULL".into();
    }
    let mut parts = Vec::new();
    let mut h = hwnd;
    for _ in 0..6 {
        if h.is_null() {
            break;
        }
        let mut cls = [0u16; 64];
        let n = unsafe { GetClassNameW(h, cls.as_mut_ptr(), 64) } as usize;
        let mut r: RECT = unsafe { std::mem::zeroed() };
        unsafe { GetWindowRect(h, &mut r) };
        parts.push(format!(
            "{h:?} \"{}\" {} {} style {:#x} ex {:#x}",
            String::from_utf16_lossy(&cls[..n]),
            if unsafe { IsWindowVisible(h) } != 0 {
                "visible"
            } else {
                "HIDDEN"
            },
            rect_str(&r),
            unsafe { GetWindowLongW(h, GWL_STYLE) } as u32,
            unsafe { GetWindowLongW(h, GWL_EXSTYLE) } as u32
        ));
        h = unsafe { GetAncestor(h, GA_PARENT) };
    }
    parts.join(" < ")
}

/// Log the first calls of a kind fully, then every 240th.
fn log_every(n: u32) -> bool {
    n <= 40 || n % 240 == 0
}

/// Names of interfaces hosts ask for, for the log.
fn iid_name(iid: &GUID) -> String {
    const KNOWN: &[(u128, &str)] = &[
        (0x00000000_0000_0000_C000_000000000046, "IUnknown"),
        (0x00000112_0000_0000_C000_000000000046, "IOleObject"),
        (0x0000010C_0000_0000_C000_000000000046, "IPersist"),
        (
            0x37D84F60_42CB_11CE_8135_00AA004BB851,
            "IPersistPropertyBag",
        ),
        (0x7FD52380_4E07_101B_AE2D_08002B2EC713, "IPersistStreamInit"),
        (0x00000109_0000_0000_C000_000000000046, "IPersistStream"),
        (0x0000010A_0000_0000_C000_000000000046, "IPersistStorage"),
        (0x0000010D_0000_0000_C000_000000000046, "IViewObject"),
        (0x00000127_0000_0000_C000_000000000046, "IViewObject2"),
        (0x3AF24292_0C96_11CE_A0CF_00AA00600AB8, "IViewObjectEx"),
        (0x00000114_0000_0000_C000_000000000046, "IOleWindow"),
        (0x00000113_0000_0000_C000_000000000046, "IOleInPlaceObject"),
        (
            0x1C2056CC_5EF4_101B_8BC8_00AA003E3B29,
            "IOleInPlaceObjectWindowless",
        ),
        (
            0x00000117_0000_0000_C000_000000000046,
            "IOleInPlaceActiveObject",
        ),
        (0xFC4801A3_2BA9_11CF_A229_00AA003D7352, "IObjectWithSite"),
        (0xB196B288_BAB4_101A_B69C_00AA00341D07, "IOleControl"),
        (0x00020400_0000_0000_C000_000000000046, "IDispatch"),
        (0xD27CDB6C_AE6D_11cf_96B8_444553540000, "IShockwaveFlash"),
        (
            0xB196B284_BAB4_101A_B69C_00AA00341D07,
            "IConnectionPointContainer",
        ),
        (0xCF51ED10_62FE_11CF_BF86_00A0C9034836, "IQuickActivate"),
        (0xB196B283_BAB4_101A_B69C_00AA00341D07, "IProvideClassInfo"),
        (0xA6BC3AC0_DBAA_11CE_9DE3_00AA004BB851, "IProvideClassInfo2"),
        (0x0000010E_0000_0000_C000_000000000046, "IDataObject"),
        (0x00000126_0000_0000_C000_000000000046, "IRunnableObject"),
        (0x0000011E_0000_0000_C000_000000000046, "IOleCache"),
        (0x00000122_0000_0000_C000_000000000046, "IDropTarget"),
        (
            0x376BD3AA_3845_101B_84ED_08002B2EC713,
            "IPerPropertyBrowsing",
        ),
        (
            0xB196B28B_BAB4_101A_B69C_00AA00341D07,
            "ISpecifyPropertyPages",
        ),
        (0x55980BA0_35AA_11CF_B671_00AA004CD6D8, "IPointerInactive"),
        (
            0x00000019_0000_0000_C000_000000000046,
            "IExternalConnection",
        ),
        (0x0000001B_0000_0000_C000_000000000046, "IStdMarshalInfo"),
        (0x00000003_0000_0000_C000_000000000046, "IMarshal"),
        (0x94EA2B94_E9CC_49E0_C0FF_EE64CA8F5B90, "IAgileObject"),
        (0x6D5140C1_7436_11CE_8034_00AA006009FA, "IServiceProvider"),
        (0x3050F3F0_98B5_11CF_BB82_00AA00BDCE0B, "ICustomDoc"),
    ];
    for (v, n) in KNOWN {
        if guid_eq(iid, &GUID::from_u128(*v)) {
            return (*n).to_string();
        }
    }
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        iid.data1,
        iid.data2,
        iid.data3,
        iid.data4[0],
        iid.data4[1],
        iid.data4[2],
        iid.data4[3],
        iid.data4[4],
        iid.data4[5],
        iid.data4[6],
        iid.data4[7]
    )
}

static NEXT_CONTROL: AtomicU32 = AtomicU32::new(1);

const ADVF_PRIMEFIRST: u32 = 2;
const ADVF_ONLYONCE: u32 = 4;
/// Repaint requests after a frame the host has not drawn yet.
const RETRY_MS: u32 = 100;
const RETRY_CAP: u32 = 100; // 10 s without a Draw

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

/// A frame as a GDI bitmap, for AlphaBlend.
struct GdiFrame {
    serial: u64,
    frame: Rc<Frame>,
    dc: HDC,
    bmp: HBITMAP,
    old: *mut c_void,
}

impl Drop for GdiFrame {
    fn drop(&mut self) {
        unsafe {
            SelectObject(self.dc, self.old);
            DeleteObject(self.bmp);
            DeleteDC(self.dc);
        }
    }
}

#[repr(C)]
pub struct Control {
    vtbls: [*const usize; INTERFACES],
    refs: AtomicU32,
    /// Number for the log.
    id: u32,
    /// The hidden window whose Instance plays the movie.
    hwnd: Cell<HWND>,
    flash: Cell<*mut FlashObject>,
    client_site: Cell<Unk>,
    site: Cell<Unk>,
    inplace_site: Cell<Unk>,
    /// Kind of `inplace_site`: 0 plain, 1 Ex, 2 windowless.
    site_kind: Cell<u8>,
    active: Cell<bool>,
    /// Position from GetWindowContext (the host's whole client area for
    /// boxelyRenderer), used until the host gives a real rectangle.
    pos: Cell<RECT>,
    /// The rectangle from SetObjectRects (or DoVerb), once known.
    obj_rect: Cell<Option<RECT>>,
    extent: Cell<SIZE>, // HIMETRIC
    dpi: (i32, i32),
    view_sink: Cell<Unk>,
    view_aspects: Cell<u32>,
    view_advf: Cell<u32>,
    advise_holder: Cell<Unk>,
    in_draw: Cell<bool>,
    /// GDI copies of recent frames, one per size drawn.
    gdi: RefCell<Vec<GdiFrame>>,
    /// Serial of the newest frame the host has drawn.
    drawn_serial: Cell<u64>,
    /// Repaint requests since the host last drew.
    retries: Cell<u32>,
    retry_armed: Cell<bool>,
    draws: Cell<u32>,
    notifies: Cell<u32>,
    misc_calls: Cell<u32>,
    last_draw_size: Cell<(i32, i32)>,
    qi_seen: RefCell<Vec<(GUID, bool)>>,
    /// The site's window (IOleWindow::GetWindow): where its InvalidateRect goes.
    site_hwnd: Cell<HWND>,
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

    fn clog(&self, msg: &str) {
        log(&format!("control #{}: {msg}", self.id));
    }

    /// Logs a host call that is not per-frame (first 200 per control).
    fn call_log(&self, msg: &str) {
        let n = self.misc_calls.get() + 1;
        self.misc_calls.set(n);
        if n <= 200 {
            self.clog(msg);
        }
    }

    /// A new control with one reference, or an error.
    fn create() -> Result<*mut Control, HRESULT> {
        crate::RegisterFlashWindowClass();
        let dpi = screen_dpi();
        let c = Box::into_raw(Box::new(Control {
            vtbls: vtables(),
            refs: AtomicU32::new(1),
            id: NEXT_CONTROL.fetch_add(1, Ordering::Relaxed),
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
            obj_rect: Cell::new(None),
            extent: Cell::new(SIZE {
                cx: himetric_from_px(100, dpi.0),
                cy: himetric_from_px(100, dpi.1),
            }),
            dpi,
            view_sink: Cell::new(null_mut()),
            view_aspects: Cell::new(0),
            view_advf: Cell::new(0),
            advise_holder: Cell::new(null_mut()),
            in_draw: Cell::new(false),
            gdi: RefCell::new(Vec::new()),
            drawn_serial: Cell::new(0),
            retries: Cell::new(0),
            retry_armed: Cell::new(false),
            draws: Cell::new(0),
            notifies: Cell::new(0),
            misc_calls: Cell::new(0),
            last_draw_size: Cell::new((0, 0)),
            qi_seen: RefCell::new(Vec::new()),
            site_hwnd: Cell::new(null_mut()),
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
            (*(me as *const Control)).notify("new frame")
        }));
        *inst.on_control_timer.borrow_mut() = Some(Box::new(move || unsafe {
            (*(me as *const Control)).retry()
        }));
        control.clog(&format!("created (screen {}x{} dpi)", dpi.0, dpi.1));
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
        let hr = if let Some(i) = index {
            self.refs.fetch_add(1, Ordering::Relaxed);
            unsafe { *out = self.ptr(i) };
            S_OK
        } else {
            let flash = self.flash.get();
            if !flash.is_null()
                && (guid_eq(iid, &IID_IDISPATCH)
                    || guid_eq(iid, &IID_ISHOCKWAVEFLASH)
                    || guid_eq(iid, &IID_ICONNECTIONPOINTCONTAINER))
            {
                unsafe { (*flash).own_query(iid, out) }
            } else {
                unsafe { *out = null_mut() };
                E_NOINTERFACE
            }
        };
        // Each interface once per control: what the host asks for, and misses.
        let mut seen = self.qi_seen.borrow_mut();
        if !seen.iter().any(|(g, _)| guid_eq(g, iid)) {
            seen.push((*iid, hr >= 0));
            drop(seen);
            self.clog(&format!(
                "QueryInterface({}) -> {}",
                iid_name(iid),
                if hr >= 0 {
                    "ok".to_string()
                } else {
                    format!("{hr:#x}")
                }
            ));
        }
        hr
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
        self.clog(&format!(
            "released: {} Draw calls, {} repaint notifications",
            self.draws.get(),
            self.notifies.get()
        ));
        self.deactivate();
        if let Some(inst) = self.inst() {
            inst.on_frame.borrow_mut().take();
            inst.on_control_timer.borrow_mut().take();
        }
        let flash = self.flash.replace(null_mut());
        if !flash.is_null() {
            unsafe { (*flash).set_outer(null_mut()) };
        }
        let hwnd = self.hwnd.replace(null_mut());
        if !hwnd.is_null() {
            unsafe { KillTimer(hwnd, instance::CONTROL_TIMER) };
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
        self.gdi.borrow_mut().clear();
    }

    /// IOleInPlaceSiteWindowless::InvalidateRect; the HRESULT, or None when
    /// there is no active windowless site.
    fn invalidate(&self, rect: Option<RECT>) -> Option<HRESULT> {
        let site = self.inplace_site.get();
        if !self.active.get() || site.is_null() || self.site_kind.get() != 2 {
            return None;
        }
        let p = rect.as_ref().map_or(null(), |r| r as *const RECT);
        Some(unsafe { vcall!(site, 25, fn(*const RECT, i32) -> HRESULT, p, 0) })
    }

    /// When the site's window is hidden (boxelyRenderer's ActiveX frame
    /// window can be), its InvalidateRect produces no paint: also invalidate
    /// the nearest visible ancestor over our rectangle. Returns what was done.
    fn invalidate_visible_ancestor(&self) -> Option<String> {
        use windows_sys::Win32::Graphics::Gdi::{InvalidateRect, MapWindowPoints};
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GA_PARENT, GetAncestor, IsWindowVisible,
        };
        let site = self.site_hwnd.get();
        if site.is_null() || unsafe { IsWindowVisible(site) } != 0 {
            return None;
        }
        let mut a = unsafe { GetAncestor(site, GA_PARENT) };
        while !a.is_null() && unsafe { IsWindowVisible(a) } == 0 {
            a = unsafe { GetAncestor(a, GA_PARENT) };
        }
        if a.is_null() {
            return Some("site window hidden, no visible ancestor".into());
        }
        let mut r = self.obj_rect.get().unwrap_or(self.pos.get());
        unsafe {
            MapWindowPoints(site, a, (&mut r as *mut RECT).cast(), 2);
            InvalidateRect(a, &r, 0);
        }
        Some(format!(
            "site window hidden: invalidated visible ancestor {a:?} at {}",
            rect_str(&r)
        ))
    }

    /// IAdviseSink::OnViewChange on the view sink; false without a sink.
    fn view_change(&self) -> bool {
        let sink = self.view_sink.get();
        if sink.is_null() {
            return false;
        }
        unsafe { vcall!(sink, 4, fn(u32, i32) -> (), DVASPECT_CONTENT, -1) };
        if self.view_advf.get() & ADVF_ONLYONCE != 0 {
            unsafe { com_release(self.view_sink.replace(null_mut())) };
        }
        true
    }

    fn arm_retry(&self) {
        if self.retry_armed.get() || self.retries.get() >= RETRY_CAP {
            return;
        }
        let hwnd = self.hwnd.get();
        if !hwnd.is_null() {
            unsafe { SetTimer(hwnd, instance::CONTROL_TIMER, RETRY_MS, None) };
            self.retry_armed.set(true);
        }
    }

    fn disarm_retry(&self) {
        if self.retry_armed.replace(false) {
            unsafe { KillTimer(self.hwnd.get(), instance::CONTROL_TIMER) };
        }
    }

    fn current_serial(&self) -> Option<u64> {
        let inst = self.inst()?;
        inst.frame.borrow().as_ref()?;
        Some(inst.frame_serial.get())
    }

    /// There is a frame the host should show: tell it through every channel
    /// a host may listen to, and keep asking (retry) until it draws it.
    fn notify(&self, reason: &str) {
        if self.in_draw.get() {
            return;
        }
        let Some(serial) = self.current_serial() else {
            return;
        };
        let n = self.notifies.get() + 1;
        self.notifies.set(n);
        let rect = self.obj_rect.get();
        let inv = self.invalidate(rect);
        let vc = self.view_change();
        let anc = self.invalidate_visible_ancestor();
        if log_every(n) {
            self.clog(&format!(
                "repaint request #{n} ({reason}, frame {serial}, host drew {}): InvalidateRect({}) {}; OnViewChange {}{}",
                self.drawn_serial.get(),
                rect.as_ref().map_or("NULL".into(), rect_str),
                match inv {
                    Some(hr) => format!("-> {hr:#x}"),
                    None if !self.active.get() => "skipped (not in-place active yet)".into(),
                    None => "skipped (no windowless site)".into(),
                },
                if vc { "sent" } else { "no sink" },
                anc.map_or(String::new(), |a| format!("; {a}"))
            ));
        }
        if self.drawn_serial.get() < serial {
            self.arm_retry();
        }
    }

    /// CONTROL_TIMER: the host has not drawn the newest frame yet.
    fn retry(&self) {
        let Some(serial) = self.current_serial() else {
            self.disarm_retry();
            return;
        };
        if self.drawn_serial.get() >= serial {
            self.disarm_retry();
            return;
        }
        let r = self.retries.get() + 1;
        self.retries.set(r);
        if r > RETRY_CAP {
            self.disarm_retry();
            self.clog(&format!(
                "host has not drawn frame {serial} after {RETRY_CAP} repaint requests; waiting for its next Draw"
            ));
            return;
        }
        // The whole host window, in case our rectangle is stale.
        let inv = self.invalidate(None);
        let vc = self.view_change();
        let anc = self.invalidate_visible_ancestor();
        if r <= 10 || r % 20 == 0 {
            self.clog(&format!(
                "retry {r}: frame {serial} not drawn yet (host drew {}): InvalidateRect(NULL) {}; OnViewChange {}{}{}",
                self.drawn_serial.get(),
                inv.map_or("skipped".into(), |hr| format!("-> {hr:#x}")),
                if vc { "sent" } else { "no sink" },
                anc.map_or(String::new(), |a| format!("; {a}")),
                if r == 1 { format!("; site window now: {}", describe_window(self.site_hwnd.get())) } else { String::new() }
            ));
        }
    }

    /// The size to render at before the host draws: its rectangle, else the
    /// extent (HIMETRIC at the screen DPI).
    fn pixel_size(&self) -> (u32, u32) {
        if let Some(r) = self.obj_rect.get() {
            if r.right > r.left && r.bottom > r.top {
                return ((r.right - r.left) as u32, (r.bottom - r.top) as u32);
            }
        }
        let e = self.extent.get();
        (
            px_from_himetric(e.cx, self.dpi.0).max(1) as u32,
            px_from_himetric(e.cy, self.dpi.1).max(1) as u32,
        )
    }

    fn resize(&self) {
        let (w, h) = self.pixel_size();
        if let Some(inst) = self.inst() {
            self.in_draw.set(true);
            inst.set_size(w, h);
            self.in_draw.set(false);
        }
    }

    fn activate(&self, rect: *const RECT) -> HRESULT {
        let client = self.client_site.get();
        if client.is_null() {
            self.clog("activate: no client site -> E_UNEXPECTED");
            return E_UNEXPECTED;
        }
        if self.active.get() {
            if !rect.is_null() {
                self.obj_rect.set(Some(unsafe { *rect }));
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
            let mut can_windowless = None;
            let mut s: Unk = null_mut();
            if q(&IID_IOLEINPLACESITEWINDOWLESS, &mut s) {
                let hr = vcall!(s, 18, fn() -> HRESULT);
                can_windowless = Some(hr);
                if hr == S_OK {
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
                self.clog("activate: the client site has no IOleInPlaceSite -> E_NOINTERFACE");
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
                        self.clog("activate: CanInPlaceActivate refused");
                        return E_FAIL;
                    }
                    vcall!(site, 6, fn() -> HRESULT)
                }
            };
            if hr < 0 {
                com_release(site);
                self.clog(&format!("activate: OnInPlaceActivate(Ex) -> {hr:#x}"));
                return hr;
            }
            // GetWindowContext for the position rectangle.
            let mut frame: Unk = null_mut();
            let mut doc: Unk = null_mut();
            let mut pos: RECT = std::mem::zeroed();
            let mut clip: RECT = std::mem::zeroed();
            let mut info = [0u32; 5];
            info[0] = 20; // OLEINPLACEFRAMEINFO.cb
            let ctx_hr = vcall!(
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
            if ctx_hr >= 0 {
                self.pos.set(pos);
            }
            if !rect.is_null() {
                self.obj_rect.set(Some(*rect));
                self.pos.set(*rect);
            }
            self.inplace_site.set(site);
            self.site_kind.set(kind);
            self.active.set(true);
            let mut sh: HWND = null_mut();
            let wh = vcall!(site, 3, fn(*mut HWND) -> HRESULT, &mut sh);
            self.site_hwnd.set(if wh >= 0 { sh } else { null_mut() });
            self.clog(&format!(
                "site window (IOleWindow::GetWindow -> {wh:#x}): {}",
                describe_window(sh)
            ));
            self.clog(&format!(
                "in-place active: {} site (CanWindowlessActivate {}), OnInPlaceActivate{} -> {hr:#x}, \
                 GetWindowContext -> {ctx_hr:#x} pos {} clip {}, DoVerb rect {}",
                ["plain", "Ex", "windowless"][kind as usize],
                can_windowless.map_or("n/a".into(), |h| format!("{h:#x}")),
                if kind == 0 { "" } else { "Ex" },
                rect_str(&pos),
                rect_str(&clip),
                opt_rect_str(rect)
            ));
            // IOleClientSite::ShowObject
            vcall!(client, 6, fn() -> HRESULT);
        }
        self.resize();
        self.notify("activated");
        S_OK
    }

    fn deactivate(&self) {
        self.disarm_retry();
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
        self.clog("in-place deactivated");
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
        let wmode = read("WMode");
        if let Some(w) = &wmode {
            d.transparent = w.trim().eq_ignore_ascii_case("transparent");
        }
        let scale = read("Scale");
        if let Some(s) = scale.as_deref().and_then(crate::movie::scale_mode) {
            d.scale = s;
        }
        let quality = read("Quality");
        inst.set_display(d);
        let movie = read("Movie")
            .or_else(|| read("Src"))
            .filter(|m| !m.trim().is_empty());
        let play = read("Play");
        let playing = play
            .as_deref()
            .is_none_or(|p| !p.trim().eq_ignore_ascii_case("false"));
        self.clog(&format!(
            "IPersistPropertyBag::Load: Movie {movie:?}, WMode {wmode:?}, Scale {scale:?}, Quality {quality:?}, Play {play:?} \
             -> transparent {}, scale {:?}",
            d.transparent, d.scale
        ));
        if let Some(m) = movie {
            inst.load(&m);
            if !playing {
                inst.stop_play();
            }
        }
        S_OK
    }

    /// The frame at exactly `w`x`h` device pixels as a GDI bitmap: cached
    /// per size for the current frame, else rendered now at that size.
    /// Returns (dc, frame, serial, rendered now).
    fn frame_for(&self, inst: &Instance, w: u32, h: u32) -> Option<(HDC, Rc<Frame>, u64, bool)> {
        let serial_before = inst.frame_serial.get();
        if inst.frame.borrow().is_none() {
            return None;
        }
        {
            let gdi = self.gdi.borrow();
            if let Some(g) = gdi
                .iter()
                .find(|g| g.serial == serial_before && g.frame.width == w && g.frame.height == h)
            {
                return Some((g.dc, g.frame.clone(), g.serial, false));
            }
        }
        self.in_draw.set(true);
        let fresh = inst.frame_at(w, h);
        self.in_draw.set(false);
        let serial = inst.frame_serial.get();
        let rendered = serial != serial_before;
        // Rendering at this size failed: fall back to the last frame, stretched.
        let frame = match fresh {
            Some(f) => f,
            None => inst.frame.borrow().clone()?,
        };
        let (bmp, bits) = crate::instance::new_dib(frame.width, frame.height)?;
        let entry = unsafe {
            std::ptr::copy_nonoverlapping(frame.pixels.as_ptr(), bits, frame.pixels.len());
            let dc = CreateCompatibleDC(null_mut());
            let old = SelectObject(dc, bmp);
            GdiFrame {
                serial,
                frame: frame.clone(),
                dc,
                bmp,
                old,
            }
        };
        let dc = entry.dc;
        let mut gdi = self.gdi.borrow_mut();
        gdi.retain(|g| g.serial == serial);
        gdi.push(entry);
        while gdi.len() > 4 {
            gdi.remove(0);
        }
        Some((dc, frame, serial, rendered))
    }

    fn draw(&self, hdc: HDC, bounds: *const RECT) -> HRESULT {
        let n = self.draws.get() + 1;
        self.draws.set(n);
        if hdc.is_null() {
            self.clog("Draw: hdc NULL -> E_POINTER");
            return E_POINTER;
        }
        let (r, from) = if !bounds.is_null() {
            (unsafe { *bounds }, "lprcBounds")
        } else if let Some(r) = self.obj_rect.get() {
            (r, "SetObjectRects")
        } else {
            (self.pos.get(), "GetWindowContext")
        };
        let (w, h) = (r.right - r.left, r.bottom - r.top);
        if w <= 0 || h <= 0 {
            self.clog(&format!(
                "Draw #{n}: empty rectangle {} ({from}), nothing drawn",
                rect_str(&r)
            ));
            return S_OK;
        }
        // Render at the destination's size in device pixels, so AlphaBlend
        // copies 1:1 and nothing is stretched.
        let mut pts = [
            POINT {
                x: r.left,
                y: r.top,
            },
            POINT {
                x: r.right,
                y: r.bottom,
            },
        ];
        let (dw, dh) = unsafe {
            if windows_sys::Win32::Graphics::Gdi::LPtoDP(hdc, pts.as_mut_ptr(), 2) != 0 {
                ((pts[1].x - pts[0].x).abs(), (pts[1].y - pts[0].y).abs())
            } else {
                (w, h)
            }
        };
        let (dw, dh) = if dw > 0 && dh > 0 { (dw, dh) } else { (w, h) };
        let Some(inst) = self.inst() else { return S_OK };
        let got = self.frame_for(&inst, dw as u32, dh as u32);
        let size_changed = self.last_draw_size.replace((dw, dh)) != (dw, dh);
        let Some((src, frame, serial, rendered)) = got else {
            if log_every(n) || size_changed {
                self.clog(&format!(
                    "Draw #{n}: {} {} (device {dw}x{dh}): no frame yet, nothing drawn",
                    from,
                    rect_str(&r)
                ));
            }
            return S_OK;
        };
        let blend = BLENDFUNCTION {
            BlendOp: AC_SRC_OVER as u8,
            BlendFlags: 0,
            SourceConstantAlpha: 255,
            AlphaFormat: AC_SRC_ALPHA as u8,
        };
        let ok = unsafe {
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
            )
        };
        let first_after_wait = self.drawn_serial.get() < serial && self.retries.get() > 0;
        if serial > self.drawn_serial.get() {
            self.drawn_serial.set(serial);
        }
        self.retries.set(0);
        if log_every(n) || size_changed || first_after_wait {
            let map = unsafe { windows_sys::Win32::Graphics::Gdi::GetMapMode(hdc) };
            self.clog(&format!(
                "Draw #{n}: {from} {} (device {dw}x{dh}, map mode {map}), frame {serial} {}x{} {}, AlphaBlend {}",
                rect_str(&r),
                frame.width,
                frame.height,
                if rendered { "rendered for this Draw" } else { "cached" },
                if ok != 0 { "ok" } else { "FAILED" }
            ));
        }
        S_OK
    }

    fn hit(&self, bounds: *const RECT, x: i32, y: i32) -> u32 {
        let r = if !bounds.is_null() {
            unsafe { *bounds }
        } else {
            self.obj_rect.get().unwrap_or(self.pos.get())
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

unsafe extern "system" fn ole_set_host_names(
    this: Unk,
    app: *const u16,
    obj: *const u16,
) -> HRESULT {
    g!("SetHostNames", E_FAIL, {
        let s = |p: *const u16| -> String {
            if p.is_null() {
                return "NULL".into();
            }
            let n = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
        };
        unsafe { ctl(this, I_OLEOBJECT) }.call_log(&format!(
            "IOleObject::SetHostNames({:?}, {:?})",
            s(app),
            s(obj)
        ));
        S_OK
    })
}

unsafe extern "system" fn ole_set_client_site(this: Unk, site: Unk) -> HRESULT {
    g!("SetClientSite", E_FAIL, {
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        c.call_log(&format!(
            "IOleObject::SetClientSite({})",
            if site.is_null() { "NULL" } else { "site" }
        ));
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
unsafe extern "system" fn ole_close(this: Unk, save: u32) -> HRESULT {
    g!("Close", E_FAIL, {
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        c.call_log(&format!("IOleObject::Close({save})"));
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
    parent: HWND,
    rect: *const RECT,
) -> HRESULT {
    g!("DoVerb", E_FAIL, {
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        let hr = match verb {
            OLEIVERB_PRIMARY | OLEIVERB_SHOW | OLEIVERB_INPLACEACTIVATE | OLEIVERB_UIACTIVATE => {
                c.activate(rect)
            }
            OLEIVERB_HIDE => {
                c.deactivate();
                S_OK
            }
            _ => OLEOBJ_S_INVALIDVERB,
        };
        c.call_log(&format!(
            "IOleObject::DoVerb({verb}, parent {parent:?}, rect {}) -> {hr:#x}",
            opt_rect_str(rect)
        ));
        hr
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
        let c = unsafe { ctl(this, I_OLEOBJECT) };
        let e = unsafe { *size };
        if aspect != DVASPECT_CONTENT {
            c.call_log(&format!(
                "IOleObject::SetExtent(aspect {aspect}, {}x{}) -> E_FAIL",
                e.cx, e.cy
            ));
            return E_FAIL;
        }
        c.extent.set(e);
        c.call_log(&format!(
            "IOleObject::SetExtent({}x{} HIMETRIC = {}x{} px at {}x{} dpi)",
            e.cx,
            e.cy,
            px_from_himetric(e.cx, c.dpi.0),
            px_from_himetric(e.cy, c.dpi.1),
            c.dpi.0,
            c.dpi.1
        ));
        if c.obj_rect.get().is_none() {
            c.resize();
        }
        S_OK
    })
}
unsafe extern "system" fn ole_get_extent(this: Unk, aspect: u32, size: *mut SIZE) -> HRESULT {
    if size.is_null() {
        return E_POINTER;
    }
    let c = unsafe { ctl(this, I_OLEOBJECT) };
    let e = c.extent.get();
    unsafe { *size = e };
    c.call_log(&format!(
        "IOleObject::GetExtent(aspect {aspect}) -> {}x{} HIMETRIC",
        e.cx, e.cy
    ));
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
        let hr = unsafe { vcall!(h, 3, fn(Unk, *mut u32) -> HRESULT, sink, cookie) };
        c.call_log(&format!("IOleObject::Advise -> {hr:#x}"));
        hr
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
unsafe extern "system" fn ole_get_misc_status(this: Unk, aspect: u32, out: *mut u32) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { *out = MISC_STATUS };
    unsafe { ctl(this, I_OLEOBJECT) }.call_log(&format!(
        "IOleObject::GetMiscStatus({aspect}) -> {MISC_STATUS:#x}"
    ));
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
        ole_set_host_names as *const () as usize,  // SetHostNames(app, obj)
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

unsafe extern "system" fn pb_init_new(this: Unk) -> HRESULT {
    unsafe { ctl(this, I_PROPBAG) }.call_log("IPersistPropertyBag::InitNew");
    S_OK
}
unsafe extern "system" fn psi_init_new(this: Unk) -> HRESULT {
    unsafe { ctl(this, I_STREAMINIT) }.call_log("IPersistStreamInit::InitNew");
    S_OK
}

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
        pb_init_new as *const () as usize,  // InitNew
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
        psi_init_new as *const () as usize,     // InitNew
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
        c.call_log(&format!(
            "IViewObject::SetAdvise(aspects {aspects:#x}, advf {advf:#x}, {})",
            if sink.is_null() { "NULL" } else { "sink" }
        ));
        // ADVF_PRIMEFIRST: one notification right away.
        if !sink.is_null() && advf & ADVF_PRIMEFIRST != 0 {
            c.view_change();
        }
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
    aspect: u32,
    _lindex: i32,
    _ptd: Unk,
    size: *mut SIZE,
) -> HRESULT {
    if size.is_null() {
        return E_POINTER;
    }
    let c = unsafe { ctl(this, I_VIEW) };
    let e = c.extent.get();
    unsafe { *size = e };
    c.call_log(&format!(
        "IViewObject2::GetExtent(aspect {aspect}) -> {}x{} HIMETRIC",
        e.cx, e.cy
    ));
    S_OK
}
unsafe extern "system" fn view_get_rect(this: Unk, aspect: u32, out: *mut RECT) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let c = unsafe { ctl(this, I_VIEW) };
    if aspect != DVASPECT_CONTENT {
        c.call_log(&format!(
            "IViewObjectEx::GetRect(aspect {aspect}) -> E_NOTIMPL"
        ));
        return E_NOTIMPL;
    }
    let r = c.obj_rect.get().unwrap_or(c.pos.get());
    unsafe { *out = r };
    c.call_log(&format!("IViewObjectEx::GetRect -> {}", rect_str(&r)));
    S_OK
}
unsafe extern "system" fn view_get_view_status(this: Unk, out: *mut u32) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let c = unsafe { ctl(this, I_VIEW) };
    let transparent = c.inst().is_none_or(|i| i.display.get().transparent);
    let v = if transparent { 0 } else { VIEWSTATUS_OPAQUE };
    unsafe { *out = v };
    c.call_log(&format!("IViewObjectEx::GetViewStatus -> {v:#x}"));
    S_OK
}
unsafe extern "system" fn view_query_hit_point(
    this: Unk,
    aspect: u32,
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
        let c = unsafe { ctl(this, I_VIEW) };
        let r = c.hit(bounds, x, y);
        unsafe { *out = r };
        c.call_log(&format!(
            "IViewObjectEx::QueryHitPoint(aspect {aspect}, {}, ({x},{y})) -> {r}",
            opt_rect_str(bounds)
        ));
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
        let c = unsafe { ctl(this, I_INPLACE) };
        c.call_log("IOleInPlaceObject::InPlaceDeactivate");
        c.deactivate();
        S_OK
    })
}
unsafe extern "system" fn ipo_set_object_rects(
    this: Unk,
    pos: *const RECT,
    clip: *const RECT,
) -> HRESULT {
    g!("SetObjectRects", E_FAIL, {
        if pos.is_null() {
            return E_POINTER;
        }
        let c = unsafe { ctl(this, I_INPLACE) };
        let r = unsafe { *pos };
        let old = c.obj_rect.replace(Some(r));
        c.pos.set(r);
        c.call_log(&format!(
            "IOleInPlaceObject::SetObjectRects(pos {}, clip {})",
            rect_str(&r),
            opt_rect_str(clip)
        ));
        let size = |r: &RECT| (r.right - r.left, r.bottom - r.top);
        let resized = old.as_ref().map(size) != Some(size(&r));
        c.resize();
        if resized {
            c.notify("new size");
        }
        S_OK
    })
}
unsafe extern "system" fn ipo_on_window_message(
    this: Unk,
    msg: u32,
    _wp: usize,
    _lp: isize,
    result: *mut isize,
) -> HRESULT {
    if !result.is_null() {
        unsafe { *result = 0 };
    }
    unsafe { ctl(this, I_INPLACE) }.call_log(&format!(
        "IOleInPlaceObjectWindowless::OnWindowMessage({msg:#x}) -> S_FALSE"
    ));
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
        c.call_log(&format!(
            "IObjectWithSite::SetSite({})",
            if site.is_null() { "NULL" } else { "site" }
        ));
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
