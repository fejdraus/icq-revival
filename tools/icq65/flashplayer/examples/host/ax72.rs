//! ICQ 7.2's Flash avatar ("devil") host, reproduced.
//!
//! ICQ 7.2 (build 3525) shows a Flash avatar with the `icqFlashPlayer` gadget
//! of `imApp\content\MUIUtils\ToolkitEx.box` (`windowless="false"`, params
//! Quality High, Scale ShowAll, Menu False), created by
//! `MCDevilImpl::CreateFlashDevil` (MUICoreLib). MUIUtils' Boxely object box
//! hosts it with ATL-style code:
//!
//! - a dedicated child window per control, class `__oxFrame.class__`
//!   (style 0x46000000), created hidden and 0x0, later moved and shown;
//! - `ActivateAx` (MUIUtils 0x32edfbd0): GetMiscStatus, SetClientSite,
//!   IPersistPropertyBag::Load, IViewObjectEx, Advise, SetAdvise,
//!   SetHostNames("AXWIN"), SetExtent, GetExtent, DoVerb(INPLACEACTIVATE,
//!   hwndParent = the frame window), IObjectWithSite::SetSite;
//! - its site answers CanWindowlessActivate with S_FALSE (0x32edea40: the
//!   box's windowless attribute), so the control is activated windowed. Its
//!   OnInPlaceActivateEx (0x32edeea0) then calls
//!   IOleInPlaceObject::SetObjectRects(pos, pos) itself;
//! - the site never calls IViewObject::Draw, and its InvalidateRect does
//!   nothing for a windowed control: the control must paint its own window;
//! - `MCFlashPlayerImpl::_OnMovieChanged` puts Movie through IDispatch, then
//!   `Play`; `MCDevilImpl` sends `SetVariable("face.emotion", ...)` at once,
//!   while the movie still loads;
//! - later SetExtent and SetObjectRects with the real size (62x62 in the
//!   message window) and the frame window is shown.
//!
//! The owner's live log of ICQ 7.2 shows exactly this order. This test hosts
//! avatars so and checks that each frame window shows the movie.

use std::cell::Cell;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::Com::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{GUID, HRESULT};

use crate::axhost::{
    Bag, CLSID_FLASH, IID_IDISPATCH, IID_IDISPATCHEX, IID_IOBJECTWITHSITE, IID_IOLEINPLACEOBJECT,
    IID_IOLEOBJECT, IID_IPERSISTPROPERTYBAG, IID_IRUNNABLEOBJECT, IID_IUNKNOWN, IID_IVIEWOBJECTEX,
    Site, bag_vtbl, container_window, grab, qi, save_png, site_vtbls,
};
use crate::{IID_ISHOCKWAVEFLASH, Unk, pump_for, wide};

/// Green: a frame window pixel the control did not paint over.
const FRAME_BG: u32 = 0x0000FF00;
/// The frame size: 62 (main window) or 100 (message window); `AX72_PX`.
fn frame_px() -> i32 {
    std::env::var("AX72_PX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(62)
}

struct Devil {
    name: String,
    frame: HWND,
    unk: Unk,
    ole: Unk,
    view: Unk,
    flash: Unk,
    site: Box<Site>,
    _bag: Box<Bag>,
    at: (i32, i32),
}

fn frame_class() -> Vec<u16> {
    let cls = wide("FpcOxFrame");
    unsafe {
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(DefWindowProcW),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: GetModuleHandleW(null()),
            hIcon: null_mut(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: CreateSolidBrush(FRAME_BG),
            lpszMenuName: null(),
            lpszClassName: cls.as_ptr(),
        };
        RegisterClassW(&wc);
    }
    cls
}

fn put_movie(unk: Unk, url: &str) -> HRESULT {
    #[repr(C)]
    struct Var {
        vt: u16,
        r: [u16; 3],
        value: u64,
    }
    #[repr(C)]
    struct Dp {
        args: *mut Var,
        named: *mut i32,
        c: u32,
        cn: u32,
    }
    unsafe {
        let disp = qi(unk, &IID_IDISPATCH);
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
            vcall!(disp, 2, fn() -> u32);
            return hr;
        }
        let w = wide(url);
        let mut arg = Var {
            vt: 8,
            r: [0; 3],
            value: SysAllocString(w.as_ptr()) as usize as u64,
        };
        let mut named = -3i32; // DISPID_PROPERTYPUT
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
            4,
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

fn set_variable(flash: Unk, name: &str, value: &str) -> HRESULT {
    unsafe {
        let (n, v) = (wide(name), wide(value));
        let (bn, bv) = (SysAllocString(n.as_ptr()), SysAllocString(v.as_ptr()));
        let hr = vcall!(flash, 65, fn(*const u16, *const u16) -> HRESULT, bn, bv);
        SysFreeString(bn);
        SysFreeString(bv);
        hr
    }
}

fn get_variable(flash: Unk, name: &str) -> String {
    unsafe {
        let n = wide(name);
        let bn = SysAllocString(n.as_ptr());
        let mut out: *const u16 = null();
        let hr = vcall!(
            flash,
            66,
            fn(*const u16, *mut *const u16) -> HRESULT,
            bn,
            &mut out
        );
        SysFreeString(bn);
        let s = if out.is_null() {
            format!("<{hr:#x}>")
        } else {
            crate::bstr_str(out)
        };
        if !out.is_null() {
            SysFreeString(out);
        }
        s
    }
}

fn ready_state(flash: Unk) -> i32 {
    let mut v = 0i32;
    unsafe { vcall!(flash, 7, fn(*mut i32) -> HRESULT, &mut v) };
    v
}

fn set_extent(ole: Unk, w: i32, h: i32) -> HRESULT {
    let e = SIZE {
        cx: w * 2540 / 96,
        cy: h * 2540 / 96,
    };
    unsafe { vcall!(ole, 17, fn(u32, *const SIZE) -> HRESULT, 1, &e) }
}

fn set_object_rects(unk: Unk, r: RECT) -> HRESULT {
    unsafe {
        let ipo = qi(unk, &IID_IOLEINPLACEOBJECT);
        let hr = vcall!(ipo, 7, fn(*const RECT, *const RECT) -> HRESULT, &r, &r);
        vcall!(ipo, 2, fn() -> u32);
        hr
    }
}

/// IOleInPlaceObject::GetWindow: the control's own window when windowed.
fn control_window(unk: Unk) -> (HRESULT, HWND) {
    unsafe {
        let ipo = qi(unk, &IID_IOLEINPLACEOBJECT);
        let mut h: HWND = null_mut();
        let hr = vcall!(ipo, 3, fn(*mut HWND) -> HRESULT, &mut h);
        vcall!(ipo, 2, fn() -> u32);
        (hr, h)
    }
}

fn rect(l: i32, t: i32, r: i32, b: i32) -> RECT {
    RECT {
        left: l,
        top: t,
        right: r,
        bottom: b,
    }
}

/// Hosts one avatar in the order of ICQ 7.2's log, up to Play and the faces.
fn host(
    container: HWND,
    cls: &[u16],
    name: &str,
    url: &str,
    at: (i32, i32),
) -> Result<Devil, String> {
    unsafe {
        // The dedicated frame window: hidden and 0x0 at first.
        let frame = CreateWindowExW(
            0,
            cls.as_ptr(),
            null(),
            WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
            0,
            0,
            0,
            0,
            container,
            null_mut(),
            GetModuleHandleW(null()),
            null(),
        );
        let mut unk: Unk = null_mut();
        let hr = CoCreateInstance(
            &CLSID_FLASH,
            null_mut(),
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
            &IID_IUNKNOWN,
            &mut unk,
        );
        if hr < 0 {
            return Err(format!("CoCreateInstance {hr:#x}"));
        }
        let disp = qi(unk, &IID_IDISPATCH);
        let dispex = qi(unk, &IID_IDISPATCHEX);
        for p in [disp, dispex] {
            if !p.is_null() {
                vcall!(p, 2, fn() -> u32);
            }
        }
        let site = Box::new(Site {
            vtbls: site_vtbls(),
            hwnd: frame,
            pos: Cell::new(rect(0, 0, 0, 0)),
            invalidations: Cell::new(0),
            view_changes: Cell::new(0),
            activate_flags: Cell::new(-1),
            windowless: false,
            control: Cell::new(unk),
            rects_from_activate: Cell::new(None),
        });
        let site_unk = &*site as *const Site as Unk;
        let sink = (site_unk as *mut u8).add(2 * size_of::<usize>()) as Unk;
        let ole = qi(unk, &IID_IOLEOBJECT);
        let mut misc = 0u32;
        vcall!(ole, 22, fn(u32, *mut u32) -> HRESULT, 1, &mut misc);
        vcall!(ole, 3, fn(Unk) -> HRESULT, site_unk);
        let bag = Box::new(Bag {
            vtbl: bag_vtbl(),
            params: [("Quality", "High"), ("Scale", "ShowAll"), ("Menu", "False")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            reads: Default::default(),
        });
        let pb = qi(unk, &IID_IPERSISTPROPERTYBAG);
        let load_hr = vcall!(
            pb,
            5,
            fn(Unk, Unk) -> HRESULT,
            &*bag as *const Bag as Unk,
            null_mut()
        );
        vcall!(pb, 2, fn() -> u32);
        let view = qi(unk, &IID_IVIEWOBJECTEX);
        let mut cookie = 0u32;
        vcall!(ole, 19, fn(Unk, *mut u32) -> HRESULT, sink, &mut cookie);
        vcall!(view, 7, fn(u32, u32, Unk) -> HRESULT, 1, 0, sink);
        let app = wide("AXWIN");
        vcall!(
            ole,
            5,
            fn(*const u16, *const u16) -> HRESULT,
            app.as_ptr(),
            null()
        );
        set_extent(ole, 0, 0);
        let mut got = SIZE { cx: 0, cy: 0 };
        vcall!(ole, 18, fn(u32, *mut SIZE) -> HRESULT, 1, &mut got);
        let run = qi(unk, &IID_IRUNNABLEOBJECT);
        if !run.is_null() {
            vcall!(run, 2, fn() -> u32);
        }
        let zero = rect(0, 0, 0, 0);
        let verb_hr = vcall!(
            ole,
            11,
            fn(i32, Unk, Unk, i32, HWND, *const RECT) -> HRESULT,
            -5,
            null_mut(),
            site_unk,
            0,
            frame,
            &zero
        );
        let ows = qi(unk, &IID_IOBJECTWITHSITE);
        vcall!(ows, 3, fn(Unk) -> HRESULT, site_unk);
        vcall!(ows, 2, fn() -> u32);
        let movie_hr = put_movie(unk, url);
        let flash = qi(unk, &IID_ISHOCKWAVEFLASH);
        if flash.is_null() {
            return Err("no IShockwaveFlash".into());
        }
        let play_hr = vcall!(flash, 28, fn() -> HRESULT);
        let faces: Vec<HRESULT> = (0..if std::env::var("AX72_NOFACE").is_ok() {
            0
        } else {
            2
        })
            .map(|_| set_variable(flash, "face.emotion", "stam"))
            .collect();
        let (win_hr, win) = control_window(unk);
        say!(
            "[{name}] misc {misc:#x}; Load {load_hr:#x} read {:?}; DoVerb {verb_hr:#x}: site saw \
             OnInPlaceActivateEx flags {} (0 = windowed), SetObjectRects from it {:?}; \
             IOleInPlaceObject::GetWindow {win_hr:#x} {win:?} (parent {:?}, frame {frame:?}); \
             Movie {movie_hr:#x}; Play {play_hr:#x}; SetVariable(face.emotion, stam) while loading {faces:x?}",
            bag.reads.borrow(),
            site.activate_flags.get(),
            site.rects_from_activate.get().map(|h| format!("{h:#x}")),
            if win.is_null() {
                null_mut()
            } else {
                GetParent(win)
            },
        );
        Ok(Devil {
            name: name.to_string(),
            frame,
            unk,
            ole,
            view,
            flash,
            site,
            _bag: bag,
            at,
        })
    }
}

/// Share of the frame's pixels the control painted (not the frame's green).
fn painted(px: &[u8], w: i32, at: (i32, i32), size: i32) -> f64 {
    let mut n = 0;
    for y in at.1..at.1 + size {
        for x in at.0..at.0 + size {
            let i = ((y * w + x) * 4) as usize;
            let (b, g, r) = (px[i], px[i + 1], px[i + 2]);
            if !(r < 16 && g > 240 && b < 16) {
                n += 1;
            }
        }
    }
    n as f64 / (size * size) as f64
}

fn region(px: &[u8], w: i32, at: (i32, i32), size: i32) -> Vec<u8> {
    let mut v = Vec::new();
    for y in at.1..at.1 + size {
        let i = ((y * w + at.0) * 4) as usize;
        v.extend_from_slice(&px[i..i + size as usize * 4]);
    }
    v
}

/// avatars at `base` (a directory or an http URL); `extras`: also one avatar
/// through an ICQ extras document (XML naming the SWF).
pub fn run(base: &str, out: &str, names: &[String]) -> bool {
    let _ = std::fs::create_dir_all(out);
    let sz = frame_px();
    let sep = if base.starts_with("http") { "/" } else { "\\" };
    let mut movies: Vec<(String, String)> = names
        .iter()
        .map(|n| (n.clone(), format!("{base}{sep}{n}")))
        .collect();
    // One avatar through an ICQ extras document, as a BART item holds it.
    if let Some(first) = movies.first().cloned() {
        let xml = format!("{out}\\extras-{}.xml", first.0);
        let doc = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DOCUMENT><RESSET TYPE=\"ICQ_EXTRAS\"><URL>{}</URL></RESSET></DOCUMENT>",
            first.1.replace('&', "&amp;")
        );
        let _ = std::fs::write(&xml, doc);
        movies.push((format!("{} (extras XML)", first.0), xml));
    }
    let cols = 6;
    let rows = movies.len().div_ceil(cols) as i32;
    let step = sz + 10;
    let win = container_window(
        cols as i32 * step + 10,
        rows * step + 10,
        "ICQ 7.2 devil host",
    );
    let cls = frame_class();
    let mut devils = Vec::new();
    for (i, (name, url)) in movies.iter().enumerate() {
        let at = (10 + (i % cols) as i32 * step, 10 + (i / cols) as i32 * step);
        match host(win, &cls, name, url, at) {
            Ok(d) => devils.push(d),
            Err(e) => {
                say!("[{name}] cannot host: {e}");
                return false;
            }
        }
    }
    // Later: the real size, then the frame window is placed and shown.
    pump_for(Duration::from_millis(100));
    for d in &devils {
        let r = rect(0, 0, sz, sz);
        d.site.pos.set(r);
        let e = set_extent(d.ole, sz, sz);
        let s = set_object_rects(d.unk, r);
        unsafe {
            SetWindowPos(
                d.frame,
                null_mut(),
                d.at.0,
                d.at.1,
                sz,
                sz,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            ShowWindow(d.frame, SW_SHOWNA);
        }
        if e < 0 || s < 0 {
            say!("[{}] SetExtent {e:#x}, SetObjectRects {s:#x}", d.name);
        }
    }
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) && devils.iter().any(|d| ready_state(d.flash) != 4)
    {
        pump_for(Duration::from_millis(50));
    }
    say!(
        "{} controls loaded in {} ms ({} not ready)",
        devils.len(),
        t.elapsed().as_millis(),
        devils.iter().filter(|d| ready_state(d.flash) != 4).count()
    );
    pump_for(Duration::from_millis(1500));
    let (w, h, px) = grab(win);
    save_png(&format!("{out}\\icq72-devils.png"), w as u32, h as u32, &px);
    if std::env::var("AX72_PROBE").is_ok() {
        for d in &devils {
            for v in [
                "face.MyEmotion",
                "face.emotion",
                "face._currentframe",
                "_global.devilRoot.initEmo",
                "emotion",
            ] {
                say!(
                    "[{}] GetVariable({v}) = {:?}",
                    d.name,
                    get_variable(d.flash, v)
                );
            }
        }
    }
    // The idle face over time: one row per avatar, a column per second.
    let secs = std::env::var("AX72_WATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0usize);
    if secs > 0 {
        let (sw, sh) = (secs * sz as usize, devils.len() * sz as usize);
        let mut sheet = vec![0u8; sw * sh * 4];
        for c in 0..secs {
            pump_for(Duration::from_millis(1000));
            let (_, _, now) = grab(win);
            for (r, d) in devils.iter().enumerate() {
                let reg = region(&now, w, d.at, sz);
                for y in 0..sz as usize {
                    let dst = ((r * sz as usize + y) * sw + c * sz as usize) * 4;
                    sheet[dst..dst + sz as usize * 4]
                        .copy_from_slice(&reg[y * sz as usize * 4..(y + 1) * sz as usize * 4]);
                }
            }
        }
        save_png(
            &format!("{out}\\icq72-idle-{sz}px.png"),
            sw as u32,
            sh as u32,
            &sheet,
        );
        say!("idle sheet -> {out}\\icq72-idle-{sz}px.png ({secs} s)");
    }
    let mut ok = true;
    for d in &devils {
        let share = painted(&px, w, d.at, sz);
        let (hr, cw) = control_window(d.unk);
        let mut cr: RECT = unsafe { std::mem::zeroed() };
        unsafe { GetClientRect(cw, &mut cr) };
        let visible = unsafe { IsWindowVisible(cw) } != 0;
        let good = share > 0.9 && hr >= 0 && visible && cr.right == sz && cr.bottom == sz;
        say!(
            "[{}] frame painted {:.0}%, own window {hr:#x} {cw:?} {}x{} {}, site InvalidateRect {}, OnViewChange {} -> {}",
            d.name,
            share * 100.0,
            cr.right,
            cr.bottom,
            if visible { "visible" } else { "HIDDEN" },
            d.site.invalidations.get(),
            d.site.view_changes.get(),
            if good { "ok" } else { "FAILED" }
        );
        ok &= good;
    }
    // The faces change the picture (the ones sent while loading were kept).
    let mut changed = 0;
    let mut prev = px;
    for e in ["smile", "laugh", "sad"] {
        for d in &devils {
            set_variable(d.flash, "face.emotion", "stam");
            set_variable(d.flash, "face.emotion", e);
        }
        pump_for(Duration::from_millis(900));
        let (_, _, now) = grab(win);
        let n = devils
            .iter()
            .filter(|d| region(&now, w, d.at, sz) != region(&prev, w, d.at, sz))
            .count();
        say!("face {e}: {n}/{} frames changed on screen", devils.len());
        changed += n;
        prev = now;
    }
    save_png(
        &format!("{out}\\icq72-devils-faces.png"),
        w as u32,
        h as u32,
        &prev,
    );
    ok &= changed > 0;
    // A resize: the own window follows SetObjectRects.
    let d = &devils[0];
    let big = rect(0, 0, 80, 80);
    unsafe {
        SetWindowPos(
            d.frame,
            null_mut(),
            0,
            0,
            80,
            80,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    set_extent(d.ole, 80, 80);
    set_object_rects(d.unk, big);
    pump_for(Duration::from_millis(300));
    let (_, cw) = control_window(d.unk);
    let mut cr: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetClientRect(cw, &mut cr) };
    let resized = cr.right == 80 && cr.bottom == 80;
    say!(
        "[{}] resized to 80x80: own window {}x{} -> {}",
        d.name,
        cr.right,
        cr.bottom,
        if resized { "ok" } else { "FAILED" }
    );
    ok &= resized;
    // Teardown like the box: Close, SetClientSite(NULL), release.
    let mut gone = true;
    for d in devils {
        let (_, cw) = control_window(d.unk);
        unsafe {
            vcall!(d.ole, 6, fn(u32) -> HRESULT, 1);
            vcall!(d.ole, 3, fn(Unk) -> HRESULT, null_mut());
            vcall!(d.view, 7, fn(u32, u32, Unk) -> HRESULT, 1, 0, null_mut());
            vcall!(d.flash, 2, fn() -> u32);
            vcall!(d.view, 2, fn() -> u32);
            vcall!(d.ole, 2, fn() -> u32);
            vcall!(d.unk, 2, fn() -> u32);
            if IsWindow(cw) != 0 {
                say!("[{}] own window {cw:?} still exists after Close", d.name);
                gone = false;
            }
            DestroyWindow(d.frame);
        }
        drop(d.site);
    }
    unsafe { DestroyWindow(win) };
    say!(
        "summary: frames painted and sized ok {}, faces changed {changed}, own windows gone {gone}",
        ok
    );
    ok && gone
}
