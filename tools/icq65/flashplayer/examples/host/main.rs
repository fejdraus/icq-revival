//! Test host that drives FlashPlayerControl.dll the way ICQ 6.5 does.
//!
//!   host <dll> play <swf path or url> <out dir>   play one movie over an owner window
//!   host <dll> two <swf path> <url> <out dir>     two windows at once (file + http)
//!   host <dll> reg | check | unreg                per-user type library registration
//!
//! Build: cargo build --release --example host (32-bit, like ICQ).

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::Com::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Ole::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{BOOL, GUID, HRESULT};

pub type Unk = *mut c_void;

pub const IID_ISHOCKWAVEFLASH: GUID = GUID::from_u128(0xD27CDB6C_AE6D_11cf_96B8_444553540000);
pub const DIID_EVENTS: GUID = GUID::from_u128(0xD27CDB6D_AE6D_11cf_96B8_444553540000);
const LIBID: GUID = GUID::from_u128(0xD27CDB6B_AE6D_11cf_96B8_444553540000);
const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_C000_000000000046);
const IID_IDISPATCH: GUID = GUID::from_u128(0x00020400_0000_0000_C000_000000000046);
pub const IID_ICPC: GUID = GUID::from_u128(0xB196B284_BAB4_101A_B69C_00AA00341D07);

macro_rules! vcall {
    ($p:expr, $slot:expr, fn($($t:ty),* $(,)?) -> $r:ty $(, $a:expr)* $(,)?) => {{
        let p: *mut std::ffi::c_void = $p;
        let vtbl = *(p as *const *const usize);
        let f: unsafe extern "system" fn(*mut std::ffi::c_void $(, $t)*) -> $r =
            std::mem::transmute(*vtbl.add($slot));
        f(p $(, $a)*)
    }};
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn t0() -> Instant {
    static T0: OnceLock<Instant> = OnceLock::new();
    *T0.get_or_init(Instant::now)
}

macro_rules! say {
    ($($a:tt)*) => { println!("[{:7.3}s] {}", crate::t0().elapsed().as_secs_f64(), format!($($a)*)) };
}

mod avatar;
mod axhost;
mod stacks;

// ---------------------------------------------------------------------------
// The DLL

struct Fpc {
    RegisterFlashWindowClass: extern "system" fn() -> BOOL,
    UnregisterFlashWindowClass: extern "system" fn() -> BOOL,
    FPCIsFlashInstalled: extern "system" fn() -> BOOL,
    FPC_LoadMovieW: extern "system" fn(HWND, i32, *const u16) -> HRESULT,
    FPC_Play: extern "system" fn(HWND) -> HRESULT,
    FPC_Stop: extern "system" fn(HWND) -> HRESULT,
    FPC_StopPlay: extern "system" fn(HWND) -> HRESULT,
    FPC_IsPlaying: extern "system" fn(HWND, *mut i16) -> HRESULT,
    FPC_UpdateWindow: extern "system" fn(HWND) -> HRESULT,
    FPCSetEventListener: extern "system" fn(
        HWND,
        Option<extern "system" fn(HWND, LPARAM, *mut c_void)>,
        LPARAM,
    ) -> BOOL,
    DllRegisterServer: extern "system" fn() -> HRESULT,
    DllUnregisterServer: extern "system" fn() -> HRESULT,
}

fn load_dll(path: &str) -> Fpc {
    let w = wide(path);
    let h = unsafe { LoadLibraryW(w.as_ptr()) };
    assert!(!h.is_null(), "LoadLibrary {path} failed");
    macro_rules! get {
        ($name:ident) => {{
            let n = concat!(stringify!($name), "\0");
            let p = unsafe { GetProcAddress(h, n.as_ptr()) }
                .unwrap_or_else(|| panic!("missing export {}", stringify!($name)));
            unsafe { std::mem::transmute(p) }
        }};
    }
    Fpc {
        RegisterFlashWindowClass: get!(RegisterFlashWindowClass),
        UnregisterFlashWindowClass: get!(UnregisterFlashWindowClass),
        FPCIsFlashInstalled: get!(FPCIsFlashInstalled),
        FPC_LoadMovieW: get!(FPC_LoadMovieW),
        FPC_Play: get!(FPC_Play),
        FPC_Stop: get!(FPC_Stop),
        FPC_StopPlay: get!(FPC_StopPlay),
        FPC_IsPlaying: get!(FPC_IsPlaying),
        FPC_UpdateWindow: get!(FPC_UpdateWindow),
        FPCSetEventListener: get!(FPCSetEventListener),
        DllRegisterServer: get!(DllRegisterServer),
        DllUnregisterServer: get!(DllUnregisterServer),
    }
}

// ---------------------------------------------------------------------------
// Event sink: a minimal IDispatch that logs every Invoke

#[repr(C)]
struct Sink {
    vtbl: *const [usize; 7],
    name: &'static str,
    anim_end_at: std::cell::Cell<Option<f64>>,
    ready: std::cell::RefCell<Vec<i32>>,
    fscommands: std::cell::RefCell<Vec<(String, String)>>,
    /// Avatar jobs: window to post 0x7BA/0x7BB to on ready states 3/4.
    post_to: std::cell::Cell<isize>,
}

#[repr(C)]
struct Variant {
    vt: u16,
    r: [u16; 3],
    value: u64,
}

#[repr(C)]
struct DispParams {
    rgvarg: *const Variant,
    named: *const i32,
    c_args: u32,
    c_named: u32,
}

unsafe fn bstr_str(b: *const u16) -> String {
    if b.is_null() {
        return String::new();
    }
    let n = unsafe { SysStringLen(b) } as usize;
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(b, n) })
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

unsafe extern "system" fn sink_qi(this: Unk, iid: *const GUID, out: *mut Unk) -> HRESULT {
    let iid = unsafe { &*iid };
    if guid_eq(iid, &IID_IUNKNOWN) || guid_eq(iid, &IID_IDISPATCH) || guid_eq(iid, &DIID_EVENTS) {
        unsafe { *out = this };
        S_OK
    } else {
        unsafe { *out = null_mut() };
        E_NOINTERFACE
    }
}
unsafe extern "system" fn sink_addref(_: Unk) -> u32 {
    2
}
unsafe extern "system" fn sink_release(_: Unk) -> u32 {
    1
}
unsafe extern "system" fn sink_notimpl1(_: Unk, _: usize) -> HRESULT {
    E_NOTIMPL
}
unsafe extern "system" fn sink_notimpl3(_: Unk, _: usize, _: usize, _: usize) -> HRESULT {
    E_NOTIMPL
}
unsafe extern "system" fn sink_notimpl5(
    _: Unk,
    _: usize,
    _: usize,
    _: usize,
    _: usize,
    _: usize,
) -> HRESULT {
    E_NOTIMPL
}
unsafe extern "system" fn sink_invoke(
    this: Unk,
    dispid: i32,
    _riid: *const GUID,
    _lcid: u32,
    flags: u16,
    params: *const DispParams,
    _res: Unk,
    _exc: Unk,
    _argerr: *mut u32,
) -> HRESULT {
    let sink = unsafe { &*(this as *const Sink) };
    let p = unsafe { &*params };
    let args: Vec<&Variant> = (0..p.c_args as usize)
        .map(|i| unsafe { &*p.rgvarg.add(i) })
        .collect();
    let desc: Vec<String> = args
        .iter()
        .enumerate()
        .map(|(i, v)| match v.vt {
            3 => format!("rgvarg[{i}]=VT_I4 {}", v.value as u32 as i32),
            8 => format!("rgvarg[{i}]=VT_BSTR {:?}", unsafe {
                bstr_str(v.value as usize as *const u16)
            }),
            vt => format!("rgvarg[{i}]=vt {vt}"),
        })
        .collect();
    say!(
        "{}: Invoke dispid={} flags={} cArgs={} {}",
        sink.name,
        dispid,
        flags,
        p.c_args,
        desc.join(", ")
    );
    if dispid == -609 && args.len() == 1 && args[0].vt == 3 {
        let state = args[0].value as u32 as i32;
        sink.ready.borrow_mut().push(state);
        let to = sink.post_to.get();
        if to != 0 && (state == 3 || state == 4) {
            let m = if state == 3 {
                avatar::MSG_STATE3
            } else {
                avatar::MSG_STATE4
            };
            unsafe { PostMessageW(to as HWND, m, 0, 0) };
        }
    }
    if dispid == 0x96 && args.len() == 2 && args[0].vt == 8 && args[1].vt == 8 {
        let cmd = unsafe { bstr_str(args[1].value as usize as *const u16) };
        let a = unsafe { bstr_str(args[0].value as usize as *const u16) };
        if cmd.eq_ignore_ascii_case("animEnd") && sink.anim_end_at.get().is_none() {
            sink.anim_end_at.set(Some(t0().elapsed().as_secs_f64()));
        }
        sink.fscommands.borrow_mut().push((cmd, a));
    }
    S_OK
}

static SINK_VTBL: OnceLock<[usize; 7]> = OnceLock::new();

fn new_sink(name: &'static str) -> Box<Sink> {
    let vtbl = SINK_VTBL.get_or_init(|| {
        [
            sink_qi as *const () as usize,
            sink_addref as *const () as usize,
            sink_release as *const () as usize,
            sink_notimpl1 as *const () as usize, // GetTypeInfoCount(pctinfo)
            sink_notimpl3 as *const () as usize, // GetTypeInfo(i, lcid, pp)
            sink_notimpl5 as *const () as usize, // GetIDsOfNames(riid, names, n, lcid, ids)
            sink_invoke as *const () as usize,
        ]
    });
    Box::new(Sink {
        vtbl,
        name,
        anim_end_at: Default::default(),
        ready: Default::default(),
        fscommands: Default::default(),
        post_to: Default::default(),
    })
}

// ---------------------------------------------------------------------------
// Windows

static mut OLD_PROC: [isize; 4] = [0; 4];
static mut SEEN_LBUTTONUP: u32 = 0;
static mut SEEN_SETCURSOR: u32 = 0;
static mut SEEN_TIMER_25D: u32 = 0;

unsafe extern "system" fn subclass_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_LBUTTONUP => SEEN_LBUTTONUP += 1,
            WM_SETCURSOR => SEEN_SETCURSOR += 1,
            WM_TIMER if wp == 0x25D => SEEN_TIMER_25D += 1,
            _ => {}
        }
        let idx = GetWindowLongW(hwnd, GWL_USERDATA) as usize;
        let old: WNDPROC = std::mem::transmute(OLD_PROC[idx]);
        CallWindowProcW(old, hwnd, msg, wp, lp)
    }
}

unsafe extern "system" fn owner_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_PAINT {
        unsafe {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let dc = BeginPaint(hwnd, &mut ps);
            let mut rc: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rc);
            // Blue/yellow stripes so the layered window's transparency is visible.
            let blue = CreateSolidBrush(0x00C06020);
            let yellow = CreateSolidBrush(0x0000E0F0);
            let mut x = 0;
            while x < rc.right {
                let r = RECT {
                    left: x,
                    top: 0,
                    right: x + 40,
                    bottom: rc.bottom,
                };
                FillRect(dc, &r, if (x / 40) % 2 == 0 { blue } else { yellow });
                x += 40;
            }
            DeleteObject(blue);
            DeleteObject(yellow);
            EndPaint(hwnd, &ps);
        }
        return 0;
    }
    unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
}

fn create_owner(x: i32, y: i32, w: i32, h: i32) -> HWND {
    let cls = wide("FpcTestOwner");
    let hinst = unsafe { GetModuleHandleW(null()) };
    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(owner_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinst,
        hIcon: null_mut(),
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hbrBackground: null_mut(),
        lpszMenuName: null(),
        lpszClassName: cls.as_ptr(),
    };
    unsafe { RegisterClassW(&wc) };
    let title = wide("FlashPlayerControl test owner");
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST,
            cls.as_ptr(),
            title.as_ptr(),
            WS_POPUP | WS_VISIBLE,
            x,
            y,
            w,
            h,
            null_mut(),
            null_mut(),
            hinst,
            null(),
        )
    };
    assert!(!hwnd.is_null());
    unsafe { UpdateWindow(hwnd) };
    hwnd
}

fn create_flash(fpc: &Fpc, owner: HWND, x: i32, y: i32, w: i32, h: i32, slot: usize) -> HWND {
    let cls = wide("FlashPlayerControl");
    let hwnd = unsafe {
        CreateWindowExW(
            0x08080080,
            cls.as_ptr(),
            null(),
            0x90000000,
            x,
            y,
            w,
            h,
            owner,
            null_mut(),
            GetModuleHandleW(null()),
            null(),
        )
    };
    assert!(!hwnd.is_null(), "CreateWindowExW failed: {}", unsafe {
        GetLastError()
    });
    unsafe {
        SetWindowLongW(hwnd, GWL_USERDATA, slot as i32);
        OLD_PROC[slot] =
            SetWindowLongW(hwnd, GWL_WNDPROC, subclass_proc as *const () as i32) as isize;
    }
    say!(
        "flash window {hwnd:?} created and subclassed (old proc {:#x})",
        unsafe { OLD_PROC[slot] }
    );
    let ok = (fpc.FPCSetEventListener)(hwnd, Some(listener), 0x1234);
    say!("FPCSetEventListener -> {ok}");
    hwnd
}

extern "system" fn listener(_: HWND, _: LPARAM, _: *mut c_void) {
    say!("listener called");
}

fn pump_for(d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end {
        pump_once();
        std::thread::sleep(Duration::from_millis(2));
    }
}

// Longest single DispatchMessage on this thread: (microseconds, message).
thread_local! {
    static SLOWEST: std::cell::Cell<(u128, u32)> = const { std::cell::Cell::new((0, 0)) };
}

thread_local! {
    /// Total time spent in DispatchMessage on this thread, microseconds.
    static BUSY_US: std::cell::Cell<u128> = const { std::cell::Cell::new(0) };
}

fn busy_us() -> u128 {
    BUSY_US.with(|b| b.get())
}

fn slowest_dispatch() -> String {
    let (us, msg) = SLOWEST.with(|s| s.get());
    format!("{:.1} ms (message {msg:#x})", us as f64 / 1000.0)
}

fn pump_once() {
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        // Bounded, so a flood of messages cannot keep the caller here forever.
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(200)
            && PeekMessageW(&mut msg, null_mut(), 0, 0, PM_REMOVE) != 0
        {
            TranslateMessage(&msg);
            let t = Instant::now();
            DispatchMessageW(&msg);
            let us = t.elapsed().as_micros();
            BUSY_US.with(|b| b.set(b.get() + us));
            SLOWEST.with(|s| {
                if us > s.get().0 {
                    s.set((us, msg.message))
                }
            });
        }
    }
}

/// Message 0x1401: QueryInterface through the window.
fn query_flash(hwnd: HWND) -> Unk {
    #[repr(C)]
    struct Query {
        iid: GUID,
        pv: Unk,
        hr: HRESULT,
    }
    let mut q = Query {
        iid: IID_ISHOCKWAVEFLASH,
        pv: null_mut(),
        hr: -1,
    };
    let r = unsafe { SendMessageW(hwnd, 0x1401, 0, &mut q as *mut Query as LPARAM) };
    say!(
        "0x1401 IShockwaveFlash -> ret {r:#x}, hr {:#x}, pv {:?}",
        q.hr,
        q.pv
    );
    assert!(q.hr >= 0 && !q.pv.is_null());
    q.pv
}

fn advise(flash: Unk, sink: &Sink) -> (Unk, u32) {
    unsafe {
        let mut cpc: Unk = null_mut();
        let hr = vcall!(
            flash,
            0,
            fn(*const GUID, *mut Unk) -> HRESULT,
            &IID_ICPC,
            &mut cpc
        );
        say!("QI IConnectionPointContainer -> {hr:#x}");
        let mut cp: Unk = null_mut();
        let hr = vcall!(
            cpc,
            4,
            fn(*const GUID, *mut Unk) -> HRESULT,
            &DIID_EVENTS,
            &mut cp
        );
        say!("FindConnectionPoint(DIID__IShockwaveFlashEvents) -> {hr:#x}");
        let mut cookie = 0u32;
        let hr = vcall!(
            cp,
            5,
            fn(Unk, *mut u32) -> HRESULT,
            sink as *const Sink as Unk,
            &mut cookie
        );
        say!("Advise -> {hr:#x}, cookie {cookie}");
        vcall!(cpc, 2, fn() -> u32,);
        (cp, cookie)
    }
}

fn snapshot(hwnd: HWND, path: &str) -> Option<(u32, u32, usize, usize, [u8; 4])> {
    let mut bmp: HBITMAP = null_mut();
    let r = unsafe { SendMessageW(hwnd, 0x1404, 0, &mut bmp as *mut HBITMAP as LPARAM) };
    if bmp.is_null() {
        say!("0x1404 returned no bitmap (ret {r})");
        return None;
    }
    let mut ds: DIBSECTION = unsafe { std::mem::zeroed() };
    unsafe {
        GetObjectW(
            bmp,
            size_of::<DIBSECTION>() as i32,
            &mut ds as *mut _ as *mut c_void,
        )
    };
    let (w, h) = (ds.dsBm.bmWidth as u32, ds.dsBm.bmHeight as u32);
    let raw =
        unsafe { std::slice::from_raw_parts(ds.dsBm.bmBits as *const u8, (w * h * 4) as usize) };
    // The DLL hands out a bottom-up DIB (positive biHeight), as the client
    // expects: turn it top-down for the PNG.
    let stride = (w * 4) as usize;
    let bits: Vec<u8> = if ds.dsBmih.biHeight > 0 {
        raw.chunks_exact(stride).rev().flatten().copied().collect()
    } else {
        raw.to_vec()
    };
    let mut rgba = Vec::with_capacity(bits.len());
    let (mut transparent, mut opaque) = (0, 0);
    for px in bits.chunks_exact(4) {
        let a = px[3];
        if a == 0 {
            transparent += 1;
        } else if a == 255 {
            opaque += 1;
        }
        // premultiplied BGRA -> straight RGBA for the PNG
        let un = |c: u8| {
            if a == 0 {
                0
            } else {
                ((c as u32 * 255 + a as u32 / 2) / a as u32).min(255) as u8
            }
        };
        rgba.extend_from_slice(&[un(px[2]), un(px[1]), un(px[0]), a]);
    }
    let corner = [bits[0], bits[1], bits[2], bits[3]];
    image::RgbaImage::from_raw(w, h, rgba)
        .unwrap()
        .save(path)
        .unwrap();
    say!(
        "0x1404 -> ret {r}, {w}x{h} bpp {} (rows written to the PNG in memory order): {transparent} px alpha=0, {opaque} px alpha=255, corner BGRA {corner:?} -> {path}",
        ds.dsBm.bmBitsPixel
    );
    unsafe { DeleteObject(bmp) };
    Some((w, h, transparent, opaque, corner))
}

fn screenshot(owner: HWND, path: &str) {
    unsafe {
        let mut rc: RECT = std::mem::zeroed();
        GetWindowRect(owner, &mut rc);
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
        let rgba: Vec<u8> = buf
            .chunks_exact(4)
            .flat_map(|p| [p[2], p[1], p[0], 255])
            .collect();
        image::RgbaImage::from_raw(w as u32, h as u32, rgba)
            .unwrap()
            .save(path)
            .unwrap();
    }
    say!("screenshot of the owner area -> {path}");
}

fn is_playing(fpc: &Fpc, hwnd: HWND) -> bool {
    let mut v: i16 = 0x55;
    let hr = (fpc.FPC_IsPlaying)(hwnd, &mut v);
    assert!(hr == S_OK, "FPC_IsPlaying hr {hr:#x}");
    v != 0
}

fn audio_stats(hwnd: HWND) -> [u64; 3] {
    let mut s = [0u64; 3];
    unsafe { SendMessageW(hwnd, 0x8000 + 0xF12, 0, &mut s as *mut _ as LPARAM) };
    s
}

// ---------------------------------------------------------------------------

fn play(fpc: &Fpc, movie: &str, out: &str) {
    let _ = std::fs::create_dir_all(out);
    let t = Instant::now();
    let installed = (fpc.FPCIsFlashInstalled)();
    say!(
        "FPCIsFlashInstalled -> {installed} ({} ms on the UI thread)",
        t.elapsed().as_millis()
    );
    say!(
        "RegisterFlashWindowClass -> {}",
        (fpc.RegisterFlashWindowClass)()
    );
    say!(
        "RegisterFlashWindowClass again -> {}",
        (fpc.RegisterFlashWindowClass)()
    );

    let owner = create_owner(100, 100, 900, 700);
    let hwnd = create_flash(fpc, owner, 172, 170, 755, 560, 0);
    let flash = query_flash(hwnd);
    let sink = new_sink("sink");
    let (cp, cookie) = advise(flash, &sink);

    let null_hr = (fpc.FPC_IsPlaying)(hwnd, null_mut());
    say!("FPC_IsPlaying(NULL) -> {null_hr:#x} (E_POINTER = 0x80004003)");
    say!("FPC_Stop before load -> {:#x}", (fpc.FPC_Stop)(hwnd));
    let w = wide(movie);
    let start = Instant::now();
    say!(
        "FPC_LoadMovieW({movie}) -> {:#x}",
        (fpc.FPC_LoadMovieW)(hwnd, 0, w.as_ptr())
    );
    say!("FPC_Play -> {:#x}", (fpc.FPC_Play)(hwnd));
    say!(
        "IsPlaying right after Play (movie not loaded yet) -> {}",
        is_playing(fpc, hwnd)
    );

    let mut last = None;
    let mut shot_taken = false;
    let mut ended_at = None;
    let mut went_playing = false;
    while start.elapsed() < Duration::from_secs(20) {
        pump_for(Duration::from_millis(100));
        let p = is_playing(fpc, hwnd);
        if last != Some(p) {
            say!("IsPlaying -> {p}");
            last = Some(p);
            if p {
                went_playing = true;
            }
        }
        if !shot_taken && start.elapsed() > Duration::from_millis(3000) {
            shot_taken = true;
            let total = unsafe {
                let mut n = 0i32;
                let hr = vcall!(flash, 8, fn(*mut i32) -> HRESULT, &mut n);
                say!("get_TotalFrames (vtable +0x20) -> hr {hr:#x}, {n}");
                n
            };
            let _ = total;
            screenshot(owner, &format!("{out}\\screen-3s.png"));
            snapshot(hwnd, &format!("{out}\\snapshot-3s.png"));
            say!("FPC_UpdateWindow -> {:#x}", (fpc.FPC_UpdateWindow)(hwnd));
        }
        if went_playing && !p && ended_at.is_none() {
            ended_at = Some(start.elapsed().as_secs_f64());
        }
        if ended_at.is_some_and(|e| start.elapsed().as_secs_f64() > e + 1.0) {
            break;
        }
    }
    say!(
        "summary: OnReadyStateChange states {:?}",
        sink.ready.borrow()
    );
    say!("summary: FSCommands {:?}", sink.fscommands.borrow());
    say!(
        "summary: animEnd at {:?} s after start; IsPlaying false at {:?} s",
        sink.anim_end_at.get(),
        ended_at
    );
    let a = audio_stats(hwnd);
    say!(
        "summary: audio streams started {}, samples mixed {}, audible samples {}; slowest UI-thread message {}",
        a[0],
        a[1],
        a[2],
        slowest_dispatch()
    );

    // Snapshot-service path: GotoFrame then 0x1404.
    unsafe {
        let mut n = 0i32;
        let hr = vcall!(flash, 8, fn(*mut i32) -> HRESULT, &mut n);
        say!("get_TotalFrames (vtable +0x20) -> hr {hr:#x}, {n}");
        let hr = vcall!(flash, 34, fn(i32) -> HRESULT, n / 2);
        say!("GotoFrame({}) (vtable +0x88) -> hr {hr:#x}", n / 2);
        let mut cur = -1i32;
        vcall!(flash, 35, fn(*mut i32) -> HRESULT, &mut cur);
        say!("CurrentFrame -> {cur}");
        snapshot(hwnd, &format!("{out}\\snapshot-goto-{}.png", n / 2));
        let hr = vcall!(flash, 34, fn(i32) -> HRESULT, 10);
        vcall!(flash, 35, fn(*mut i32) -> HRESULT, &mut cur);
        say!("GotoFrame(10) -> hr {hr:#x}, CurrentFrame -> {cur}");
        snapshot(hwnd, &format!("{out}\\snapshot-goto-10.png"));
        say!("IsPlaying after GotoFrame -> {}", is_playing(fpc, hwnd));
        // IDispatch path: GetIDsOfNames + Invoke(TotalFrames)
        let name = wide("TotalFrames");
        let names = [name.as_ptr()];
        let mut id = 0i32;
        let hr = vcall!(
            flash,
            5,
            fn(*const GUID, *const *const u16, u32, u32, *mut i32) -> HRESULT,
            &GUID::from_u128(0),
            names.as_ptr(),
            1,
            0x400,
            &mut id
        );
        let mut res = Variant {
            vt: 0,
            r: [0; 3],
            value: 0,
        };
        let dp = DispParams {
            rgvarg: null(),
            named: null(),
            c_args: 0,
            c_named: 0,
        };
        let hr2 = vcall!(
            flash,
            6,
            fn(
                i32,
                *const GUID,
                u32,
                u16,
                *const DispParams,
                *mut Variant,
                Unk,
                *mut u32,
            ) -> HRESULT,
            id,
            &GUID::from_u128(0),
            0x400,
            2, /*DISPATCH_PROPERTYGET*/
            &dp,
            &mut res,
            null_mut(),
            null_mut()
        );
        say!(
            "IDispatch: GetIDsOfNames(TotalFrames) -> {hr:#x} id {id:#x}; Invoke -> {hr2:#x} vt {} value {}",
            res.vt,
            res.value as i32
        );
    }

    // Replay from the start after the end.
    say!("FPC_Play again -> {:#x}", (fpc.FPC_Play)(hwnd));
    pump_for(Duration::from_millis(500));
    say!("IsPlaying after replay -> {}", is_playing(fpc, hwnd));
    say!("FPC_StopPlay -> {:#x}", (fpc.FPC_StopPlay)(hwnd));
    say!("IsPlaying after StopPlay -> {}", is_playing(fpc, hwnd));
    say!("FPC_Stop -> {:#x}", (fpc.FPC_Stop)(hwnd));
    unsafe {
        let mut cur = -1i32;
        vcall!(flash, 35, fn(*mut i32) -> HRESULT, &mut cur);
        say!("CurrentFrame after Stop -> {cur}");
    }

    // Messages the client relies on reaching the (subclassed) window.
    unsafe {
        SendMessageW(hwnd, WM_LBUTTONUP, 0, 0);
        SendMessageW(
            hwnd,
            WM_SETCURSOR,
            hwnd as WPARAM,
            (HTCLIENT as u32 | (WM_MOUSEMOVE << 16)) as LPARAM,
        );
        SetTimer(hwnd, 0x25D, 50, None);
    }
    pump_for(Duration::from_millis(300));
    unsafe {
        KillTimer(hwnd, 0x25D);
        let (up, cur, tim) = (SEEN_LBUTTONUP, SEEN_SETCURSOR, SEEN_TIMER_25D);
        say!(
            "subclass saw WM_LBUTTONUP x{up}, WM_SETCURSOR x{cur}, WM_TIMER 0x25D x{tim} (passed on to the DLL's proc)"
        );
        let r = SendMessageW(hwnd, 0x1405, 0, &mut 0i16 as *mut i16 as LPARAM);
        say!("0x1405 -> {r}");
    }

    unsafe {
        let hr = vcall!(cp, 6, fn(u32) -> HRESULT, cookie);
        say!("Unadvise -> {hr:#x}");
        vcall!(cp, 2, fn() -> u32,);
        // Restore the window procedure, as the client does, then destroy.
        SetWindowLongW(hwnd, GWL_WNDPROC, OLD_PROC[0] as i32);
        say!(
            "UnregisterFlashWindowClass while the window exists -> {}",
            (fpc.UnregisterFlashWindowClass)()
        );
        DestroyWindow(hwnd);
        say!(
            "window destroyed; IShockwaveFlash Release -> {}",
            vcall!(flash, 2, fn() -> u32,)
        );
        say!(
            "UnregisterFlashWindowClass -> {}",
            (fpc.UnregisterFlashWindowClass)()
        );
        DestroyWindow(owner);
    }
}

fn two(fpc: &Fpc, file: &str, url: &str, out: &str) {
    let _ = std::fs::create_dir_all(out);
    (fpc.RegisterFlashWindowClass)();
    let owner = create_owner(100, 100, 1000, 700);
    let a = create_flash(fpc, owner, 110, 170, 480, 356, 1);
    let b = create_flash(fpc, owner, 610, 170, 480, 356, 2);
    let fa = query_flash(a);
    let fb = query_flash(b);
    let sa = new_sink("file-window");
    let sb = new_sink("http-window");
    advise(fa, &sa);
    advise(fb, &sb);
    let wa = wide(file);
    let wb = wide(url);
    let start = Instant::now();
    say!(
        "FPC_LoadMovieW(file) -> {:#x}",
        (fpc.FPC_LoadMovieW)(a, 0, wa.as_ptr())
    );
    say!(
        "FPC_LoadMovieW({url}) -> {:#x}",
        (fpc.FPC_LoadMovieW)(b, 0, wb.as_ptr())
    );
    (fpc.FPC_Play)(a);
    (fpc.FPC_Play)(b);
    let mut shot = false;
    while start.elapsed() < Duration::from_secs(15) {
        pump_for(Duration::from_millis(100));
        if !shot && start.elapsed() > Duration::from_millis(2500) {
            shot = true;
            screenshot(owner, &format!("{out}\\screen-two.png"));
        }
        if sa.anim_end_at.get().is_some()
            && sb.anim_end_at.get().is_some()
            && !is_playing(fpc, a)
            && !is_playing(fpc, b)
        {
            break;
        }
    }
    for (n, s, h) in [("file", &sa, a), ("http", &sb, b)] {
        say!(
            "summary {n}: ready {:?}, fscommands {:?}, animEnd at {:?}, IsPlaying now {}",
            s.ready.borrow(),
            s.fscommands.borrow(),
            s.anim_end_at.get(),
            is_playing(fpc, h)
        );
    }
    unsafe {
        DestroyWindow(a);
        DestroyWindow(b);
        DestroyWindow(owner);
    }
    say!(
        "UnregisterFlashWindowClass -> {}",
        (fpc.UnregisterFlashWindowClass)()
    );
}

fn typelib_check() {
    unsafe {
        let mut lib: Unk = null_mut();
        let hr = LoadRegTypeLib(&LIBID, 1, 0, 0, (&mut lib as *mut Unk).cast());
        say!("LoadRegTypeLib(LIBID, 1, 0) -> {hr:#x}");
        if hr < 0 {
            return;
        }
        for (label, iid) in [
            ("_IShockwaveFlashEvents", DIID_EVENTS),
            ("IShockwaveFlash", IID_ISHOCKWAVEFLASH),
        ] {
            let mut ti: Unk = null_mut();
            let hr = vcall!(lib, 6, fn(*const GUID, *mut Unk) -> HRESULT, &iid, &mut ti);
            say!("GetTypeInfoOfGuid({label}) -> {hr:#x}");
            if hr < 0 {
                continue;
            }
            let mut attr: *mut TYPEATTR = null_mut();
            vcall!(ti, 3, fn(*mut *mut TYPEATTR) -> HRESULT, &mut attr);
            let (n, kind) = ((*attr).cFuncs, (*attr).typekind);
            vcall!(ti, 19, fn(*mut TYPEATTR) -> (), attr);
            say!("  typekind {kind}, {n} functions");
            if label.starts_with('_') {
                for i in 0..n as u32 {
                    let mut fd: *mut FUNCDESC = null_mut();
                    vcall!(ti, 5, fn(u32, *mut *mut FUNCDESC) -> HRESULT, i, &mut fd);
                    let f = &*fd;
                    let mut names = [null::<u16>(); 4];
                    let mut got = 0u32;
                    vcall!(
                        ti,
                        7,
                        fn(i32, *mut *const u16, u32, *mut u32) -> HRESULT,
                        f.memid,
                        names.as_mut_ptr(),
                        4,
                        &mut got
                    );
                    let names: Vec<String> =
                        names[..got as usize].iter().map(|b| bstr_str(*b)).collect();
                    let vts: Vec<u16> = (0..f.cParams as usize)
                        .map(|p| (*f.lprgelemdescParam.add(p)).tdesc.vt)
                        .collect();
                    say!(
                        "  DISPID {} ({:#x}) {}({}) param VTs {vts:?}",
                        f.memid,
                        f.memid,
                        names[0],
                        names[1..].join(", ")
                    );
                    vcall!(ti, 20, fn(*mut FUNCDESC) -> (), fd);
                }
            }
            vcall!(ti, 2, fn() -> u32,);
        }
        vcall!(lib, 2, fn() -> u32,);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    t0();
    if args[1] == "dumpstacks" {
        stacks::dump(
            args[2].parse().unwrap(),
            args.get(3).map_or("", |s| s.as_str()),
        );
        return;
    }
    say!("pid {}", std::process::id());
    unsafe { OleInitialize(null_mut()) };
    let fpc: &'static Fpc = Box::leak(Box::new(load_dll(&args[1])));
    match args[2].as_str() {
        "play" => play(fpc, &args[3], &args[4]),
        "two" => two(fpc, &args[3], &args[4], &args[5]),
        "reg" => say!("DllRegisterServer -> {:#x}", (fpc.DllRegisterServer)()),
        "unreg" => say!("DllUnregisterServer -> {:#x}", (fpc.DllUnregisterServer)()),
        "check" => typelib_check(),
        // avatars <base-url> <out> <mta|none|sta|mixed> <concurrency> <rounds> <spawn|pool> <tzer.swf|-> <names...>
        "avatars" => {
            let plan = avatar::Plan {
                base_url: args[3].clone(),
                out: args[4].clone(),
                apt: args[5].clone(),
                concurrency: args[6].parse().unwrap(),
                rounds: args[7].parse().unwrap(),
                pool: args[8] == "pool",
                tzer: (args[9] != "-").then(|| args[9].clone()),
                names: args[10..].to_vec(),
            };
            let ok = avatar::run_all(fpc, plan);
            std::process::exit(if ok { 0 } else { 1 });
        }
        // ShockwaveFlash ActiveX control: registration under a test root.
        "axreg" => {
            let ok = axhost::registration(fpc);
            std::process::exit(if ok { 0 } else { 1 });
        }
        // ax <base dir|url> <out> <names...>: windowless container + ATL host.
        "ax" => {
            axhost::register_class(&args[1]);
            let names = args[5..].to_vec();
            let r = axhost::avatars_emotions(&args[3], &args[4], &names);
            let atl = axhost::atl_host(&args[3], &args[4], &names[..names.len().min(3)]);
            say!("result: container ok {}, ATL host ok {atl}", r.ok);
            std::process::exit(if r.ok && atl { 0 } else { 1 });
        }
        m => panic!("unknown mode {m}"),
    }
}
