//! State of one "FlashPlayerControl" window and its window procedure.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    E_FAIL, E_INVALIDARG, E_POINTER, HWND, LPARAM, LRESULT, POINT, RECT, S_OK, SIZE, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{AC_SRC_ALPHA, AC_SRC_OVER, BLENDFUNCTION};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
    DeleteDC, DeleteObject, HBITMAP, HDC, SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DefWindowProcW, GetClientRect, KillTimer, PostMessageW, SetTimer, ULW_ALPHA,
    UpdateLayeredWindow, WM_NCCREATE, WM_NCDESTROY, WM_SIZE, WM_TIMER,
};
use windows_sys::core::HRESULT;

use crate::com::FlashObject;
use crate::log;
use crate::movie::{Frame, FsQueue, Movie};

/// Messages the client sends to the window.
pub const MSG_QUERY_INTERFACE: u32 = 0x1401;
pub const MSG_SNAPSHOT: u32 = 0x1404;
pub const MSG_ENABLE_MENU: u32 = 0x1405;
/// Private: a background load finished (wParam = load generation).
const MSG_LOADED: u32 = 0x8000 + 0x0F11; // WM_APP + 0xF11
/// Private, for the test host: lParam -> [u64; 3] audio counters.
pub const MSG_AUDIO_STATS: u32 = 0x8000 + 0x0F12;

const TICK_TIMER: usize = 0x46505431; // "FPT1", distinct from the client's 0x25D
const TICK_MS: u32 = 10;

pub type Listener = unsafe extern "system" fn(HWND, LPARAM, *mut c_void);

pub struct Instance {
    pub hwnd: HWND,
    pub com: *mut FlashObject,
    pub listener: Cell<Option<(Listener, LPARAM)>>,
    pub ready_state: Cell<i32>,
    pub url: RefCell<String>,
    movie: RefCell<Option<Movie>>,
    load_gen: Cell<u32>,
    want_play: Cell<bool>,
    ended: Cell<bool>,
    destroyed: Cell<bool>,
    last_tick: Cell<Option<Instant>>,
    fs: FsQueue,
    surface: RefCell<Option<Surface>>,
}

thread_local! {
    static INSTANCES: RefCell<HashMap<usize, Rc<Instance>>> = RefCell::new(HashMap::new());
}

/// Finished background loads, keyed by (window, generation).
static LOADS: Mutex<Vec<(usize, u32, Result<Vec<u8>, String>)>> = Mutex::new(Vec::new());

pub fn get(hwnd: HWND) -> Option<Rc<Instance>> {
    if hwnd.is_null() {
        return None;
    }
    INSTANCES.with(|m| m.borrow().get(&(hwnd as usize)).cloned())
}

/// A DIB section the frames are copied into for UpdateLayeredWindow.
struct Surface {
    dc: HDC,
    bitmap: HBITMAP,
    old: *mut c_void,
    bits: *mut u8,
    width: u32,
    height: u32,
}

impl Surface {
    fn new(width: u32, height: u32) -> Option<Surface> {
        let (bitmap, bits) = new_dib(width, height)?;
        let dc = unsafe { CreateCompatibleDC(null_mut()) };
        let old = unsafe { SelectObject(dc, bitmap) };
        Some(Surface {
            dc,
            bitmap,
            old,
            bits,
            width,
            height,
        })
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        unsafe {
            SelectObject(self.dc, self.old);
            DeleteObject(self.bitmap);
            DeleteDC(self.dc);
        }
    }
}

/// A 32bpp top-down DIB section.
fn new_dib(width: u32, height: u32) -> Option<(HBITMAP, *mut u8)> {
    let mut info: BITMAPINFO = unsafe { std::mem::zeroed() };
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: width as i32,
        biHeight: -(height as i32),
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        ..unsafe { std::mem::zeroed() }
    };
    let mut bits: *mut c_void = null_mut();
    let bmp =
        unsafe { CreateDIBSection(null_mut(), &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0) };
    if bmp.is_null() || bits.is_null() {
        None
    } else {
        Some((bmp, bits.cast()))
    }
}

fn client_size(hwnd: HWND) -> (u32, u32) {
    let mut r = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe { GetClientRect(hwnd, &mut r) };
    (
        (r.right - r.left).max(0) as u32,
        (r.bottom - r.top).max(0) as u32,
    )
}

impl Instance {
    fn new(hwnd: HWND) -> Instance {
        Instance {
            hwnd,
            com: FlashObject::create(hwnd),
            listener: Cell::new(None),
            ready_state: Cell::new(0),
            url: RefCell::new(String::new()),
            movie: RefCell::new(None),
            load_gen: Cell::new(0),
            want_play: Cell::new(true),
            ended: Cell::new(false),
            destroyed: Cell::new(false),
            last_tick: Cell::new(None),
            fs: Rc::new(RefCell::new(VecDeque::new())),
            surface: RefCell::new(None),
        }
    }

    fn com(&self) -> &FlashObject {
        unsafe { &*self.com }
    }

    pub fn total_frames(&self) -> i32 {
        self.movie
            .borrow()
            .as_ref()
            .map_or(0, |m| m.total_frames as i32)
    }

    /// 0-based, like Flash's CurrentFrame.
    pub fn current_frame(&self) -> i32 {
        self.movie
            .borrow()
            .as_ref()
            .map_or(0, |m| (m.root_state().0 as i32 - 1).max(0))
    }

    pub fn is_playing(&self) -> bool {
        let movie = self.movie.borrow();
        let Some(m) = movie.as_ref() else {
            return false;
        };
        !self.ended.get() && m.running() && m.root_state().1
    }

    /// Starts loading `url` (http(s) URL, file: URL or local path).
    pub fn load(&self, url: &str) -> HRESULT {
        if url.is_empty() {
            return E_INVALIDARG;
        }
        log(&format!("load {url}"));
        let generation = self.load_gen.get().wrapping_add(1);
        self.load_gen.set(generation);
        self.movie.borrow_mut().take();
        self.fs.borrow_mut().clear();
        *self.url.borrow_mut() = url.to_owned();
        self.ready_state.set(1);
        self.ended.set(false);
        self.want_play.set(true);
        let hwnd = self.hwnd as usize;
        let url = url.to_owned();
        std::thread::spawn(move || {
            let result = crate::fetch::fetch(&url);
            if let Err(e) = &result {
                log(&format!("load failed: {url}: {e}"));
            }
            LOADS.lock().unwrap().push((hwnd, generation, result));
            unsafe { PostMessageW(hwnd as HWND, MSG_LOADED, generation as usize, 0) };
        });
        S_OK
    }

    fn on_loaded(&self, generation: u32) {
        let result = {
            let mut loads = LOADS.lock().unwrap();
            let pos = loads
                .iter()
                .position(|(h, g, _)| *h == self.hwnd as usize && *g == generation);
            pos.map(|p| loads.remove(p).2)
        };
        let Some(result) = result else { return };
        if generation != self.load_gen.get() {
            return; // superseded by a newer load
        }
        let data = match result {
            Ok(d) => d,
            Err(_) => return,
        };
        let url = crate::fetch::movie_url(&self.url.borrow());
        let (w, h) = client_size(self.hwnd);
        let movie = match Movie::new(&data, &url, w, h, self.fs.clone()) {
            Ok(m) => m,
            Err(e) => {
                log(&format!("cannot play {url}: {e}"));
                return;
            }
        };
        log(&format!(
            "loaded {url}: {} frames at {} fps, {}x{}",
            movie.total_frames, movie.frame_rate, movie.width, movie.height
        ));
        if !self.want_play.get() {
            movie.pause();
        }
        *self.movie.borrow_mut() = Some(movie);
        self.last_tick.set(None);
        unsafe { SetTimer(self.hwnd, TICK_TIMER, TICK_MS, None) };
        self.present();

        self.ready_state.set(3);
        self.com().fire_ready_state(3);
        if self.destroyed.get() || generation != self.load_gen.get() {
            return;
        }
        self.ready_state.set(4);
        self.com().fire_ready_state(4);
    }

    pub fn play(&self) -> HRESULT {
        self.want_play.set(true);
        self.ended.set(false);
        if let Some(m) = self.movie.borrow().as_ref() {
            let (frame, _) = m.root_state();
            if m.total_frames > 1 && frame >= m.total_frames {
                // Like Flash: playing from the last frame starts over.
                m.goto_frame(1);
            }
            m.play();
        }
        self.last_tick.set(None);
        S_OK
    }

    /// Flash's Stop: stop and rewind to the first frame.
    pub fn stop(&self) -> HRESULT {
        self.want_play.set(false);
        if let Some(m) = self.movie.borrow().as_ref() {
            m.pause();
            m.goto_frame(1);
        }
        self.present();
        S_OK
    }

    /// Flash's StopPlay: pause where we are.
    pub fn stop_play(&self) -> HRESULT {
        self.want_play.set(false);
        if let Some(m) = self.movie.borrow().as_ref() {
            m.pause();
        }
        S_OK
    }

    /// Flash's GotoFrame: `frame` is 0-based; the movie stops there.
    pub fn goto_frame(&self, frame: i32) -> HRESULT {
        if let Some(m) = self.movie.borrow().as_ref() {
            m.goto_frame((frame.max(0) + 1).min(u16::MAX as i32) as u16);
        } else {
            return E_FAIL;
        }
        self.present();
        S_OK
    }

    /// Renders the current frame and puts it on the layered window.
    pub fn present(&self) {
        if self.destroyed.get() {
            return;
        }
        let (w, h) = client_size(self.hwnd);
        if w == 0 || h == 0 {
            return;
        }
        let frame = {
            let mut movie = self.movie.borrow_mut();
            let Some(m) = movie.as_mut() else { return };
            m.resize(w, h);
            m.render()
        };
        if let Some(f) = frame {
            self.show(&f);
        }
    }

    fn show(&self, f: &Frame) {
        let mut surface = self.surface.borrow_mut();
        if surface
            .as_ref()
            .is_none_or(|s| s.width != f.width || s.height != f.height)
        {
            *surface = None;
            *surface = Surface::new(f.width, f.height);
        }
        let Some(s) = surface.as_ref() else { return };
        unsafe {
            std::ptr::copy_nonoverlapping(f.pixels.as_ptr(), s.bits, f.pixels.len());
            let size = SIZE {
                cx: f.width as i32,
                cy: f.height as i32,
            };
            let origin = POINT { x: 0, y: 0 };
            let blend = BLENDFUNCTION {
                BlendOp: AC_SRC_OVER as u8,
                BlendFlags: 0,
                SourceConstantAlpha: 255,
                AlphaFormat: AC_SRC_ALPHA as u8,
            };
            UpdateLayeredWindow(
                self.hwnd,
                null_mut(),
                std::ptr::null(),
                &size,
                s.dc,
                &origin,
                0,
                &blend,
                ULW_ALPHA,
            );
        }
    }

    /// Message 0x1404: a new 32bpp top-down DIB of the current frame.
    fn snapshot(&self) -> HBITMAP {
        let (w, h) = client_size(self.hwnd);
        let frame = {
            let mut movie = self.movie.borrow_mut();
            let Some(m) = movie.as_mut() else {
                return null_mut();
            };
            m.resize(w, h);
            m.render()
        };
        let Some(f) = frame else { return null_mut() };
        let Some((bmp, bits)) = new_dib(f.width, f.height) else {
            return null_mut();
        };
        unsafe { std::ptr::copy_nonoverlapping(f.pixels.as_ptr(), bits, f.pixels.len()) };
        bmp
    }

    fn tick(&self) {
        let now = Instant::now();
        let dt = self
            .last_tick
            .replace(Some(now))
            .map_or(Duration::ZERO, |t| now - t);
        let changed = {
            let movie = self.movie.borrow();
            let Some(m) = movie.as_ref() else { return };
            let changed = m.tick(dt);
            // The root timeline reached its last frame: a tZer is a one-shot,
            // so stop there instead of looping (Flash with Loop=false).
            let (frame, playing) = m.root_state();
            if playing && m.total_frames > 1 && frame >= m.total_frames {
                m.stop_root();
            }
            if !self.ended.get()
                && m.total_frames > 0
                && frame >= m.total_frames
                && !m.root_state().1
            {
                self.ended.set(true);
                log(&format!("movie ended on frame {frame}"));
            }
            changed
        };
        if changed {
            self.present();
        }
        self.deliver_fscommands();
    }

    fn deliver_fscommands(&self) {
        loop {
            let next = self.fs.borrow_mut().pop_front();
            let Some((cmd, args)) = next else { break };
            log(&format!("fscommand {cmd:?} {args:?}"));
            if cmd.eq_ignore_ascii_case("animEnd") {
                self.ended.set(true);
            }
            self.com().fire_fscommand(&cmd, &args);
            if self.destroyed.get() {
                break;
            }
        }
    }

    fn destroy(&self) {
        self.destroyed.set(true);
        unsafe { KillTimer(self.hwnd, TICK_TIMER) };
        self.load_gen.set(self.load_gen.get().wrapping_add(1));
        self.movie.borrow_mut().take();
        self.surface.borrow_mut().take();
        let com = self.com();
        com.hwnd.set(null_mut());
        com.drop_sink();
        unsafe { FlashObject::release(self.com) };
    }
}

/// The window procedure of class "FlashPlayerControl".
pub unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let r = std::panic::catch_unwind(|| unsafe { handle(hwnd, msg, wp, lp) });
    match r {
        Ok(Some(v)) => v,
        Ok(None) => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
        Err(_) => {
            log(&format!("panic handling message {msg:#x}"));
            0
        }
    }
}

unsafe fn handle(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> Option<LRESULT> {
    match msg {
        WM_NCCREATE => {
            let inst = Rc::new(Instance::new(hwnd));
            INSTANCES.with(|m| m.borrow_mut().insert(hwnd as usize, inst));
            None
        }
        WM_NCDESTROY => {
            let inst = INSTANCES.with(|m| m.borrow_mut().remove(&(hwnd as usize)));
            if let Some(i) = inst {
                i.destroy();
            }
            None
        }
        WM_TIMER if wp == TICK_TIMER => {
            if let Some(i) = get(hwnd) {
                i.tick();
            }
            Some(0)
        }
        WM_SIZE => {
            if let Some(i) = get(hwnd) {
                i.present();
            }
            None
        }
        MSG_LOADED => {
            if let Some(i) = get(hwnd) {
                i.on_loaded(wp as u32);
            }
            Some(0)
        }
        MSG_QUERY_INTERFACE => {
            #[repr(C)]
            struct Query {
                iid: windows_sys::core::GUID,
                pv: *mut c_void,
                hr: HRESULT,
            }
            let q = lp as *mut Query;
            if q.is_null() {
                return Some(E_POINTER as LRESULT);
            }
            let hr = match get(hwnd) {
                Some(i) => unsafe { i.com().query(&(*q).iid, &mut (*q).pv) },
                None => E_FAIL,
            };
            unsafe { (*q).hr = hr };
            Some(hr as LRESULT)
        }
        MSG_SNAPSHOT => {
            let out = lp as *mut HBITMAP;
            let bmp = get(hwnd).map_or(null_mut(), |i| i.snapshot());
            if !out.is_null() {
                unsafe { *out = bmp };
            }
            Some(!bmp.is_null() as LRESULT)
        }
        MSG_ENABLE_MENU => Some(0),
        MSG_AUDIO_STATS => {
            use std::sync::atomic::Ordering::Relaxed;
            let out = lp as *mut [u64; 3];
            if !out.is_null() {
                unsafe {
                    *out = [
                        crate::audio::STREAMS_STARTED.load(Relaxed),
                        crate::audio::SAMPLES_MIXED.load(Relaxed),
                        crate::audio::SAMPLES_AUDIBLE.load(Relaxed),
                    ]
                };
            }
            Some(1)
        }
        _ => None,
    }
}
