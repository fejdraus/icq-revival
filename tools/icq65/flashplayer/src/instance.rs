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
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DefWindowProcW, GetClientRect, KillTimer, PostMessageW, SetTimer, ULW_ALPHA,
    UpdateLayeredWindow, WM_NCCREATE, WM_NCDESTROY, WM_SIZE, WM_TIMER,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GW_OWNER, GetParent, GetWindow};
use windows_sys::core::HRESULT;

const RPC_E_WRONG_THREAD: HRESULT = 0x8001010Eu32 as i32;

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
/// The ActiveX control's repaint-retry timer on the same hidden window.
pub const CONTROL_TIMER: usize = 0x46505432; // "FPT2"
/// A Flash avatar's face goes back to its status face (face.rs).
const FACE_TIMER: usize = 0x46505433; // "FPT3"
const TICK_MS: u32 = 10;
/// How long the root timeline has to stand on its last frame before a movie
/// without animEnd counts as finished, so a nested clip there can finish.
/// A root stopped anywhere else is waiting for a nested clip to move it on
/// (three of the tZers do that): the movie still plays.
const END_GRACE: Duration = Duration::from_millis(250);

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
    /// A movie is being fetched or parsed.
    loading: Cell<bool>,
    /// Since when the root timeline has stood on its last frame.
    idle_since: Cell<Option<Instant>>,
    destroyed: Cell<bool>,
    last_tick: Cell<Option<Instant>>,
    fs: FsQueue,
    surface: RefCell<Option<Surface>>,
    /// Created without owner or parent: the client's offscreen snapshot
    /// service (Flash avatars). Its movies play without sound.
    muted: Cell<bool>,
    /// Part of the ShockwaveFlash ActiveX control (control.rs) instead of a
    /// layered FlashPlayerControl window: frames are kept for
    /// IViewObject::Draw, the size comes from the host, and movies loop.
    control: Cell<bool>,
    /// The host's size in pixels (control mode).
    size: Cell<(u32, u32)>,
    /// WMode/Scale for the next movie.
    pub display: Cell<crate::movie::Display>,
    /// The last rendered frame (control mode).
    pub frame: RefCell<Option<Rc<Frame>>>,
    /// Called after a new frame was rendered (control mode).
    pub on_frame: RefCell<Option<Box<dyn Fn()>>>,
    /// Called on CONTROL_TIMER (control mode).
    pub on_control_timer: RefCell<Option<Box<dyn Fn()>>>,
    /// Counts frames rendered in control mode; the control compares it with
    /// the last frame the host drew.
    pub frame_serial: Cell<u64>,
    /// The faces a Flash avatar was told to show (face.rs).
    faces: crate::face::Faces,
    /// SetVariable calls made while the movie was still loading, applied
    /// once its first frame has run (the last value per variable).
    pending_vars: RefCell<Vec<(String, String)>>,
    /// The devil face's start state has been checked (see `init_devil_face`).
    face_checked: Cell<bool>,
}

/// The windows of one thread. Each window lives on the thread that created
/// it; every export and message for it runs there.
struct Registry(RefCell<HashMap<usize, Rc<Instance>>>);

impl Drop for Registry {
    /// Runs from the DLL's TLS callback when a thread exits, under the loader
    /// lock. Windows still registered here (not destroyed before the thread
    /// ended) are leaked: dropping a player tears down GPU and audio objects,
    /// which must not happen under the loader lock.
    fn drop(&mut self) {
        for (_, inst) in self.0.get_mut().drain() {
            std::mem::forget(inst);
        }
    }
}

thread_local! {
    static INSTANCES: Registry = Registry(RefCell::new(HashMap::new()));
}

/// Which thread owns each window, to tell "wrong thread" from "not ours".
static OWNERS: Mutex<Vec<(usize, u32)>> = Mutex::new(Vec::new());

/// Finished background loads, keyed by (window, generation).
/// The result is the movie and the URL it came from (see `fetch::fetch_movie`).
#[allow(clippy::type_complexity)]
static LOADS: Mutex<Vec<(usize, u32, Result<(Vec<u8>, String), String>)>> = Mutex::new(Vec::new());

pub fn get(hwnd: HWND) -> Option<Rc<Instance>> {
    if hwnd.is_null() {
        return None;
    }
    INSTANCES.with(|m| m.0.borrow().get(&(hwnd as usize)).cloned())
}

/// Like `get`, but says why a window has no instance on this thread.
pub fn lookup(hwnd: HWND) -> Result<Rc<Instance>, HRESULT> {
    if let Some(i) = get(hwnd) {
        return Ok(i);
    }
    let owner = OWNERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(h, _)| *h == hwnd as usize)
        .map(|(_, t)| *t);
    match owner {
        Some(t) => {
            log(&format!(
                "window {hwnd:?} belongs to thread {t}, called from thread {}",
                unsafe { GetCurrentThreadId() }
            ));
            Err(RPC_E_WRONG_THREAD)
        }
        None => Err(E_INVALIDARG),
    }
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
pub(crate) fn new_dib(width: u32, height: u32) -> Option<(HBITMAP, *mut u8)> {
    new_dib_rows(width, height, true)
}

/// A 32bpp DIB section, its rows top-down or, as Windows has them by
/// default, bottom-up.
fn new_dib_rows(width: u32, height: u32, top_down: bool) -> Option<(HBITMAP, *mut u8)> {
    let mut info: BITMAPINFO = unsafe { std::mem::zeroed() };
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: width as i32,
        biHeight: if top_down {
            -(height as i32)
        } else {
            height as i32
        },
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
            loading: Cell::new(false),
            idle_since: Cell::new(None),
            destroyed: Cell::new(false),
            last_tick: Cell::new(None),
            fs: Rc::new(RefCell::new(VecDeque::new())),
            surface: RefCell::new(None),
            muted: Cell::new(unsafe {
                GetWindow(hwnd, GW_OWNER).is_null() && GetParent(hwnd).is_null()
            }),
            control: Cell::new(false),
            size: Cell::new((0, 0)),
            display: Cell::new(crate::movie::Display::default()),
            frame: RefCell::new(None),
            on_frame: RefCell::new(None),
            on_control_timer: RefCell::new(None),
            frame_serial: Cell::new(0),
            faces: crate::face::Faces::default(),
            pending_vars: RefCell::new(Vec::new()),
            face_checked: Cell::new(false),
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

    /// Flash's IsPlaying as the client relies on it for a tZer: true from
    /// Play (also while the movie still loads) until the movie has ended -
    /// animEnd, or the root timeline stopped on its last frame (see `tick`) -
    /// and false at once after Stop, StopPlay or GotoFrame. A root timeline
    /// stopped mid-movie while a nested clip plays is still playing.
    pub fn is_playing(&self) -> bool {
        if !self.want_play.get() || self.ended.get() {
            return false;
        }
        if self.loading.get() {
            return true;
        }
        self.movie.borrow().as_ref().is_some_and(|m| m.running())
    }

    /// Starts loading `url` (http(s) URL, file: URL or local path).
    pub fn load(&self, url: &str) -> HRESULT {
        if url.is_empty() {
            return E_INVALIDARG;
        }
        log(&format!("load {url}"));
        let generation = self.load_gen.get().wrapping_add(1);
        self.load_gen.set(generation);
        let old = self.movie.borrow_mut().take();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(old))).is_err() {
            log("releasing a player failed");
        }
        self.fs.borrow_mut().clear();
        self.faces.reset();
        self.pending_vars.borrow_mut().clear();
        self.face_checked.set(false);
        unsafe { KillTimer(self.hwnd, FACE_TIMER) };
        *self.url.borrow_mut() = url.to_owned();
        self.ready_state.set(1);
        self.ended.set(false);
        self.want_play.set(true);
        self.loading.set(true);
        self.idle_since.set(None);
        let hwnd = self.hwnd as usize;
        let url = url.to_owned();
        // Fetch, and wait for the graphics device and sound output, on a
        // background thread; the window's thread only builds the player.
        let spawned = std::thread::Builder::new()
            .name("FlashPlayerControl load".into())
            .spawn(move || {
                crate::install_panic_hook();
                let result = std::panic::catch_unwind(|| {
                    let mut result = crate::fetch::fetch_movie(&url);
                    if result.is_ok() {
                        if let Err(e) = crate::gpu::wait(Duration::from_secs(60)) {
                            result = Err(e);
                        }
                        crate::audio::wait(Duration::from_secs(10));
                    }
                    result
                })
                .unwrap_or_else(|_| Err("panic while loading".into()));
                if let Err(e) = &result {
                    log(&format!("load failed: {url}: {e}"));
                }
                LOADS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((hwnd, generation, result));
                unsafe { PostMessageW(hwnd as HWND, MSG_LOADED, generation as usize, 0) };
            });
        if spawned.is_err() {
            self.loading.set(false);
            self.ended.set(true);
            return E_FAIL;
        }
        S_OK
    }

    fn on_loaded_inner(&self, generation: u32) {
        let result = {
            let mut loads = LOADS.lock().unwrap_or_else(|e| e.into_inner());
            let pos = loads
                .iter()
                .position(|(h, g, _)| *h == self.hwnd as usize && *g == generation);
            pos.map(|p| loads.remove(p).2)
        };
        let Some(result) = result else { return };
        if generation != self.load_gen.get() {
            return; // superseded by a newer load
        }
        // Loaded or failed: a movie that cannot be had has ended.
        self.loading.set(false);
        let (data, from) = match result {
            Ok(d) => d,
            Err(_) => {
                self.ended.set(true);
                return;
            }
        };
        let url = crate::fetch::movie_url(&from);
        let (w, h) = self.size();
        let movie = match Movie::new(
            &data,
            &url,
            w,
            h,
            self.fs.clone(),
            self.muted.get(),
            self.display.get(),
        ) {
            Ok(m) => m,
            Err(e) => {
                log(&format!("cannot play {url}: {e}"));
                self.ended.set(true);
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

    fn play_inner(&self) -> HRESULT {
        self.want_play.set(true);
        self.ended.set(false);
        self.idle_since.set(None);
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
    fn stop_inner(&self) -> HRESULT {
        self.want_play.set(false);
        if let Some(m) = self.movie.borrow().as_ref() {
            m.pause();
            m.goto_frame(1);
        }
        self.present();
        S_OK
    }

    /// Flash's StopPlay: pause where we are.
    fn stop_play_inner(&self) -> HRESULT {
        self.want_play.set(false);
        if let Some(m) = self.movie.borrow().as_ref() {
            m.pause();
        }
        S_OK
    }

    /// Flash's GotoFrame: `frame` is 0-based; the movie stops there.
    fn goto_frame_inner(&self, frame: i32) -> HRESULT {
        if let Some(m) = self.movie.borrow().as_ref() {
            self.want_play.set(false);
            m.goto_frame((frame.max(0) + 1).min(u16::MAX as i32) as u16);
        } else {
            return E_FAIL;
        }
        self.present();
        S_OK
    }

    /// Renders the current frame and puts it on the layered window.
    fn present_inner(&self) {
        if self.destroyed.get() {
            return;
        }
        let (w, h) = self.size();
        if w == 0 || h == 0 {
            return;
        }
        let frame = {
            let mut movie = self.movie.borrow_mut();
            let Some(m) = movie.as_mut() else { return };
            m.resize(w, h);
            m.render()
        };
        let Some(f) = frame else { return };
        if self.control.get() {
            *self.frame.borrow_mut() = Some(Rc::new(f));
            self.frame_serial.set(self.frame_serial.get() + 1);
            let notify = self.on_frame.borrow();
            if let Some(cb) = notify.as_ref() {
                cb();
            }
        } else {
            self.show(&f);
        }
    }

    /// The size to render at: the host's (control) or the window's client area.
    fn size(&self) -> (u32, u32) {
        if self.control.get() {
            self.size.get()
        } else {
            client_size(self.hwnd)
        }
    }

    /// Makes this the engine of a ShockwaveFlash ActiveX control.
    pub fn set_control_mode(&self) {
        self.control.set(true);
        self.muted.set(false);
    }

    /// The host's new size in pixels (control mode); re-renders.
    pub fn set_size(&self, w: u32, h: u32) {
        if self.size.get() != (w, h) {
            self.size.set((w, h));
            self.present();
        }
    }

    /// The current picture rendered at exactly `w`x`h` (control mode): the
    /// last frame if it has that size, else a fresh render at that size,
    /// which also becomes the size later frames are rendered at. None when
    /// there is no movie or rendering failed.
    pub fn frame_at(&self, w: u32, h: u32) -> Option<Rc<Frame>> {
        if let Some(f) = self.frame.borrow().as_ref() {
            if f.width == w && f.height == h {
                return Some(f.clone());
            }
        }
        self.size.set((w, h));
        self.present();
        let f = self.frame.borrow().clone();
        f.filter(|f| f.width == w && f.height == h)
    }

    /// New WMode/Scale; applies to the loaded movie too.
    pub fn set_display(&self, d: crate::movie::Display) {
        self.display.set(d);
        let applied = self.guarded("display", false, || {
            let movie = self.movie.borrow();
            let Some(m) = movie.as_ref() else {
                return false;
            };
            m.set_display(d);
            true
        });
        if applied {
            self.present();
        }
    }

    /// Runs `f` on the loaded movie (guarded); None without a movie.
    fn with_movie<R>(&self, what: &str, f: impl FnOnce(&Movie) -> R) -> Option<R> {
        let r = self.guarded(what, None, || {
            let movie = self.movie.borrow();
            movie.as_ref().map(f)
        });
        // Variables and gotos change the picture: show it now.
        if r.is_some() {
            self.present();
        }
        r
    }

    pub fn set_variable(&self, path: &str, value: &str) -> HRESULT {
        // ICQ 7.2 sets the face right after the Movie, while the movie still
        // loads: keep it for the movie (Flash queues such calls as well).
        let waiting = self.loading.get()
            || self
                .movie
                .borrow()
                .as_ref()
                .is_some_and(|m| m.root_state().0 < 1);
        let hr = if waiting {
            let mut q = self.pending_vars.borrow_mut();
            q.retain(|(p, _)| p != path);
            q.push((path.to_owned(), value.to_owned()));
            log(&format!(
                "SetVariable({path:?}, {value:?}) -> 0x0 (kept until the movie has loaded)"
            ));
            S_OK
        } else {
            let hr = match self.with_movie("SetVariable", |m| m.set_variable(path, value)) {
                Some(true) => S_OK,
                _ => E_FAIL,
            };
            log(&format!("SetVariable({path:?}, {value:?}) -> {hr:#x}"));
            hr
        };
        let delay = crate::face::delay_ms();
        match self.faces.on_set(path, value, Instant::now(), delay) {
            crate::face::Action::Arm(ms) => {
                unsafe { SetTimer(self.hwnd, FACE_TIMER, ms, None) };
            }
            crate::face::Action::Cancel => {
                unsafe { KillTimer(self.hwnd, FACE_TIMER) };
            }
            crate::face::Action::None => {}
        }
        hr
    }

    /// FACE_TIMER: the smiley's face has been shown long enough.
    fn face_timer(&self) {
        unsafe { KillTimer(self.hwnd, FACE_TIMER) };
        if let Some(face) = self.faces.take_return() {
            log(&format!("face returns to {face:?}"));
            self.set_variable(crate::face::VARIABLE, &face);
        }
    }

    pub fn get_variable(&self, path: &str) -> Option<String> {
        self.with_movie("GetVariable", |m| m.get_variable(path))
            .flatten()
    }

    pub fn t_goto_label(&self, target: &str, label: &str) -> HRESULT {
        let hr = match self.with_movie("TGotoLabel", |m| m.t_goto_label(target, label)) {
            Some(true) => S_OK,
            _ => E_FAIL,
        };
        log(&format!("TGotoLabel({target:?}, {label:?}) -> {hr:#x}"));
        hr
    }

    pub fn t_goto_frame(&self, target: &str, frame: i32) -> HRESULT {
        let frame = frame.clamp(0, u16::MAX as i32) as u16;
        match self.with_movie("TGotoFrame", |m| m.t_goto_frame(target, frame)) {
            Some(true) => S_OK,
            _ => E_FAIL,
        }
    }

    pub fn t_play(&self, target: &str, play: bool) -> HRESULT {
        match self.with_movie("TPlay", |m| m.t_play(target, play)) {
            Some(true) => S_OK,
            _ => E_FAIL,
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

    /// Message 0x1404: a new 32bpp DIB of the current frame. Bottom-up, the
    /// Windows default: ICQ's image class reads the bits in that order and
    /// showed a top-down frame upside down in the contact list.
    fn snapshot_inner(&self) -> HBITMAP {
        let (w, h) = self.size();
        let frame = {
            let mut movie = self.movie.borrow_mut();
            let Some(m) = movie.as_mut() else {
                return null_mut();
            };
            m.resize(w, h);
            m.render()
        };
        let Some(f) = frame else { return null_mut() };
        let Some((bmp, bits)) = new_dib_rows(f.width, f.height, false) else {
            return null_mut();
        };
        let stride = f.width as usize * 4;
        let rows = f.height as usize;
        for (i, row) in f.pixels.chunks_exact(stride).take(rows).enumerate() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    row.as_ptr(),
                    bits.add((rows - 1 - i) * stride),
                    stride,
                )
            };
        }
        bmp
    }

    fn tick_inner(&self) {
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
            if !self.control.get() && playing && m.total_frames > 1 && frame >= m.total_frames {
                m.stop_root();
            }
            // The end of a movie that sends no animEnd: its root timeline
            // stands on the last frame for a moment.
            if !self.control.get() && !self.ended.get() && self.want_play.get() {
                let (frame, root_playing) = m.root_state();
                if root_playing || m.total_frames == 0 || frame < m.total_frames {
                    self.idle_since.set(None);
                } else {
                    let since = self.idle_since.get().unwrap_or(now);
                    self.idle_since.set(Some(since));
                    if now - since >= END_GRACE {
                        self.ended.set(true);
                        log(&format!("movie ended on frame {frame}"));
                    }
                }
            }
            changed
        };
        if changed {
            self.present();
        }
        self.init_devil_face();
        self.apply_pending_vars();
        self.deliver_fscommands();
    }

    /// The start state of an ICQ devil's face, as Flash Player has it.
    ///
    /// Every devil (the ICQ devil kit's `avatar` class, registered for the
    /// `face` clip with `Object.registerClass` in an #initclip) starts in its
    /// constructor: `__set__emotion(devilRoot.initEmo)`, "stam", which sets
    /// `MyEmotion`. Flash runs #initclip code before it builds the frame, so
    /// the constructor runs. Ruffle registers the class after the face is on
    /// stage and never runs the constructor: `MyEmotion` stays undefined.
    /// Then the host's first `face.emotion = "stam"` is not a no-op as in
    /// Flash: the setter does `gotoAndPlay("stam")` on the frame it stands on,
    /// which plays on into the next label ("smile"), and the face stays there
    /// (ICQ 7.2 sends "stam" at load: the pirate kept drinking its beer).
    /// So once the first frame has run, a face that stands on its first frame
    /// ("stam") with `MyEmotion` undefined gets what the constructor sets.
    fn init_devil_face(&self) {
        if self.face_checked.get() || !self.control.get() {
            return;
        }
        let started = self
            .movie
            .borrow()
            .as_ref()
            .is_some_and(|m| m.root_state().0 >= 1);
        if !started {
            return;
        }
        self.face_checked.set(true);
        // GetVariable gives "" or "undefined" for an undefined variable.
        let get = |p: &str| {
            self.get_variable(p)
                .filter(|v| v != "undefined")
                .unwrap_or_default()
        };
        if get("_global.avatar").is_empty() || get("face._currentframe") != "1" {
            return;
        }
        if !get("face.MyEmotion").is_empty() {
            return; // the constructor ran
        }
        let init = match get("_global.devilRoot.initEmo") {
            v if v.is_empty() => "stam".to_owned(),
            v => v,
        };
        let ok = self.with_movie("devil face", |m| {
            m.set_variable("_global.devilRoot.initEmo", &init)
                && m.set_variable("face.MyEmotion", &init)
        });
        log(&format!(
            "devil face: constructor did not run, face starts as {init:?} -> {}",
            if ok == Some(true) { "set" } else { "failed" }
        ));
    }

    /// SetVariable calls kept while loading, once the first frame has run.
    fn apply_pending_vars(&self) {
        if self.pending_vars.borrow().is_empty() {
            return;
        }
        let started = self
            .movie
            .borrow()
            .as_ref()
            .is_some_and(|m| m.root_state().0 >= 1);
        if !started {
            return;
        }
        let vars = std::mem::take(&mut *self.pending_vars.borrow_mut());
        for (path, value) in vars {
            let ok = self.with_movie("SetVariable", |m| m.set_variable(&path, &value));
            log(&format!(
                "SetVariable({path:?}, {value:?}) applied after load -> {}",
                if ok == Some(true) { "0x0" } else { "failed" }
            ));
        }
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

    /// Runs `f`; if it panics, the movie is taken out of service: its timer
    /// stops, the player is leaked (dropping a player whose renderer just
    /// failed could fail again), and the movie counts as ended. The window
    /// stays usable and shows nothing new.
    fn guarded<R>(&self, what: &str, default: R, f: impl FnOnce() -> R) -> R {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
            Ok(v) => v,
            Err(_) => {
                log(&format!("{what} failed; this movie stops"));
                unsafe { KillTimer(self.hwnd, TICK_TIMER) };
                if let Ok(mut m) = self.movie.try_borrow_mut() {
                    std::mem::forget(m.take());
                }
                self.loading.set(false);
                self.ended.set(true);
                default
            }
        }
    }

    fn tick(&self) {
        self.guarded("playing", (), || self.tick_inner())
    }

    /// Renders the current frame and puts it on the layered window.
    pub fn present(&self) {
        self.guarded("drawing", (), || self.present_inner())
    }

    /// Message 0x1404: a new 32bpp top-down DIB of the current frame. Never
    /// null: when nothing can be drawn it is a fully transparent bitmap of
    /// the window's size, so a caller that does not check gets a valid one.
    fn snapshot(&self) -> HBITMAP {
        let bmp = self.guarded("snapshot", null_mut(), || self.snapshot_inner());
        if !bmp.is_null() {
            return bmp;
        }
        let (w, h) = self.size();
        new_dib(w.max(1), h.max(1)).map_or(null_mut(), |(b, _)| b)
    }

    fn on_loaded(&self, generation: u32) {
        self.guarded("loading", (), || self.on_loaded_inner(generation))
    }

    pub fn play(&self) -> HRESULT {
        if self.control.get() {
            log("Play");
        }
        self.guarded("Play", E_FAIL, || self.play_inner())
    }

    /// Flash's Stop: stop and rewind to the first frame.
    pub fn stop(&self) -> HRESULT {
        if self.control.get() {
            log("Stop");
        }
        self.guarded("Stop", E_FAIL, || self.stop_inner())
    }

    /// Flash's StopPlay: pause where we are.
    pub fn stop_play(&self) -> HRESULT {
        self.guarded("StopPlay", E_FAIL, || self.stop_play_inner())
    }

    /// Flash's GotoFrame: `frame` is 0-based; the movie stops there.
    pub fn goto_frame(&self, frame: i32) -> HRESULT {
        self.guarded("GotoFrame", E_FAIL, || self.goto_frame_inner(frame))
    }

    fn destroy(&self) {
        self.destroyed.set(true);
        unsafe { KillTimer(self.hwnd, TICK_TIMER) };
        unsafe { KillTimer(self.hwnd, FACE_TIMER) };
        self.load_gen.set(self.load_gen.get().wrapping_add(1));
        let old = self.movie.borrow_mut().take();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(old))).is_err() {
            log("releasing a player failed");
        }
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
            INSTANCES.with(|m| m.0.borrow_mut().insert(hwnd as usize, inst));
            OWNERS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((hwnd as usize, unsafe { GetCurrentThreadId() }));
            // Start opening the GPU device and sound output in the background.
            crate::gpu::start();
            crate::audio::start();
            None
        }
        WM_NCDESTROY => {
            OWNERS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|(h, _)| *h != hwnd as usize);
            let inst = INSTANCES.with(|m| m.0.borrow_mut().remove(&(hwnd as usize)));
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
        WM_TIMER if wp == FACE_TIMER => {
            if let Some(i) = get(hwnd) {
                i.face_timer();
            }
            Some(0)
        }
        WM_TIMER if wp == CONTROL_TIMER => {
            if let Some(i) = get(hwnd) {
                let cb = i.on_control_timer.borrow();
                if let Some(cb) = cb.as_ref() {
                    cb();
                }
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
