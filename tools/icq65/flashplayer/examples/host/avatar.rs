//! `host <dll> avatars ...`: reproduces ICQ 6.5's Flash avatar snapshot jobs
//! (MCore FlashSnapshotImgService). Each job runs on a worker thread with its
//! own GetMessage loop: an ownerless offscreen window, an event sink that posts
//! 0x7BA/0x7BB on ready states 3/4, an http SWF, then GotoFrame + 0x1404 and
//! teardown. Several jobs run at once while the UI thread plays a tZer.

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Com::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{GUID, HRESULT};

use crate::{DIID_EVENTS, Fpc, IID_ICPC, Unk, new_sink, query_flash, snapshot, wide};

pub const MSG_STATE3: u32 = 0x7BA;
pub const MSG_STATE4: u32 = 0x7BB;
const SNAP_TIMER: usize = 0x25D;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Apt {
    Mta,
    None,
    Sta,
}

impl Apt {
    fn parse(s: &str, i: usize) -> Apt {
        match s {
            "mta" => Apt::Mta,
            "none" => Apt::None,
            "sta" => Apt::Sta,
            _ => [Apt::Mta, Apt::None, Apt::Sta][i % 3], // "mixed"
        }
    }
}

/// One snapshot job, run on the calling (worker) thread.
pub fn job(fpc: &Fpc, id: usize, url: &str, png: &str, apt: Apt) -> Result<String, String> {
    let started = Instant::now();
    let inited = match apt {
        Apt::Mta => (unsafe { CoInitializeEx(null(), COINIT_MULTITHREADED as u32) }) >= 0,
        Apt::Sta => (unsafe { CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32) }) >= 0,
        Apt::None => false,
    };
    let r = run(fpc, id, url, png);
    if inited {
        unsafe { CoUninitialize() };
    }
    let ms = started.elapsed().as_millis();
    r.map(|s| format!("{s}, {ms} ms"))
}

fn run(fpc: &Fpc, id: usize, url: &str, png: &str) -> Result<String, String> {
    (fpc.RegisterFlashWindowClass)();
    let (cx, cy) = (87, 109);
    let cls = wide("FlashPlayerControl");
    let hwnd = unsafe {
        CreateWindowExW(
            0x08080080,
            cls.as_ptr(),
            null(),
            WS_POPUP,
            0xFFFF - cx,
            0xFFFF - cy,
            cx,
            cy,
            null_mut(),
            null_mut(),
            GetModuleHandleW(null()),
            null(),
        )
    };
    if hwnd.is_null() {
        return Err(format!("CreateWindowExW failed {}", unsafe {
            GetLastError()
        }));
    }
    unsafe { ShowWindow(hwnd, SW_SHOW) };
    let flash = query_flash(hwnd);
    let sink = new_sink("avatar");
    sink.post_to.set(hwnd as isize);
    let (cp, cookie) = unsafe {
        let mut cpc: Unk = null_mut();
        vcall!(
            flash,
            0,
            fn(*const GUID, *mut Unk) -> HRESULT,
            &IID_ICPC,
            &mut cpc
        );
        let mut cp: Unk = null_mut();
        vcall!(
            cpc,
            4,
            fn(*const GUID, *mut Unk) -> HRESULT,
            &DIID_EVENTS,
            &mut cp
        );
        let mut cookie = 0u32;
        let hr = vcall!(
            cp,
            5,
            fn(Unk, *mut u32) -> HRESULT,
            &*sink as *const _ as Unk,
            &mut cookie
        );
        vcall!(cpc, 2, fn() -> u32);
        if hr < 0 {
            return Err(format!("Advise {hr:#x}"));
        }
        (cp, cookie)
    };
    let w = wide(url);
    let hr = (fpc.FPC_LoadMovieW)(hwnd, 0, w.as_ptr());
    if hr < 0 {
        return Err(format!("FPC_LoadMovieW {hr:#x}"));
    }
    // Give up on this job after 40 s (a thread timer, like a WM_QUIT from the queue).
    let abort = unsafe { SetTimer(null_mut(), 0, 40_000, None) };
    let result;
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        loop {
            let r = GetMessageW(&mut msg, null_mut(), 0, 0);
            if r <= 0 {
                result = Err("WM_QUIT".into());
                break;
            }
            if msg.message == WM_TIMER && msg.hwnd.is_null() && msg.wParam == abort {
                result = Err("timed out waiting for ready state".into());
                break;
            }
            if msg.hwnd == hwnd && msg.message == MSG_STATE3 {
                SetTimer(hwnd, SNAP_TIMER, 1500, None);
                continue;
            }
            if msg.hwnd == hwnd
                && (msg.message == MSG_STATE4
                    || (msg.message == WM_TIMER && msg.wParam == SNAP_TIMER))
            {
                let mut total = 0i32;
                vcall!(flash, 8, fn(*mut i32) -> HRESULT, &mut total);
                let frame = total / 2;
                let hr = vcall!(flash, 34, fn(i32) -> HRESULT, frame);
                result = match snapshot(hwnd, png) {
                    Some((w, h, transparent, opaque, _)) => Ok(format!(
                        "job {id}: {total} frames, GotoFrame({frame}) {hr:#x}, snapshot {w}x{h}, {} px drawn ({opaque} opaque, {transparent} transparent)",
                        (w * h) as usize - transparent
                    )),
                    None => Err("0x1404 gave no bitmap".into()),
                };
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        KillTimer(null_mut(), abort);
        vcall!(cp, 6, fn(u32) -> HRESULT, cookie);
        vcall!(cp, 2, fn() -> u32);
        vcall!(flash, 2, fn() -> u32);
        DestroyWindow(hwnd);
        (fpc.UnregisterFlashWindowClass)();
        KillTimer(hwnd, SNAP_TIMER);
    }
    drop(sink);
    result
}

pub struct Plan {
    pub base_url: String,
    pub out: String,
    pub apt: String,
    pub concurrency: usize,
    pub rounds: usize,
    pub pool: bool,
    pub tzer: Option<String>,
    pub names: Vec<String>,
}

/// Runs all jobs; the UI thread meanwhile pumps messages and replays a tZer.
pub fn run_all(fpc: &'static Fpc, plan: Plan) -> bool {
    let _ = std::fs::create_dir_all(&plan.out);
    (fpc.RegisterFlashWindowClass)();
    let tzer = plan.tzer.as_ref().map(|swf| {
        let owner = crate::create_owner(100, 100, 800, 600);
        let h = crate::create_flash(fpc, owner, 120, 120, 755 / 2, 560 / 2, 3);
        let w = wide(swf);
        say!(
            "tZer on the UI thread: FPC_LoadMovieW -> {:#x}",
            (fpc.FPC_LoadMovieW)(h, 0, w.as_ptr())
        );
        (fpc.FPC_Play)(h);
        (owner, h)
    });

    if let Some((_, h)) = tzer {
        // Exports called for a window from a thread that does not own it
        // must fail at once (not hang, not touch the other thread's state).
        let hw = h as usize;
        std::thread::spawn(move || {
            let mut p = 0i16;
            let hr1 = (fpc.FPC_IsPlaying)(hw as HWND, &mut p);
            let hr2 = (fpc.FPC_Play)(hw as HWND);
            let hr3 = (fpc.FPC_UpdateWindow)(hw as HWND);
            say!("tZer window called from another thread: IsPlaying {hr1:#x}, Play {hr2:#x}, UpdateWindow {hr3:#x} (RPC_E_WRONG_THREAD = 0x8001010e)");
        })
        .join()
        .unwrap();
    }
    let mut work: Vec<(usize, String, Apt)> = Vec::new();
    for round in 0..plan.rounds {
        for (i, n) in plan.names.iter().enumerate() {
            let id = round * plan.names.len() + i;
            work.push((id, n.clone(), Apt::parse(&plan.apt, id)));
        }
    }
    let total = work.len();
    let queue = Arc::new(Mutex::new(work.into_iter()));
    let done = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut handles = Vec::new();

    let run_one = {
        let base = plan.base_url.clone();
        let out = plan.out.clone();
        let done = done.clone();
        let failed = failed.clone();
        move |(id, name, apt): (usize, String, Apt)| {
            let url = format!("{base}/{name}");
            let png = format!("{out}\\{:03}-{}.png", id, name.trim_end_matches(".swf"));
            say!("job {id} start: {name} ({apt:?}) on thread {}", unsafe {
                windows_sys::Win32::System::Threading::GetCurrentThreadId()
            });
            match job(fpc, id, &url, &png, apt) {
                Ok(s) => say!("{s}"),
                Err(e) => {
                    say!("job {id} FAILED: {name}: {e}");
                    failed.lock().unwrap().push(format!("{id} {name}: {e}"));
                }
            }
            done.fetch_add(1, Ordering::SeqCst);
        }
    };

    if plan.pool {
        // Long-lived workers that take jobs from a queue.
        for _ in 0..plan.concurrency {
            let q = queue.clone();
            let f = run_one.clone();
            handles.push(std::thread::spawn(move || {
                loop {
                    let next = q.lock().unwrap().next();
                    match next {
                        Some(w) => f(w),
                        None => break,
                    }
                }
            }));
        }
    }
    let mut running: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let deadline = Instant::now()
        + Duration::from_secs(60 + 20 * total as u64 / plan.concurrency.max(1) as u64);
    let mut last_report = Instant::now();
    while done.load(Ordering::SeqCst) < total {
        if !plan.pool {
            // A new thread per job, at most `concurrency` at once; each exits when done.
            running.retain(|h| !h.is_finished());
            while running.len() < plan.concurrency {
                let next = queue.lock().unwrap().next();
                let Some(w) = next else { break };
                let f = run_one.clone();
                running.push(std::thread::spawn(move || f(w)));
            }
        }
        crate::pump_for(Duration::from_millis(50));
        if let Some((_, h)) = tzer {
            let mut p = 0i16;
            (fpc.FPC_IsPlaying)(h, &mut p);
            if p == 0 {
                (fpc.FPC_Play)(h); // replay the tZer so it keeps running alongside the jobs
            }
        }
        if last_report.elapsed() > Duration::from_secs(5) {
            say!(
                "progress: {}/{total} jobs done",
                done.load(Ordering::SeqCst)
            );
            last_report = Instant::now();
        }
        if Instant::now() > deadline {
            say!(
                "DEADLINE: {}/{total} jobs done",
                done.load(Ordering::SeqCst)
            );
            return false;
        }
    }
    for h in running.into_iter().chain(handles) {
        let _ = h.join();
    }
    if let Some((owner, h)) = tzer {
        let mut p = 0i16;
        (fpc.FPC_IsPlaying)(h, &mut p);
        say!("tZer window still alive, IsPlaying {}", p != 0);
        say!(
            "slowest message on the UI thread: {}",
            crate::slowest_dispatch()
        );
        unsafe {
            DestroyWindow(h);
            DestroyWindow(owner);
        }
    }
    let failed = failed.lock().unwrap();
    say!(
        "summary: {total} jobs, {} failed {:?}",
        failed.len(),
        *failed
    );
    failed.is_empty()
}
