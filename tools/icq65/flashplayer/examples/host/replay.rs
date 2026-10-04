//! Replays ICQ 6.5's call sequence for Flash avatars (from a real
//! FLASHPLAYERCONTROL_LOG of the client) against the control, and saves what
//! IViewObject::Draw gives.
//!
//!   host <dll> axreplay <base dir|url> <out> <rounds> <variant...>
//!
//! A variant is a list of steps separated by '+':
//!   pre    SetVariable("face.emotion", "stam") x4 before the movie loads
//!   twice  Movie, Play and two "stam" put a second time (ICQ does)
//!   zero   SetObjectRects 0x0 before the real rectangle
//!   late   the real rectangle only after the load has finished
//!   busy   stam, busy, stam, stam once loaded
//!   pair   a second control (avatar_girl.swf) created alongside
//! "icq" is pre+twice+zero+busy+pair; "plain" is none of them.

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::RECT;

use crate::axhost::{Hosted, PAINT, PaintItem, container_window, host_control, save_png};
use crate::pump_for;

fn rect(l: i32, t: i32, r: i32, b: i32) -> RECT {
    RECT {
        left: l,
        top: t,
        right: r,
        bottom: b,
    }
}

const ZERO: RECT = RECT {
    left: 0,
    top: 0,
    right: 0,
    bottom: 0,
};

fn visible(px: &[u8]) -> usize {
    px.chunks_exact(4).filter(|p| p[3] != 0).count()
}

/// Mean absolute difference per channel, 0..255.
fn diff(a: &[u8], b: &[u8]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 255.0;
    }
    a.iter()
        .zip(b)
        .map(|(x, y)| (*x as i32 - *y as i32).unsigned_abs() as u64)
        .sum::<u64>() as f64
        / a.len() as f64
}

struct Ctl {
    h: Hosted,
    file: String,
    rect: RECT,
}

/// One round; returns the first non-empty capture of the first control.
fn round(base: &str, out: &str, tag: &str, steps: &[&str]) -> Option<Vec<u8>> {
    let has = |s: &str| steps.contains(&s) || (steps.contains(&"icq") && s != "late");
    let win = container_window(700, 600, "replay");
    let params = [("Scale", "NoBorder"), ("Quality", "High")];
    let sep = if base.starts_with("http") { "/" } else { "\\" };
    let mut wanted = vec![("avatar_10526.swf", rect(561, 104, 611, 164))];
    if has("pair") {
        wanted.push(("avatar_girl.swf", rect(560, 346, 610, 410)));
    }
    let mut ctls = Vec::new();
    for (file, r) in &wanted {
        let start = if has("zero") || has("late") { ZERO } else { *r };
        let h = host_control(win, start, &params, file, false).ok()?;
        h.put_movie_dispatch(&format!("{base}{sep}{file}"));
        h.play();
        if has("pre") {
            for _ in 0..4 {
                h.set_variable("face.emotion", "stam");
            }
        }
        ctls.push(Ctl {
            h,
            file: file.to_string(),
            rect: *r,
        });
    }
    if has("twice") {
        for c in &ctls {
            c.h.put_movie_dispatch(&format!("{base}{sep}{}", c.file));
            c.h.play();
            if has("pre") {
                c.h.set_variable("face.emotion", "stam");
                c.h.set_variable("face.emotion", "stam");
            }
        }
    }
    let real = |ctls: &[Ctl]| {
        for c in ctls {
            if has("zero") {
                c.h.set_object_rects(ZERO);
            }
        }
        for c in ctls {
            c.h.set_object_rects(c.rect);
            PAINT.with(|p| {
                p.borrow_mut().push(PaintItem {
                    view: c.h.view,
                    rect: c.rect,
                    ready: true,
                    path_a: false,
                })
            });
        }
    };
    if !has("late") {
        real(&ctls);
    }
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) && ctls.iter().any(|c| c.h.ready_state() != 4) {
        pump_for(Duration::from_millis(5));
    }
    if has("late") {
        real(&ctls);
    }
    let mut first: Option<Vec<u8>> = None;
    let mut busy_done = !has("busy");
    let t = Instant::now();
    let mut n = 0;
    while t.elapsed() < Duration::from_millis(2500) {
        pump_for(Duration::from_millis(40));
        let c = &ctls[0];
        let (w, h) = (c.rect.right - c.rect.left, c.rect.bottom - c.rect.top);
        let (_, px) = c.h.capture(w, h);
        if visible(&px) > 0 && first.is_none() {
            save_png(&format!("{out}\\{tag}-first.png"), w as u32, h as u32, &px);
            first = Some(px.clone());
        }
        if !busy_done && first.is_some() {
            busy_done = true;
            for c in &ctls {
                for v in ["stam", "busy", "stam", "stam"] {
                    c.h.set_variable("face.emotion", v);
                }
            }
        }
        n += 1;
        if n == 50 {
            save_png(&format!("{out}\\{tag}-late.png"), w as u32, h as u32, &px);
        }
    }
    PAINT.with(|p| p.borrow_mut().clear());
    for c in ctls {
        c.h.close();
    }
    unsafe { windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow(win) };
    first
}

pub fn run(base: &str, out: &str, rounds: usize, variants: &[String]) -> bool {
    let _ = std::fs::create_dir_all(out);
    // Reference: a plain host, rectangle first, nothing else.
    let reference = round(base, out, "ref", &[]);
    let Some(reference) = reference else {
        say!("reference: nothing drawn");
        return false;
    };
    for v in variants {
        let steps: Vec<&str> = v.split('+').collect();
        let mut bad = 0;
        for i in 0..rounds {
            let tag = format!("{}-{i}", v.replace('+', "_"));
            match round(base, out, &tag, &steps) {
                Some(px) => {
                    let d = diff(&px, &reference);
                    if d > 20.0 {
                        bad += 1;
                    }
                    say!("{v} round {i}: first frame differs from reference by {d:.1}");
                }
                None => say!("{v} round {i}: nothing drawn"),
            }
        }
        say!("variant {v}: {bad}/{rounds} rounds with a different first frame");
    }
    true
}

/// IShockwaveFlash::TGotoFrame (slot 59), 0-based frame.
fn t_goto_frame(h: &Hosted, target: &str, frame: i32) -> i32 {
    unsafe {
        let t = crate::wide(target);
        let b = windows_sys::Win32::Foundation::SysAllocString(t.as_ptr());
        let hr = vcall!(h.flash, 59, fn(*const u16, i32) -> i32, b, frame);
        windows_sys::Win32::Foundation::SysFreeString(b);
        hr
    }
}

/// Every frame of `target` (e.g. "face") in one sheet, at the control size.
pub fn frames(base: &str, out: &str, file: &str, target: &str, w: i32, h: i32) -> bool {
    let _ = std::fs::create_dir_all(out);
    let win = container_window(200, 200, "frames");
    let params = [("Scale", "NoBorder"), ("Quality", "High")];
    let sep = if base.starts_with("http") { "/" } else { "\\" };
    let Ok(c) = host_control(win, rect(10, 10, 10 + w, 10 + h), &params, file, false) else {
        return false;
    };
    c.put_movie_dispatch(&format!("{base}{sep}{file}"));
    c.play();
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) && c.ready_state() != 4 {
        pump_for(Duration::from_millis(20));
    }
    pump_for(Duration::from_millis(500));
    let total: i32 = c
        .get_variable(&format!("{target}._totalframes"))
        .1
        .parse()
        .unwrap_or(0);
    say!("{file} {target}: {total} frames");
    let cols = 20usize;
    let n = total.max(1) as usize;
    let rows = n.div_ceil(cols);
    let mut sheet = vec![0u8; cols * rows * (w * h * 4) as usize];
    let sw = cols * w as usize;
    for k in 0..n {
        t_goto_frame(&c, target, k as i32);
        pump_for(Duration::from_millis(60));
        let (_, px) = c.capture(w, h);
        let (cx, cy) = ((k % cols) * w as usize, (k / cols) * h as usize);
        for y in 0..h as usize {
            let src = &px[y * w as usize * 4..(y + 1) * w as usize * 4];
            let dst = ((cy + y) * sw + cx) * 4;
            sheet[dst..dst + src.len()].copy_from_slice(src);
        }
    }
    save_png(
        &format!("{out}/frames-{file}-{target}.png"),
        sw as u32,
        (rows * h as usize) as u32,
        &sheet,
    );
    PAINT.with(|p| p.borrow_mut().clear());
    c.close();
    true
}

/// Creates a control the way ICQ 6.5 does (0x0 extent and rectangles, Movie
/// through IDispatch, Play, four "stam" while it loads).
fn icq_control(
    win: windows_sys::Win32::Foundation::HWND,
    base: &str,
    file: &str,
) -> Option<Hosted> {
    let params = [("Scale", "NoBorder"), ("Quality", "High")];
    let sep = if base.starts_with("http") { "/" } else { "\\" };
    let h = host_control(win, ZERO, &params, file, false).ok()?;
    h.put_movie_dispatch(&format!("{base}{sep}{file}"));
    h.play();
    for _ in 0..4 {
        h.set_variable("face.emotion", "stam");
    }
    Some(h)
}

fn show(h: &Hosted, r: RECT) {
    h.set_object_rects(r);
    PAINT.with(|p| {
        p.borrow_mut().push(PaintItem {
            view: h.view,
            rect: r,
            ready: true,
            path_a: false,
        })
    });
}

fn unshow(h: &Hosted) {
    PAINT.with(|p| p.borrow_mut().retain(|i| i.view != h.view));
}

/// Pumps for `ms`, capturing `h` at `r`'s size each 40 ms; saves the first
/// visible capture and returns how many captures had girl-hair pixels
/// (97,0,0), which avatar_10526.swf does not have.
fn watch(h: &Hosted, r: RECT, ms: u64, out: &str, tag: &str) -> (usize, usize) {
    let (w, hh) = (r.right - r.left, r.bottom - r.top);
    let t = Instant::now();
    let (mut seen, mut bad, mut saved_bad) = (0, 0, false);
    let mut first = true;
    while t.elapsed() < Duration::from_millis(ms) {
        pump_for(Duration::from_millis(40));
        let (_, px) = h.capture(w, hh);
        if visible(&px) == 0 {
            continue;
        }
        seen += 1;
        let hair = px
            .chunks_exact(4)
            .filter(|p| p[0] == 0 && p[1] == 0 && p[2] == 97)
            .count();
        if first {
            first = false;
            save_png(&format!("{out}/{tag}-first.png"), w as u32, hh as u32, &px);
        }
        if hair > 20 {
            bad += 1;
            if !saved_bad {
                saved_bad = true;
                save_png(&format!("{out}/{tag}-BAD.png"), w as u32, hh as u32, &px);
            }
        }
    }
    (seen, bad)
}

/// The whole first session of the owner's log, `rounds` times.
pub fn session(base: &str, out: &str, rounds: usize) -> bool {
    let _ = std::fs::create_dir_all(out);
    let win = container_window(700, 600, "session");
    let r1 = rect(16, 60, 54, 109);
    let fluffy = rect(561, 104, 611, 164);
    let girl = rect(560, 346, 610, 410);
    let prof = rect(27, 54, 112, 160);
    // #1: contact list, kept.
    let Some(c1) = icq_control(win, base, "avatar_girl.swf") else {
        return false;
    };
    show(&c1, r1);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Ok(dll) = std::env::var("SNAP_DLL") {
        snapshot_thread(
            dll,
            format!("{base}/avatar_10526.swf"),
            (87, 109),
            stop.clone(),
        );
    }
    let mut total_bad = 0;
    for round in 0..rounds {
        for pass in 0..2 {
            // #2/#3 (and #6/#7): the pair, created at once.
            let a = icq_control(win, base, "avatar_10526.swf").unwrap();
            let b = icq_control(win, base, "avatar_girl.swf").unwrap();
            for (h, f) in [(&a, "avatar_10526.swf"), (&b, "avatar_girl.swf")] {
                h.put_movie_dispatch(&format!("{base}/{f}"));
                h.play();
                h.set_variable("face.emotion", "stam");
                h.set_variable("face.emotion", "stam");
            }
            a.set_object_rects(ZERO);
            b.set_object_rects(ZERO);
            show(&a, fluffy);
            show(&b, girl);
            let tag = format!("r{round}-p{pass}");
            let (seen, bad) = watch(&a, fluffy, 2500, out, &tag);
            say!("{tag}: fluffy {seen} frames, {bad} with girl hair");
            total_bad += bad;
            for h in [&a, &b] {
                for v in ["stam", "busy", "stam", "stam"] {
                    h.set_variable("face.emotion", v);
                }
            }
            pump_for(Duration::from_millis(300));
            unshow(&b);
            unshow(&a);
            b.close();
            a.close();
            if pass == 0 {
                // #4, #5: the profile, one after the other.
                for ms in [1000, 2000] {
                    let p = icq_control(win, base, "avatar_girl.swf").unwrap();
                    show(&p, prof);
                    pump_for(Duration::from_millis(ms));
                    unshow(&p);
                    p.close();
                }
            }
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    unshow(&c1);
    c1.close();
    say!("session: {total_bad} fluffy frames with girl hair");
    true
}

/// What MCore's FlashSnapshotImgService does, on a thread of its own, over
/// and over: an ownerless FlashPlayerControl window, the movie, a 0x1404
/// snapshot once it has loaded, then the window is destroyed.
pub fn snapshot_thread(
    dll: String,
    url: String,
    size: (i32, i32),
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleW, GetProcAddress, LoadLibraryW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    std::thread::spawn(move || unsafe {
        let w = crate::wide(&dll);
        let m = LoadLibraryW(w.as_ptr());
        let reg: extern "system" fn() -> i32 = std::mem::transmute(
            GetProcAddress(m, c"RegisterFlashWindowClass".as_ptr().cast()).unwrap(),
        );
        let load: extern "system" fn(windows_sys::Win32::Foundation::HWND, i32, *const u16) -> i32 =
            std::mem::transmute(GetProcAddress(m, c"FPC_LoadMovieW".as_ptr().cast()).unwrap());
        reg();
        let cls = crate::wide("FlashPlayerControl");
        let u = crate::wide(&url);
        let mut n = 0;
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            let hwnd = CreateWindowExW(
                0,
                cls.as_ptr(),
                std::ptr::null(),
                WS_POPUP,
                -2000,
                -2000,
                size.0,
                size.1,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );
            load(hwnd, 0, u.as_ptr());
            let t = Instant::now();
            while t.elapsed() < Duration::from_millis(1500) {
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let bmp = SendMessageW(hwnd, 0x1404, 0, 0);
            if bmp != 0 {
                windows_sys::Win32::Graphics::Gdi::DeleteObject(bmp as _);
            }
            DestroyWindow(hwnd);
            n += 1;
        }
        say!("snapshot thread: {n} snapshots");
    });
}

/// After load: SetVariable("face.emotion", each of `seq` in turn), then a
/// capture every 40 ms for `ms`, all in one sheet (20 per row).
pub fn anim(base: &str, out: &str, file: &str, seq: &[String], ms: u64, w: i32, h: i32) -> bool {
    let _ = std::fs::create_dir_all(out);
    let win = container_window(200, 200, "anim");
    let params = [("Scale", "NoBorder"), ("Quality", "High")];
    let Ok(c) = host_control(win, rect(10, 10, 10 + w, 10 + h), &params, file, false) else {
        return false;
    };
    c.put_movie_dispatch(&format!("{base}/{file}"));
    c.play();
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) && c.ready_state() != 4 {
        pump_for(Duration::from_millis(20));
    }
    pump_for(Duration::from_millis(300));
    for v in seq {
        if v == "-" {
            pump_for(Duration::from_millis(100));
        } else {
            c.set_variable("face.emotion", v);
        }
    }
    let mut caps = Vec::new();
    let t = Instant::now();
    while t.elapsed() < Duration::from_millis(ms) {
        pump_for(Duration::from_millis(40));
        caps.push(c.capture(w, h).1);
    }
    let cols = 20usize;
    let rows = caps.len().div_ceil(cols);
    let sw = cols * w as usize;
    let mut sheet = vec![0u8; sw * rows * h as usize * 4];
    for (k, px) in caps.iter().enumerate() {
        let (cx, cy) = ((k % cols) * w as usize, (k / cols) * h as usize);
        for y in 0..h as usize {
            let src = &px[y * w as usize * 4..(y + 1) * w as usize * 4];
            let dst = ((cy + y) * sw + cx) * 4;
            sheet[dst..dst + src.len()].copy_from_slice(src);
        }
    }
    let tag = seq.join("_").replace('-', "w");
    save_png(
        &format!("{out}/anim-{file}-{tag}.png"),
        sw as u32,
        (rows * h as usize) as u32,
        &sheet,
    );
    c.close();
    true
}

/// Foreign colours: girl hair in avatar_10526.swf, the fluffy's peach in
/// avatar_girl.swf. Returns the number of such pixels.
fn foreign(file: &str, px: &[u8]) -> usize {
    let (b, g, r) = if file.contains("10526") {
        (0, 0, 97)
    } else {
        (132, 215, 255)
    };
    px.chunks_exact(4)
        .filter(|p| p[0] == b && p[1] == g && p[2] == r && p[3] == 255)
        .count()
}

/// Many controls of both movies, created and closed in a varying order at
/// ICQ's sizes; every capture is checked for the other movie's colours.
pub fn stress(base: &str, out: &str, iterations: usize) -> bool {
    let _ = std::fs::create_dir_all(out);
    let win = container_window(700, 600, "stress");
    let sizes = [(38, 49), (50, 60), (50, 64), (85, 106), (87, 109)];
    let files = ["avatar_10526.swf", "avatar_girl.swf"];
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Ok(dll) = std::env::var("SNAP_DLL") {
        snapshot_thread(
            dll.clone(),
            format!("{base}/avatar_10526.swf"),
            (87, 109),
            stop.clone(),
        );
    }
    let mut others = Vec::new();
    if let Ok(dll) = std::env::var("UI2_DLL") {
        others.push(other_ui_thread(
            dll.clone(),
            base.to_string(),
            "avatar_girl.swf",
            (38, 49),
            stop.clone(),
        ));
        others.push(other_ui_thread(
            dll,
            base.to_string(),
            "avatar_10526.swf",
            (50, 60),
            stop.clone(),
        ));
    }
    let mut seed = 12345u32;
    let mut rnd = move |n: u32| {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        (seed >> 16) % n
    };
    let mut live: Vec<(Hosted, String, RECT)> = Vec::new();
    let (mut caps, mut bad) = (0usize, 0usize);
    for it in 0..iterations {
        // Open 1-3 controls.
        for _ in 0..1 + rnd(3) {
            if live.len() >= 6 {
                break;
            }
            let file = files[rnd(2) as usize];
            let (w, h) = sizes[rnd(sizes.len() as u32) as usize];
            let slot = live.len() as i32;
            let x = 10 + (slot % 6) * 110;
            let r = rect(
                x,
                10 + 120 * (it as i32 % 4),
                x + w,
                10 + 120 * (it as i32 % 4) + h,
            );
            let Some(c) = icq_control(win, base, file) else {
                continue;
            };
            if rnd(2) == 0 {
                c.put_movie_dispatch(&format!("{base}/{file}"));
                c.play();
            }
            c.set_object_rects(ZERO);
            show(&c, r);
            live.push((c, file.to_string(), r));
        }
        let ms = 300 + rnd(1500) as u64;
        let t = Instant::now();
        let mut k = 0;
        while t.elapsed() < Duration::from_millis(ms) {
            pump_for(Duration::from_millis(40));
            k += 1;
            if k % 5 == 0 {
                for (c, _, _) in &live {
                    let e = ["stam", "busy", "smile", "offline"][rnd(4) as usize];
                    c.set_variable("face.emotion", e);
                }
            }
            for (i, (c, file, r)) in live.iter().enumerate() {
                let (w, h) = (r.right - r.left, r.bottom - r.top);
                let (_, px) = c.capture(w, h);
                if visible(&px) == 0 {
                    continue;
                }
                caps += 1;
                let n = foreign(file, &px);
                if n > 20 {
                    bad += 1;
                    if bad <= 30 {
                        save_png(
                            &format!("{out}/BAD-{it}-{i}-{file}-{w}x{h}.png"),
                            w as u32,
                            h as u32,
                            &px,
                        );
                        say!("iteration {it}: control {i} {file} {w}x{h}: {n} foreign pixels");
                    }
                }
            }
        }
        // Close some.
        let close = rnd(live.len() as u32 + 1) as usize;
        for _ in 0..close {
            let i = rnd(live.len() as u32) as usize;
            let (c, _, _) = live.remove(i);
            unshow(&c);
            c.close();
        }
        if it % 20 == 0 {
            say!(
                "iteration {it}: {caps} captures, {bad} with foreign colours, {} live",
                live.len()
            );
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for o in others {
        let _ = o.join();
    }
    say!("stress: {caps} captures, {bad} with foreign colours");
    for (c, _, _) in live {
        unshow(&c);
        c.close();
    }
    true
}

/// A second UI thread, as a second ICQ window may have: its own container
/// and a control with `file` at `size`, animating until `stop`. Checks its
/// own captures for the other movie's colours.
pub fn other_ui_thread(
    dll: String,
    base: String,
    file: &'static str,
    size: (i32, i32),
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || unsafe {
        windows_sys::Win32::System::Com::CoInitializeEx(
            std::ptr::null(),
            windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED as u32,
        );
        crate::axhost::register_class(&dll);
        let win = container_window(300, 200, "second UI thread");
        let r = rect(16, 60, 16 + size.0, 60 + size.1);
        let Some(c) = icq_control(win, &base, file) else {
            say!("second thread: no control");
            return;
        };
        show(&c, r);
        let (mut caps, mut bad) = (0, 0);
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            pump_for(Duration::from_millis(30));
            let (_, px) = c.capture(size.0, size.1);
            if visible(&px) > 0 {
                caps += 1;
                if foreign(file, &px) > 20 {
                    bad += 1;
                }
            }
        }
        say!("second thread ({file}): {caps} captures, {bad} with foreign colours");
        unshow(&c);
        c.close();
    })
}
