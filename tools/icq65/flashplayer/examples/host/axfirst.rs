//! `host <dll> axfirst <base dir|url> <out> <names...>`: the two field bugs of
//! the ShockwaveFlash control in ICQ's Boxely UI, reproduced in the container.
//!
//! 1. First paint. The container paints an element only while it is "ready"
//!    (like boxelyRenderer, which skips an element whose state flag is not
//!    set), and repaints only when the control calls InvalidateRect. Movies
//!    load while no element is ready; then the elements become ready without
//!    any repaint of the container's own. Every avatar must appear anyway.
//!    Then the same while a modal dialog loop runs (the "tip" dialog).
//! 2. Size. Draw with a rectangle that differs from SetObjectRects, in both of
//!    boxelyRenderer's paths, with sizes that change, and with Scale NoBorder,
//!    ShowAll and ExactFit: the smiley's round face must stay round except
//!    with ExactFit.

use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::{InvalidateRect, UpdateWindow};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::axhost::{Hosted, PAINT, PaintItem, container_window, grab, host_control, save_png};
use crate::pump_for;

/// Background colour at client pixel (x, y) of the container (BGR).
fn bg_at(x: i32, y: i32) -> [u8; 3] {
    let (sx, sy) = (x / 16 * 16, y / 16 * 16);
    if ((sx + sy) / 16) % 2 == 0 {
        [0xC0, 0x60, 0x20]
    } else {
        [0xA0, 0xA0, 0xA0]
    }
}

/// Width/height of the yellow face in BGRA pixels (w x h), None if none.
fn face_aspect(px: &[u8], w: usize, x0: usize, y0: usize, cw: usize, ch: usize) -> Option<f64> {
    let (mut minx, mut miny, mut maxx, mut maxy) = (usize::MAX, usize::MAX, 0, 0);
    for y in y0..y0 + ch {
        for x in x0..x0 + cw {
            let i = (y * w + x) * 4;
            let (b, g, r) = (px[i], px[i + 1], px[i + 2]);
            if r > 200 && g > 190 && b < 90 {
                minx = minx.min(x);
                maxx = maxx.max(x);
                miny = miny.min(y);
                maxy = maxy.max(y);
            }
        }
    }
    if maxx <= minx || maxy <= miny {
        return None;
    }
    Some((maxx - minx + 1) as f64 / (maxy - miny + 1) as f64)
}

/// Draw into a memory DC whose mapping mode scales logical lw x lh to
/// device dw x dh (MM_ANISOTROPIC). Premultiplied BGRA device pixels.
unsafe fn scaled_capture(view: crate::Unk, lw: i32, lh: i32, dw: i32, dh: i32) -> Vec<u8> {
    use windows_sys::Win32::Graphics::Gdi::*;
    unsafe {
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = dw;
        bi.bmiHeader.biHeight = -dh;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        let mut bits: *mut core::ffi::c_void = null_mut();
        let bmp = CreateDIBSection(null_mut(), &bi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        let dc = CreateCompatibleDC(null_mut());
        let old = SelectObject(dc, bmp);
        SetMapMode(dc, MM_ANISOTROPIC);
        SetWindowExtEx(dc, lw, lh, null_mut());
        SetViewportExtEx(dc, dw, dh, null_mut());
        let r = RECT {
            left: 0,
            top: 0,
            right: lw,
            bottom: lh,
        };
        vcall!(
            view,
            3,
            fn(
                u32,
                i32,
                crate::Unk,
                crate::Unk,
                HDC,
                HDC,
                *const RECT,
                *const RECT,
                usize,
                usize,
            ) -> i32,
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
        let px = std::slice::from_raw_parts(bits as *const u8, (dw * dh * 4) as usize).to_vec();
        SelectObject(dc, old);
        DeleteDC(dc);
        DeleteObject(bmp);
        px
    }
}

fn set_ready(ready: bool) {
    PAINT.with(|p| {
        for item in p.borrow_mut().iter_mut() {
            item.ready = ready;
        }
    });
}

// A modal dialog that closes itself after `ms` milliseconds.
unsafe extern "system" fn dlg_proc(hwnd: HWND, msg: u32, _wp: WPARAM, lp: LPARAM) -> isize {
    unsafe {
        match msg {
            WM_INITDIALOG => {
                SetWindowPos(hwnd, null_mut(), 1100, 60, 300, 120, SWP_NOZORDER);
                SetTimer(hwnd, 1, lp as u32, None);
                1
            }
            WM_TIMER => {
                EndDialog(hwnd, 1);
                1
            }
            _ => 0,
        }
    }
}

fn modal_dialog(owner: HWND, ms: u32) {
    // DLGTEMPLATE + empty menu, class and title, DWORD-aligned.
    let mut t = vec![0u32; 16];
    unsafe {
        let p = t.as_mut_ptr() as *mut u8;
        let style = (WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE) | DS_MODALFRAME as u32;
        std::ptr::write_unaligned(p as *mut u32, style);
        // dwExtendedStyle 0, cdit 0, x, y, cx, cy
        std::ptr::write_unaligned(p.add(10) as *mut i16, 10);
        std::ptr::write_unaligned(p.add(12) as *mut i16, 10);
        std::ptr::write_unaligned(p.add(14) as *mut i16, 150);
        std::ptr::write_unaligned(p.add(16) as *mut i16, 60);
        DialogBoxIndirectParamW(
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(null()),
            t.as_ptr().cast(),
            owner,
            Some(dlg_proc),
            ms as LPARAM,
        );
    }
}

pub fn run(base: &str, out: &str, names: &[String]) -> bool {
    let _ = std::fs::create_dir_all(out);
    let ok1 = first_paint(base, out, names, Model::StaticLater);
    let ok2 = first_paint(base, out, names, Model::HiddenFrame);
    let ok3 = sizes(base, out);
    say!(
        "result: first paint (static movies, host ready later) ok {ok1}, first paint (hidden frame window) ok {ok2}, sizes ok {ok3}"
    );
    ok1 && ok2 && ok3
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Model {
    /// Every movie pauses after its first frame (one repaint request only);
    /// the host starts painting the elements later, without a repaint of
    /// its own. Then a modal dialog runs while the faces change.
    StaticLater,
    /// The site's window is a hidden child of the container (like
    /// boxelyRenderer's ActiveX frame window when it is hidden): the
    /// control's InvalidateRect produces no paint; only the visible
    /// container paints the elements, and never on its own.
    HiddenFrame,
}

fn first_paint(base: &str, out: &str, names: &[String], model: Model) -> bool {
    let (cw, ch) = (87, 109);
    let cols = 8;
    let rows = names.len().div_ceil(cols) as i32;
    let (ww, wh) = (cols as i32 * (cw + 4) + 4, rows * (ch + 4) + 4);
    let win = container_window(ww, wh, "first paint");
    let tag = format!("{model:?}");
    // The window the site reports (IOleWindow::GetWindow) and invalidates.
    let site_win = if model == Model::HiddenFrame {
        let cls: Vec<u16> = "STATIC".encode_utf16().chain(Some(0)).collect();
        unsafe {
            CreateWindowExW(
                0,
                cls.as_ptr(),
                null(),
                WS_CHILD,
                0,
                0,
                ww,
                wh,
                win,
                null_mut(),
                windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(null()),
                null(),
            )
        }
    } else {
        win
    };
    let params = [
        ("WMode", "transparent"),
        ("Scale", "NoBorder"),
        ("Quality", "High"),
    ];
    let mut hosted: Vec<(Hosted, RECT)> = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let x = 4 + (i % cols) as i32 * (cw + 4);
        let y = 4 + (i / cols) as i32 * (ch + 4);
        let rect = RECT {
            left: x,
            top: y,
            right: x + cw,
            bottom: y + ch,
        };
        match host_control(site_win, rect, &params, n, false) {
            Ok(h) => {
                let ready = model == Model::HiddenFrame;
                PAINT.with(|p| {
                    p.borrow_mut().push(PaintItem {
                        view: h.view,
                        rect,
                        ready,
                        path_a: i % 2 == 1,
                    })
                });
                hosted.push((h, rect));
            }
            Err(e) => {
                say!("[{n}] cannot host: {e}");
                return false;
            }
        }
    }
    let sep = if base.starts_with("http") { "/" } else { "\\" };
    for (h, _) in &hosted {
        h.put_movie_dispatch(&format!("{base}{sep}{}", h.name));
        h.play();
    }
    unsafe { UpdateWindow(win) }; // the host paints once, before any frame
    let t = Instant::now();
    let mut paused = vec![false; hosted.len()];
    let mut loaded: Vec<Option<Instant>> = vec![None; hosted.len()];
    while t.elapsed() < Duration::from_secs(30) && paused.iter().any(|p| !p) {
        pump_for(Duration::from_millis(5));
        for (i, (h, _)) in hosted.iter().enumerate() {
            if loaded[i].is_none() && h.ready_state() == 4 {
                loaded[i] = Some(Instant::now());
            }
            // After 700 ms of playing the picture stops changing (a still
            // avatar): no more frames, so no more repaint requests.
            if !paused[i] && loaded[i].is_some_and(|l| l.elapsed() > Duration::from_millis(700)) {
                if model == Model::StaticLater {
                    h.stop_play();
                }
                paused[i] = true;
            }
        }
    }
    pump_for(Duration::from_millis(1500));
    let inv_before: Vec<u32> = hosted.iter().map(|(h, _)| h.invalidations()).collect();
    say!(
        "[{tag}] {} movies loaded{}; repaint requests the site got so far: {:?}",
        hosted.len(),
        if model == Model::StaticLater {
            " and paused, while the host painted no element"
        } else {
            " behind a hidden site window"
        },
        inv_before
    );
    if model == Model::StaticLater {
        // The elements become ready; the container does not repaint on its own.
        set_ready(true);
    }
    pump_for(Duration::from_millis(1500));
    let (missing, blank) = check_shown(win, &hosted, &format!("{out}\\first-paint-{tag}.png"));
    say!(
        "[{tag}] {}/{} avatars show their current frame on screen ({} have no picture yet and are not counted); not shown {:?}",
        hosted.len() - missing.len() - blank,
        hosted.len() - blank,
        blank,
        missing
    );
    if model == Model::HiddenFrame {
        PAINT.with(|p| p.borrow_mut().clear());
        for (h, _) in hosted {
            h.close();
        }
        unsafe {
            DestroyWindow(site_win);
            DestroyWindow(win);
        }
        return missing.is_empty();
    }

    // Modal dialog: the host paints no element while it runs; the faces
    // change to "love" and play, then stand still before the dialog closes
    // and the elements become ready (no repaint of the container's own).
    set_ready(false);
    for (h, _) in &hosted {
        h.play();
        h.set_variable("face.emotion", "love");
    }
    let t = Instant::now();
    modal_dialog(win, 2000);
    for (h, _) in &hosted {
        h.stop_play();
    }
    say!(
        "[{tag}] modal dialog loop ran {} ms while the faces changed and no element was painted",
        t.elapsed().as_millis()
    );
    pump_for(Duration::from_millis(300));
    set_ready(true);
    pump_for(Duration::from_millis(1500));
    let (stale, blank2) = check_shown(win, &hosted, &format!("{out}\\after-modal-{tag}.png"));
    say!(
        "[{tag}] after the modal dialog: {}/{} avatars show their new frame; not shown {:?}",
        hosted.len() - stale.len() - blank2,
        hosted.len() - blank2,
        stale
    );
    PAINT.with(|p| p.borrow_mut().clear());
    for (h, _) in hosted {
        h.close();
    }
    unsafe { DestroyWindow(win) };
    missing.is_empty() && stale.is_empty()
}

/// Whether each control's current frame is what the screen shows: the
/// screenshot against the control's own Draw into a memory DC, composited on
/// the background. Captures come after the screenshot (a capture is a Draw,
/// and would count as the host having drawn). Returns (not shown, blank).
fn check_shown(win: HWND, hosted: &[(Hosted, RECT)], png: &str) -> (Vec<String>, usize) {
    let shot = grab(win);
    crate::axhost::screenshot(win, png);
    let mut missing = Vec::new();
    let mut blank = 0;
    for (h, r) in hosted {
        let (w, hgt) = (r.right - r.left, r.bottom - r.top);
        let (_, cap) = h.capture(w, hgt);
        if cap.chunks_exact(4).filter(|p| p[3] > 0).count() < (w * hgt / 20) as usize {
            blank += 1; // nothing to show yet
            continue;
        }
        let (mut n, mut ok) = (0u32, 0u32);
        for y in 0..hgt {
            for x in 0..w {
                let c = &cap[((y * w + x) * 4) as usize..][..4];
                let bg = bg_at(r.left + x, r.top + y);
                let a = c[3] as i32;
                let si = (((r.top + y) * shot.0 + r.left + x) * 4) as usize;
                n += 1;
                let good = (0..3).all(|k| {
                    let expect = c[k] as i32 + bg[k] as i32 * (255 - a) / 255;
                    (shot.2[si + k] as i32 - expect).abs() <= 40
                });
                if good {
                    ok += 1;
                }
            }
        }
        let share = ok as f64 / n.max(1) as f64;
        if share < 0.9 {
            missing.push(format!(
                "{} ({:.0}% of pixels match)",
                h.name,
                share * 100.0
            ));
        }
    }
    (missing, blank)
}

fn sizes(base: &str, out: &str) -> bool {
    let win = container_window(760, 300, "sizes");
    let params = [("WMode", "transparent"), ("Scale", "NoBorder")];
    let obj = RECT {
        left: 10,
        top: 10,
        right: 97,
        bottom: 119,
    };
    let h = match host_control(win, obj, &params, "smile.swf", false) {
        Ok(h) => h,
        Err(e) => {
            say!("sizes: cannot host: {e}");
            return false;
        }
    };
    let sep = if base.starts_with("http") { "/" } else { "\\" };
    h.put_movie_dispatch(&format!("{base}{sep}smile.swf"));
    h.play();
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(20) && h.ready_state() != 4 {
        pump_for(Duration::from_millis(50));
    }
    pump_for(Duration::from_millis(300));
    let sizes = [
        (87, 109),
        (38, 49),
        (50, 60),
        (60, 40),
        (30, 80),
        (120, 120),
    ];
    let mut ok = true;
    // Reference: the face at the movie's own size.
    let (_, px) = h.capture(87, 109);
    let reference = face_aspect(&px, 87, 0, 0, 87, 109).unwrap_or(1.0);
    say!("sizes: face aspect at 87x109 (NoBorder) {reference:.3}");
    let sheet_w: usize = sizes.iter().map(|s| s.0 as usize + 4).sum();
    let sheet_h = 3 * 124;
    let mut sheet = vec![0u8; sheet_w * sheet_h * 4];
    for (row, scale) in ["NoBorder", "ShowAll", "ExactFit"].iter().enumerate() {
        let hr = h.put_scale(scale);
        pump_for(Duration::from_millis(200));
        let mut line = Vec::new();
        let mut x0 = 0usize;
        for (w, hgt) in sizes {
            // Draw into a memory DC with a rectangle unlike SetObjectRects.
            let (_, px) = h.capture(w, hgt);
            for y in 0..hgt as usize {
                let d = ((row * 124 + y) * sheet_w + x0) * 4;
                sheet[d..d + w as usize * 4]
                    .copy_from_slice(&px[y * w as usize * 4..(y + 1) * w as usize * 4]);
            }
            x0 += w as usize + 4;
            let a = face_aspect(&px, w as usize, 0, 0, w as usize, hgt as usize);
            let rel = a.map(|a| a / reference);
            // Round must stay round unless ExactFit stretches it.
            let expect = if *scale == "ExactFit" {
                (w as f64 / hgt as f64) / (87.0 / 109.0)
            } else {
                1.0
            };
            let cropped = *scale == "NoBorder"
                && ((w as f64 / hgt as f64) / (87.0 / 109.0) - 1.0).abs() > 0.15;
            let good = cropped || rel.is_some_and(|r| (r - expect).abs() / expect < 0.12);
            ok &= good;
            line.push(format!(
                "{w}x{hgt}: {}",
                rel.map_or("no face".into(), |r| {
                    if cropped {
                        format!("{r:.2} (face cropped, not checked)")
                    } else {
                        format!(
                            "{r:.2} (expect {expect:.2}){}",
                            if good { "" } else { " WRONG" }
                        )
                    }
                })
            ));
        }
        say!(
            "sizes: Scale {scale} (put_Scale {hr:#x}): face aspect relative to 87x109: {}",
            line.join(", ")
        );
    }
    save_png(
        &format!("{out}\\sizes-scale-modes.png"),
        sheet_w as u32,
        sheet_h as u32,
        &sheet,
    );
    h.put_scale("NoBorder");

    // A DC that scales: logical 49x49 is 38x49 device pixels (a host that
    // lays out in its own units). The face must stay round on the device.
    for (lw, lh, dw, dh) in [(49, 49, 38, 49), (60, 60, 60, 40), (87, 109, 87, 109)] {
        let px = unsafe { scaled_capture(h.view, lw, lh, dw, dh) };
        let a = face_aspect(&px, dw as usize, 0, 0, dw as usize, dh as usize);
        let rel = a.map(|a| a / reference);
        let cropped = ((dw as f64 / dh as f64) / (87.0 / 109.0) - 1.0).abs() > 0.15;
        let good = cropped || rel.is_some_and(|r| (r - 1.0).abs() < 0.12);
        ok &= good;
        save_png(
            &format!("{out}\\sizes-scaled-dc-{lw}x{lh}-to-{dw}x{dh}.png"),
            dw as u32,
            dh as u32,
            &px,
        );
        say!(
            "sizes: Draw({lw}x{lh} logical) into a DC mapped to {dw}x{dh} device pixels: face aspect {}{}",
            rel.map_or("no face".into(), |r| format!("{r:.2}")),
            if cropped {
                " (NoBorder crops the face here, not checked)"
            } else if good {
                ""
            } else {
                " WRONG (squeezed)"
            }
        );
    }

    // Windowless painting while SetObjectRects changes, and boxelyRenderer's
    // memory-DC path with an element rectangle unlike SetObjectRects.
    let mut item_rects = Vec::new();
    for (i, (w, hgt)) in [(38, 49), (60, 40), (120, 120), (50, 60)]
        .iter()
        .enumerate()
    {
        let r = RECT {
            left: 10,
            top: 10,
            right: 10 + w,
            bottom: 10 + hgt,
        };
        let path_a = i % 2 == 1;
        let draw_rect = if path_a {
            // Path A: the element sits elsewhere at another size.
            RECT {
                left: 300,
                top: 20,
                right: 300 + hgt,
                bottom: 20 + w,
            }
        } else {
            r
        };
        h.set_object_rects(r);
        PAINT.with(|p| {
            let mut p = p.borrow_mut();
            p.clear();
            p.push(PaintItem {
                view: h.view,
                rect: draw_rect,
                ready: true,
                path_a,
            });
        });
        unsafe { InvalidateRect(win, null(), 0) };
        pump_for(Duration::from_millis(300));
        let shot = grab(win);
        let (sw, _, spx) = &shot;
        let dw = (draw_rect.right - draw_rect.left) as usize;
        let dh = (draw_rect.bottom - draw_rect.top) as usize;
        let a = face_aspect(
            spx,
            *sw as usize,
            draw_rect.left as usize,
            draw_rect.top as usize,
            dw,
            dh,
        );
        let rel = a.map(|a| a / reference);
        let good = rel.is_some_and(|r| (r - 1.0).abs() < 0.12);
        ok &= good;
        say!(
            "sizes: SetObjectRects {w}x{hgt}, host draws {} at {dw}x{dh}: face aspect {}{}",
            if path_a {
                "through a memory DC (path A)"
            } else {
                "windowless into its DC"
            },
            rel.map_or("no face".into(), |r| format!("{r:.2}")),
            if good { "" } else { " WRONG" }
        );
        item_rects.push(draw_rect);
        crate::axhost::screenshot(win, &format!("{out}\\sizes-window-{i}.png"));
    }
    PAINT.with(|p| p.borrow_mut().clear());
    h.close();
    unsafe { DestroyWindow(win) };
    ok
}
