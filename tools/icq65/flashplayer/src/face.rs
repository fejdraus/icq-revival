//! The return of a Flash avatar's face to its status face after a smiley.
//!
//! An ICQ 6 animated avatar (a "devil") has a clip `face` whose `emotion`
//! property plays one of the frame labels stam, smile, sad, laugh, mad, cry,
//! love, busy, offline. Each emotion's animation plays once and then stands
//! on its last frame; nothing in the movie goes back to stam.
//!
//! ICQ 6.5 (MUICoreLib `MCDevilImpl::PlayEffect`) sends every face as a pair,
//! `SetVariable("face.emotion", "stam")` and then `SetVariable("face.emotion",
//! e)`, where `e` is the status face (stam, busy, offline, from
//! `ChangeDevilStatus`) or a smiley's face (from `PlayEmoticon`). It never
//! sends the status face again after a smiley, so the smiley's face stays until
//! the next status change. ICQ's own devil testing page (devils.zip) went back
//! to stam 9 seconds after a smiley face.
//!
//! So the player does that for the host: after a smiley face it sets the last
//! status face again, 9 seconds later by default. A new smiley starts the wait
//! again; a status face ends it. The leading "stam" of ICQ's pair is not taken
//! for a status: a smiley that follows a "stam" at once restores the status
//! from before that "stam".
//!
//! A host that times the faces itself (the Miranda plugin) turns this off with
//! `FPCSetFaceReturn(0)`. `FLASHPLAYERCONTROL_FACE_RETURN` (seconds, 0 = off)
//! sets the default.

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// The variable the faces are set through.
pub const VARIABLE: &str = "face.emotion";

/// The wait after a smiley face, as ICQ's devil testing page had it.
pub const DEFAULT_MS: u32 = 9000;

/// How soon after its "stam" the second face of ICQ's pair arrives: the two
/// calls follow each other in the same function.
const PAIR_WINDOW: Duration = Duration::from_millis(250);

/// u32::MAX: not set by the host, see `delay_ms`.
static DELAY_MS: AtomicU32 = AtomicU32::new(u32::MAX);

/// The wait after a smiley face in this process, in milliseconds; 0 = never.
pub fn delay_ms() -> u32 {
    match DELAY_MS.load(Ordering::Relaxed) {
        u32::MAX => {
            let ms = from_env(
                std::env::var("FLASHPLAYERCONTROL_FACE_RETURN")
                    .ok()
                    .as_deref(),
            );
            // A host's FPCSetFaceReturn in between wins.
            let _ = DELAY_MS.compare_exchange(u32::MAX, ms, Ordering::Relaxed, Ordering::Relaxed);
            DELAY_MS.load(Ordering::Relaxed)
        }
        ms => ms,
    }
}

/// Sets the wait for the whole process (FPCSetFaceReturn).
pub fn set_delay_ms(ms: u32) {
    DELAY_MS.store(ms.min(u32::MAX - 1), Ordering::Relaxed);
}

/// FLASHPLAYERCONTROL_FACE_RETURN: whole or fractional seconds.
fn from_env(v: Option<&str>) -> u32 {
    match v.map(str::trim).and_then(|s| s.parse::<f64>().ok()) {
        Some(s) if s.is_finite() && s >= 0.0 => (s * 1000.0).min(86_400_000.0) as u32,
        _ => DEFAULT_MS,
    }
}

/// A status face; any other value is an emotion that ends.
pub fn is_status(value: &str) -> bool {
    ["stam", "busy", "offline"]
        .iter()
        .any(|s| value.eq_ignore_ascii_case(s))
}

/// What the player does with its face timer after a SetVariable.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Not a face.
    None,
    /// A status face: no return is due.
    Cancel,
    /// An emotion: set the status face again after this many milliseconds.
    Arm(u32),
}

/// The faces one movie was told to show.
pub struct Faces {
    /// The last status face.
    status: RefCell<String>,
    /// A "stam" just came: the status before it, and when.
    before_stam: RefCell<Option<(String, Instant)>>,
    /// The return is due (the timer runs).
    pending: Cell<bool>,
}

impl Default for Faces {
    fn default() -> Faces {
        Faces {
            status: RefCell::new("stam".to_owned()),
            before_stam: RefCell::new(None),
            pending: Cell::new(false),
        }
    }
}

impl Faces {
    /// The host set `path` to `value` at `now`; `delay` is the wait in ms.
    pub fn on_set(&self, path: &str, value: &str, now: Instant, delay: u32) -> Action {
        if !path.eq_ignore_ascii_case(VARIABLE) {
            return Action::None;
        }
        if is_status(value) {
            let previous = self.status.replace(value.to_owned());
            *self.before_stam.borrow_mut() =
                value.eq_ignore_ascii_case("stam").then(|| (previous, now));
            self.pending.set(false);
            return Action::Cancel;
        }
        // ICQ's leading "stam" was not a status.
        if let Some((status, at)) = self.before_stam.take() {
            if now.saturating_duration_since(at) <= PAIR_WINDOW {
                *self.status.borrow_mut() = status;
            }
        }
        if delay == 0 {
            self.pending.set(false);
            return Action::Cancel;
        }
        self.pending.set(true);
        Action::Arm(delay)
    }

    /// The face to go back to when the timer fires; None if none is due.
    pub fn take_return(&self) -> Option<String> {
        self.pending
            .replace(false)
            .then(|| self.status.borrow().clone())
    }

    /// A new movie: no return is due for the old one.
    pub fn reset(&self) {
        self.pending.set(false);
        self.before_stam.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: u32 = DEFAULT_MS;

    fn set(f: &Faces, v: &str, t: Instant) -> Action {
        f.on_set(VARIABLE, v, t, D)
    }

    #[test]
    fn a_smiley_returns_to_stam() {
        let f = Faces::default();
        let t = Instant::now();
        assert_eq!(set(&f, "stam", t), Action::Cancel);
        assert_eq!(set(&f, "smile", t), Action::Arm(D));
        assert_eq!(f.take_return().as_deref(), Some("stam"));
        assert_eq!(f.take_return(), None);
    }

    #[test]
    fn icq_pairs_keep_the_status() {
        // ChangeDevilStatus(busy), then PlayEmoticon(":-)"), as ICQ 6.5 sends them.
        let f = Faces::default();
        let t = Instant::now();
        set(&f, "stam", t);
        set(&f, "busy", t);
        set(&f, "stam", t + Duration::from_secs(60));
        assert_eq!(
            set(&f, "smile", t + Duration::from_secs(60)),
            Action::Arm(D)
        );
        assert_eq!(f.take_return().as_deref(), Some("busy"));
    }

    #[test]
    fn offline_pair_and_status_change() {
        let f = Faces::default();
        let t = Instant::now();
        set(&f, "stam", t);
        set(&f, "offline", t);
        let t2 = t + Duration::from_secs(5);
        set(&f, "stam", t2);
        set(&f, "stam", t2); // back online
        let t3 = t2 + Duration::from_secs(5);
        set(&f, "stam", t3);
        set(&f, "laugh", t3);
        assert_eq!(f.take_return().as_deref(), Some("stam"));
    }

    #[test]
    fn a_status_face_cancels_the_return() {
        let f = Faces::default();
        let t = Instant::now();
        set(&f, "sad", t);
        assert_eq!(set(&f, "busy", t + Duration::from_secs(2)), Action::Cancel);
        assert_eq!(f.take_return(), None);
    }

    #[test]
    fn a_late_smiley_after_stam_changes_nothing() {
        // A host without ICQ's pairs: stam is a real status.
        let f = Faces::default();
        let t = Instant::now();
        set(&f, "busy", t);
        set(&f, "stam", t + Duration::from_secs(1));
        set(&f, "cry", t + Duration::from_secs(3));
        assert_eq!(f.take_return().as_deref(), Some("stam"));
    }

    #[test]
    fn off_and_other_variables() {
        let f = Faces::default();
        let t = Instant::now();
        assert_eq!(f.on_set(VARIABLE, "love", t, 0), Action::Cancel);
        assert_eq!(f.take_return(), None);
        assert_eq!(f.on_set("face.other", "love", t, D), Action::None);
        assert_eq!(f.on_set("FACE.EMOTION", "Mad", t, D), Action::Arm(D));
    }

    #[test]
    fn env_values() {
        assert_eq!(from_env(None), DEFAULT_MS);
        assert_eq!(from_env(Some("0")), 0);
        assert_eq!(from_env(Some(" 4.5 ")), 4500);
        assert_eq!(from_env(Some("x")), DEFAULT_MS);
        assert_eq!(from_env(Some("-1")), DEFAULT_MS);
    }
}
