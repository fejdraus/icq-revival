//! Shared engine for the ICQ end-to-end-encryption add-on.
//!
//! Phase 0 is observation only: the loaders (tbdiag.dll for ICQ 7.2, msimg32.dll
//! for ICQ 6.5) call [`install`] from their DllMain. It hooks the client's own
//! Winsock `send`/`recv` in the networking core, reassembles FLAP frames, parses
//! ICBM (channel 1 and channel 2) and ICQ offline messages, and writes the
//! decoded text to a log. Every byte reaches the client and server unchanged;
//! there is no crypto and no rewriting in this phase.
//!
//! The parsing modules ([`flap`], [`snac`], [`icbm`], [`text`], [`engine`]) are
//! plain Rust with no Windows dependencies, so they are unit-tested directly and
//! driven in-process by the test host. Only [`hook`] and [`log`] touch the
//! Windows API.

pub mod engine;
pub mod flap;
pub mod icbm;
pub mod snac;
pub mod text;

#[cfg(windows)]
pub mod hook;
#[cfg(windows)]
pub mod log;

/// Installs the observation hooks. Idempotent; call once from DllMain on
/// `DLL_PROCESS_ATTACH`. Returns immediately: the actual hooking happens on a
/// worker thread that waits for the networking module to load.
#[cfg(windows)]
pub fn install() {
    log::line("Phase 0 observer loading (log-only; bytes pass through unchanged)");
    hook::start();
}
