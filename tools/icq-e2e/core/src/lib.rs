//! Shared engine for the ICQ end-to-end-encryption add-on.
//!
//! Phase 1 is a pass-through rewrite harness: the loaders (tbdiag.dll for ICQ
//! 7.2, msimg32.dll for ICQ 6.5) call [`install`] from their DllMain. It hooks
//! the client's own Winsock calls in the networking core, reassembles FLAP
//! frames, and rewrites the text of instant messages in place with a trivial
//! reversible transform ([`harness`]) - outbound it is applied, inbound undone -
//! fixing every length and keeping the client's frame count and sequence
//! numbers. There is no crypto yet; the point is to prove the transport. With
//! `ICQE2E_MODE=observe` it is the Phase 0 observer: bytes untouched, log only
//! ([`config`]).
//!
//! The protocol modules ([`stream`], [`rewrite`], [`harness`], [`snac`],
//! [`icbm`], [`text`], [`engine`], [`config`]) are plain Rust with no Windows
//! dependencies, so they are unit-tested directly and driven in-process by the
//! test host. Only [`hook`] and [`log`] touch the Windows API.

pub mod caps;
pub mod config;
pub mod engine;
pub mod harness;
pub mod icbm;
pub mod rewrite;
pub mod snac;
pub mod stream;
pub mod text;

#[cfg(windows)]
pub mod hook;
#[cfg(windows)]
pub mod log;

/// Installs the hooks. Idempotent; call once from DllMain on
/// `DLL_PROCESS_ATTACH`. Returns immediately: the actual hooking happens on a
/// worker thread that waits for the networking module to load.
#[cfg(windows)]
pub fn install() {
    let policy = config::Policy::from_env();
    log::line(&format!("Phase 1 add-on loading: {}", policy.describe()));
    hook::start(policy);
}

/// Frame builders shared with the integration tests, for the socket tests.
#[cfg(all(test, windows))]
#[path = "../tests/common/mod.rs"]
mod test_frames;
