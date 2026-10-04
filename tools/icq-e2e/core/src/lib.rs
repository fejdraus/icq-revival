//! Shared engine for the ICQ end-to-end-encryption add-on.
//!
//! The loaders (tbdiag.dll for ICQ 7.2, msimg32.dll for ICQ 6.5) call
//! [`install`] from their DllMain. It hooks the client's own Winsock calls in
//! the networking core, reassembles FLAP frames and rewrites the text of
//! instant messages in place, fixing every length around them.
//!
//! Three modes, chosen by [`config::Policy`]:
//!
//! - `observe`: bytes untouched, log only. The first thing that ever ran.
//! - `harness`: the text of a message is passed through a trivial reversible
//!   transform ([`harness`]) - outbound it is applied, inbound undone - with the
//!   client's own frame count and sequence numbers untouched. This is what
//!   proved the transport before there was any crypto.
//! - `encrypt` (the default): messages are Olm-encrypted to the recipient's
//!   device ([`crypto`], [`keys`], [`container`]) and the key directory
//!   ([`directory`]) hands out the keys. A message to someone without the add-on
//!   still goes out, in clear, with a note saying so.
//!
//! [`session`] is what ties it together: it owns the one engine per signed-on
//! connection, its state file ([`store`]), and the publish and refill steps. The
//! socket layer ([`stream`]) knows frames, not keys.
//!
//! The protocol modules are plain Rust with no Windows dependencies, so they are
//! unit-tested directly and driven in-process by the test host. Only [`hook`],
//! [`log`], [`store`] and [`winhttp`] touch Windows.

// The same name inside the crate and from outside it, so code shared between
// the library's unit tests and the integration tests can name it either way.
extern crate self as icqe2e_core;
pub mod actions;
pub mod alert;
pub mod authz;
pub mod bytes;
pub mod callmedia;
pub mod callneg;
pub mod calls;
pub mod caps;
pub mod config;
pub mod container;
pub mod crypto;
pub mod direct;
pub mod directory;
pub mod engine;
pub mod files;
pub mod filesneg;
pub mod filestream;
pub mod gate;
pub mod harness;
pub mod icbm;
pub mod keys;
pub mod kt;
pub mod pe;
pub mod policy;
pub mod rewrite;
pub mod route;
pub mod safety;
pub mod session;
pub mod sign;
pub mod snac;
pub mod store;
pub mod stream;
pub mod text;
pub mod tls;
pub mod token;
pub mod tzer;

#[cfg(windows)]
pub mod winhttp;

#[cfg(windows)]
pub mod hook;
#[cfg(windows)]
pub mod log;

/// Starts the add-on. Idempotent; call once from DllMain on
/// `DLL_PROCESS_ATTACH`. Only what is safe under the loader lock happens
/// here (the loader notification, patching a networking module already
/// mapped, creating the bootstrap thread); reading the settings, logging and
/// everything else happen on the bootstrap thread once the lock is released
/// ([`hook::start_from_loader`]). Until then the protection gate holds every
/// hooked call ([`gate`]).
#[cfg(windows)]
pub fn install() {
    hook::start_from_loader(None);
}

/// [`install`], with `prewarm` run first on the bootstrap thread: a loader
/// stub's own work that must stay out of `DllMain` (msimg32's real exports).
#[cfg(windows)]
pub fn install_with(prewarm: fn()) {
    hook::start_from_loader(Some(prewarm));
}

/// Frame builders shared with the integration tests, for the socket tests.
#[cfg(all(test, windows))]
#[path = "../tests/common/mod.rs"]
mod test_frames;
