//! What the add-on does, read once from the environment at start.
//!
//! - `ICQE2E_MODE=observe` - Phase 0 behaviour: bytes pass untouched, messages
//!   are only logged. `harness` keeps the Phase 1 transform for transport
//!   checks. Anything else, or nothing, is stage 3: real encryption, unless
//!   `e2e=off` says otherwise. Both are for debugging; the patch never sets
//!   them.
//! - `ICQE2E_E2E` - overrides the `e2e=` line of `icq-e2e.ini`. `off` is an
//!   install that only wants TLS to the server: no message is encrypted, no
//!   key is published, the key directory is never called, the add-on is not
//!   announced to contacts, and the message bytes are the client's own. A
//!   `/e2e` command typed in a chat is still taken out and answered with "end-
//!   to-end encryption is off on this install", so a command typed by mistake
//!   never reaches the contact. Absent, empty or anything but off means on.
//! - `ICQE2E_PEERS=uin1,uin2` - encrypt outbound messages only to these
//!   contacts; inbound containers are always decrypted, whoever sent them.
//! - `ICQE2E_DIRECTORY` - the key directory's base URL. Overrides
//!   `icq-e2e.ini`, which the patch writes next to the client executable with
//!   the domain it configured, and which the add-on looks for there on its own
//!   - it is never told where it is.
//! - `ICQE2E_INI` - a different `icq-e2e.ini` to read. Only an override: the
//!   add-on finds the patch's file without being told.
//! - `ICQE2E_HOME` - where the state files live; `%APPDATA%\ICQ E2E` by
//!   default. Tests point it at a temporary folder.
//! - `ICQE2E_NO_INJECT=1` - the fall back that never adds or removes frames on
//!   the BOS connection: control messages and notes are dropped and the log
//!   says why. For a client that does not take renumbered frames.
//! - `ICQE2E_SERVER`, `ICQE2E_TLS`, `ICQE2E_TLS_PIN` - override the `server=`,
//!   `tls=` and `tls_pin=` lines of `icq-e2e.ini` (STAGE-TLS 2.2, 3.4, 3.5):
//!   the server's DNS name, whose connections are wrapped in TLS 1.3, the
//!   deliberate opt-out `tls=off`, and an optional key pin.
//! - `ICQE2E_CALLS_LOG` - overrides the `calls_log=` line of `icq-e2e.ini`.
//!   `on` hooks the call modules (`sipXtapi.dll`, `sipXmediaLib.dll`) when
//!   they load and logs what kind each media datagram is and what the SIP of
//!   a call says about its media, never content (stage C0 of
//!   `docs/e2e/CALLS-RESEARCH.md`, observation only). Off by default.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

#[cfg(windows)]
use crate::log;

/// Whether the add-on only watches, only rewrites, or encrypts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Phase 0: log only, every byte unchanged.
    Observe,
    /// Phase 1: rewrite message text with the reversible harness transform.
    Harness,
    /// Stage 3: encrypt message text end to end.
    Encrypt,
    /// `e2e=off`: no message encryption, no key directory, no announcement;
    /// message bytes pass as the client wrote them, and only `/e2e` commands
    /// are taken out and answered. TLS works as in encrypt mode.
    Plain,
}

/// The add-on's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mode: Mode,
    /// Contacts outbound encryption is limited to, normalised; `None` for all.
    pub peers: Option<Vec<String>>,
    /// The key directory's base URL, if one is configured. Encryption needs
    /// it; harness and observe mode do not.
    pub directory: Option<String>,
    /// Where the state files go.
    pub home: PathBuf,
    /// Whether frames may be added and removed (the default). With this off
    /// the add-on never changes the frame count on the connection.
    pub inject: bool,
    /// TLS 1.3 on the client's connections to the server.
    pub tls: TlsPolicy,
    /// `calls_log=on`: observe the call media and signalling (stage C0).
    pub calls_log: bool,
}

/// What `server=`, `tls=` and `tls_pin=` say (STAGE-TLS 3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsPolicy {
    /// No `server=` (an ini from before TLS): nothing is mapped, and the log
    /// says so once. Not a failure.
    NoServer,
    /// `tls=off`: the user's deliberate opt-out. Nothing is mapped, and every
    /// sign-on says in the chat that the connection is not encrypted.
    Off { server: String },
    /// Every connection to `server` goes over TLS 1.3, checked against the
    /// Windows trust store and, if any are given, the pins.
    On { server: String, pins: Vec<[u8; 32]> },
    /// `server=`, `tls=` or `tls_pin=` could not be read. Fail closed: the
    /// connections to the server are refused, with the reason.
    Invalid { server: String, why: String },
}

impl TlsPolicy {
    /// Reads the three values. `tls` absent or empty means on.
    pub fn parse(server: Option<&str>, tls: Option<&str>, pins: Option<&str>) -> Self {
        let server = server.map(str::trim).unwrap_or("").trim_matches('"');
        if server.is_empty() {
            return TlsPolicy::NoServer;
        }
        let server = server.to_ascii_lowercase();
        if server.contains(['/', ':', ' ', '\\']) {
            return TlsPolicy::Invalid {
                why: format!("server={server} is not a host name; give the domain only"),
                server,
            };
        }
        let on = match tls.map(str::trim).unwrap_or("") {
            "" => true,
            t if ["on", "1", "true", "yes"]
                .iter()
                .any(|v| t.eq_ignore_ascii_case(v)) =>
            {
                true
            }
            t if ["off", "0", "false", "no"]
                .iter()
                .any(|v| t.eq_ignore_ascii_case(v)) =>
            {
                false
            }
            t => {
                return TlsPolicy::Invalid {
                    why: format!("tls={t} is neither on nor off"),
                    server,
                }
            }
        };
        if !on {
            return TlsPolicy::Off { server };
        }
        match crate::tls::parse_pins(pins.unwrap_or("")) {
            Ok(pins) => TlsPolicy::On { server, pins },
            Err(why) => TlsPolicy::Invalid {
                why: format!("tls_pin: {why}"),
                server,
            },
        }
    }

    /// The server's name, when one is configured.
    pub fn server(&self) -> Option<&str> {
        match self {
            TlsPolicy::NoServer => None,
            TlsPolicy::Off { server }
            | TlsPolicy::On { server, .. }
            | TlsPolicy::Invalid { server, .. } => Some(server),
        }
    }

    /// One phrase for the log.
    pub fn describe(&self) -> String {
        match self {
            TlsPolicy::NoServer => "tls=off (no server= in icq-e2e.ini)".to_string(),
            TlsPolicy::Off { server } => format!("tls=off (opted out) for {server}"),
            TlsPolicy::On { server, pins } if pins.is_empty() => format!("tls=on for {server}"),
            TlsPolicy::On { server, pins } => {
                format!("tls=on for {server} with {} pin(s)", pins.len())
            }
            TlsPolicy::Invalid { server, why } => {
                format!("tls=refused for {server} (settings: {why})")
            }
        }
    }
}

/// The raw values of the settings, as they come from the environment and the
/// `icq-e2e.ini` the patch writes. Every field is optional, so a test can name
/// only what it cares about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings<'a> {
    pub mode: Option<&'a str>,
    pub peers: Option<&'a str>,
    pub directory: Option<&'a str>,
    pub home: Option<&'a str>,
    pub no_inject: Option<&'a str>,
    /// `on` or `off`; the `e2e=` line of the ini.
    pub e2e: Option<&'a str>,
    /// Path of the `icq-e2e.ini` to read the `directory=`, `e2e=`, `server=`,
    /// `tls=` and `tls_pin=` lines from.
    pub ini_path: Option<&'a str>,
    pub server: Option<&'a str>,
    pub tls: Option<&'a str>,
    pub tls_pin: Option<&'a str>,
}

impl Settings<'_> {
    /// Where the ini the patch wrote is looked for, and whether it was there.
    ///
    /// The patch puts it in the client's own folder, next to the executable,
    /// because that is the one place both the patch and the add-on can agree on
    /// without either of them being told the other's name. `ICQE2E_INI` still
    /// wins, so a test or a second installation can point somewhere else.
    pub fn ini_location() -> (PathBuf, bool) {
        if let Ok(given) = std::env::var("ICQE2E_INI") {
            let p = PathBuf::from(given);
            let found = p.is_file();
            return (p, found);
        }
        let p = client_folder().join(INI_FILE);
        let found = p.is_file();
        (p, found)
    }
}

/// The folder the client's executable is in, which is where the patch writes
/// `icq-e2e.ini`.
///
/// The add-on is a DLL loaded into ICQ.exe, so its own module path is inside
/// the client folder but is not the executable: on 7.2 the add-on is
/// `tbdiag.dll`, and on 6.5 it is `msimg32.dll`. Asking the process for the
/// main module gets the executable itself, which is the folder the patch uses.
#[cfg(windows)]
fn client_folder() -> PathBuf {
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    let mut buf = [0u16; 260];
    // A module whose path does not fit is not the client's own folder, and a
    // truncated path would look like a wrong one.
    let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        return PathBuf::from(".");
    }
    let path = PathBuf::from(OsString::from_wide(&buf[..n as usize]));
    path.parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

#[cfg(not(windows))]
fn client_folder() -> PathBuf {
    PathBuf::from(".")
}

/// The name the patch writes: `tools/patcher/Icq{65,72}/*Client.cs`.
pub const INI_FILE: &str = "icq-e2e.ini";

impl Policy {
    /// Log-only, as in Phase 0.
    pub fn observe() -> Self {
        Policy {
            mode: Mode::Observe,
            peers: None,
            directory: None,
            home: default_home(),
            inject: false,
            tls: TlsPolicy::NoServer,
            calls_log: false,
        }
    }

    /// Rewriting for every contact, no directory.
    pub fn harness() -> Self {
        Policy {
            mode: Mode::Harness,
            peers: None,
            directory: None,
            home: default_home(),
            inject: false,
            tls: TlsPolicy::NoServer,
            calls_log: false,
        }
    }

    /// Reads the environment and the `icq-e2e.ini` the patch writes next to the
    /// client executable.
    ///
    /// The ini is found without the environment having to name it, because the
    /// patch writes it beside the client and never tells the add-on where it
    /// put it. Without this the add-on logs `directory=unset` right next to a
    /// perfectly good ini, and encryption stays off with nothing to publish to.
    pub fn from_env() -> Self {
        let (path, found) = Settings::ini_location();
        let path = path.to_string_lossy().into_owned();
        log::line(&format!(
            "Looking for {INI_FILE} in {}: {}",
            path.rsplit_once(['\\', '/']).map_or(".", |(dir, _)| dir),
            if found { "found" } else { "not found" }
        ));
        Policy::from_settings(Settings {
            ini_path: Some(&path),
            ..Settings::default()
        })
    }

    /// Builds a policy from the settings, falling back to what the environment
    /// says for every value the settings leave out.
    pub fn from_settings(s: Settings<'_>) -> Self {
        fn pick(set: Option<&str>, env: Option<String>) -> Option<String> {
            match set {
                Some(v) => Some(v.to_string()),
                None => env,
            }
        }
        fn env(name: &str) -> Option<String> {
            std::env::var(name).ok()
        }
        // A `directory` given as an argument wins over both the environment and
        // the ini file; an empty or missing one lets the ini file speak.
        let directory = s
            .directory
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_string);
        Policy::build(Raw {
            mode: pick(s.mode, env("ICQE2E_MODE")),
            peers: pick(s.peers, env("ICQE2E_PEERS")),
            directory: directory.or_else(|| {
                env("ICQE2E_DIRECTORY")
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())
            }),
            home: pick(s.home, env("ICQE2E_HOME")),
            no_inject: pick(s.no_inject, env("ICQE2E_NO_INJECT")),
            e2e: pick(s.e2e, env("ICQE2E_E2E")),
            ini_path: pick(s.ini_path, env("ICQE2E_INI")),
            server: pick(s.server, env("ICQE2E_SERVER")),
            tls: pick(s.tls, env("ICQE2E_TLS")),
            tls_pin: pick(s.tls_pin, env("ICQE2E_TLS_PIN")),
            calls_log: env("ICQE2E_CALLS_LOG"),
        })
    }

    /// The shared body of [`Policy::from_settings`] and [`Policy::from_env`].
    /// A value the arguments and the environment leave out is read from the
    /// ini file.
    fn build(raw: Raw) -> Self {
        let ini = |key: &str| raw.ini_path.as_deref().and_then(|p| read_ini_value(p, key));
        let mode = match raw.mode.as_deref().map(str::trim) {
            Some(m) if m.eq_ignore_ascii_case("observe") => Mode::Observe,
            Some(m) if m.eq_ignore_ascii_case("harness") => Mode::Harness,
            _ if !e2e_on(raw.e2e.clone().or_else(|| ini("e2e")).as_deref()) => Mode::Plain,
            _ => Mode::Encrypt,
        };
        let peers: Vec<String> = raw
            .peers
            .as_deref()
            .unwrap_or("")
            .split([',', ';'])
            .map(normalise)
            .filter(|p| !p.is_empty())
            .collect();
        let directory = raw.directory.clone().or_else(|| ini("directory"));
        let home = raw
            .home
            .as_deref()
            .filter(|h| !h.trim().is_empty())
            .map_or_else(default_home, PathBuf::from);
        let server = raw.server.clone().or_else(|| ini("server"));
        let tls = raw.tls.clone().or_else(|| ini("tls"));
        let tls_pin = raw.tls_pin.clone().or_else(|| ini("tls_pin"));
        let calls_log = raw.calls_log.clone().or_else(|| ini("calls_log"));
        Policy {
            mode,
            peers: (!peers.is_empty()).then_some(peers),
            directory,
            home,
            inject: !matches!(
                raw.no_inject.as_deref().map(str::trim),
                Some("1") | Some("true")
            ),
            tls: TlsPolicy::parse(server.as_deref(), tls.as_deref(), tls_pin.as_deref()),
            calls_log: switched_on(calls_log.as_deref()),
        }
    }

    /// Whether a message to `peer` is encrypted or rewritten.
    pub fn rewrites_to(&self, peer: &str) -> bool {
        match &self.peers {
            None => true,
            Some(list) => {
                let p = normalise(peer);
                list.contains(&p)
            }
        }
    }

    /// Whether frames may be added and removed on the connection. Only
    /// encryption adds control messages and notes, and `e2e=off` takes out a
    /// `/e2e` command and answers it, so only those two modes are ever allowed
    /// to; observe mode is the log-only kill switch.
    pub fn may_inject(&self) -> bool {
        self.inject && matches!(self.mode, Mode::Encrypt | Mode::Plain)
    }

    /// One line for the log.
    pub fn describe(&self) -> String {
        let what = match self.mode {
            Mode::Observe => "mode=observe (log only, bytes unchanged)",
            Mode::Harness => "mode=harness (rewriting message text)",
            Mode::Encrypt => "mode=encrypt (end-to-end encryption)",
            Mode::Plain => "mode=plain (e2e=off: no message encryption, no key directory)",
        };
        let peers = match &self.peers {
            None => String::new(),
            Some(p) => format!(", peers={}", p.join(",")),
        };
        format!(
            "{what}{peers}, directory={}, frames={}, {}, home={}{}",
            self.directory.as_deref().unwrap_or("unset"),
            if self.inject {
                "may be added"
            } else {
                "never added"
            },
            self.tls.describe(),
            self.home.display(),
            if self.calls_log {
                ", calls_log=on (call media observed, nothing changed)"
            } else {
                ""
            }
        )
    }
}

/// `%APPDATA%\ICQ E2E`, where the state files go unless `ICQE2E_HOME` says
/// otherwise.
fn default_home() -> PathBuf {
    match std::env::var("APPDATA") {
        Ok(app) if !app.is_empty() => PathBuf::from(app).join("ICQ E2E"),
        _ => PathBuf::from("ICQ E2E"),
    }
}

/// The values the policy is built from, each optional.
#[derive(Default)]
struct Raw {
    mode: Option<String>,
    peers: Option<String>,
    directory: Option<String>,
    home: Option<String>,
    no_inject: Option<String>,
    e2e: Option<String>,
    ini_path: Option<String>,
    server: Option<String>,
    tls: Option<String>,
    tls_pin: Option<String>,
    calls_log: Option<String>,
}

/// Whether a switch that is off unless asked for (`calls_log=`) is on: only a
/// clear yes.
fn switched_on(v: Option<&str>) -> bool {
    matches!(v.map(str::trim), Some(t) if ["on", "1", "true", "yes"]
        .iter()
        .any(|o| t.eq_ignore_ascii_case(o)))
}

/// Whether `e2e=` asks for end-to-end encryption. Only a clear "off" turns it
/// off: a missing line (an ini from before the setting) or a value that cannot
/// be read keeps the stricter behaviour.
fn e2e_on(v: Option<&str>) -> bool {
    !matches!(v.map(str::trim), Some(t) if ["off", "0", "false", "no"]
        .iter()
        .any(|o| t.eq_ignore_ascii_case(o)))
}

/// The `key=` line of `icq-e2e.ini`, which the patch writes next to the
/// client. `key = value` lines, `#` and `;` comments, blank lines; keys
/// without case. An empty value counts as absent.
fn read_ini_value(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((k, value)) = line.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(key) {
            let v = value.trim().trim_matches('"');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Screen names compare without case and spaces, as OSCAR does.
fn normalise(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy from settings alone, so the tests read nothing from the
    /// environment.
    fn policy(s: Settings<'_>) -> Policy {
        let own = |v: Option<&str>| v.map(str::to_string);
        Policy::build(Raw {
            mode: Some(s.mode.unwrap_or("encrypt").to_string()),
            peers: own(s.peers),
            directory: own(s.directory),
            home: own(s.home),
            no_inject: own(s.no_inject),
            e2e: own(s.e2e),
            ini_path: own(s.ini_path),
            server: own(s.server),
            tls: own(s.tls),
            tls_pin: own(s.tls_pin),
            calls_log: None,
        })
    }

    #[test]
    fn defaults_to_encrypt() {
        let p = policy(Settings::default());
        assert_eq!(p.mode, Mode::Encrypt);
        assert!(p.rewrites_to("12345"));
        assert!(p.directory.is_none());
        assert!(p.inject);
        assert!(p.may_inject());
    }

    #[test]
    fn observe_and_harness_switches() {
        assert_eq!(
            policy(Settings {
                mode: Some(" Observe "),
                ..Default::default()
            })
            .mode,
            Mode::Observe
        );
        assert_eq!(
            policy(Settings {
                mode: Some("harness"),
                ..Default::default()
            })
            .mode,
            Mode::Harness
        );
        // Neither mode may change the frame count.
        assert!(!policy(Settings {
            mode: Some("observe"),
            ..Default::default()
        })
        .may_inject());
        assert!(!policy(Settings {
            mode: Some("harness"),
            ..Default::default()
        })
        .may_inject());
    }

    #[test]
    fn no_inject_falls_back_to_never_adding_frames() {
        let p = policy(Settings {
            no_inject: Some("1"),
            ..Default::default()
        });
        assert!(!p.inject);
        assert!(!p.may_inject());
        assert!(
            policy(Settings {
                no_inject: Some("0"),
                ..Default::default()
            })
            .inject
        );
    }

    #[test]
    fn peer_list() {
        let p = policy(Settings {
            peers: Some("100001, 100002;Some Name"),
            ..Default::default()
        });
        assert!(p.rewrites_to("100001"));
        assert!(p.rewrites_to("100002"));
        assert!(p.rewrites_to("somename"));
        assert!(!p.rewrites_to("100003"));
        assert_eq!(
            policy(Settings {
                peers: Some(" , "),
                ..Default::default()
            })
            .peers,
            None
        );
    }

    #[test]
    fn the_ini_file_gives_the_directory() {
        let dir = std::env::temp_dir().join("icqe2e-ini-test");
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("icq-e2e.ini");
        std::fs::write(
            &ini,
            "# written by the patch\ndirectory = https://example.test:8102/e2e/v1/\n\n",
        )
        .unwrap();
        let path = ini.to_str().unwrap();
        let p = policy(Settings {
            ini_path: Some(path),
            ..Default::default()
        });
        assert_eq!(
            p.directory.as_deref(),
            Some("https://example.test:8102/e2e/v1/")
        );
        // A directory named in the settings wins over the file.
        let p = policy(Settings {
            directory: Some("https://other.test:8102/e2e/v1/"),
            ini_path: Some(path),
            ..Default::default()
        });
        assert_eq!(
            p.directory.as_deref(),
            Some("https://other.test:8102/e2e/v1/")
        );
        assert!(read_ini_value("no such file here", "directory").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The patch writes `icq-e2e.ini` beside the client executable and never
    /// tells the add-on where it put it, so the add-on has to look there on its
    /// own. This is the bug that made a patched ICQ 7.2 log `directory=unset`
    /// with a good ini sitting in the same folder.
    #[test]
    fn the_ini_is_looked_for_next_to_the_client_without_being_named() {
        // ICQE2E_INI wins, so it has to be out of the way for this.
        let given = std::env::var("ICQE2E_INI");
        unsafe { std::env::remove_var("ICQE2E_INI") };

        let (path, found) = Settings::ini_location();
        assert_eq!(path, client_folder().join(INI_FILE));
        // The test binary sits next to nothing, so this is normally absent; the
        // point is the folder, not the file.
        assert_eq!(found, path.is_file());

        // Named explicitly, it is that exact file and nothing else.
        unsafe { std::env::set_var("ICQE2E_INI", "D:\\somewhere\\icq-e2e.ini") };
        let (path, found) = Settings::ini_location();
        assert_eq!(path, PathBuf::from("D:\\somewhere\\icq-e2e.ini"));
        assert!(!found);

        if let Ok(v) = given {
            unsafe { std::env::set_var("ICQE2E_INI", v) };
        } else {
            unsafe { std::env::remove_var("ICQE2E_INI") };
        }
    }

    /// The folder is the client's own, not the add-on's: the DLL is `tbdiag.dll`
    /// on 7.2 and `msimg32.dll` on 6.5, and the ini goes beside the executable
    /// the patch was pointed at.
    #[test]
    fn the_client_folder_is_the_folder_of_the_executable() {
        let folder = client_folder();
        assert!(folder.is_absolute(), "got {}", folder.display());
        assert!(
            folder.join(INI_FILE).parent() == Some(folder.as_path()),
            "the ini lands in the client's own folder"
        );
    }

    #[test]
    fn home_moves_with_the_variable() {
        let p = policy(Settings {
            home: Some("C:\\tmp\\e2e"),
            ..Default::default()
        });
        assert_eq!(p.home, PathBuf::from("C:\\tmp\\e2e"));
        assert!(policy(Settings {
            home: Some(" "),
            ..Default::default()
        })
        .home
        .ends_with("ICQ E2E"));
    }

    /// The patch's ini from this stage on: `server=` and `tls=on`.
    #[test]
    fn the_ini_gives_the_tls_settings() {
        let dir = std::env::temp_dir().join("icqe2e-ini-tls-test");
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("icq-e2e.ini");
        let path = ini.to_str().unwrap();
        let read = |text: &str| {
            std::fs::write(&ini, text).unwrap();
            policy(Settings {
                ini_path: Some(path),
                ..Default::default()
            })
            .tls
        };
        assert_eq!(
            read("directory = https://icq.example.org:8102/e2e/v1/\r\nserver = ICQ.example.org\r\ntls = on\r\n"),
            TlsPolicy::On {
                server: "icq.example.org".into(),
                pins: Vec::new()
            }
        );
        // An old ini without server= keeps working in plaintext.
        assert_eq!(
            read("directory = https://icq.example.org:8102/e2e/v1/\r\n"),
            TlsPolicy::NoServer
        );
        // The deliberate opt-out.
        assert_eq!(
            read("server = icq.example.org\r\ntls = off\r\n"),
            TlsPolicy::Off {
                server: "icq.example.org".into()
            }
        );
        // No tls= line at all is on.
        assert!(matches!(
            read("server = icq.example.org\r\n"),
            TlsPolicy::On { .. }
        ));
        // The environment or the arguments win over the file.
        let p = policy(Settings {
            ini_path: Some(path),
            tls: Some("on"),
            ..Default::default()
        });
        assert!(matches!(p.tls, TlsPolicy::On { .. }), "{:?}", p.tls);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `calls_log=` is off unless it says on, whatever else the ini says.
    #[test]
    fn calls_log_is_off_unless_switched_on() {
        let dir = std::env::temp_dir().join("icqe2e-ini-calls-test");
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("icq-e2e.ini");
        let path = ini.to_str().unwrap();
        let read = |text: &str| {
            std::fs::write(&ini, text).unwrap();
            policy(Settings {
                ini_path: Some(path),
                ..Default::default()
            })
        };
        for (text, on) in [
            ("", false),
            ("calls_log = off\n", false),
            ("calls_log =\n", false),
            ("calls_log = maybe\n", false),
            ("calls_log = on\n", true),
            ("CALLS_LOG=On\n", true),
            ("e2e = off\ncalls_log = 1\n", true),
        ] {
            let p = read(text);
            assert_eq!(p.calls_log, on, "{text:?}");
            assert_eq!(p.describe().contains("calls_log=on"), on, "{text:?}");
        }
        assert_eq!(read("calls_log = on\n").mode, Mode::Encrypt);
        assert!(!Policy::observe().calls_log);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `e2e=off` (the patch's "TLS only" install) turns encryption off and
    /// nothing else; observe and harness stay what they were.
    #[test]
    fn e2e_off_is_plain_mode_with_tls() {
        let dir = std::env::temp_dir().join("icqe2e-ini-e2e-test");
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("icq-e2e.ini");
        let path = ini.to_str().unwrap();
        let read = |text: &str, e2e: Option<&str>| {
            std::fs::write(&ini, text).unwrap();
            policy(Settings {
                ini_path: Some(path),
                e2e,
                ..Default::default()
            })
        };
        let base = "directory = https://icq.example.org:8102/e2e/v1/
server = icq.example.org
";
        // The patch's two rows.
        let p = read(
            &format!(
                "{base}e2e = off
tls = on
"
            ),
            None,
        );
        assert_eq!(p.mode, Mode::Plain);
        assert!(matches!(p.tls, TlsPolicy::On { .. }), "{:?}", p.tls);
        assert!(p.may_inject(), "a /e2e command is still taken out");
        assert!(p.describe().contains("mode=plain"));
        assert_eq!(
            read(
                &format!(
                    "{base}e2e = on
tls = off
"
                ),
                None
            )
            .mode,
            Mode::Encrypt
        );
        // An ini from before the setting, an empty value or one that cannot be
        // read keeps encryption on.
        for text in [
            "",
            "e2e =
",
            "e2e = maybe
",
        ] {
            assert_eq!(
                read(&format!("{base}{text}"), None).mode,
                Mode::Encrypt,
                "{text:?}"
            );
        }
        for off in ["OFF", " 0 ", "false", "no"] {
            assert_eq!(read(base, Some(off)).mode, Mode::Plain, "{off:?}");
        }
        // The environment (here the settings) wins over the file.
        assert_eq!(
            read(
                &format!(
                    "{base}e2e = off
"
                ),
                Some("on")
            )
            .mode,
            Mode::Encrypt
        );
        // Observe and harness are debugging switches and stay as they are.
        std::fs::write(
            &ini,
            format!(
                "{base}e2e = off
"
            ),
        )
        .unwrap();
        for (m, want) in [("observe", Mode::Observe), ("harness", Mode::Harness)] {
            let p = policy(Settings {
                mode: Some(m),
                ini_path: Some(path),
                ..Default::default()
            });
            assert_eq!(p.mode, want);
            assert!(!p.may_inject());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// What cannot be read fails closed rather than falling back to plaintext.
    #[test]
    fn unreadable_tls_settings_fail_closed() {
        let invalid = |server: &str, tls: Option<&str>, pin: Option<&str>| {
            matches!(
                TlsPolicy::parse(Some(server), tls, pin),
                TlsPolicy::Invalid { .. }
            )
        };
        assert!(invalid("icq.example.org", Some("maybe"), None));
        assert!(invalid("icq.example.org", None, Some("md5/abc")));
        assert!(invalid("icq.example.org:5190", None, None));
        assert!(invalid("https://icq.example.org", None, None));
        assert_eq!(
            TlsPolicy::parse(Some("  "), Some("on"), None),
            TlsPolicy::NoServer
        );
        let pin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(
            TlsPolicy::parse(Some("icq.example.org"), Some("ON"), Some(pin)),
            TlsPolicy::On {
                server: "icq.example.org".into(),
                pins: vec![[0u8; 32]]
            }
        );
        assert!(TlsPolicy::parse(Some("icq.example.org"), Some("off"), None)
            .describe()
            .contains("opted out"));
    }
}
