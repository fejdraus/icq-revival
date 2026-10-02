//! Where our keys live between runs.
//!
//! `%APPDATA%\ICQ E2E\<uin>.state` holds the JSON of [`OwnKeys`] - the Olm
//! account, the sessions, the pins - protected with DPAPI for the Windows user
//! who is signed in, so another account on the machine cannot read it and a
//! stolen disk cannot either. `ICQE2E_HOME` moves the folder; the tests use
//! that to keep their own state.
//!
//! Every change is written through a temporary file and renamed over the old
//! one, so an interrupted write leaves the previous state intact rather than a
//! half-written file - and a device whose state was lost would silently be a
//! different device to everyone, so a corrupt file is an error and never a
//! reason to start again with fresh keys.
//!
//! The JSON carries its format in `version` ([`STATE_VERSION`]). Fields this
//! build does not know are ignored, and a missing field takes its default, so
//! adding an optional field needs no new version. A change an older build
//! must not read - one that would lose data when it saves the state back,
//! such as post-quantum sessions (CHECKLIST 9.8) - raises the version, and
//! [`migrate`] brings every older version up to the current one. A file of a
//! newer version than this build knows is refused and left untouched.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::keys::OwnKeys;

/// A magic marker so a file that is not ours is not mistaken for one that is.
const MAGIC: &[u8; 8] = b"IQE2E\0S\0";

/// The state format this build writes and reads up to.
///
/// - 1: the first recorded version.
/// - 2: a pin can carry the key the user verified and a hold after a change
///   of a verified contact's key (`keys::PinnedKey::verified`, `held`;
///   CHECKLIST 10.10). A version-1 build would read such a file but drop both
///   when it saves it back - a verification silently lost, and a held
///   conversation released - so it must refuse it instead.
pub const STATE_VERSION: u32 = 2;

/// Brings a state read from disk up to [`STATE_VERSION`], one version at a
/// time. A new version adds its step here.
fn migrate(mut keys: OwnKeys) -> OwnKeys {
    // Version 0 is a file from before the version was recorded; its layout
    // is version 1's.
    if keys.version == 0 {
        keys.version = 1;
    }
    // Version 1 has no verifications: every pin reads as unverified and not
    // held, which is what the field defaults give.
    if keys.version == 1 {
        keys.version = 2;
    }
    keys
}

/// One device's state.
pub struct Store {
    path: PathBuf,
}

impl Store {
    /// The state file of `uin` under `home`.
    pub fn new(home: &Path, uin: &str) -> Store {
        Store {
            path: home.join(format!("{uin}.state")),
        }
    }

    /// Where this store's file is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the state, or `None` if there is none yet. A file that cannot be
    /// opened, unprotected, or parsed is an error: replacing it would throw
    /// away this device's identity, which no peer could then verify.
    pub fn load(&self) -> Result<Option<OwnKeys>, String> {
        if !self.path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&self.path)
            .map_err(|e| format!("{} cannot be read: {e}", self.path.display()))?;
        if !raw.starts_with(MAGIC) {
            return Err(format!(
                "{} is not an ICQ E2E state file",
                self.path.display()
            ));
        }
        let body = protect::unprotect(&raw[MAGIC.len()..])?;
        let json = String::from_utf8(body)
            .map_err(|_| format!("{} did not hold text", self.path.display()))?;
        let not_understood = |e: serde_json::Error| {
            format!(
                "{} did not hold a state this build understands: {e}",
                self.path.display()
            )
        };
        let value: serde_json::Value = serde_json::from_str(&json).map_err(not_understood)?;
        // The version is read before the rest, so a newer file is refused
        // whole rather than half read and then saved back without what this
        // build could not see.
        let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        if version > STATE_VERSION as u64 {
            return Err(format!(
                "{} was written by a newer ICQ E2E add-on (state version {version}, this build reads up to {STATE_VERSION}); it is left as it is",
                self.path.display()
            ));
        }
        let keys: OwnKeys = serde_json::from_value(value).map_err(not_understood)?;
        Ok(Some(migrate(keys)))
    }

    /// Writes the state, creating the folder if it is not there yet.
    pub fn save(&self, keys: &OwnKeys) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)
                .map_err(|e| format!("{} cannot be created: {e}", dir.display()))?;
        }
        let json = serde_json::to_string(keys)
            .map_err(|e| format!("the state cannot be written as text: {e}"))?;
        let mut blob = Vec::with_capacity(MAGIC.len() + json.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&protect::protect(json.as_bytes())?);

        // Written beside the real file and renamed over it: rename is atomic
        // within a folder, so the state is either the old one or the new one.
        let tmp = self.path.with_extension("state.tmp");
        {
            let mut f = fs::File::create(&tmp)
                .map_err(|e| format!("{} cannot be created: {e}", tmp.display()))?;
            f.write_all(&blob)
                .map_err(|e| format!("{} cannot be written: {e}", tmp.display()))?;
            f.sync_all()
                .map_err(|e| format!("{} cannot be flushed: {e}", tmp.display()))?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("{} cannot be replaced: {e}", self.path.display())
        })
    }

    /// The state of `uin` in `home`, making a new one if there is none.
    /// Fails rather than making a new state when a file is there but unusable.
    pub fn open_or_create(home: &Path, uin: &str) -> Result<OwnKeys, String> {
        let store = Store::new(home, uin);
        match store.load()? {
            Some(keys) => Ok(keys),
            None => {
                let keys = OwnKeys::create(uin);
                store.save(&keys)?;
                Ok(keys)
            }
        }
    }
}

#[cfg(windows)]
mod protect {
    //! DPAPI for the signed-in user (`DESIGN.md` section 9).
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    /// A `CRYPT_INTEGER_BLOB` over data this module does not own.
    ///
    /// # Safety
    /// `data` must stay alive and unmodified while the blob is used.
    unsafe fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    unsafe fn reason(op: &str) -> String {
        format!("{op} failed: {}", GetLastError())
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        unsafe {
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // The description only shows in the Windows UI; it is not secret.
            let desc: Vec<u16> = "ICQ E2E state\0".encode_utf16().collect();
            if CryptProtectData(
                &blob(plain),
                desc.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            ) == 0
            {
                return Err(reason("CryptProtectData"));
            }
            let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData.cast());
            Ok(bytes)
        }
    }

    pub fn unprotect(cipher: &[u8]) -> Result<Vec<u8>, String> {
        unsafe {
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            if CryptUnprotectData(
                &blob(cipher),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            ) == 0
            {
                // Wrong user, wrong machine, or a tampered file: none of these
                // may pass for "no state yet".
                return Err(reason("CryptUnprotectData"));
            }
            let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData.cast());
            Ok(bytes)
        }
    }
}

#[cfg(not(windows))]
mod protect {
    //! Off Windows there is no DPAPI, so the tests - and only the tests - get
    //! the bytes back unchanged. The add-on itself is a Windows DLL.
    pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        Ok(plain.to_vec())
    }
    pub fn unprotect(cipher: &[u8]) -> Result<Vec<u8>, String> {
        Ok(cipher.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder of its own per test, removed afterwards.
    struct Home(PathBuf);

    impl Home {
        fn new(name: &str) -> Home {
            let p = std::env::temp_dir().join(format!("icqe2e-store-{name}"));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Home(p)
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_new_uin_gets_a_state_and_an_existing_one_keeps_it() {
        let home = Home::new("new");
        let keys = Store::open_or_create(&home.0, "100001").unwrap();
        assert_eq!(keys.screen_name, "100001");
        assert!(Store::new(&home.0, "100001").path().exists());

        // A second run reads the same account key rather than making a new one.
        let again = Store::open_or_create(&home.0, "100001").unwrap();
        assert_eq!(again.account_key_b64(), keys.account_key_b64());
        assert_eq!(again.device_id, keys.device_id);
    }

    #[test]
    fn what_is_written_is_not_readable_as_text() {
        let home = Home::new("opaque");
        let keys = OwnKeys::create("100001");
        Store::new(&home.0, "100001").save(&keys).unwrap();
        let raw = fs::read(home.0.join("100001.state")).unwrap();
        assert!(raw.starts_with(MAGIC));
        assert!(
            !String::from_utf8_lossy(&raw).contains("100001"),
            "the state must not sit on disk in the clear"
        );
    }

    /// Writes `json` as the state of 100001, protected the way `save` does.
    fn write_json(home: &Home, json: &str) -> PathBuf {
        let path = home.0.join("100001.state");
        let mut blob = MAGIC.to_vec();
        blob.extend_from_slice(&protect::protect(json.as_bytes()).unwrap());
        fs::write(&path, blob).unwrap();
        path
    }

    #[test]
    fn a_state_without_a_version_is_migrated_and_unknown_fields_are_ignored() {
        let home = Home::new("migrate");
        let keys = OwnKeys::create("100001");
        let mut json = serde_json::to_value(&keys).unwrap();
        let obj = json.as_object_mut().unwrap();
        assert_eq!(obj.remove("version"), Some(STATE_VERSION.into()));
        obj.insert("a_field_from_later".into(), serde_json::json!({"x": 1}));
        write_json(&home, &json.to_string());

        let loaded = Store::new(&home.0, "100001").load().unwrap().unwrap();
        assert_eq!(loaded.version, STATE_VERSION);
        assert_eq!(loaded.account_key_b64(), keys.account_key_b64());
        assert_eq!(loaded.device_id, keys.device_id);
    }

    #[test]
    fn a_version_one_state_keeps_its_pins_unverified_and_a_verification_survives() {
        let home = Home::new("v1");
        let mut keys = OwnKeys::create("100001");
        keys.pin("100002", "AAAA", 100);
        let mut json = serde_json::to_value(&keys).unwrap();
        json["version"] = 1.into();
        // A version-1 pin is just the key and the time.
        json["pins"]["100002"] = serde_json::json!({"key": "AAAA", "at": 100});
        write_json(&home, &json.to_string());

        let store = Store::new(&home.0, "100001");
        let mut loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.version, STATE_VERSION);
        let pin = loaded.pinned("100002").unwrap();
        assert_eq!(pin.key, "AAAA");
        assert!(!pin.is_verified() && !pin.held);

        assert!(loaded.verify("100002"));
        store.save(&loaded).unwrap();
        let again = store.load().unwrap().unwrap();
        assert!(again.pinned("100002").unwrap().is_verified());
    }

    #[test]
    fn a_state_from_a_newer_build_is_refused_and_left_alone() {
        let home = Home::new("newer");
        let mut json = serde_json::to_value(OwnKeys::create("100001")).unwrap();
        json["version"] = (STATE_VERSION + 1).into();
        let path = write_json(&home, &json.to_string());
        let before = fs::read(&path).unwrap();

        let Err(err) = Store::new(&home.0, "100001").load() else {
            panic!("a newer state must not load");
        };
        assert!(err.contains("newer ICQ E2E add-on"), "{err}");
        assert!(Store::open_or_create(&home.0, "100001").is_err());
        assert_eq!(fs::read(&path).unwrap(), before, "and is not replaced");
    }

    #[test]
    fn a_file_that_is_not_ours_is_an_error_and_is_left_alone() {
        let home = Home::new("foreign");
        let path = home.0.join("100001.state");
        fs::write(&path, b"not our file at all").unwrap();
        let Err(err) = Store::new(&home.0, "100001").load() else {
            panic!("a foreign file must not load as state");
        };
        assert!(err.contains("not an ICQ E2E state file"), "{err}");
        assert!(Store::open_or_create(&home.0, "100001").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not our file at all");
    }

    #[test]
    fn a_write_that_does_not_finish_leaves_the_previous_state() {
        let home = Home::new("atomic");
        let store = Store::new(&home.0, "100001");
        let mut keys = OwnKeys::create("100001");
        store.save(&keys).unwrap();

        // A leftover temporary file from a write that was killed is ignored,
        // and the real state is what the next run reads.
        fs::write(home.0.join("100001.state.tmp"), b"half written").unwrap();
        assert_eq!(store.load().unwrap().unwrap().device_id, keys.device_id);

        keys.pin("100002", "AAAA", 100);
        store.save(&keys).unwrap();
        assert!(!home.0.join("100001.state.tmp").exists());
        assert_eq!(store.load().unwrap().unwrap().device_id, keys.device_id);
    }

    #[test]
    fn each_uin_has_its_own_file() {
        let home = Home::new("per-uin");
        let a = Store::open_or_create(&home.0, "100001").unwrap();
        let b = Store::open_or_create(&home.0, "100002").unwrap();
        assert_ne!(a.account_key_b64(), b.account_key_b64());
        assert!(home.0.join("100001.state").exists());
        assert!(home.0.join("100002.state").exists());
    }
}
