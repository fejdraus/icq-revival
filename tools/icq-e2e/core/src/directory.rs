//! The key directory client (docs/e2e/KEY-DIRECTORY-API.md).
//!
//! [`DirectoryApi`] is what the key manager ([`crate::keys`]) needs of the
//! directory, one method per endpoint. [`HttpDirectory`] implements it as the
//! API document says - JSON bodies, the token as a bearer header, errors as
//! `{"error": code}` - over a [`Transport`], which on Windows is WinHTTP
//! (`crate::winhttp`). [`MemoryDirectory`] implements it in memory, checking
//! signatures and announcements the way the server does, for the tests and the
//! test host.
//!
//! Keys, signatures and key ids travel as the base64 strings of the API
//! (standard alphabet, no padding, as vodozemac writes them).

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::sign;
use crate::token::{self, Token};

/// A failed call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirError {
    /// The directory answered with an error: HTTP status, the API's code, and
    /// the message it sent with it.
    ///
    /// The message says which check failed - "missing bearer token" against
    /// "the session of this token has ended" are both `401 unauthorized`, and
    /// only the message tells them apart.
    Api {
        status: u16,
        code: String,
        message: String,
    },
    /// No answer: network, TLS, timeout, or a reply that is not the API's.
    Net(String),
}

impl DirError {
    /// The API error code, or "" for a network failure.
    pub fn code(&self) -> &str {
        match self {
            DirError::Api { code, .. } => code,
            DirError::Net(_) => "",
        }
    }
}

impl std::fmt::Display for DirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirError::Api {
                status,
                code,
                message,
            } if message.is_empty() => write!(f, "{status} {code}"),
            DirError::Api {
                status,
                code,
                message,
            } => write!(f, "{status} {code}: {message}"),
            DirError::Net(why) => write!(f, "directory unreachable: {why}"),
        }
    }
}

pub type DirResult<T> = Result<T, DirError>;

/// A device as the directory lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub device_id: u32,
    pub curve25519_key: String,
    pub ed25519_key: String,
    pub account_signature: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub last_seen_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

/// One of the caller's own devices and its pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceState {
    pub device: Device,
    pub one_time_key_count: u32,
    pub has_fallback_key: bool,
}

/// A one-time or fallback key with the device's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKey {
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
}

/// An account's key and devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDevices {
    pub screen_name: String,
    pub account_key: String,
    pub devices: Vec<Device>,
}

/// What a claim hands out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub screen_name: String,
    pub account_key: String,
    pub device: Device,
    #[serde(default)]
    pub one_time_key: Option<SignedKey>,
    #[serde(default)]
    pub fallback_key: Option<SignedKey>,
}

/// What the key manager needs of the directory.
pub trait DirectoryApi: Send + Sync {
    /// `PUT /account` without proof: publish (201), keep (200) or reset (200).
    fn put_account(&self, bearer: &str, account_key: &str, self_signature: &str) -> DirResult<()>;
    /// `PUT /devices/{id}`.
    fn put_device(
        &self,
        bearer: &str,
        device_id: u32,
        curve25519_key: &str,
        ed25519_key: &str,
        account_signature: &str,
    ) -> DirResult<DeviceState>;
    /// `GET /devices/{id}`.
    fn get_device(&self, bearer: &str, device_id: u32) -> DirResult<DeviceState>;
    /// `POST /devices/{id}/one-time-keys`; the pool's new size.
    fn upload_one_time_keys(
        &self,
        bearer: &str,
        device_id: u32,
        keys: &[SignedKey],
    ) -> DirResult<u32>;
    /// `PUT /devices/{id}/fallback-key`.
    fn put_fallback_key(&self, bearer: &str, device_id: u32, key: &SignedKey) -> DirResult<()>;
    /// `GET /users/{uin}/devices`.
    fn user_devices(&self, uin: &str) -> DirResult<UserDevices>;
    /// `POST /users/{uin}/devices/{id}/claim`.
    fn claim(&self, bearer: &str, uin: &str, device_id: u32) -> DirResult<Claim>;
    /// `POST /token`: a fresh token for the same session.
    fn refresh_token(&self, bearer: &str) -> DirResult<String>;
    /// `GET /log/checkpoint`: the key log's signed checkpoint, `None` if the
    /// server keeps no log (docs/e2e/KEY-TRANSPARENCY.md).
    fn log_checkpoint(&self) -> DirResult<Option<String>> {
        Ok(None)
    }
    /// `GET /log/key`: the key log's verifier key, `None` without a log.
    fn log_key(&self) -> DirResult<Option<String>> {
        Ok(None)
    }
    /// `GET /log/entries`: up to `count` leaves from index `start`.
    fn log_entries(&self, _start: u64, _count: u64) -> DirResult<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
}

/// A shared directory is the directory: a session owns its directory so it
/// needs no lifetime of its own, and `Arc` is how it shares one.
impl<T: DirectoryApi + ?Sized> DirectoryApi for std::sync::Arc<T> {
    fn put_account(&self, bearer: &str, account_key: &str, self_signature: &str) -> DirResult<()> {
        (**self).put_account(bearer, account_key, self_signature)
    }
    fn put_device(
        &self,
        bearer: &str,
        device_id: u32,
        curve25519_key: &str,
        ed25519_key: &str,
        account_signature: &str,
    ) -> DirResult<DeviceState> {
        (**self).put_device(
            bearer,
            device_id,
            curve25519_key,
            ed25519_key,
            account_signature,
        )
    }
    fn get_device(&self, bearer: &str, device_id: u32) -> DirResult<DeviceState> {
        (**self).get_device(bearer, device_id)
    }
    fn upload_one_time_keys(
        &self,
        bearer: &str,
        device_id: u32,
        keys: &[SignedKey],
    ) -> DirResult<u32> {
        (**self).upload_one_time_keys(bearer, device_id, keys)
    }
    fn put_fallback_key(&self, bearer: &str, device_id: u32, key: &SignedKey) -> DirResult<()> {
        (**self).put_fallback_key(bearer, device_id, key)
    }
    fn user_devices(&self, uin: &str) -> DirResult<UserDevices> {
        (**self).user_devices(uin)
    }
    fn claim(&self, bearer: &str, uin: &str, device_id: u32) -> DirResult<Claim> {
        (**self).claim(bearer, uin, device_id)
    }
    fn refresh_token(&self, bearer: &str) -> DirResult<String> {
        (**self).refresh_token(bearer)
    }
    fn log_checkpoint(&self) -> DirResult<Option<String>> {
        (**self).log_checkpoint()
    }
    fn log_key(&self) -> DirResult<Option<String>> {
        (**self).log_key()
    }
    fn log_entries(&self, start: u64, count: u64) -> DirResult<Vec<Vec<u8>>> {
        (**self).log_entries(start, count)
    }
}

// --- over HTTP -----------------------------------------------------------------

/// One HTTP exchange: method, path under the API's base URL, bearer token, JSON
/// body. Returns the status and the body.
pub trait Transport: Send + Sync {
    fn call(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), String>;
}

/// The directory over HTTP.
pub struct HttpDirectory<T: Transport> {
    transport: T,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    /// The directory's own words about what it refused, the only thing that
    /// separates the several reasons for one `401 unauthorized`.
    #[serde(default)]
    message: String,
}

impl<T: Transport> HttpDirectory<T> {
    pub fn new(transport: T) -> Self {
        HttpDirectory { transport }
    }

    fn call<R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> DirResult<Option<R>> {
        let body = body.map(|b| b.to_string().into_bytes());
        let (status, reply) = self
            .transport
            .call(method, path, bearer, body.as_deref())
            .map_err(DirError::Net)?;
        if !(200..300).contains(&status) {
            let (code, message) = serde_json::from_slice::<ErrorBody>(&reply)
                .map(|e| (e.error, e.message))
                .unwrap_or_else(|_| (format!("http_{status}"), String::new()));
            return Err(DirError::Api {
                status,
                code,
                message,
            });
        }
        if status == 204 || reply.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&reply)
            .map(Some)
            .map_err(|e| DirError::Net(format!("unexpected reply to {method} {path}: {e}")))
    }

    fn need<R>(r: DirResult<Option<R>>, what: &str) -> DirResult<R> {
        r?.ok_or_else(|| DirError::Net(format!("empty reply to {what}")))
    }

    /// A `GET` whose answer is plain text; `None` for a 404, the answer of a
    /// server that does not have the endpoint.
    fn text(&self, path: &str) -> DirResult<Option<String>> {
        let (status, reply) = self
            .transport
            .call("GET", path, None, None)
            .map_err(DirError::Net)?;
        match status {
            404 => Ok(None),
            200..=299 => String::from_utf8(reply)
                .map(Some)
                .map_err(|_| DirError::Net(format!("unexpected reply to GET {path}"))),
            _ => Err(DirError::Api {
                status,
                code: format!("http_{status}"),
                message: String::new(),
            }),
        }
    }
}

impl<T: Transport> DirectoryApi for HttpDirectory<T> {
    fn put_account(&self, bearer: &str, account_key: &str, self_signature: &str) -> DirResult<()> {
        let body =
            serde_json::json!({"account_key": account_key, "self_signature": self_signature});
        self.call::<serde_json::Value>("PUT", "account", Some(bearer), Some(body))
            .map(|_| ())
    }

    fn put_device(
        &self,
        bearer: &str,
        device_id: u32,
        curve25519_key: &str,
        ed25519_key: &str,
        account_signature: &str,
    ) -> DirResult<DeviceState> {
        let body = serde_json::json!({
            "curve25519_key": curve25519_key,
            "ed25519_key": ed25519_key,
            "account_signature": account_signature,
        });
        let path = format!("devices/{device_id}");
        Self::need(self.call("PUT", &path, Some(bearer), Some(body)), &path)
    }

    fn get_device(&self, bearer: &str, device_id: u32) -> DirResult<DeviceState> {
        let path = format!("devices/{device_id}");
        Self::need(self.call("GET", &path, Some(bearer), None), &path)
    }

    fn upload_one_time_keys(
        &self,
        bearer: &str,
        device_id: u32,
        keys: &[SignedKey],
    ) -> DirResult<u32> {
        #[derive(Deserialize)]
        struct Count {
            one_time_key_count: u32,
        }
        let path = format!("devices/{device_id}/one-time-keys");
        let body = serde_json::json!({ "keys": keys });
        Self::need::<Count>(self.call("POST", &path, Some(bearer), Some(body)), &path)
            .map(|c| c.one_time_key_count)
    }

    fn put_fallback_key(&self, bearer: &str, device_id: u32, key: &SignedKey) -> DirResult<()> {
        let path = format!("devices/{device_id}/fallback-key");
        let body = serde_json::to_value(key).map_err(|e| DirError::Net(e.to_string()))?;
        self.call::<serde_json::Value>("PUT", &path, Some(bearer), Some(body))
            .map(|_| ())
    }

    fn user_devices(&self, uin: &str) -> DirResult<UserDevices> {
        let path = format!("users/{}/devices", sign::ident(uin));
        Self::need(self.call("GET", &path, None, None), &path)
    }

    fn claim(&self, bearer: &str, uin: &str, device_id: u32) -> DirResult<Claim> {
        let path = format!("users/{}/devices/{device_id}/claim", sign::ident(uin));
        Self::need(self.call("POST", &path, Some(bearer), None), &path)
    }

    fn refresh_token(&self, bearer: &str) -> DirResult<String> {
        #[derive(Deserialize)]
        struct Fresh {
            token: String,
        }
        Self::need::<Fresh>(self.call("POST", "token", Some(bearer), None), "token")
            .map(|f| f.token)
    }

    fn log_checkpoint(&self) -> DirResult<Option<String>> {
        self.text("log/checkpoint")
    }

    fn log_key(&self) -> DirResult<Option<String>> {
        self.text("log/key")
    }

    fn log_entries(&self, start: u64, count: u64) -> DirResult<Vec<Vec<u8>>> {
        #[derive(Deserialize)]
        struct Entries {
            entries: Vec<String>,
        }
        let path = format!("log/entries?start={start}&count={count}");
        Self::need::<Entries>(self.call("GET", &path, None, None), &path)?
            .entries
            .iter()
            .map(|e| {
                vodozemac::base64_decode(e)
                    .map_err(|_| DirError::Net(format!("a log entry is not base64 ({path})")))
            })
            .collect()
    }
}

// --- in memory -----------------------------------------------------------------

/// A key directory in memory that keeps the server's rules that matter to a
/// client: signatures are checked, a first publish or a reset needs the key
/// announced on the connection, a claim hands a one-time key out once and the
/// fallback key after that.
#[derive(Default)]
pub struct MemoryDirectory {
    inner: Mutex<Memory>,
}

#[derive(Default)]
struct Memory {
    accounts: HashMap<String, MemAccount>,
    announced: HashMap<String, String>,
    /// Calls that fail as if the directory could not be reached.
    offline: bool,
    /// Requests seen, for tests: "METHOD path". The key log's are not.
    log: Vec<String>,
    /// The key log: its leaves, and whether changes are written to it.
    kt: Vec<Vec<u8>>,
    kt_off: bool,
    /// Changes are made without a leaf: a directory that lies.
    kt_paused: bool,
    /// The log's signing key; another seed is another key.
    kt_seed: u8,
}

impl Memory {
    fn kt_append(&mut self, kind: &str, sn: &str, fields: &[&[u8]]) {
        if !self.kt_paused {
            let time = self.kt.len() as u64 + 1;
            self.kt.push(crate::kt::build_leaf(kind, sn, time, fields));
        }
    }

    fn kt_device(&mut self, sn: &str, d: &Device) {
        let raw = |s: &str| vodozemac::base64_decode(s).unwrap_or_default();
        let (c, e, s) = (
            raw(&d.curve25519_key),
            raw(&d.ed25519_key),
            raw(&d.account_signature),
        );
        self.kt_append("device", sn, &[&d.device_id.to_be_bytes(), &c, &e, &s]);
    }
}

/// The name the in-memory key log signs its checkpoints with.
pub const MEMORY_LOG: &str = "memory.test/e2e-kt";

#[derive(Default, Clone)]
struct MemAccount {
    key: String,
    devices: Vec<MemDevice>,
}

#[derive(Clone)]
struct MemDevice {
    device: Device,
    one_time: Vec<SignedKey>,
    fallback: Option<SignedKey>,
}

fn api(status: u16, code: &str) -> DirError {
    DirError::Api {
        status,
        code: code.to_string(),
        message: String::new(),
    }
}

fn key32(b64: &str) -> Option<[u8; 32]> {
    vodozemac::base64_decode(b64).ok()?.try_into().ok()
}

fn verify(signer_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (
        vodozemac::Ed25519PublicKey::from_base64(signer_b64),
        vodozemac::Ed25519Signature::from_base64(sig_b64),
    ) else {
        return false;
    };
    pk.verify(msg, &sig).is_ok()
}

impl MemoryDirectory {
    pub fn new() -> Self {
        MemoryDirectory::default()
    }

    /// A token for an account, as the MOTD would carry it.
    pub fn token(&self, screen_name: &str) -> Vec<u8> {
        token::unsigned(&sign::ident(screen_name), u32::MAX)
    }

    /// Records the account key announced on the account's BOS connection
    /// (`LocateSetInfo` TLV 0x0E2E).
    pub fn announce(&self, screen_name: &str, key: &[u8]) {
        let mut m = self.inner.lock().unwrap();
        m.announced
            .insert(sign::ident(screen_name), vodozemac::base64_encode(key));
    }

    /// Makes every call fail as unreachable (or work again).
    pub fn set_offline(&self, offline: bool) {
        self.inner.lock().unwrap().offline = offline;
    }

    /// Requests seen so far.
    pub fn requests(&self) -> Vec<String> {
        self.inner.lock().unwrap().log.clone()
    }

    /// One-time keys left in a device's pool.
    pub fn pool(&self, screen_name: &str, device_id: u32) -> usize {
        let m = self.inner.lock().unwrap();
        m.accounts
            .get(&sign::ident(screen_name))
            .and_then(|a| a.devices.iter().find(|d| d.device.device_id == device_id))
            .map_or(0, |d| d.one_time.len())
    }

    /// Revokes a device, as the management API does.
    pub fn revoke(&self, screen_name: &str, device_id: u32) {
        let mut m = self.inner.lock().unwrap();
        let sn = sign::ident(screen_name);
        let mut revoked = false;
        if let Some(a) = m.accounts.get_mut(&sn) {
            for d in &mut a.devices {
                if d.device.device_id == device_id && d.device.revoked_at.is_none() {
                    d.device.revoked_at = Some(1);
                    d.one_time.clear();
                    d.fallback = None;
                    revoked = true;
                }
            }
        }
        if revoked {
            m.kt_append("revoke", &sn, &[&device_id.to_be_bytes()]);
        }
    }

    /// Takes the key log away (or brings it back), as an older server.
    pub fn set_log(&self, on: bool) {
        self.inner.lock().unwrap().kt_off = !on;
    }

    /// Changes made while paused get no leaf: the directory then serves keys
    /// the log does not have.
    pub fn pause_log(&self, paused: bool) {
        self.inner.lock().unwrap().kt_paused = paused;
    }

    /// Replaces a leaf: the log's history rewritten.
    pub fn rewrite_log(&self, index: usize, leaf: Vec<u8>) {
        self.inner.lock().unwrap().kt[index] = leaf;
    }

    /// Drops the leaves from `size` on: the log restored from an old backup.
    pub fn truncate_log(&self, size: usize) {
        self.inner.lock().unwrap().kt.truncate(size);
    }

    /// The number of leaves in the log.
    pub fn log_size(&self) -> usize {
        self.inner.lock().unwrap().kt.len()
    }

    /// Signs the log with another key from now on.
    pub fn rekey_log(&self) {
        self.inner.lock().unwrap().kt_seed += 1;
    }

    /// Adds a device to an account as it is, unchecked - as a server that
    /// slips its own device into someone's account would. It goes into the
    /// log like any device, unless the log is paused.
    pub fn plant_device(&self, screen_name: &str, device: Device) {
        let mut m = self.inner.lock().unwrap();
        let sn = sign::ident(screen_name);
        m.kt_device(&sn, &device);
        if let Some(a) = m.accounts.get_mut(&sn) {
            a.devices.push(MemDevice {
                device,
                one_time: Vec::new(),
                fallback: None,
            });
        }
    }

    fn kt_checkpoint(m: &Memory) -> (String, String) {
        let mut edge = crate::kt::Edge::default();
        for l in &m.kt {
            edge.push(crate::kt::leaf_hash(l));
        }
        crate::kt::sign_checkpoint(
            MEMORY_LOG,
            &[m.kt_seed.wrapping_add(1); 32],
            edge.size,
            &edge.root().unwrap_or_default(),
        )
    }

    fn with<R>(
        &self,
        what: String,
        bearer: Option<&str>,
        f: impl FnOnce(&mut Memory, &str) -> DirResult<R>,
    ) -> DirResult<R> {
        let mut m = self.inner.lock().unwrap();
        m.log.push(what);
        if m.offline {
            return Err(DirError::Net("offline (test)".into()));
        }
        let sn = match bearer {
            Some(b) => {
                Token::from_bearer(b)
                    .ok_or_else(|| api(401, "unauthorized"))?
                    .screen_name
            }
            None => String::new(),
        };
        f(&mut m, &sn)
    }
}

impl Memory {
    fn device_mut(&mut self, sn: &str, id: u32) -> DirResult<&mut MemDevice> {
        let a = self
            .accounts
            .get_mut(sn)
            .ok_or_else(|| api(404, "no_account"))?;
        let d = a
            .devices
            .iter_mut()
            .find(|d| d.device.device_id == id)
            .ok_or_else(|| api(404, "no_device"))?;
        if d.device.revoked_at.is_some() {
            return Err(api(410, "device_revoked"));
        }
        Ok(d)
    }

    fn state(d: &MemDevice) -> DeviceState {
        DeviceState {
            device: d.device.clone(),
            one_time_key_count: d.one_time.len() as u32,
            has_fallback_key: d.fallback.is_some(),
        }
    }
}

impl DirectoryApi for MemoryDirectory {
    fn put_account(&self, bearer: &str, account_key: &str, self_signature: &str) -> DirResult<()> {
        self.with("PUT account".into(), Some(bearer), |m, sn| {
            let key = key32(account_key).ok_or_else(|| api(400, "invalid_key"))?;
            if !verify(account_key, &sign::account(sn, &key), self_signature) {
                return Err(api(400, "invalid_signature"));
            }
            let announced = m.announced.get(sn).is_some_and(|k| k == account_key);
            match m.accounts.get_mut(sn) {
                Some(a) if a.key == account_key => Ok(()),
                Some(a) => {
                    if a.devices.iter().any(|d| d.device.revoked_at.is_none()) {
                        return Err(api(409, "active_devices"));
                    }
                    if !announced {
                        return Err(api(403, "not_announced"));
                    }
                    a.key = account_key.to_string();
                    m.kt_append("account", sn, &[b"reset", &key]);
                    Ok(())
                }
                None => {
                    if !announced {
                        return Err(api(403, "not_announced"));
                    }
                    m.accounts.insert(
                        sn.to_string(),
                        MemAccount {
                            key: account_key.to_string(),
                            devices: Vec::new(),
                        },
                    );
                    m.kt_append("account", sn, &[b"publish", &key]);
                    Ok(())
                }
            }
        })
    }

    fn put_device(
        &self,
        bearer: &str,
        device_id: u32,
        curve25519_key: &str,
        ed25519_key: &str,
        account_signature: &str,
    ) -> DirResult<DeviceState> {
        self.with(format!("PUT devices/{device_id}"), Some(bearer), |m, sn| {
            let resigned = vodozemac::base64_decode(account_signature).unwrap_or_default();
            let a = m
                .accounts
                .get_mut(sn)
                .ok_or_else(|| api(404, "no_account"))?;
            let (Some(c), Some(e)) = (key32(curve25519_key), key32(ed25519_key)) else {
                return Err(api(400, "invalid_key"));
            };
            if !verify(
                &a.key,
                &sign::device(sn, device_id, &c, &e),
                account_signature,
            ) {
                return Err(api(400, "invalid_signature"));
            }
            if let Some(d) = a
                .devices
                .iter_mut()
                .find(|d| d.device.device_id == device_id)
            {
                if d.device.revoked_at.is_some() {
                    return Err(api(410, "device_revoked"));
                }
                if d.device.curve25519_key != curve25519_key || d.device.ed25519_key != ed25519_key
                {
                    return Err(api(409, "device_conflict"));
                }
                let changed = d.device.account_signature != account_signature;
                d.device.account_signature = account_signature.to_string();
                let state = Memory::state(d);
                if changed {
                    m.kt_append("resign", sn, &[&device_id.to_be_bytes(), &resigned]);
                }
                return Ok(state);
            }
            let d = MemDevice {
                device: Device {
                    device_id,
                    curve25519_key: curve25519_key.to_string(),
                    ed25519_key: ed25519_key.to_string(),
                    account_signature: account_signature.to_string(),
                    created_at: 1,
                    last_seen_at: 1,
                    revoked_at: None,
                },
                one_time: Vec::new(),
                fallback: None,
            };
            let state = Memory::state(&d);
            let logged = d.device.clone();
            a.devices.push(d);
            m.kt_device(sn, &logged);
            Ok(state)
        })
    }

    fn get_device(&self, bearer: &str, device_id: u32) -> DirResult<DeviceState> {
        self.with(format!("GET devices/{device_id}"), Some(bearer), |m, sn| {
            Ok(Memory::state(m.device_mut(sn, device_id)?))
        })
    }

    fn upload_one_time_keys(
        &self,
        bearer: &str,
        device_id: u32,
        keys: &[SignedKey],
    ) -> DirResult<u32> {
        let sn_keys = keys.to_vec();
        self.with(
            format!("POST devices/{device_id}/one-time-keys"),
            Some(bearer),
            move |m, sn| {
                let d = m.device_mut(sn, device_id)?;
                for k in &sn_keys {
                    let pk = key32(&k.public_key).ok_or_else(|| api(400, "invalid_key"))?;
                    let msg = sign::one_time_key(sn, device_id, &k.key_id, &pk);
                    if !verify(&d.device.ed25519_key, &msg, &k.signature) {
                        return Err(api(400, "invalid_signature"));
                    }
                }
                let new: Vec<SignedKey> = sn_keys
                    .into_iter()
                    .filter(|k| !d.one_time.iter().any(|o| o.key_id == k.key_id))
                    .collect();
                if d.one_time.len() + new.len() > 100 {
                    return Err(api(409, "pool_full"));
                }
                d.one_time.extend(new);
                Ok(d.one_time.len() as u32)
            },
        )
    }

    fn put_fallback_key(&self, bearer: &str, device_id: u32, key: &SignedKey) -> DirResult<()> {
        self.with(
            format!("PUT devices/{device_id}/fallback-key"),
            Some(bearer),
            |m, sn| {
                let d = m.device_mut(sn, device_id)?;
                let pk = key32(&key.public_key).ok_or_else(|| api(400, "invalid_key"))?;
                let msg = sign::fallback_key(sn, device_id, &key.key_id, &pk);
                if !verify(&d.device.ed25519_key, &msg, &key.signature) {
                    return Err(api(400, "invalid_signature"));
                }
                d.fallback = Some(key.clone());
                Ok(())
            },
        )
    }

    fn user_devices(&self, uin: &str) -> DirResult<UserDevices> {
        let who = sign::ident(uin);
        self.with(format!("GET users/{who}/devices"), None, |m, _| {
            let a = m.accounts.get(&who).ok_or_else(|| api(404, "no_account"))?;
            Ok(UserDevices {
                screen_name: who.clone(),
                account_key: a.key.clone(),
                devices: a.devices.iter().map(|d| d.device.clone()).collect(),
            })
        })
    }

    fn claim(&self, bearer: &str, uin: &str, device_id: u32) -> DirResult<Claim> {
        let who = sign::ident(uin);
        self.with(
            format!("POST users/{who}/devices/{device_id}/claim"),
            Some(bearer),
            |m, _| {
                let key = m
                    .accounts
                    .get(&who)
                    .ok_or_else(|| api(404, "no_account"))?
                    .key
                    .clone();
                let d = m.device_mut(&who, device_id)?;
                let one_time_key = (!d.one_time.is_empty()).then(|| d.one_time.remove(0));
                let fallback_key = if one_time_key.is_none() {
                    d.fallback.clone()
                } else {
                    None
                };
                Ok(Claim {
                    screen_name: who.clone(),
                    account_key: key,
                    device: d.device.clone(),
                    one_time_key,
                    fallback_key,
                })
            },
        )
    }

    fn refresh_token(&self, bearer: &str) -> DirResult<String> {
        self.with("POST token".into(), Some(bearer), |_, sn| {
            Ok(Token::parse(&token::unsigned(sn, u32::MAX))
                .expect("a token we built")
                .bearer)
        })
    }

    fn log_checkpoint(&self) -> DirResult<Option<String>> {
        let m = self.inner.lock().unwrap();
        if m.offline {
            return Err(DirError::Net("offline (test)".into()));
        }
        Ok((!m.kt_off).then(|| Self::kt_checkpoint(&m).0))
    }

    fn log_key(&self) -> DirResult<Option<String>> {
        let m = self.inner.lock().unwrap();
        if m.offline {
            return Err(DirError::Net("offline (test)".into()));
        }
        Ok((!m.kt_off).then(|| Self::kt_checkpoint(&m).1))
    }

    fn log_entries(&self, start: u64, count: u64) -> DirResult<Vec<Vec<u8>>> {
        let m = self.inner.lock().unwrap();
        if m.offline {
            return Err(DirError::Net("offline (test)".into()));
        }
        if m.kt_off {
            return Err(api(404, "http_404"));
        }
        let count = count.min(crate::kt::MAX_ENTRIES) as usize;
        Ok(m.kt
            .iter()
            .skip(start as usize)
            .take(count)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that answers from a script and records the requests.
    struct Script {
        answers: Mutex<Vec<(u16, &'static str)>>,
        seen: Mutex<Vec<String>>,
    }

    impl Transport for Script {
        fn call(
            &self,
            method: &str,
            path: &str,
            bearer: Option<&str>,
            body: Option<&[u8]>,
        ) -> Result<(u16, Vec<u8>), String> {
            self.seen.lock().unwrap().push(format!(
                "{method} {path} {} {}",
                bearer.unwrap_or("-"),
                body.map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default()
            ));
            let (status, body) = self.answers.lock().unwrap().remove(0);
            Ok((status, body.as_bytes().to_vec()))
        }
    }

    fn script(answers: Vec<(u16, &'static str)>) -> HttpDirectory<Script> {
        HttpDirectory::new(Script {
            answers: Mutex::new(answers),
            seen: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn the_key_log_endpoints_read_as_the_server_writes_them() {
        let d = script(vec![
            (200, "log\n0\nAAAA\n\n- log x\n"),
            (200, "log+01020304+AQ\n"),
            (200, r#"{"start":2,"entries":["T1NDQVI","AQID"]}"#),
            (404, "404 page not found\n"),
            (502, "Bad Gateway"),
        ]);
        assert!(d.log_checkpoint().unwrap().unwrap().starts_with("log\n0\n"));
        assert_eq!(d.log_key().unwrap().as_deref(), Some("log+01020304+AQ\n"));
        assert_eq!(
            d.log_entries(2, 1000).unwrap(),
            vec![b"OSCAR".to_vec(), vec![1, 2, 3]]
        );
        // An older server has no log; a broken one is an error.
        assert_eq!(d.log_checkpoint().unwrap(), None);
        assert_eq!(d.log_checkpoint().unwrap_err().code(), "http_502");
        let seen = d.transport.seen.lock().unwrap().clone();
        assert_eq!(seen[0], "GET log/checkpoint - ");
        assert_eq!(seen[2], "GET log/entries?start=2&count=1000 - ");
    }

    #[test]
    fn http_bodies_and_errors_follow_the_api() {
        let d = script(vec![
            (403, r#"{"error":"not_announced","message":"x"}"#),
            (
                201,
                r#"{"screen_name":"1","account_key":"k","created_at":1,"updated_at":1}"#,
            ),
            (502, "Bad Gateway"),
            (
                200,
                r#"{"screen_name":"100002","account_key":"A","device":{"device_id":7,"curve25519_key":"C","ed25519_key":"E","account_signature":"S","created_at":1,"last_seen_at":2},"fallback_key":{"key_id":"AAAAAg","public_key":"P","signature":"G"}}"#,
            ),
            (204, ""),
        ]);
        assert_eq!(
            d.put_account("tok", "k", "s").unwrap_err().code(),
            "not_announced"
        );
        assert!(d.put_account("tok", "k", "s").is_ok());
        assert_eq!(d.user_devices("100002").unwrap_err().code(), "http_502");
        let c = d.claim("tok", "100002", 7).unwrap();
        assert_eq!(c.device.device_id, 7);
        assert!(c.one_time_key.is_none());
        assert_eq!(c.fallback_key.unwrap().key_id, "AAAAAg");
        let key = SignedKey {
            key_id: "AAAAAg".into(),
            public_key: "P".into(),
            signature: "G".into(),
        };
        assert!(d.put_fallback_key("tok", 7, &key).is_ok());
        let seen = d.transport.seen.lock().unwrap();
        assert_eq!(
            seen[0],
            r#"PUT account tok {"account_key":"k","self_signature":"s"}"#
        );
        assert_eq!(seen[2], "GET users/100002/devices - ");
        assert_eq!(seen[3], "POST users/100002/devices/7/claim tok ");
        assert_eq!(
            seen[4],
            r#"PUT devices/7/fallback-key tok {"key_id":"AAAAAg","public_key":"P","signature":"G"}"#
        );
    }
}
