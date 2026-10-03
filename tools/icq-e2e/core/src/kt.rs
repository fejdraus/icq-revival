//! The key transparency log of the key directory (docs/e2e/KEY-TRANSPARENCY.md).
//!
//! The server appends every change of the directory - account keys, devices
//! added, re-signed and revoked - to an RFC 6962 Merkle tree and signs its
//! size and root hash as a checkpoint. This client keeps its own copy: it
//! downloads what was appended since it last looked, folds each leaf into the
//! tree's right edge and replays it into the accounts it describes. The copy
//! is kept only when its root is the checkpoint's root, so a log that was
//! rewritten - not merely appended to - can never be accepted silently.
//!
//! What the log is good for is in [`LogState`]: a contact's keys from the
//! directory must be the log's keys for them, and our own account in the log
//! must hold nothing we did not put there.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ring::digest;
use serde::{Deserialize, Serialize};

use crate::directory::{DirError, DirectoryApi};

/// The context every leaf starts with.
pub const CONTEXT: &[u8] = b"OSCAR-E2E-KT-v1";

/// Most leaves asked for in one request; the server's own limit.
pub const MAX_ENTRIES: u64 = 1000;

/// A SHA-256 hash of the tree.
pub type Hash = [u8; 32];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut c = digest::Context::new(&digest::SHA256);
    for p in parts {
        c.update(p);
    }
    c.finish().as_ref().try_into().expect("SHA-256 is 32 bytes")
}

/// RFC 6962 leaf hash.
pub fn leaf_hash(leaf: &[u8]) -> Hash {
    sha256(&[&[0], leaf])
}

/// RFC 6962 interior node hash.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[1], left, right])
}

// --- the tree's right edge -------------------------------------------------------

/// The right edge of a tree of `size` leaves: the hashes of its complete
/// subtrees, largest (leftmost) first, one per bit set in `size`. Enough to
/// append and to compute the root, at most 64 hashes for any size.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Edge {
    pub size: u64,
    pub hashes: Vec<Hash>,
}

impl Edge {
    /// Appends a leaf hash.
    pub fn push(&mut self, leaf: Hash) {
        let mut h = leaf;
        let mut n = self.size;
        while n & 1 == 1 {
            let left = self.hashes.pop().expect("one hash per bit of the size");
            h = node_hash(&left, &h);
            n >>= 1;
        }
        self.hashes.push(h);
        self.size += 1;
    }

    /// The root hash, `None` for an empty tree.
    pub fn root(&self) -> Option<Hash> {
        let mut it = self.hashes.iter().rev();
        let mut r = *it.next()?;
        for left in it {
            r = node_hash(left, &r);
        }
        Some(r)
    }
}

// --- leaves ------------------------------------------------------------------------

/// What one leaf changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The account key is now `key` (`change` is publish, rotate or reset);
    /// a rotation carries the old key's proof.
    Account {
        change: String,
        key: String,
        proof: Option<String>,
    },
    /// A device was added.
    Device { id: u32, device: LogDevice },
    /// A device has a new account signature.
    Resign { id: u32, signature: String },
    /// A device was revoked.
    Revoke { id: u32 },
    /// The account was deleted, with its key and devices.
    Delete,
    /// The owner's signed revoke of a device: the revoke leaf of that device
    /// comes next (second audit of 2026-10, finding 1).
    OwnerRevoke {
        id: u32,
        issued_at: u64,
        signature: String,
    },
    /// The owner's signed delete of the account's keys: the delete comes
    /// next.
    OwnerDelete { issued_at: u64, signature: String },
    /// The operator revoked a device without the owner's key: the revoke of
    /// that device comes next, and the account's next key is a new identity.
    RecoveryRevoke { id: u32, why: String },
    /// The operator deleted the account without the owner's key: the delete
    /// comes next, and a key published afterwards is a new identity.
    RecoveryDelete { why: String },
    /// A kind this build does not know. It is part of the tree like any
    /// other leaf, and changes nothing here.
    Unknown,
}

/// One leaf, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub screen_name: String,
    pub time: u64,
    pub change: Change,
}

/// Builds a leaf: the context, then the kind, the screen name, the time (Unix
/// seconds, 8 bytes big endian) and the kind's fields, each as a big-endian
/// u16 length and the bytes. What the server does, for the in-memory
/// directory and the tests.
pub fn build_leaf(kind: &str, screen_name: &str, time: u64, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = CONTEXT.to_vec();
    let time = time.to_be_bytes();
    for f in [kind.as_bytes(), screen_name.as_bytes(), &time[..]]
        .into_iter()
        .chain(fields.iter().copied())
    {
        out.extend_from_slice(&(f.len() as u16).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

fn fields(leaf: &[u8]) -> Option<Vec<&[u8]>> {
    let mut rest = leaf.strip_prefix(CONTEXT)?;
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 2 {
            return None;
        }
        let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        let f = rest.get(2..2 + n)?;
        out.push(f);
        rest = &rest[2 + n..];
    }
    Some(out)
}

fn b64_of(b: &[u8], len: usize) -> Option<String> {
    (b.len() == len).then(|| vodozemac::base64_encode(b))
}

fn device_id(b: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(b.try_into().ok()?))
}

/// Reads a leaf; `None` if it is not one at all. Keys and signatures come out
/// as the directory writes them (base64, no padding), so they compare as
/// strings with what `GET /users/{uin}/devices` returns.
pub fn parse_leaf(leaf: &[u8]) -> Option<Leaf> {
    let f = fields(leaf)?;
    if f.len() < 3 {
        return None;
    }
    let screen_name = String::from_utf8(f[1].to_vec()).ok()?;
    let time = u64::from_be_bytes(f[2].try_into().ok()?);
    let time8 = |b: &[u8]| -> Option<u64> { Some(u64::from_be_bytes(b.try_into().ok()?)) };
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
    let change = match (f[0], &f[3..]) {
        // A rotation carries the old key's proof, for the auditor.
        (b"account", [change, key, proof @ ..])
            if proof.iter().all(|p| p.len() == 64) && proof.len() <= 1 =>
        {
            Change::Account {
                change: String::from_utf8(change.to_vec()).ok()?,
                key: b64_of(key, 32)?,
                proof: proof.first().map(|p| vodozemac::base64_encode(p)),
            }
        }
        (b"device", [id, curve, ed, sig]) => Change::Device {
            id: device_id(id)?,
            device: LogDevice {
                curve25519_key: b64_of(curve, 32)?,
                ed25519_key: b64_of(ed, 32)?,
                account_signature: b64_of(sig, 64)?,
                added: time,
                stale: false,
            },
        },
        (b"resign", [id, sig]) => Change::Resign {
            id: device_id(id)?,
            signature: b64_of(sig, 64)?,
        },
        (b"revoke", [id]) => Change::Revoke { id: device_id(id)? },
        (b"delete", []) => Change::Delete,
        (b"owner-revoke", [id, at, sig]) => Change::OwnerRevoke {
            id: device_id(id)?,
            issued_at: time8(at)?,
            signature: b64_of(sig, 64)?,
        },
        (b"owner-delete", [at, sig]) => Change::OwnerDelete {
            issued_at: time8(at)?,
            signature: b64_of(sig, 64)?,
        },
        (b"recovery-revoke", [id, why]) => Change::RecoveryRevoke {
            id: device_id(id)?,
            why: text(why)?,
        },
        (b"recovery-delete", [why]) => Change::RecoveryDelete { why: text(why)? },
        (
            b"account" | b"device" | b"resign" | b"revoke" | b"delete" | b"owner-revoke"
            | b"owner-delete" | b"recovery-revoke" | b"recovery-delete",
            _,
        ) => return None,
        _ => Change::Unknown,
    };
    Some(Leaf {
        screen_name,
        time,
        change,
    })
}

// --- the replayed state ------------------------------------------------------------

/// An active device as the log has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogDevice {
    pub curve25519_key: String,
    pub ed25519_key: String,
    pub account_signature: String,
    /// When it was added, Unix seconds, as the leaf says.
    #[serde(default)]
    pub added: u64,
    /// Set by a rotation, cleared by a re-signature: no signature by the
    /// current account key vouches for the device, so a rotation may revoke
    /// it without a leaf of its own.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

/// An account as the log has it: its key and its active devices.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogAccount {
    pub key: String,
    #[serde(default)]
    pub devices: BTreeMap<u32, LogDevice>,
    /// Every device id the account has had, revoked ones too: an id is never
    /// used again. A copy from before this field holds only what it replayed
    /// since.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub used: Vec<u32>,
    /// The account keys the current one descends from by rotations, each
    /// signed by the one before, oldest first, the current key last: a key
    /// in here was handed over by its owner (second audit of 2026-10,
    /// finding 1). Empty in a copy from before; the current key then counts
    /// alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
    /// Why the chain started without the previous key's word: a reset, or a
    /// key published after the operator deleted the account. `None` for an
    /// account's first key and for one published after the owner's own
    /// delete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_identity: Option<String>,
    /// The operator revoked a device without the owner's key since the
    /// last key change: the next key that is not a rotation is a new
    /// identity, for this reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
}

impl LogAccount {
    fn fresh(key: &str, new_identity: Option<String>) -> LogAccount {
        LogAccount {
            key: key.to_string(),
            chain: vec![key.to_string()],
            new_identity,
            ..LogAccount::default()
        }
    }

    /// Whether `old` was this account's key and handed over to the current
    /// one by rotations alone.
    pub fn continues(&self, old: &str) -> bool {
        old == self.key || self.chain.iter().any(|k| k == old)
    }
}

/// How many keys [`LogAccount::chain`] keeps; an older one counts as not
/// continued, which only ever asks more of the user.
pub const CHAIN_KEEP: usize = 32;

/// A revoke or delete that the leaf before it authorised, which must be the
/// next leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub kind: String,
    pub account: String,
    #[serde(default)]
    pub device: u32,
    pub from: String,
}

/// The accounts replayed from the log and what the rules need between
/// leaves. [`LogState`] holds one for the whole copy; [`LogState::vouched`]
/// another, for the part of it an auditor has cosigned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replay {
    #[serde(default)]
    pub accounts: BTreeMap<String, LogAccount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    /// Accounts the operator deleted without the owner's key, with why,
    /// until a key is published for them again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deleted: BTreeMap<String, String>,
}

fn verify_b64(key: &str, msg: &[u8], sig: &str) -> bool {
    let (Ok(k), Ok(s)) = (
        vodozemac::Ed25519PublicKey::from_base64(key),
        vodozemac::Ed25519Signature::from_base64(sig),
    ) else {
        return false;
    };
    k.verify(msg, &s).is_ok()
}

fn raw32(b64: &str) -> [u8; 32] {
    vodozemac::base64_decode(b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or([0; 32])
}

impl Replay {
    /// Checks one leaf against the directory's rules, as the auditor does
    /// (`server/e2e/audit.go`, `AuditState.apply`), and replays it. `Err` is
    /// a leaf that breaks a rule: the log is not to be trusted. `Ok(Some)`
    /// says what the leaf did without the owner's key - the operator's
    /// recovery, which keeps the rules and which the auditor logs.
    ///
    /// Unlike the auditor, a kind this build does not know changes nothing
    /// and breaks nothing, so a newer server's log still reads.
    pub fn apply(&mut self, leaf: &Leaf) -> Result<Option<String>, String> {
        let sn = leaf.screen_name.clone();
        let pending = self.pending.take();
        if let Some(p) = &pending {
            let ok = match &leaf.change {
                Change::Revoke { id } => p.kind == "revoke" && p.account == sn && p.device == *id,
                Change::Delete => p.kind == "delete" && p.account == sn,
                _ => false,
            };
            if !ok {
                return Err(format!(
                    "the {} entry is not followed by its {}",
                    p.from, p.kind
                ));
            }
        }
        let acc = self.accounts.get_mut(&sn);
        let mut recovered = None;
        match (&leaf.change, acc) {
            (Change::Account { change, key, proof }, acc) => match (change.as_str(), acc) {
                ("publish", None) if proof.is_none() => {
                    let why = self.deleted.remove(&sn).map(|why| {
                        format!("a key published after the operator deleted the account ({why})")
                    });
                    recovered = why.clone();
                    self.accounts.insert(sn, LogAccount::fresh(key, why));
                }
                ("publish", Some(_)) => {
                    return Err("a publish over an account that has a key".into())
                }
                ("rotate", Some(a)) => {
                    let ok = proof.as_deref().is_some_and(|p| {
                        verify_b64(
                            &a.key,
                            &crate::sign::rotate(&sn, &raw32(&a.key), &raw32(key)),
                            p,
                        )
                    });
                    if !ok {
                        return Err("a rotation not signed by the old key".into());
                    }
                    if a.chain.is_empty() {
                        a.chain.push(a.key.clone());
                    }
                    a.chain.push(key.clone());
                    if a.chain.len() > CHAIN_KEEP {
                        a.chain.remove(0);
                    }
                    a.key = key.clone();
                    a.recovery = None;
                    for d in a.devices.values_mut() {
                        d.stale = true;
                    }
                }
                ("reset", Some(a)) if proof.is_none() => {
                    if !a.devices.is_empty() {
                        return Err("a reset while the account has active devices".into());
                    }
                    let why = match a.recovery.take() {
                        Some(r) => format!("a reset after {r}"),
                        None => "a reset: a new key without the old key's proof".to_string(),
                    };
                    recovered = Some(why.clone());
                    a.key = key.clone();
                    a.chain = vec![key.clone()];
                    a.new_identity = Some(why);
                }
                _ => {
                    return Err(format!(
                        "an account change ({change}) the rules do not allow"
                    ))
                }
            },
            (Change::Device { id, device }, Some(a)) => {
                if a.used.contains(id) || a.devices.contains_key(id) {
                    return Err(format!("device id {id} used again"));
                }
                let msg = crate::sign::device(
                    &sn,
                    *id,
                    &raw32(&device.curve25519_key),
                    &raw32(&device.ed25519_key),
                );
                if !verify_b64(&a.key, &msg, &device.account_signature) {
                    return Err(format!("device {id} is not signed by the account key"));
                }
                a.used.push(*id);
                a.devices.insert(*id, device.clone());
            }
            (Change::Resign { id, signature }, Some(a)) => {
                let key = a.key.clone();
                let Some(d) = a.devices.get_mut(id) else {
                    return Err(format!(
                        "a re-signature of device {id}, which is not active"
                    ));
                };
                let msg = crate::sign::device(
                    &sn,
                    *id,
                    &raw32(&d.curve25519_key),
                    &raw32(&d.ed25519_key),
                );
                if !verify_b64(&key, &msg, signature) {
                    return Err(format!(
                        "device {id}'s new signature is not by the account key"
                    ));
                }
                d.account_signature = signature.clone();
                d.stale = false;
            }
            (
                Change::OwnerRevoke {
                    id,
                    issued_at,
                    signature,
                },
                Some(a),
            ) => {
                if !a.devices.contains_key(id) {
                    return Err(format!(
                        "an owner's revoke of device {id}, which is not active"
                    ));
                }
                if !verify_b64(
                    &a.key,
                    &crate::sign::revoke(&sn, *id, *issued_at),
                    signature,
                ) {
                    return Err(format!(
                        "the revoke of device {id} is not signed by the account key"
                    ));
                }
                self.pending = Some(Pending {
                    kind: "revoke".into(),
                    account: sn,
                    device: *id,
                    from: "owner-revoke".into(),
                });
            }
            (Change::RecoveryRevoke { id, why }, Some(a)) => {
                if !a.devices.contains_key(id) {
                    return Err(format!(
                        "a recovery revoke of device {id}, which is not active"
                    ));
                }
                let what =
                    format!("the operator revoked device {id} without the owner's key ({why})");
                a.recovery = Some(what.clone());
                recovered = Some(what);
                self.pending = Some(Pending {
                    kind: "revoke".into(),
                    account: sn,
                    device: *id,
                    from: "recovery-revoke".into(),
                });
            }
            (Change::Revoke { id }, Some(a)) => {
                let Some(d) = a.devices.get(id) else {
                    return Err(format!("a revoke of device {id}, which is not active"));
                };
                if pending.is_none() && !d.stale {
                    return Err(format!(
                        "device {id} revoked without the owner's signature or a recovery entry"
                    ));
                }
                a.devices.remove(id);
            }
            (
                Change::OwnerDelete {
                    issued_at,
                    signature,
                },
                Some(a),
            ) => {
                if !verify_b64(&a.key, &crate::sign::delete(&sn, *issued_at), signature) {
                    return Err("the delete is not signed by the account key".into());
                }
                self.pending = Some(Pending {
                    kind: "delete".into(),
                    account: sn,
                    device: 0,
                    from: "owner-delete".into(),
                });
            }
            (Change::RecoveryDelete { why }, Some(_)) => {
                recovered = Some(format!(
                    "the operator deleted the account without the owner's key ({why})"
                ));
                self.deleted.insert(sn.clone(), why.clone());
                self.pending = Some(Pending {
                    kind: "delete".into(),
                    account: sn,
                    device: 0,
                    from: "recovery-delete".into(),
                });
            }
            (Change::Delete, Some(_)) => {
                if pending.is_none() {
                    return Err(
                        "the account deleted without the owner's signature or a recovery entry"
                            .into(),
                    );
                }
                self.accounts.remove(&sn);
            }
            (Change::Unknown, _) => {}
            (_, None) => return Err("an entry for an account that has no key".into()),
        }
        Ok(recovered)
    }
}

/// Our copy of the log, in the state file: the log's key, pinned on first
/// sight; the tree's right edge; every account replayed from the leaves.
/// `own_seen` are our own account's devices the user has been told about.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default)]
    pub size: u64,
    /// The edge's hashes, hex.
    #[serde(default)]
    pub edge: Vec<String>,
    #[serde(default)]
    pub accounts: BTreeMap<String, LogAccount>,
    /// The revoke or delete the last leaf authorised (it comes next).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    /// Accounts the operator deleted without the owner's key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deleted: BTreeMap<String, String>,
    #[serde(default)]
    pub own_seen: Vec<u32>,
    /// Our account key in the log that is not ours, once the user was told.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_key_said: Option<String>,
    /// Every leaf hash, concatenated, base64: what a checkpoint of any
    /// earlier size is checked against.
    #[serde(default)]
    pub hashes: String,
    /// The auditors' verifier keys we trust: pinned on first sight from
    /// `GET /log/auditors`, or, when `icq-e2e.ini` has an `auditors =` line,
    /// exactly the keys it gives.
    #[serde(default)]
    pub auditors: Vec<String>,
    /// The latest cosignature that checked out, by any auditor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audited: Option<Audited>,
    /// Per trusted auditor, its latest cosignature that checked out. A state
    /// file from before several auditors has none; it fills on the next look.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audits: Vec<Audited>,
    /// Why the log broke after we had trusted it - rewritten, signed by
    /// another key, gone, or a split view an auditor saw (audit 2026-10,
    /// finding 4). Sticky: kept in the state file across sign-ons until
    /// `/e2e resetlog`. While it is set, the rest of this copy is frozen as
    /// it was last trusted, and only what was vouched for by then is used:
    /// sessions already made, account keys already pinned, devices this copy
    /// shows. State version 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broken: Option<String>,
    /// The log replayed only as far as a pinned auditor has cosigned it, the
    /// largest such size: what new keys are taken from once an auditor has
    /// vouched for this copy (second audit of 2026-10, finding 3). Empty and
    /// 0 in a copy from before; filled at the next look at the auditors.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub vouched_size: u64,
    #[serde(default, skip_serializing_if = "Replay::is_empty")]
    pub vouched: Replay,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Replay {
    fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.pending.is_none() && self.deleted.is_empty()
    }
}

/// What the client can rely on from the key log right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// No log was ever seen: an older server, or none read yet. Keys are
    /// trusted on first use, as before the log existed.
    NeverHadLog,
    /// The copy is up to date and adds up: keys are checked against it.
    Trusted,
    /// The copy is up to date, and a pinned auditor has vouched for this
    /// copy before but has not within [`AUDIT_MAX_AGE`]: what is known goes
    /// on, nothing new is taken (second audit of 2026-10, finding 3).
    Unaudited(String),
    /// The log was trusted on this state before, and cannot be read now:
    /// the last trusted copy stands, nothing new is taken until it can be
    /// read again (second audit of 2026-10, finding 2). Not sticky.
    TemporarilyUnavailableAfterTrust(String),
    /// A log we had trusted broke; nothing new is taken until `/e2e
    /// resetlog`, see [`LogState::broken`].
    BrokenAfterTrust(String),
}

impl LogState {
    /// Whether a log was ever seen and trusted in this copy: its key is
    /// pinned or it has entries. Both are written only after a sync whose
    /// entries added up, so this is kept in the state file.
    pub fn was_trusted(&self) -> bool {
        self.key.is_some() || self.size > 0
    }

    /// Whether a pinned auditor has ever cosigned a checkpoint that agrees
    /// with this copy: from then on new keys are taken only from the part an
    /// auditor vouched for, and only while one has done so lately.
    pub fn audit_required(&self) -> bool {
        self.audited.is_some() || !self.audits.is_empty()
    }

    /// Whether a pinned auditor's cosignature that agrees with this copy is
    /// at most [`AUDIT_MAX_AGE`] old at `now`.
    pub fn audit_fresh(&self, now: u64) -> bool {
        self.audits
            .iter()
            .chain(self.audited.iter())
            .any(|a| now <= a.time.saturating_add(AUDIT_MAX_AGE))
    }

    /// The largest log size a pinned auditor cosigned in agreement with
    /// this copy.
    pub fn audited_size(&self) -> u64 {
        self.audits
            .iter()
            .chain(self.audited.iter())
            .map(|a| a.size)
            .max()
            .unwrap_or(0)
            .min(self.size)
    }

    /// The replayed state as far as this copy goes, rules and all.
    fn replay(&self) -> Replay {
        Replay {
            accounts: self.accounts.clone(),
            pending: self.pending.clone(),
            deleted: self.deleted.clone(),
        }
    }

    fn set_replay(&mut self, r: Replay) {
        self.accounts = r.accounts;
        self.pending = r.pending;
        self.deleted = r.deleted;
    }
}

/// A checkpoint an auditor cosigned and that agrees with our copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Audited {
    pub auditor: String,
    pub size: u64,
    /// The cosignature's time, Unix seconds.
    pub time: u64,
}

fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl LogState {
    /// The right edge, `None` if the state file holds something that is not
    /// one.
    pub fn edge(&self) -> Option<Edge> {
        let hashes = self
            .edge
            .iter()
            .map(|h| unhex(h))
            .collect::<Option<Vec<_>>>()?;
        (hashes.len() == self.size.count_ones() as usize).then_some(Edge {
            size: self.size,
            hashes,
        })
    }

    fn set_edge(&mut self, e: &Edge) {
        self.size = e.size;
        self.edge = e.hashes.iter().map(hex).collect();
    }

    /// Checks one leaf against the directory's rules and replays it
    /// ([`Replay::apply`]).
    pub fn apply(&mut self, leaf: &Leaf) -> Result<Option<String>, String> {
        let mut r = self.replay();
        let out = r.apply(leaf)?;
        self.set_replay(r);
        Ok(out)
    }

    /// Every leaf hash, in order, `None` if the state file holds something
    /// that is not a list of them.
    pub fn leaf_hashes(&self) -> Option<Vec<Hash>> {
        let raw = STANDARD.decode(&self.hashes).ok()?;
        (raw.len() % 32 == 0).then(|| {
            raw.chunks(32)
                .map(|c| c.try_into().expect("32 bytes"))
                .collect()
        })
    }

    /// The root of the log's first `size` leaves, as our copy has them.
    pub fn root_at(&self, size: u64) -> Option<Hash> {
        let hashes = self.leaf_hashes()?;
        if size == 0 || size as usize > hashes.len() {
            return None;
        }
        let mut e = Edge::default();
        for h in &hashes[..size as usize] {
            e.push(*h);
        }
        e.root()
    }
}

// --- checkpoints ---------------------------------------------------------------------

/// The log's public key as `GET /log/key` gives it:
/// `<name>+<key hash, 8 hex>+<base64(0x01 || Ed25519 key)>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    pub name: String,
    pub hash: u32,
    pub key: [u8; 32],
}

fn key_hash(name: &str, alg_key: &[u8]) -> u32 {
    let h = sha256(&[name.as_bytes(), b"\n", alg_key]);
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

/// Reads a verifier key and checks that its hash is its own.
pub fn parse_verifier(vkey: &str) -> Result<Verifier, String> {
    let vkey = vkey.trim();
    // The base64 key may itself hold plus signs.
    let mut parts = vkey.splitn(3, '+');
    let (Some(name), Some(hash), Some(key), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the log key is not name+hash+key".into());
    };
    let hash = u32::from_str_radix(hash, 16).map_err(|_| "the log key hash is not hex")?;
    let raw = STANDARD
        .decode(key)
        .map_err(|_| "the log key is not base64")?;
    if raw.len() != 33 || raw[0] != 1 {
        return Err("the log key is not an Ed25519 key".into());
    }
    if name.is_empty() || key_hash(name, &raw) != hash {
        return Err("the log key's hash does not match it".into());
    }
    Ok(Verifier {
        name: name.to_string(),
        hash,
        key: raw[1..].try_into().expect("33 - 1 bytes"),
    })
}

/// A checkpoint whose signature checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub size: u64,
    pub root: Hash,
}

/// Opens a signed checkpoint (a signed note, c2sp.org/tlog-checkpoint) with
/// the log's key: the text, a blank line, and signature lines
/// `— <name> <base64(key hash || signature)>`. The origin must be the key's
/// name.
pub fn open_checkpoint(note: &str, v: &Verifier) -> Result<Checkpoint, String> {
    let split = note.find("\n\n").ok_or("the checkpoint has no signature")?;
    let (text, sigs) = (&note[..split + 1], &note[split + 2..]);
    let signed = sigs.lines().any(|line| {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            return false;
        };
        let Some((name, sig)) = rest.split_once(' ') else {
            return false;
        };
        let Ok(raw) = STANDARD.decode(sig) else {
            return false;
        };
        name == v.name
            && raw.len() == 68
            && u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) == v.hash
            && ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &v.key)
                .verify(text.as_bytes(), &raw[4..])
                .is_ok()
    });
    if !signed {
        return Err("the checkpoint is not signed by the log's key".into());
    }
    let mut lines = text.lines();
    if lines.next() != Some(v.name.as_str()) {
        return Err("the checkpoint names another log".into());
    }
    let size = lines
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or("the checkpoint has no size")?;
    let root = lines
        .next()
        .and_then(|s| STANDARD.decode(s).ok())
        .and_then(|r| <Hash>::try_from(r).ok())
        .ok_or("the checkpoint has no root hash")?;
    Ok(Checkpoint { size, root })
}

/// Signs a checkpoint, as the server does: for the in-memory directory and
/// the tests. `seed` is the Ed25519 private key.
pub fn sign_checkpoint(name: &str, seed: &[u8; 32], size: u64, root: &Hash) -> (String, String) {
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("a 32-byte seed");
    use ring::signature::KeyPair;
    let mut alg_key = vec![1u8];
    alg_key.extend_from_slice(pair.public_key().as_ref());
    let hash = key_hash(name, &alg_key);
    let vkey = format!("{name}+{hash:08x}+{}", STANDARD.encode(&alg_key));
    let text = format!("{name}\n{size}\n{}\n", STANDARD.encode(root));
    let mut sig = hash.to_be_bytes().to_vec();
    sig.extend_from_slice(pair.sign(text.as_bytes()).as_ref());
    (
        format!("{text}\n\u{2014} {name} {}\n", STANDARD.encode(sig)),
        vkey,
    )
}

// --- syncing ---------------------------------------------------------------------------

/// Why the copy could not be brought up to date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// The server keeps no log, and we never saw one.
    NoLog,
    /// The server could not be reached or answered badly; try again later.
    Net(String),
    /// The checkpoint is not signed by the key we pinned for the log.
    BadKey(String),
    /// The log is not an extension of the one we saw before: smaller, gone,
    /// or a different history.
    Rewritten(String),
    /// An entry breaks the directory's rules - the auditor stops cosigning
    /// at the same entry.
    Violation(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::NoLog => write!(f, "the server keeps no key log"),
            SyncError::Net(e) => write!(f, "the key log could not be read: {e}"),
            SyncError::BadKey(e) => write!(f, "the key log's signature is wrong: {e}"),
            SyncError::Rewritten(e) => write!(f, "the key log was rewritten: {e}"),
            SyncError::Violation(e) => write!(f, "the key log breaks its rules: {e}"),
        }
    }
}

fn net(e: DirError) -> SyncError {
    SyncError::Net(e.to_string())
}

/// Brings a copy of the log up to date and returns the new copy; `state` is
/// left as it was, so a failure keeps the last good copy.
pub fn sync(dir: &dyn DirectoryApi, state: &LogState) -> Result<LogState, SyncError> {
    let Some(note) = dir.log_checkpoint().map_err(net)? else {
        return Err(if state.size > 0 || state.key.is_some() {
            SyncError::Rewritten("the server no longer has it".into())
        } else {
            SyncError::NoLog
        });
    };
    let mut next = state.clone();
    let vkey = match &state.key {
        Some(k) => k.clone(),
        None => dir
            .log_key()
            .map_err(net)?
            .ok_or_else(|| SyncError::Net("the server has a log but no key for it".into()))?
            .trim()
            .to_string(),
    };
    let verifier = parse_verifier(&vkey).map_err(SyncError::BadKey)?;
    let cp = open_checkpoint(&note, &verifier).map_err(SyncError::BadKey)?;
    next.key = Some(vkey);

    let mut edge = state
        .edge()
        .ok_or_else(|| SyncError::Rewritten("our copy of it is damaged".into()))?;
    let mut hashes = state.leaf_hashes().unwrap_or_default();
    if hashes.len() as u64 != edge.size {
        // A copy from before the hashes were kept: read what it has again,
        // which must come to the same tree.
        hashes = refetch_hashes(dir, edge.size)?;
        let mut again = Edge::default();
        hashes.iter().for_each(|h| again.push(*h));
        if again != edge {
            return Err(SyncError::Rewritten(
                "its first entries are not the ones we had".into(),
            ));
        }
    }
    if cp.size < edge.size {
        return Err(SyncError::Rewritten(format!(
            "it has {} entries, after {} before",
            cp.size, edge.size
        )));
    }
    while edge.size < cp.size {
        let want = (cp.size - edge.size).min(MAX_ENTRIES);
        let leaves = dir.log_entries(edge.size, want).map_err(net)?;
        if leaves.is_empty() {
            return Err(SyncError::Net(format!(
                "it ended at {} entries, short of the {} it claims",
                edge.size, cp.size
            )));
        }
        for leaf in leaves.iter().take(want as usize) {
            let read = parse_leaf(leaf).ok_or_else(|| {
                SyncError::Rewritten(format!("entry {} is not a log entry", edge.size))
            })?;
            next.apply(&read)
                .map_err(|e| SyncError::Violation(format!("entry {}: {e}", edge.size)))?;
            edge.push(leaf_hash(leaf));
            hashes.push(leaf_hash(leaf));
        }
    }
    if cp.size > 0 && edge.root() != Some(cp.root) {
        return Err(SyncError::Rewritten(
            "its entries do not add up to its signed root".into(),
        ));
    }
    next.set_edge(&edge);
    next.hashes = STANDARD.encode(hashes.concat());
    Ok(next)
}

/// Brings [`LogState::vouched`] up to `size` leaves (no further than the
/// copy): the leaves are read again and each must be the one whose hash the
/// copy keeps. Nothing changes on an error; a network error is tried again
/// at the next look.
pub fn vouch(dir: &dyn DirectoryApi, state: &mut LogState, size: u64) -> Result<(), SyncError> {
    let size = size.min(state.size);
    if size <= state.vouched_size {
        return Ok(());
    }
    let hashes = state
        .leaf_hashes()
        .ok_or_else(|| SyncError::Rewritten("our copy of it is damaged".into()))?;
    let mut at = state.vouched_size;
    let mut r = state.vouched.clone();
    while at < size {
        let want = (size - at).min(MAX_ENTRIES);
        let leaves = dir.log_entries(at, want).map_err(net)?;
        if leaves.is_empty() {
            return Err(SyncError::Net("it ended early".into()));
        }
        for leaf in leaves.iter().take(want as usize) {
            if hashes.get(at as usize) != Some(&leaf_hash(leaf)) {
                return Err(SyncError::Rewritten(format!(
                    "entry {at} is not the one it was"
                )));
            }
            let read = parse_leaf(leaf)
                .ok_or_else(|| SyncError::Rewritten(format!("entry {at} is not a log entry")))?;
            r.apply(&read)
                .map_err(|e| SyncError::Violation(format!("entry {at}: {e}")))?;
            at += 1;
        }
    }
    state.vouched = r;
    state.vouched_size = size;
    Ok(())
}

/// The hashes of the log's first `size` leaves, read again.
fn refetch_hashes(dir: &dyn DirectoryApi, size: u64) -> Result<Vec<Hash>, SyncError> {
    let mut out = Vec::new();
    while (out.len() as u64) < size {
        let want = (size - out.len() as u64).min(MAX_ENTRIES);
        let leaves = dir.log_entries(out.len() as u64, want).map_err(net)?;
        if leaves.is_empty() {
            return Err(SyncError::Net("it ended early".into()));
        }
        out.extend(leaves.iter().take(want as usize).map(|l| leaf_hash(l)));
    }
    Ok(out)
}

// --- auditors (stage 2) ------------------------------------------------------------------

/// A cosignature older than this, in seconds, no longer vouches for the log:
/// the auditor cosigns every minute, so an hour means it has stopped, or the
/// server is keeping its newer cosignatures from us.
pub const AUDIT_MAX_AGE: u64 = 3600;

/// An auditor's public key (c2sp.org/tlog-cosignature, Ed25519):
/// `<name>+<key ID, 8 hex>+<base64(0x04 || key)>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosigner {
    pub name: String,
    pub id: u32,
    pub key: [u8; 32],
}

/// Reads an auditor's verifier key and checks that its key ID is its own.
pub fn parse_cosigner(vkey: &str) -> Result<Cosigner, String> {
    let mut parts = vkey.trim().splitn(3, '+');
    let (Some(name), Some(id), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("the auditor key is not name+id+key".into());
    };
    let id = u32::from_str_radix(id, 16).map_err(|_| "the auditor key id is not hex")?;
    let raw = STANDARD
        .decode(key)
        .map_err(|_| "the auditor key is not base64")?;
    if raw.len() != 33 || raw[0] != 4 {
        return Err("the auditor key is not an Ed25519 cosignature key".into());
    }
    if name.is_empty() || key_hash(name, &raw) != id {
        return Err("the auditor key's id does not match it".into());
    }
    Ok(Cosigner {
        name: name.to_string(),
        id,
        key: raw[1..].try_into().expect("33 - 1 bytes"),
    })
}

fn cosignature_message(body: &str, time: u64) -> String {
    format!("cosignature/v1\ntime {time}\n{body}")
}

/// Checks a cosignature line over a checkpoint body (its text with the final
/// newline) and returns its time.
pub fn verify_cosignature(c: &Cosigner, body: &str, line: &str) -> Option<u64> {
    let (name, sig) = line.trim().strip_prefix("\u{2014} ")?.split_once(' ')?;
    let raw = STANDARD.decode(sig).ok()?;
    if name != c.name || raw.len() != 76 || u32::from_be_bytes(raw[..4].try_into().ok()?) != c.id {
        return None;
    }
    let time = u64::from_be_bytes(raw[4..12].try_into().ok()?);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &c.key)
        .verify(cosignature_message(body, time).as_bytes(), &raw[12..])
        .ok()?;
    Some(time)
}

/// Cosigns a checkpoint body, as an auditor does: the line, and the verifier
/// key. For the in-memory directory and the tests.
pub fn cosign(name: &str, seed: &[u8; 32], body: &str, time: u64) -> (String, String) {
    use ring::signature::KeyPair;
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("a 32-byte seed");
    let mut alg_key = vec![4u8];
    alg_key.extend_from_slice(pair.public_key().as_ref());
    let id = key_hash(name, &alg_key);
    let mut sig = id.to_be_bytes().to_vec();
    sig.extend_from_slice(&time.to_be_bytes());
    sig.extend_from_slice(
        pair.sign(cosignature_message(body, time).as_bytes())
            .as_ref(),
    );
    (
        format!("\u{2014} {name} {}", STANDARD.encode(sig)),
        format!("{name}+{id:08x}+{}", STANDARD.encode(&alg_key)),
    )
}

/// Why the log is not vouched for by an auditor right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// The server names no auditor, and we never pinned one.
    NoAuditor,
    /// The server could not be reached; try again later.
    Net(String),
    /// An auditor has cosigned more of the log than our copy has: bring it
    /// up to date and look again.
    Behind,
    /// No cosignature by an auditor we trust is recent enough.
    Stale(String),
    /// An auditor cosigned a checkpoint that is not in our copy: the server
    /// shows us a different log than it showed the auditor.
    SplitView(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::NoAuditor => write!(f, "the server names no auditor for its key log"),
            AuditError::Net(e) => write!(f, "the auditor's cosignature could not be read: {e}"),
            AuditError::Behind => write!(f, "our copy of the key log is behind the auditor"),
            AuditError::Stale(e) => write!(f, "{e}"),
            AuditError::SplitView(e) => write!(f, "{e}"),
        }
    }
}

/// One trusted auditor and its newest cosignature that agrees with our copy;
/// `None` if the server handed out none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditorView {
    pub name: String,
    pub last: Option<Audited>,
}

impl AuditorView {
    /// Whether its word is recent enough to vouch for the log at `now`.
    pub fn fresh(&self, now: u64) -> bool {
        self.last
            .as_ref()
            .is_some_and(|a| now <= a.time.saturating_add(AUDIT_MAX_AGE))
    }
}

/// How long ago `time` was, in words: "N min ago" within the hour, "N h"
/// beyond it.
pub fn age(now: u64, time: u64) -> String {
    let secs = now.saturating_sub(time);
    if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else {
        format!("{} h", secs / 3600)
    }
}

/// Reads a list of auditors' verifier keys - the `auditors =` line of
/// `icq-e2e.ini`, or `GET /log/auditors` - separated by commas, semicolons
/// or white space. Keys that do not read come back apart, for the log; a key
/// given twice counts once.
pub fn parse_auditor_list(line: &str) -> (Vec<String>, Vec<String>) {
    let mut good: Vec<String> = Vec::new();
    let mut bad = Vec::new();
    for k in line
        .split([',', ';', ' ', '\t', '\r', '\n'])
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        if parse_cosigner(k).is_ok() {
            if !good.iter().any(|g| g == k) {
                good.push(k.to_string());
            }
        } else {
            bad.push(k.to_string());
        }
    }
    (good, bad)
}

/// Looks at the cosignatures of the auditors we trust (stage 2). Every one
/// of them must agree with our copy - a cosigned checkpoint that our copy
/// does not have is a split view, whichever auditor cosigned it - and at
/// least one must be recent enough.
///
/// `pinned` is the `auditors =` line of `icq-e2e.ini`, when it has one: then
/// exactly those auditors are trusted, whatever the server names, and they
/// replace the ones the state file had. Without it, the auditors the server
/// names are pinned on first sight, as before. The state that comes back may
/// have the auditors pinned, whatever the result.
pub fn audit(
    dir: &dyn DirectoryApi,
    state: &LogState,
    now: u64,
    pinned: Option<&[String]>,
) -> (LogState, Result<Vec<AuditorView>, AuditError>) {
    let mut next = state.clone();
    let r = audit_into(dir, &mut next, now, pinned);
    (next, r)
}

fn audit_into(
    dir: &dyn DirectoryApi,
    next: &mut LogState,
    now: u64,
    pinned: Option<&[String]>,
) -> Result<Vec<AuditorView>, AuditError> {
    let neterr = |e: DirError| AuditError::Net(e.to_string());
    match pinned {
        Some(keys) => {
            if next.auditors != keys {
                // The patch's keys win over whatever was trusted on first
                // use, for good: without the line again, these stay pinned.
                next.auditors = keys.to_vec();
                let names: Vec<String> = keys
                    .iter()
                    .filter_map(|k| parse_cosigner(k).ok())
                    .map(|c| c.name)
                    .collect();
                next.audits.retain(|a| names.contains(&a.auditor));
            }
            if keys.is_empty() {
                return Err(AuditError::Stale(
                    "the auditors line of icq-e2e.ini holds no auditor key that reads".into(),
                ));
            }
        }
        None if next.auditors.is_empty() => {
            let listed = dir.log_auditors().map_err(neterr)?.unwrap_or_default();
            next.auditors = parse_auditor_list(&listed).0;
            if next.auditors.is_empty() {
                return Err(AuditError::NoAuditor);
            }
        }
        None => {}
    }
    let cosigners: Vec<Cosigner> = next
        .auditors
        .iter()
        .filter_map(|k| parse_cosigner(k).ok())
        .collect();
    let log_key = next.key.as_deref().ok_or(AuditError::Behind)?;
    let verifier = parse_verifier(log_key).map_err(AuditError::SplitView)?;
    // Every cosignature by a trusted auditor over a checkpoint of the log.
    let mut seen: Vec<(Audited, Hash)> = Vec::new();
    for note in dir.log_cosigned().map_err(neterr)? {
        let Ok(cp) = open_checkpoint(&note, &verifier) else {
            continue;
        };
        let Some(split) = note.find("\n\n") else {
            continue;
        };
        let body = &note[..split + 1];
        for line in note[split + 2..].lines() {
            for c in &cosigners {
                if let Some(time) = verify_cosignature(c, body, line) {
                    seen.push((
                        Audited {
                            auditor: c.name.clone(),
                            size: cp.size,
                            time,
                        },
                        cp.root,
                    ));
                }
            }
        }
    }
    // Any of them that our copy does not have means the server showed that
    // auditor another log than us. One is enough, however many agree.
    for (a, root) in &seen {
        if a.size > 0 && a.size <= next.size && next.root_at(a.size) != Some(*root) {
            return Err(AuditError::SplitView(format!(
                "the key log's auditor {} saw a different log ({} entries) than this add-on was shown",
                a.auditor, a.size
            )));
        }
    }
    if seen.iter().any(|(a, _)| a.size > next.size) {
        return Err(AuditError::Behind);
    }
    let views: Vec<AuditorView> = cosigners
        .iter()
        .map(|c| AuditorView {
            name: c.name.clone(),
            last: seen
                .iter()
                .filter(|(a, _)| a.auditor == c.name)
                .map(|(a, _)| a.clone())
                .max_by_key(|a| a.time),
        })
        .collect();
    for a in views.iter().filter_map(|v| v.last.as_ref()) {
        next.audits.retain(|o| o.auditor != a.auditor);
        next.audits.push(a.clone());
    }
    if let Some(newest) = views
        .iter()
        .filter_map(|v| v.last.clone())
        .max_by_key(|a| a.time)
    {
        next.audited = Some(newest);
    }
    if views.iter().any(|v| v.fresh(now)) {
        return Ok(views);
    }
    let why = if views.iter().all(|v| v.last.is_none()) {
        "no auditor has cosigned the key log".to_string()
    } else if let [v] = &views[..] {
        format!(
            "the key log's auditor {} last vouched for it {} minutes ago",
            v.name,
            now.saturating_sub(v.last.as_ref().map_or(0, |a| a.time)) / 60
        )
    } else {
        let said: Vec<String> = views
            .iter()
            .map(|v| match &v.last {
                Some(a) => format!(
                    "{} last vouched for it {} minutes ago",
                    v.name,
                    now.saturating_sub(a.time) / 60
                ),
                None => format!("{} never did", v.name),
            })
            .collect();
        format!(
            "no auditor of the key log has vouched for it within the hour ({})",
            said.join(", ")
        )
    };
    Err(AuditError::Stale(why))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6962's definition, the slow way, to check the edge against.
    fn tree(leaves: &[Vec<u8>]) -> Hash {
        if leaves.len() == 1 {
            return leaf_hash(&leaves[0]);
        }
        let mut k = 1;
        while k * 2 < leaves.len() {
            k *= 2;
        }
        node_hash(&tree(&leaves[..k]), &tree(&leaves[k..]))
    }

    #[test]
    fn the_edge_gives_the_rfc_6962_root_at_every_size() {
        let mut edge = Edge::default();
        assert_eq!(edge.root(), None);
        let mut leaves = Vec::new();
        for i in 0..70u8 {
            leaves.push(vec![i; i as usize + 1]);
            edge.push(leaf_hash(leaves.last().unwrap()));
            assert_eq!(edge.root(), Some(tree(&leaves)), "size {}", i + 1);
            assert_eq!(edge.hashes.len(), edge.size.count_ones() as usize);
        }
    }

    #[test]
    fn the_root_matches_the_servers_tree() {
        // golang.org/x/mod/sumdb/tlog over the leaves "a", "b", "c".
        let mut edge = Edge::default();
        for l in [b"a", b"b", b"c"] {
            edge.push(leaf_hash(l));
        }
        let ab = node_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        assert_eq!(edge.root(), Some(node_hash(&ab, &leaf_hash(b"c"))));
    }

    /// An account key from a fixed seed, its public half, and a signature.
    fn akey(seed: u8) -> vodozemac::Ed25519SecretKey {
        vodozemac::Ed25519SecretKey::from_slice(&[seed; 32])
    }

    fn pubkey(k: &vodozemac::Ed25519SecretKey) -> [u8; 32] {
        *k.public_key().as_bytes()
    }

    fn signed(k: &vodozemac::Ed25519SecretKey, msg: &[u8]) -> Vec<u8> {
        k.sign(msg).to_bytes().to_vec()
    }

    /// A device leaf of `sn` with keys `[c; 32]`, `[e; 32]`, signed by `k`.
    fn device_leaf(sn: &str, id: u32, c: u8, e: u8, k: &vodozemac::Ed25519SecretKey) -> Vec<u8> {
        let sig = signed(k, &crate::sign::device(sn, id, &[c; 32], &[e; 32]));
        build_leaf(
            "device",
            sn,
            6,
            &[&id.to_be_bytes(), &[c; 32], &[e; 32], &sig],
        )
    }

    #[test]
    fn leaves_read_back_and_replay() {
        let (k1, k2) = (akey(1), akey(9));
        let sn = "100001";
        let mut s = LogState::default();
        let resig = signed(&k2, &crate::sign::device(sn, 1, &[2; 32], &[3; 32]));
        let leaves = [
            build_leaf("account", sn, 5, &[b"publish", &pubkey(&k1)]),
            device_leaf(sn, 1, 2, 3, &k1),
            device_leaf(sn, 2, 5, 6, &k1),
            build_leaf(
                "account",
                sn,
                8,
                &[
                    b"rotate",
                    &pubkey(&k2),
                    &signed(&k1, &crate::sign::rotate(sn, &pubkey(&k1), &pubkey(&k2))),
                ],
            ),
            build_leaf("resign", sn, 8, &[&1u32.to_be_bytes(), &resig]),
            // Device 2 was not re-signed: the rotation cut it off, so its
            // revoke needs no leaf of the owner's.
            build_leaf("revoke", sn, 8, &[&2u32.to_be_bytes()]),
            build_leaf("future-kind", sn, 9, &[b"x"]),
        ];
        for l in &leaves {
            assert_eq!(s.apply(&parse_leaf(l).unwrap()), Ok(None));
        }
        let a = &s.accounts[sn];
        assert_eq!(a.key, vodozemac::base64_encode(pubkey(&k2)));
        assert_eq!(a.devices.len(), 1);
        assert_eq!(
            a.devices[&1].account_signature,
            vodozemac::base64_encode(&resig)
        );
        assert_eq!(
            a.devices[&1].ed25519_key,
            vodozemac::base64_encode([3u8; 32])
        );
        assert_eq!(a.devices[&1].added, 6);
        assert!(!a.devices[&1].stale);
        // The rotation carries the old key over: a pin of it is continued.
        assert!(a.continues(&vodozemac::base64_encode(pubkey(&k1))));
        assert_eq!(a.new_identity, None);

        // Device 1 was re-signed: revoking it takes the owner's word.
        let bare = build_leaf("revoke", sn, 9, &[&1u32.to_be_bytes()]);
        assert!(s.clone().apply(&parse_leaf(&bare).unwrap()).is_err());
        let owner = build_leaf(
            "owner-revoke",
            sn,
            9,
            &[
                &1u32.to_be_bytes(),
                &77u64.to_be_bytes(),
                &signed(&k2, &crate::sign::revoke(sn, 1, 77)),
            ],
        );
        assert_eq!(s.apply(&parse_leaf(&owner).unwrap()), Ok(None));
        assert_eq!(s.apply(&parse_leaf(&bare).unwrap()), Ok(None));

        // A reset needs every device gone, and starts a new identity.
        let k3 = akey(4);
        assert!(s
            .apply(&parse_leaf(&build_leaf("account", sn, 10, &[b"reset", &pubkey(&k3)])).unwrap())
            .unwrap()
            .is_some());
        let a = &s.accounts[sn];
        assert!(a.devices.is_empty());
        assert!(!a.continues(&vodozemac::base64_encode(pubkey(&k2))));
        assert!(a.new_identity.is_some());

        // Known kinds with the wrong fields, and things that are no leaf.
        assert_eq!(parse_leaf(&build_leaf("device", "1", 1, &[b"x"])), None);
        assert_eq!(
            parse_leaf(&build_leaf("account", "1", 1, &[b"publish", &[1; 31]])),
            None
        );
        assert_eq!(
            parse_leaf(&build_leaf("owner-revoke", "1", 1, &[&[0; 4]])),
            None
        );
        assert_eq!(
            parse_leaf(&build_leaf("recovery-delete", "1", 1, &[])),
            None
        );
        assert_eq!(parse_leaf(b"OSCAR-E2E-v1\x00\x01a"), None);
        let mut cut = leaves[1].clone();
        cut.pop();
        assert_eq!(parse_leaf(&cut), None);
    }

    /// Leaves that break the rules, as the auditor refuses them.
    #[test]
    fn the_replay_refuses_what_the_auditor_refuses() {
        let (k1, k2) = (akey(1), akey(9));
        let sn = "100001";
        let publish = build_leaf("account", sn, 1, &[b"publish", &pubkey(&k1)]);
        let cases: [(&str, Vec<Vec<u8>>); 6] = [
            ("publish over a key", vec![publish.clone(), publish.clone()]),
            (
                "a device signed by another key",
                vec![publish.clone(), device_leaf(sn, 1, 2, 3, &k2)],
            ),
            (
                "a rotation without the old key",
                vec![
                    publish.clone(),
                    build_leaf(
                        "account",
                        sn,
                        2,
                        &[
                            b"rotate",
                            &pubkey(&k2),
                            &signed(&k2, &crate::sign::rotate(sn, &pubkey(&k1), &pubkey(&k2))),
                        ],
                    ),
                ],
            ),
            (
                "a reset with a device left",
                vec![
                    publish.clone(),
                    device_leaf(sn, 1, 2, 3, &k1),
                    build_leaf("account", sn, 2, &[b"reset", &pubkey(&k2)]),
                ],
            ),
            (
                "a device id used again",
                vec![
                    publish.clone(),
                    device_leaf(sn, 1, 2, 3, &k1),
                    build_leaf("recovery-revoke", sn, 2, &[&1u32.to_be_bytes(), b"test"]),
                    build_leaf("revoke", sn, 2, &[&1u32.to_be_bytes()]),
                    device_leaf(sn, 1, 2, 3, &k1),
                ],
            ),
            (
                "an owner's delete followed by something else",
                vec![
                    publish.clone(),
                    build_leaf(
                        "owner-delete",
                        sn,
                        2,
                        &[
                            &5u64.to_be_bytes(),
                            &signed(&k1, &crate::sign::delete(sn, 5)),
                        ],
                    ),
                    device_leaf(sn, 1, 2, 3, &k1),
                ],
            ),
        ];
        for (what, leaves) in cases {
            let mut s = LogState::default();
            let r: Result<Vec<_>, _> = leaves
                .iter()
                .map(|l| s.apply(&parse_leaf(l).unwrap()))
                .collect();
            assert!(r.is_err(), "{what}");
        }
    }

    #[test]
    fn a_checkpoint_opens_only_with_its_key_and_name() {
        let root = [7u8; 32];
        let (note, vkey) = sign_checkpoint("icq.test/e2e-kt", &[1; 32], 12, &root);
        let v = parse_verifier(&vkey).unwrap();
        assert_eq!(
            open_checkpoint(&note, &v),
            Ok(Checkpoint { size: 12, root })
        );

        let (_, other) = sign_checkpoint("icq.test/e2e-kt", &[2; 32], 12, &root);
        assert!(open_checkpoint(&note, &parse_verifier(&other).unwrap()).is_err());
        let tampered = note.replacen("\n12\n", "\n13\n", 1);
        assert!(open_checkpoint(&tampered, &v).is_err());
        // A key whose hash was changed is no key.
        let mut parts: Vec<&str> = vkey.split('+').collect();
        parts[1] = "00000000";
        assert!(parse_verifier(&parts.join("+")).is_err());
    }

    /// What the Go server (server/e2e/log.go, state/e2e_kt.go) wrote for a
    /// log of three leaves under the seed [7; 32]: its key, its checkpoint
    /// and its leaves must read here as they are.
    #[test]
    fn the_go_servers_log_reads_and_adds_up() {
        let vkey = "icq.test/e2e-kt+b9e8e616+AepKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs";
        let note = "icq.test/e2e-kt\n3\nQr9t1UlRbxQaBMxColcG5aJFHVEefgt8JB71/9d+QaE=\n\n\u{2014} icq.test/e2e-kt uejmFvlvmzWmdlYn7HOfWragTH/XsV+sZvYrNQZbx1fCuZrexrGSPoxb1VgZlMwgwkZWBFh53mfu6ngHELyyS4g33AY=\n";
        let leaves = [
            "T1NDQVItRTJFLUtULXYxAAdhY2NvdW50AAYxMDAwMDEACAAAAABlU/EAAAdwdWJsaXNoACABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
            "T1NDQVItRTJFLUtULXYxAAZkZXZpY2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAUAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICACADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwBABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA",
            "T1NDQVItRTJFLUtULXYxAAZyZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAU",
        ];
        let v = parse_verifier(vkey).unwrap();
        let cp = open_checkpoint(note, &v).unwrap();
        assert_eq!(cp.size, 3);
        // The same seed signs the same way here.
        assert_eq!(
            sign_checkpoint("icq.test/e2e-kt", &[7; 32], 3, &cp.root),
            (note.to_string(), vkey.to_string())
        );

        let mut edge = Edge::default();
        let mut s = LogState::default();
        let mut verdicts = Vec::new();
        for l in leaves {
            let raw = vodozemac::base64_decode(l).unwrap();
            edge.push(leaf_hash(&raw));
            let leaf = parse_leaf(&raw).unwrap();
            assert_eq!(
                (leaf.screen_name.as_str(), leaf.time),
                ("100001", 1_700_000_000)
            );
            verdicts.push(s.apply(&leaf).is_ok());
        }
        assert_eq!(edge.root(), Some(cp.root));
        assert_eq!(
            s.accounts["100001"].key,
            vodozemac::base64_encode([1u8; 32])
        );
        // Its device carries a made-up signature, which the rules refuse
        // (and so the revoke of a device that never came in).
        assert_eq!(verdicts, [true, false, false]);
        assert!(s.accounts["100001"].devices.is_empty());
    }

    #[test]
    fn a_log_key_whose_base64_holds_a_plus_sign_reads() {
        let mut seen = 0;
        for i in 0..64u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let (note, vkey) = sign_checkpoint("x.test/e2e-kt", &seed, 1, &[3; 32]);
            if !vkey.splitn(3, '+').nth(2).unwrap().contains('+') {
                continue;
            }
            seen += 1;
            let v = parse_verifier(&vkey).unwrap();
            assert_eq!(open_checkpoint(&note, &v).unwrap().size, 1);
        }
        assert!(seen >= 3, "no key with a plus sign among the seeds");
    }

    /// What the Go auditor code (server/e2e/cosig.go) wrote under the seed
    /// [9; 32] for a checkpoint body at 1790000000.
    #[test]
    fn the_go_auditors_cosignature_reads() {
        let vkey = "auditor.test/icq+aecc7b07+BP0XJDhaoMdbZPt4zWAvodmR/ev3axPFjtcC6sg16fYY";
        let line = "\u{2014} auditor.test/icq rsx7BwAAAABqsTuAo5AAnP4gxbumK6CduYvZENoG37UMBtr51kYLkCR27KL3zqnhX+JtqSk53NBGpcxli61J6IeN8QHOpJqHr+wEAA==";
        let body = "icq.test/e2e-kt\n3\nQr9t1UlRbxQaBMxColcG5aJFHVEefgt8JB71/9d+QaE=\n";
        let c = parse_cosigner(vkey).unwrap();
        assert_eq!(verify_cosignature(&c, body, line), Some(1_790_000_000));
        assert_eq!(
            cosign("auditor.test/icq", &[9; 32], body, 1_790_000_000),
            (line.to_string(), vkey.to_string())
        );
        assert_eq!(
            verify_cosignature(&c, &body.replace("\n3\n", "\n4\n"), line),
            None
        );
        // A log key is not an auditor key, nor the other way round.
        assert!(parse_cosigner(&sign_checkpoint("x", &[1; 32], 0, &[0; 32]).1).is_err());
        assert!(parse_verifier(vkey).is_err());
    }

    #[test]
    fn deletes_and_rotation_proofs_read() {
        let (k1, k2) = (akey(1), akey(2));
        let sn = "100001";
        let mut s = LogState::default();
        for l in [
            build_leaf("account", sn, 1, &[b"publish", &pubkey(&k1)]),
            build_leaf(
                "account",
                sn,
                2,
                &[
                    b"rotate",
                    &pubkey(&k2),
                    &signed(&k1, &crate::sign::rotate(sn, &pubkey(&k1), &pubkey(&k2))),
                ],
            ),
        ] {
            s.apply(&parse_leaf(&l).unwrap()).unwrap();
        }
        assert_eq!(s.accounts[sn].key, vodozemac::base64_encode(pubkey(&k2)));
        // A delete needs the owner's signature or a recovery entry.
        let delete = build_leaf("delete", sn, 3, &[]);
        assert!(s.clone().apply(&parse_leaf(&delete).unwrap()).is_err());
        let owner = build_leaf(
            "owner-delete",
            sn,
            3,
            &[
                &5u64.to_be_bytes(),
                &signed(&k2, &crate::sign::delete(sn, 5)),
            ],
        );
        let forged = build_leaf(
            "owner-delete",
            sn,
            3,
            &[
                &5u64.to_be_bytes(),
                &signed(&k1, &crate::sign::delete(sn, 5)),
            ],
        );
        assert!(s.clone().apply(&parse_leaf(&forged).unwrap()).is_err());
        s.apply(&parse_leaf(&owner).unwrap()).unwrap();
        s.apply(&parse_leaf(&delete).unwrap()).unwrap();
        assert!(s.accounts.is_empty());
        assert_eq!(parse_leaf(&build_leaf("delete", sn, 3, &[b"x"])), None);
        assert_eq!(
            parse_leaf(&build_leaf(
                "account",
                "1",
                1,
                &[b"rotate", &[2; 32], &[3; 63]]
            )),
            None
        );
    }

    #[test]
    fn the_copy_keeps_every_leaf_hash_and_rebuilds_them() {
        use crate::directory::{DirectoryApi, MemoryDirectory};
        let dir = MemoryDirectory::new();
        let k = crate::keys::OwnKeys::create("100001");
        dir.announce("100001", &k.account_key_bytes());
        let (key, sig) = k.account_object();
        let t = crate::token::Token::parse(&dir.token("100001"))
            .unwrap()
            .bearer;
        dir.put_account(&t, &key, &sig).unwrap();
        let (c, e, d) = k.device_object().unwrap();
        dir.put_device(&t, k.device_id, &c, &e, &d).unwrap();

        let s = sync(&dir, &LogState::default()).unwrap();
        assert_eq!(s.leaf_hashes().unwrap().len(), 2);
        assert_eq!(s.root_at(2), s.edge().unwrap().root());
        assert_eq!(s.root_at(3), None);
        // A copy from before the hashes were kept gets them back.
        let mut old = s.clone();
        old.hashes.clear();
        assert_eq!(sync(&dir, &old).unwrap(), s);
        // And one whose first entries were replaced is a rewrite.
        dir.rewrite_log(
            0,
            build_leaf("account", "100009", 1, &[b"publish", &[9; 32]]),
        );
        assert!(matches!(sync(&dir, &old), Err(SyncError::Rewritten(_))));
    }

    /// The leaves of `server/e2e/audit_test.go`'s `sharedKTVectors`, as the
    /// Go server builds them.
    const SHARED_VECTORS: [&str; 11] = [
        "T1NDQVItRTJFLUtULXYxAAdhY2NvdW50AAYxMDAwMDEACAAAAABlU/EAAAdwdWJsaXNoACCKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXA==",
        "T1NDQVItRTJFLUtULXYxAAZkZXZpY2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAEAIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgBAymZM6VU7E6HkcvkIbyPYI3F+7UxZBkwaxvlPxTFkyMnL/5uAFJ6R2mFh1CuFjbt5t3+xcBgdP4/BPob0Kj3qBQ==",
        "T1NDQVItRTJFLUtULXYxAAxvd25lci1yZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAEACAAAAABlU/EAAEBtqTL0mQxf5xJahj15TZDec+7FG277JwFmOjAaE5mXzbSjatUjZLkSw/JxUXnsqSxE837cBwxn3KzjnMHrj6kE",
        "T1NDQVItRTJFLUtULXYxAAZyZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAE=",
        "T1NDQVItRTJFLUtULXYxAAxvd25lci1yZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAEACAAAAABlU/EAAED7hSQ8ksBojn+or+VHOMtZQ4C0BYnf64M9ej/d7/TbsAi0iqcXOGyiPf5Xfk+ZjP5+4RCuw7YlBGMUXOldfvED",
        "T1NDQVItRTJFLUtULXYxAA9yZWNvdmVyeS1yZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAEAC2xvc3QgbGFwdG9w",
        "T1NDQVItRTJFLUtULXYxAAdhY2NvdW50AAYxMDAwMDEACAAAAABlU/EAAAVyZXNldAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=",
        "T1NDQVItRTJFLUtULXYxAA9yZWNvdmVyeS1kZWxldGUABjEwMDAwMQAIAAAAAGVT8QAAF3RoZSBhY2NvdW50IHdhcyBkZWxldGVk",
        "T1NDQVItRTJFLUtULXYxAAZkZWxldGUABjEwMDAwMQAIAAAAAGVT8QA=",
        "T1NDQVItRTJFLUtULXYxAAdhY2NvdW50AAYxMDAwMDEACAAAAABlU/EAAAdwdWJsaXNoACBuehzdKbC3j9E69MVZj+/07yqXFm48pvLk+/zNgFBb8Q==",
        "T1NDQVItRTJFLUtULXYxAAxvd25lci1kZWxldGUABjEwMDAwMQAIAAAAAGVT8QAACAAAAABlU/EAAEBOWgjh6PMWip+xhnXoAOk4Xy37Uwfp719ulO0e2KzgtRoi7KlikRgHbJXAw/v+U10Ta1Q3fw3En5cZFIcZ5cAA",
    ];

    /// The same sequences as `sharedKTSequences` in
    /// `server/e2e/audit_test.go`, with the auditor's verdicts there: the
    /// client's replay must come to the same (second audit of 2026-10,
    /// finding 1). `None` is a violation; `Some` the positions the auditor
    /// logs as the operator's recovery.
    #[test]
    fn the_replay_comes_to_the_auditors_verdicts() {
        let cases: [(&[usize], Option<&[usize]>); 8] = [
            (&[0, 1, 2, 3], Some(&[])),
            (&[0, 1, 3], None),
            (&[0, 1, 4], None),
            (&[0, 1, 5, 3, 6], Some(&[2, 4])),
            (&[0, 7, 8, 9], Some(&[1, 3])),
            (&[0, 8], None),
            (&[0, 10, 8], Some(&[])),
            (&[0, 10, 9], None),
        ];
        let leaves: Vec<Leaf> = SHARED_VECTORS
            .iter()
            .map(|l| parse_leaf(&STANDARD.decode(l).unwrap()).unwrap())
            .collect();
        for (seq, want) in cases {
            let mut s = LogState::default();
            let mut recovered = Vec::new();
            let mut verdict = Ok(());
            for (pos, i) in seq.iter().enumerate() {
                match s.apply(&leaves[*i]) {
                    Ok(Some(_)) => recovered.push(pos),
                    Ok(None) => {}
                    Err(e) => {
                        verdict = Err(e);
                        break;
                    }
                }
            }
            match want {
                None => assert!(verdict.is_err(), "{seq:?} must break the rules"),
                Some(r) => {
                    assert_eq!(verdict, Ok(()), "{seq:?}");
                    assert_eq!(recovered, r, "{seq:?}");
                }
            }
        }
        // What the client keeps of it: a reset after a recovery is a new
        // identity, a key after the operator's delete too; the owner's own
        // delete and publish is not marked.
        let mut s = LogState::default();
        for i in [0, 1, 5, 3, 6] {
            s.apply(&leaves[i]).unwrap();
        }
        let a = &s.accounts["100001"];
        assert!(a.new_identity.as_deref().unwrap().contains("lost laptop"));
        let Change::Account { key: first, .. } = &leaves[0].change else {
            panic!("leaf 0 is a publish")
        };
        assert!(
            !a.continues(first),
            "the reset key does not continue the first"
        );
        let mut s = LogState::default();
        for i in [0, 7, 8, 9] {
            s.apply(&leaves[i]).unwrap();
        }
        assert!(s.accounts["100001"]
            .new_identity
            .as_deref()
            .unwrap()
            .contains("the account was deleted"));
    }

    #[test]
    fn the_servers_verifier_key_format_reads() {
        // note.NewEd25519VerifierKey("PeterNeumann", key of seed [1; 32]) is
        // name+hash+base64(0x01 || key); sign_checkpoint builds it the same.
        let (_, vkey) = sign_checkpoint("PeterNeumann", &[1; 32], 0, &[0; 32]);
        let v = parse_verifier(&vkey).unwrap();
        assert_eq!(v.name, "PeterNeumann");
        assert_eq!(vkey.split('+').nth(1).unwrap().len(), 8);
    }
}
