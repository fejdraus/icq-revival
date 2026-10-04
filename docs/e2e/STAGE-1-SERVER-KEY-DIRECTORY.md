# Stage 1 - Server: public key directory

> **Historical completed stage plan.** This records the plan and decisions
> of a development stage that is finished. It is kept for history and
> rationale and is **not a specification of the current add-on**; later
> stages and the audits changed several of its rules, and its "decisions
> already made" are not current requirements. For current behaviour and
> security rules use `tools/icq-e2e/README.md`, `docs/e2e/CHECKLIST.md`,
> `docs/e2e/AUDIT-2026-10.md` and the source and tests.

Self-contained task for one session. Server-side Go only; no client code.

## Goal

Add a **public key directory** to the Open OSCAR Server so ICQ clients (through a
client add-on built in later stages) can publish and fetch the public keys used for
end-to-end encrypted messages. The server stores and serves **public** material
only, relays opaque encrypted blobs for device linking, and never sees private keys
or message plaintext. Background and the overall design: `docs/e2e/DESIGN.md`
(sections 7, 8 and 9).

## Decisions already made (do not reopen)

- Crypto on clients: **vodozemac** (Olm). Each device has a Curve25519 identity key
  and an Ed25519 signing key, one-time keys and a fallback key.
- Trust model is Signal-like: **one account key per UIN** (Ed25519) shared by the
  account's devices. Every device's keys are **signed by the account key**, so the
  server cannot add a device on its own. A new device is approved on an existing
  device; the server only relays the ciphertext.
- Transport: an **HTTP JSON API** (served behind nginx over HTTPS), authenticated by
  a **bearer token the server issues at OSCAR sign-in** (DESIGN.md 8.1, option B.2).
  Not a new OSCAR food group.

## Scope

1. **Storage** (`state/`, new numbered migration `.up.sql`/`.down.sql`):
   - `e2e_account`: uin, account Ed25519 public key, created, updated.
   - `e2e_account_key_history`: uin, old key, new key, changed_at - so clients can
     warn that a contact's safety number changed.
   - `e2e_device`: uin, device_id (u32, unique per uin), curve25519 key, ed25519 key,
     account signature over the device keys, created, last_seen, revoked.
   - `e2e_fallback_key`: uin, device_id, key id, public key, device signature.
   - `e2e_one_time_key`: uin, device_id, key id, public key, device signature;
     consumed atomically (select-and-delete in one transaction).
   - `e2e_link_request`: id, uin, new-device ephemeral public key, blobs in each
     direction, created, expires (short TTL, e.g. 10 minutes).
   - Store interface in the style of `SQLiteUserStore`, with table-driven tests.
2. **Token**: a short-lived, session-bound token issued at BOS sign-in, bound to the
   UIN and the session. Reuse `state.HMACCookieBaker` (its key now persists in
   `cookie.key`) rather than inventing a new signer. How the token reaches the
   client: a TLV the stock clients ignore, in a message the server already sends
   after sign-in (DESIGN.md 8.1 B.2 names candidates). Pick one, check against the
   stock ICQ 6.5/7.2 behaviour described in the code comments that it is ignored, and
   document the choice. Revocation: a token dies with its session or at expiry.
3. **HTTP API** - decide whether it lives on `server/webapi` (port 8082, already
   reachable by ICQ 7.2 through the patches) or a new small listener wired in
   `cmd/server/factory.go`; explain the choice. Endpoints, all JSON, all but
   `GET bundle`/`GET devices`/`GET account` requiring the token of the UIN they
   change:
   - `PUT  /e2e/v1/account` - publish the account key (first time), or replace it
     with a proof signed by the current key; a replacement is recorded in the
     history.
   - `PUT  /e2e/v1/devices/{device_id}` - publish or refresh a device (keys + account
     signature); the server verifies the account signature against the stored
     account key.
   - `DELETE /e2e/v1/devices/{device_id}` - revoke a device (token of the same UIN).
   - `POST /e2e/v1/devices/{device_id}/one-time-keys` - upload a batch; verify each
     device signature; cap the pool size.
   - `PUT  /e2e/v1/devices/{device_id}/fallback-key`.
   - `GET  /e2e/v1/users/{uin}/devices` - device list with keys and signatures, and
     the account key, so the caller can verify everything itself.
   - `POST /e2e/v1/users/{uin}/devices/{device_id}/claim` - claim one one-time key
     (or the fallback key when the pool is empty), consumed atomically.
   - `GET  /e2e/v1/users/{uin}/account-history` - key changes for safety-number
     warnings.
   - Link relay: `POST /e2e/v1/link` (new device opens a request with its ephemeral
     key), `GET /e2e/v1/link/{id}` and `POST /e2e/v1/link/{id}/reply` (existing
     device answers with an encrypted blob), polled by both sides; expires quickly.
   - Rate limits and size limits on every write; reject unknown fields.
4. **Signature verification** on the server for device keys (Ed25519 via the Go
   standard library `crypto/ed25519`), so a buggy client cannot store garbage. The
   exact byte strings that are signed must be specified in the doc comment and in
   a `docs/e2e/KEY-DIRECTORY-API.md` written in this stage - later client stages
   implement against it.
5. **Management API / admin**: read-only listing of a UIN's devices in the existing
   management API (`api.yml` + handler) so the owner can inspect and revoke.
6. **Config**: any new setting goes into the `Config` struct and the settings files
   are regenerated with `make config` (never hand-edited).

## Out of scope

Client add-on, message format, encryption itself, the management page shown in
ICQ - later stages.

## Done when

- `go test -race ./...` passes (note: `state` tests already fail on Windows for
  unrelated reasons - run them in WSL/CI or compare with the baseline),
  `gofmt -s -l .` and `go vet ./...` are clean.
- `docs/e2e/KEY-DIRECTORY-API.md` describes every endpoint, request/response and
  the exact signed byte strings, with examples.
- Committed in the repository's style (English message, no AI attribution lines).
  Deploying is a separate, explicit request of the owner.
