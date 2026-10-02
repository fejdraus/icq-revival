# Key directory API (E2E stage 1)

The server side of the end-to-end encryption add-on for ICQ 6.5 and 7.2: a
directory of **public** keys and a relay for device linking. The server stores
what clients publish and hands it out again; it never holds a private key or a
plaintext message. Background: `DESIGN.md`, sections 7-9. Code: `server/e2e`
(HTTP, signatures), `state/e2e_keys.go` (storage), `state/e2e_token.go`
(token), `foodgroup/oservice.go` (`motdTLVs`, where the token is handed out),
`foodgroup/locate.go` (`SetInfo`, where the add-on announces its account key).

## 1. Model

- **Account key** - one Ed25519 key per account (ICQ UIN or AIM screen name),
  shared by all of the account's devices. It signs the devices. Only clients
  hold its private half.
- **Device** - a client install, with a random 32-bit **device id** (1 to
  4294967295, unique within the account) and two vodozemac keys: a Curve25519
  identity key and an Ed25519 signing key. The account key signs both
  together with the id. A device is either active or **revoked**. A revoked
  device keeps its row, so peers can see that it went and its id is never
  reused, but its fallback and one-time keys are deleted.
- **One-time keys** - a pool of Curve25519 keys per device, each signed by the
  device's Ed25519 key. A claim hands one out and deletes it in the same
  transaction, so no two senders get the same key.
- **Fallback key** - one Curve25519 key per device, signed like a one-time key,
  handed out when the pool is empty. It is replaced, never consumed.
- **Account key history** - every change of the account key (`publish`,
  `rotate`, `reset`), so a peer's client can warn that the safety number
  changed.
- **Device-link request** - a short-lived mailbox through which a new device
  gets the account key's private half from an existing device (DESIGN.md
  8.2). The server sees only the new device's ephemeral public key and two
  opaque blobs.

The server checks every signature on the way in, so a buggy client cannot
store what no key vouched for. Clients must still check everything they fetch
themselves: the server is untrusted.

## 2. Where it is served

On the **WebAPI server** (`server/webapi`), under `/e2e/v1/`. Production runs
it on port 8082 with `ENABLE_WEBAPI=1`, and nginx publishes it over HTTPS on
8443. That is the reason for this choice over a new listener: it is already
reachable over TLS from outside, and ICQ 7.2 already reaches it through its
patch, so there is no new port, firewall rule, certificate or nginx block. The
catch is that the directory runs only where the WebAPI runs. A standalone
listener would be a few lines in `cmd/server` if that ever matters.

The API is plain JSON over HTTP. It is not AMF and not the Web AIM envelope,
and it is independent of the WebAPI's `aimsid` sessions. Clients should use the
HTTPS address. The token is a bearer credential, so sending it over plain HTTP
exposes it to anyone on the path. It is exposed anyway, though: the BOS
connection that hands it out is not encrypted (section 3.3).

## 3. Authentication: the token

### 3.1 How the client gets it

When a client signs in over BOS, it sends `OService ClientVersions`
(`0x01/0x17`), and the server answers with `HostVersions` and then
`OService MOTD` (`0x01/0x13`). On the **BOS connection only**, this MOTD's
TLV block carries one more TLV:

| Tag      | Value                                           |
|----------|-------------------------------------------------|
| `0x000B` | MOTD text (unchanged)                           |
| `0x0E2E` | the key directory token, raw bytes (about 100)  |

The add-on reads it from the client's inbound stream without changing a byte
(DESIGN.md 8.1 B.2). The token is binary; in the `Authorization` header it is
sent as **base64url without padding**.

**Why the MOTD.** DESIGN.md 8.1 names `OServiceHostOnline` and
`OServiceClientOnline` as candidates. `HostOnline` has no TLV block: it is a
bare list of food group numbers, so an extra field would be read as food
groups. `ClientOnline` goes from the client to the server. The MOTD is sent by
the server, once per BOS sign-in, right after the client's `ClientVersions`,
and its body is a TLV block. Tag `0x0E2E` is not an AOL tag.

**Is it ignored by the stock clients?** OSCAR clients look up the TLVs of a
block by tag and pass over tags they do not know. That rule is what lets AOL
add TLVs to existing SNACs. Nothing in this repository shows ICQ 6.5 or 7.2
handling the MOTD in any other way: neither the client patches nor the code
comments mention it. **This has not been checked in a real ICQ 6.5 / 7.2
client yet.** The check is part of the first client-side stage: sign in with
the phase-0 log-only DLL, confirm that the MOTD with TLV `0x0E2E` shows up in
the log, and confirm that the client behaves exactly as before. If a client
turns out to mind the TLV, the fallback is a separate SNAC, which would have to
be hidden from the client (DESIGN.md 8.1 B.2).

### 3.2 What the token is

A token is `state.HMACCookieBaker`-signed (the key in `cookie.key`, next to
the database), the same signer as the login cookies. Its payload is:

```
magic        6 bytes  FF FF FF 'E' '2' 'E'
screen name  u8 length + bytes (ident form)
signon time  u64 BE, Unix nanoseconds of the session's sign-on
instance     u8, the session instance number
```

The magic keeps tokens and login cookies apart. A login cookie's payload
starts with its service number and is refused as a token. A token read as a
login cookie would claim a 255-byte screen name, longer than the payload, so
it fails to parse.

A token is accepted while all of these hold:

- the HMAC checks and it has not expired (`E2E_TOKEN_TTL`, default 12h);
- the account has a signed-on session whose sign-on time equals the one in
  the token (a later session of the same account does not count);
- that session still has the instance the token names, and it is open.

So **a token dies with its session instance or at expiry**, whichever comes
first. Nothing is stored server-side. A client that stays signed on longer
than the TTL calls `POST /e2e/v1/token` before expiry to get a fresh token.

### 3.3 The token is not a secret: announcing the account key

The MOTD that carries the token travels in clear, like everything else on the
BOS connection of ICQ 6.5 and 7.2 (CHECKLIST.md 7.1, 7.2). Whoever reads that
traffic has the token and can call every `T` endpoint as the account until the
session ends. The dangerous call is the one that sets an account key no key
vouches for yet: the first publish, and a reset. With the token alone, a
reader could publish **their** key for a UIN that has not enrolled, and every
peer's trust-on-first-use would pin the reader's key.

A password does not help here. ICQ 2003b sends a reversibly roasted password.
ICQ 6.5 and 7.2 send `StrongMD5Pass`, and since the salt (`AuthKey`) of an
account never changes, that digest is the same at every sign-in: a
password-equivalent that a reader of the traffic has already seen.

What a reader of the traffic cannot do is **write** into the connection. So
the add-on announces its account key on the BOS connection itself, and the
directory takes a key that no current key vouches for only when it came in
on the connection the token belongs to:

- The add-on appends TLV `0x0E2E` (value: the 32-byte account key, raw) to the
  TLV block of an outbound `Locate SetInfo` (`0x02/0x04`). It already rewrites
  that SNAC in place to add its capability, so no frame is added. The client
  sends `SetInfo` while signing on, so an add-on that has an account key
  announces it at every sign-on. It generates the key before sign-on, when it
  has none yet. `0x0E2E` is not an AOL tag; the server ignores a value that
  is not 32 bytes.
- The server remembers the last key announced on each session instance.
- `PUT /e2e/v1/account` as a **first publish** or a **reset** needs
  `account_key` to be the key announced on the token's session instance.
  Otherwise the answer is `403 not_announced`. Republishing the stored key and
  rotating (which the current key signs) need no announcement.
- `DELETE /e2e/v1/devices/{device_id}` needs **some** key announced on that
  instance, any one. A reader of the traffic therefore cannot strip an
  account of its devices either. A user who lost every device announces the
  new key they are about to reset to, and may then revoke the old devices and
  reset.

The add-on publishes after its `SetInfo` has gone out. If the directory
answers `403 not_announced` because the HTTPS request overtook the `SetInfo`,
it retries a little later.

What is left to a reader of the traffic while the session lasts:

- the `T` calls that change nothing for good or that need a signature they
  cannot make: a fresh token, reading the own device's state, claims (any
  signed-on account can make those), uploads that must be signed by a device;
- device linking: the reader can open a link request or answer one. The
  clients must guard it themselves: the user compares the short authentication
  string, and a new device accepts a reply only if it holds the private half
  of the published account key. At worst the reader answers first and the
  user has to start the linking again.

A reader who **changes** traffic (an active attacker on the path) can
announce a key too; that needs the connection itself to be encrypted
(CHECKLIST.md 7.2). So does anyone who learns the password: they sign on as
the user and hold a genuine session.

### 3.4 Rate and size limits

- Every request that needs a token counts against a per-account token bucket:
  5 requests a second, bursts of 30. When the bucket is empty the answer is
  `429 rate_limited`. The token-free `GET` endpoints are left to edge rate
  limiting in nginx, like the rest of the WebAPI.
- Request bodies are limited to 64 KiB (`413 too_large`). Unknown JSON fields
  and data after the JSON object are refused (`400 bad_request`).
- Up to 100 one-time keys per upload, and a pool of `E2E_MAX_ONE_TIME_KEYS`
  (default 100) per device.
- At most `E2E_MAX_DEVICES` (default 10) active devices per account.
- Link blobs up to 16 KiB, at most 4 pending link requests per account, each
  living `E2E_LINK_TTL` (default 10m).

## 4. Encoding conventions

- Binary fields (keys, signatures, blobs) are **standard base64**. The server
  writes them **without padding**, the way vodozemac does, and accepts them
  with or without it.
- All public keys are 32 bytes, all signatures 64 bytes (Ed25519, RFC 8032).
- Times are Unix seconds (integers).
- `{uin}` in a path is the account: an ICQ UIN in decimal, or an AIM screen
  name (it is normalised to the ident form: lower case, no spaces).
- `{device_id}` is decimal, 1 to 4294967295.
- A key id (`key_id`) is 1 to 64 characters of the base64 / base64url
  alphabet (`A-Z a-z 0-9 + / = _ -`), e.g. vodozemac's `KeyId::to_base64()`.
  It is unique within a device's pool.
- Errors are `{"error": "<code>", "message": "<text>"}`. The `error` codes are
  listed in section 7.

## 5. Signed byte strings

A signature is plain Ed25519 over a **message**. A message is the 12 ASCII
bytes `OSCAR-E2E-v1` followed by fields, each written as a **16-bit big-endian
length** and then the field's bytes:

```
message = "OSCAR-E2E-v1" || field(purpose) || field(screen name) || field(...) ...
field(x) = u16be(len(x)) || x
```

- `purpose` is an ASCII string naming the message kind (below).
- `screen name` is the account's ident form: `"123456"` for UIN 123456. It
  binds each signature to its account, so a device or key cannot be replayed
  into another account.
- a device id is its 4 bytes, big-endian;
- a key is its 32 raw bytes; a key id is its ASCII bytes.

| Message        | Fields after the screen name            | Signed by                      |
|----------------|------------------------------------------|--------------------------------|
| `account`      | account key                              | that account key (possession)  |
| `rotate`       | old account key, new account key         | the old (current) account key  |
| `device`       | device id, Curve25519 key, Ed25519 key    | the account key                |
| `one-time-key` | device id, key id, Curve25519 key         | the device's Ed25519 key       |
| `fallback-key` | device id, key id, Curve25519 key         | the device's Ed25519 key       |

The functions that build them are in `server/e2e/sign.go`. Vectors that pin
the bytes are in `sign_test.go`.

### 5.1 Worked example

Account `123456`. The keys come from fixed Ed25519 seeds (32 bytes each), so
anyone can reproduce them:

| Key                     | Seed           | Public key (base64)                             |
|-------------------------|----------------|--------------------------------------------------|
| account key             | 32 x `01`      | `iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w`    |
| device 1 Ed25519        | 32 x `02`      | `gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q`    |
| device 1 Curve25519     | (32 x `03`)    | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM`    |
| a one-time key          | (32 x `04`)    | `BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ`    |
| new account key         | 32 x `05`      | `bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E`    |

(The Curve25519 values are just 32 bytes as far as the server is concerned.
It checks their size, not whether they are points on the curve.)

`account` message (hex), for the account key:

```
4f534341522d4532452d7631                      "OSCAR-E2E-v1"
0007 6163636f756e74                           "account"
0006 313233343536                             "123456"
0020 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
```

self_signature: `MjyAKwrPALzHWNRPYbORmZJQvdklIhAXH1f5Qw/2OnpggRwVpH5UhcmYT8CdRbUcqSHDx2TcUUxQkohkehUsBw`

`device` message for device 1, signed by the account key:

```
4f534341522d4532452d7631
0006 646576696365                             "device"
0006 313233343536                             "123456"
0004 00000001                                 device id 1
0020 0303030303030303030303030303030303030303030303030303030303030303
0020 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
```

account_signature: `s966Fw1ZvqlxQGnM8pYG5uuRAMBSEw+gjdTQCHQWrQTu9zzNsE1bnOhPdE5kVSmY75GcA8S6fP/e5/Z1J8PjAQ`

`one-time-key` message, key id `AAAAAQ`, signed by device 1's Ed25519 key:

```
4f534341522d4532452d7631
000c 6f6e652d74696d652d6b6579                 "one-time-key"
0006 313233343536
0004 00000001
0006 414141414151                             "AAAAAQ"
0020 0404040404040404040404040404040404040404040404040404040404040404
```

signature: `t515M1k9PBHb/f/3K3y6Y5a+gak+BC/9Hz/9OCGPrqQZSRBOl7iKNN+0tg/kpya+rzQ0acn4rcudSzFABiHcBw`

`fallback-key` message, key id `AAAAAg`, same key bytes, signed by device 1:
`fallback-key` purpose (`000c 66616c6c6261636b2d6b6579`), key id
`0006 414141414167`. Signature:
`6yfz+5itolxEadiy8fM3owUtMLtWYVdFh0RnlTIoraly+Q7PFG7vuVmJUeSbPmdmh0+Ni8E7O9/G94hir3fdDg`

Rotation to the new account key:

- `rotate` message (`0006 726f74617465`, then the screen name, the old key and
  the new key), signed by the **old** key; the proof is
  `2fVwgVvAI7R24KWz5jdK4SaR6WTBGkqi2R5NkgrOfTjmiywn1jWuaUP+qwYAbWAtvVnWm7siYOuDDBXQr/oPDA`;
- `account` message for the new key, signed by the new key (self_signature):
  `PX3E89ta4G54iDC9G6EVrUknCrBPNg5w0YXrGauLn8Ey1hamcU8NDIzIKxAxc9hbUGa3zAw5XY3xrpX54ZQ3Bw`;
- the same `device` message as above, re-signed by the **new** key for device
  1 to stay:
  `/9EoVZbz9kv0fObtLWsoIZU0k/9LDpc9FnI3jx/NlIuKW9aKC+ddwhUR9lFunloxTe2T5SZIlF9lY8hXVhqRCA`.

## 6. Endpoints

`T` = needs `Authorization: Bearer <token>`. For the endpoints without
`{uin}`, the account is the token's own. Examples use the keys of 5.1 and
UIN 123456.

| Method | Path                                                | T | Purpose                                   |
|--------|-----------------------------------------------------|---|-------------------------------------------|
| POST   | `/e2e/v1/token`                                     | T | fresh token for the same session          |
| PUT    | `/e2e/v1/account`                                   | T | publish / rotate / reset the account key  |
| PUT    | `/e2e/v1/devices/{device_id}`                       | T | publish or refresh a device               |
| GET    | `/e2e/v1/devices/{device_id}`                       | T | own device and its key pool state         |
| DELETE | `/e2e/v1/devices/{device_id}`                       | T | revoke a device                           |
| POST   | `/e2e/v1/devices/{device_id}/one-time-keys`         | T | upload one-time keys                      |
| PUT    | `/e2e/v1/devices/{device_id}/fallback-key`          | T | replace the fallback key                  |
| GET    | `/e2e/v1/users/{uin}/account`                       |   | an account's key                          |
| GET    | `/e2e/v1/users/{uin}/devices`                       |   | an account's key and devices              |
| GET    | `/e2e/v1/users/{uin}/account-history`               |   | an account's key changes                  |
| POST   | `/e2e/v1/users/{uin}/devices/{device_id}/claim`     | T | claim a one-time (or fallback) key        |
| POST   | `/e2e/v1/link`                                      | T | new device opens a link request           |
| GET    | `/e2e/v1/link`                                      | T | existing devices list pending requests    |
| GET    | `/e2e/v1/link/{id}`                                 | T | read one request (new device polls reply) |
| POST   | `/e2e/v1/link/{id}/reply`                           | T | existing device answers                   |
| DELETE | `/e2e/v1/link/{id}`                                 | T | drop a request                            |

### 6.1 `POST /e2e/v1/token`

No body. `200`:

```json
{"token": "AEj__...", "expires_at": 1790000000}
```

The token is base64url without padding, ready for the header.

### 6.2 `PUT /e2e/v1/account`

```json
{
  "account_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
  "self_signature": "MjyAKwrPALzHWNRPYbORmZJQvdklIhAXH1f5Qw/2OnpggRwVpH5UhcmYT8CdRbUcqSHDx2TcUUxQkohkehUsBw"
}
```

`self_signature` (the `account` message, signed by `account_key`) is always
required. Depending on what is stored:

- **No key yet** - the key is published: `201`, and a history entry
  `publish`. `proof` and `devices` must be absent. The key must have been
  announced on the token's BOS connection (section 3.3).
- **The same key** - no-op, `200`.
- **Another key, with `proof`** - a **rotation**. `proof` is the `rotate`
  message signed by the current key. `devices` lists the active devices to
  keep, each with the `device` message re-signed by the **new** key:

  ```json
  {
    "account_key": "bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E",
    "self_signature": "PX3E89ta4G54iDC9G6EVrUknCrBPNg5w0YXrGauLn8Ey1hamcU8NDIzIKxAxc9hbUGa3zAw5XY3xrpX54ZQ3Bw",
    "proof": "2fVwgVvAI7R24KWz5jdK4SaR6WTBGkqi2R5NkgrOfTjmiywn1jWuaUP+qwYAbWAtvVnWm7siYOuDDBXQr/oPDA",
    "devices": [
      {"device_id": 1, "account_signature": "/9EoVZbz9kv0fObtLWsoIZU0k/9LDpc9FnI3jx/NlIuKW9aKC+ddwhUR9lFunloxTe2T5SZIlF9lY8hXVhqRCA"}
    ]
  }
  ```

  Every active device **not** listed is revoked, since only the old key vouched
  for it. It all happens in one transaction, so the invariant "every active
  device's signature verifies against the stored account key" always holds.
  History entry `rotate`. `200`.
- **Another key, without `proof`** - a **reset**, e.g. after every device was
  lost. It is allowed only when the account has no active device (revoke them
  first, from a device or from the management API). Otherwise the answer is
  `409 active_devices`. The new key must have been announced on the token's
  BOS connection (section 3.3). History entry `reset`. `200`. Peers learn about it
  from the history, as a changed safety number.

Response (`200`/`201`):

```json
{"screen_name": "123456", "account_key": "iojj...b1w", "created_at": 1790000000, "updated_at": 1790000000}
```

Errors: `400 invalid_key`, `400 invalid_signature` (self_signature, proof or
a device signature), `403 not_announced` (first publish or reset of a key not
announced on the BOS connection), `404 no_device` / `410 device_revoked` (a
listed device),
`409 active_devices`, `409 account_key_changed` (it changed during the
request; retry).

### 6.3 `PUT /e2e/v1/devices/{device_id}`

```json
{
  "curve25519_key": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
  "ed25519_key": "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q",
  "account_signature": "s966Fw1ZvqlxQGnM8pYG5uuRAMBSEw+gjdTQCHQWrQTu9zzNsE1bnOhPdE5kVSmY75GcA8S6fP/e5/Z1J8PjAQ"
}
```

`account_signature` is the `device` message signed by the stored account key.
The same id with the same keys is a refresh: the signature and `last_seen_at`
are updated. `201` for a new device, `200` for a refresh:

```json
{
  "device": {
    "device_id": 1,
    "curve25519_key": "AwMD...AwM",
    "ed25519_key": "gTl3...s5Q",
    "account_signature": "s966...jAQ",
    "created_at": 1790000000,
    "last_seen_at": 1790000000
  },
  "one_time_key_count": 0,
  "has_fallback_key": false
}
```

`revoked_at` appears in a device object only for a revoked device.

Errors: `404 no_account` (publish the account key first), `400 invalid_key`,
`400 invalid_signature`, `409 device_conflict` (the id is taken by other keys;
pick another random id), `410 device_revoked` (a revoked id is never reused),
`409 too_many_devices`, `409 account_key_changed`.

### 6.4 `GET /e2e/v1/devices/{device_id}`

The caller's own device, in the same shape as the `PUT` response. It tells the
client when to upload more one-time keys. `404 no_device`.

### 6.5 `DELETE /e2e/v1/devices/{device_id}`

Revokes one of the caller's devices: its one-time and fallback keys are
deleted, and it stays in the device list with `revoked_at`. `204`. Revoking a
revoked device is also `204`. The token's BOS connection must have announced
an account key, any one (section 3.3); otherwise `403 not_announced`.
`404 no_device`.

### 6.6 `POST /e2e/v1/devices/{device_id}/one-time-keys`

```json
{
  "keys": [
    {
      "key_id": "AAAAAQ",
      "public_key": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
      "signature": "t515M1k9PBHb/f/3K3y6Y5a+gak+BC/9Hz/9OCGPrqQZSRBOl7iKNN+0tg/kpya+rzQ0acn4rcudSzFABiHcBw"
    }
  ]
}
```

Each `signature` is the `one-time-key` message signed by the device's Ed25519
key. 1 to 100 keys, with no key id repeated within the batch. A key id already
in the pool is skipped, so a retried upload is harmless. An upload that would
take the pool over `E2E_MAX_ONE_TIME_KEYS` adds nothing and is
`409 pool_full`. `200`:

```json
{"one_time_key_count": 1}
```

Errors: `400 bad_request` (count, bad or repeated key id), `400 invalid_key`,
`400 invalid_signature`, `404 no_device`, `410 device_revoked`,
`409 pool_full`.

### 6.7 `PUT /e2e/v1/devices/{device_id}/fallback-key`

One key object as above, with the `fallback-key` message signed by the device:

```json
{
  "key_id": "AAAAAg",
  "public_key": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
  "signature": "6yfz+5itolxEadiy8fM3owUtMLtWYVdFh0RnlTIoraly+Q7PFG7vuVmJUeSbPmdmh0+Ni8E7O9/G94hir3fdDg"
}
```

`204`. It replaces the previous fallback key. Errors as for one-time keys.

### 6.8 `GET /e2e/v1/users/{uin}/account`

No token. `200` with the account object of 6.2, or `404 no_account`.

### 6.9 `GET /e2e/v1/users/{uin}/devices`

No token. The account key and every device, revoked ones included, with their
signatures, so the caller can check everything itself: each active device's
`account_signature` over the `device` message against `account_key`, and
`account_key` against the one the caller already trusts for this contact.

```json
{
  "screen_name": "123456",
  "account_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
  "devices": [
    {"device_id": 1, "curve25519_key": "AwMD...AwM", "ed25519_key": "gTl3...s5Q",
     "account_signature": "s966...jAQ", "created_at": 1790000000, "last_seen_at": 1790000000},
    {"device_id": 9, "curve25519_key": "...", "ed25519_key": "...",
     "account_signature": "...", "created_at": 1789000000, "last_seen_at": 1789500000,
     "revoked_at": 1789600000}
  ]
}
```

A revoked device's signature may be by an older account key; skip revoked
devices when checking. `404 no_account`.

### 6.10 `GET /e2e/v1/users/{uin}/account-history`

No token. Oldest first. An account that never published anything has an empty
list.

```json
{
  "screen_name": "123456",
  "changes": [
    {"kind": "publish", "new_key": "iojj...b1w", "changed_at": 1790000000},
    {"kind": "rotate", "old_key": "iojj...b1w", "new_key": "bnoc...W/E", "changed_at": 1790100000}
  ]
}
```

### 6.11 `POST /e2e/v1/users/{uin}/devices/{device_id}/claim`

Token of **any** signed-on account (the claim counts against the caller's rate
limit), no body. It hands out one one-time key of the device and deletes it
from the pool atomically; when the pool is empty, the fallback key instead.
Both are left out when the device has published neither.

```json
{
  "screen_name": "123456",
  "account_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
  "device": {"device_id": 1, "curve25519_key": "AwMD...AwM", "ed25519_key": "gTl3...s5Q",
             "account_signature": "s966...jAQ", "created_at": 1790000000, "last_seen_at": 1790000000},
  "one_time_key": {"key_id": "AAAAAQ", "public_key": "BAQE...BAQ", "signature": "t515...cBw"}
}
```

`one_time_key` and `fallback_key` have the same shape as `signedKeyJSON`
(`key_id`, `public_key`, `signature`), and both are omitted when the device has
published neither. Exactly one of the two is present: `one_time_key` when the
pool had a key left, `fallback_key` when the pool was empty, so a client reads
`one_time_key` and falls back to `fallback_key` rather than treating the field
names as alternatives to try.

```json
{
  "screen_name": "123456",
  "account_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
  "device": {"device_id": 1, "curve25519_key": "AwMD...AwM", "ed25519_key": "gTl3...s5Q",
             "account_signature": "s966...jAQ", "created_at": 1790000000, "last_seen_at": 1790000000},
  "fallback_key": {"key_id": "", "public_key": "AQID...AQ", "signature": "1a7c...bEw"}
}
```

The caller checks the chain: `account_key` → device (`device` message) →
one-time or fallback key (`one-time-key` / `fallback-key` message, by the
device's `ed25519_key`). Errors: `404 no_account`, `404 no_device`,
`410 device_revoked`.

### 6.12 Device linking

The flow (DESIGN.md 8.2): a new device signs in with the password, so it has a
token for the account. It then:

1. `POST /e2e/v1/link` with its ephemeral Curve25519 key, and optionally an
   opaque `request` blob:

   ```json
   {"ephemeral_key": "<32 bytes>", "request": "<optional, up to 16 KiB>"}
   ```

   `201`:

   ```json
   {"id": "5f0c...32 hex", "ephemeral_key": "...", "request": "...",
    "created_at": 1790000000, "expires_at": 1790000600}
   ```

2. The account's existing devices poll `GET /e2e/v1/link`, which returns
   `{"links": [ ... ]}` with the unexpired requests, oldest first. One of them
   shows the user a short authentication string derived from both sides'
   ephemeral keys. Once the user confirms it, that device answers:
   `POST /e2e/v1/link/{id}/reply` with `{"reply": "<blob, 1 B to 16 KiB>"}`
   (the account key's private half, encrypted to the ephemeral key). `204`.
   A request is answered once only: a second reply is `409 link_replied`.
3. The new device polls `GET /e2e/v1/link/{id}`. When `reply` and `replied_at`
   appear, it reads them and drops the request with `DELETE /e2e/v1/link/{id}`
   (`204`). Then it publishes itself with `PUT /e2e/v1/devices/{id}`.

Requests expire after `E2E_LINK_TTL`, and expired requests act as if they were
gone (`404 no_link`). An account holds at most 4 unexpired requests
(`409 too_many_links`). Only the account's own tokens can see or answer its
requests.

## 7. Error codes

| HTTP | `error`               | Meaning                                                 |
|------|-----------------------|---------------------------------------------------------|
| 400  | `bad_request`         | malformed JSON, unknown field, bad id, bad count        |
| 400  | `invalid_key`         | a key is not 32 bytes                                   |
| 400  | `invalid_signature`   | a signature does not verify                             |
| 401  | `unauthorized`        | no, bad or expired token, or its session has ended      |
| 403  | `not_announced`       | the key was not announced on the token's BOS connection |
| 404  | `no_account`          | the account has no account key                          |
| 404  | `no_device`           | no such device                                          |
| 404  | `no_link`             | no such unexpired link request for this account         |
| 409  | `account_exists`      | (internal race) another key was published meanwhile     |
| 409  | `account_key_changed` | the account key changed during the request; retry       |
| 409  | `active_devices`      | a reset needs every device revoked first                |
| 409  | `device_conflict`     | the device id is taken by other keys                    |
| 409  | `too_many_devices`    | `E2E_MAX_DEVICES` reached                               |
| 409  | `pool_full`           | the upload would exceed `E2E_MAX_ONE_TIME_KEYS`         |
| 409  | `link_replied`        | the link request already has a reply                    |
| 409  | `too_many_links`      | 4 pending link requests already                         |
| 410  | `device_revoked`      | the device is revoked; its id is not reused             |
| 413  | `too_large`           | body over 64 KiB, or a link blob over 16 KiB            |
| 429  | `rate_limited`        | the account's request budget is spent; slow down        |
| 500  | `internal`            | server error (logged)                                   |

## 8. Owner's tools

The management API (`api.yml`, local only) shows and revokes devices:

- `GET /user/{screenname}/e2e/devices` - the account key (null if none),
  when it was set, and every device with `revoked_at`;
- `DELETE /user/{screenname}/e2e/devices/{device_id}` - revoke a device (a
  lost laptop, say). After that the user can publish a new account key without
  proof (a reset) once no active device is left.

## 9. Settings

In the `Config` struct, generated into `config/settings.env` by `make config`:

| Variable                | Default | Meaning                                   |
|-------------------------|---------|-------------------------------------------|
| `E2E_TOKEN_TTL`         | `12h`   | token lifetime (it also dies with its session) |
| `E2E_MAX_DEVICES`       | `10`    | active devices per account                |
| `E2E_MAX_ONE_TIME_KEYS` | `100`   | one-time key pool per device              |
| `E2E_LINK_TTL`          | `10m`   | life of a device-link request             |

## 10. Not in this stage

Push notifications (device-list-changed, pool-low: DESIGN.md 8.1). For now
clients poll `GET /e2e/v1/devices/{device_id}` and the peers' device lists.
Also not here: the message container, the encryption itself, and the
management page shown in ICQ. Those are later stages.

### Post-quantum keys (planned, CHECKLIST 9.1, 9.8)

PQXDH needs ML-KEM-768 keys next to the Curve25519 ones. They come as an
addition to v1; nothing that exists changes, so current clients and the
current server keep working:

- **Key kinds**: ML-KEM-768 one-time keys (a pool) and one last-resort key per
  device, 1184-byte encapsulation keys, each signed by the device's Ed25519
  key over new purposes: `"pq-one-time-key"` / `"pq-last-resort-key"` |
  screen name | device id | key id | key bytes (the 16-bit field length takes
  1184). They get their own length check; the 32-byte rule of section 4 stays
  for the Curve25519 and Ed25519 keys.
- **Endpoints** (new, so the strict request decoding stays as it is):
  `POST /e2e/v1/devices/{device_id}/pq-one-time-keys`,
  `PUT /e2e/v1/devices/{device_id}/pq-last-resort-key`, and
  `POST /e2e/v1/users/{uin}/devices/{device_id}/claim-pq`, which answers with
  everything PQXDH needs at once: the fallback key (PQXDH's signed prekey), a
  Curve25519 one-time key if one is left, and a PQ one-time key or else the PQ
  last-resort key. `claim` stays as it is for scheme 1. A server without the
  new endpoints answers `404`, which a new client takes as "scheme 1 only".
- **Replies** may gain fields, such as the PQ pool count in
  `GET /e2e/v1/devices/{device_id}`: the add-on ignores reply fields it does
  not know, and reads replies up to 512 KiB.
- **Sizes**: one PQ key is about 1.75 KB of JSON, so a 64 KiB body takes about
  35; uploads are limited to 25 keys and the pool to 50 per device (about
  60 KB stored per device).
- **Storage**: a new migration with `e2e_pq_one_time_key` and
  `e2e_pq_last_resort_key`, with the columns of the Curve25519 tables (`BLOB`
  has no size limit in SQLite); revoking a device deletes them with it.
- **Downgrade**: a server could leave a device's PQ keys out and so push
  senders back to scheme 1. The device's PQ support therefore has to be
  covered by a signature the account key makes, and a client that has once
  seen it for a contact's device does not fall back silently (CHECKLIST 10).
