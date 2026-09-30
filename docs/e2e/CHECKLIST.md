# E2E checklist - what a complete implementation must handle

Every stage of the end-to-end encryption work checks itself against this list. It
is distilled from the XMPP specifications that describe a mature system of this
kind - we do not aim at XMPP compatibility, we use them so nothing is forgotten:

- XEP-0384 OMEMO Encryption, version 0.9.1 (2026-04-06) -
  https://xmpp.org/extensions/xep-0384.html
- XEP-0420 Stanza Content Encryption - https://xmpp.org/extensions/xep-0420.html
- XEP-0060 Publish-Subscribe and XEP-0163 Personal Eventing Protocol -
  https://xmpp.org/extensions/xep-0163.html
- XEP-0380 Explicit Message Encryption - https://xmpp.org/extensions/xep-0380.html
- XEP-0280 Message Carbons - https://xmpp.org/extensions/xep-0280.html
- For sections 7 and 8: XEP-0450, 0454, 0334, 0184, 0333, 0392, 0388, 0440, 0474,
  0484 and RFC 7677 (SCRAM-SHA-256)

Our design (`DESIGN.md`) differs from OMEMO on purpose in one point: one account
key per UIN signs every device (Signal-like), so the server cannot add a device.
Crypto is vodozemac (Olm), not the OMEMO wire format.

Status: **done** (in the repository), **stage N** (planned there), **open** (no
stage owns it yet - decide before the stage that needs it).

## 1. Keys and bundles (XEP-0384 §4.2, §5.3.2)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 1.1 | A device publishes its identity key, a signed key and a pool of one-time keys (a "bundle"). | Key directory: device keys, fallback key, one-time keys, all signed. | done (stage 1) |
| 1.2 | The pool holds about 100 one-time keys and never fewer than 25; the client refills it. | Server caps the pool (`E2E_MAX_ONE_TIME_KEYS`, 100). The client must watch the count and refill below 25. | server done; client stage 3 |
| 1.3 | Every key exchange uses a one-time key; exchanges without one are rejected. | vodozemac falls back to the fallback key when the pool is empty - decide whether to accept that (Olm's design) or require a one-time key (OMEMO). | open |
| 1.4 | The signed key is rotated every week to month; the old private part is kept one more period for late messages. | Fallback key rotation on the client; the server stores the current one. | stage 3 |
| 1.5 | A one-time key is used once: the receiver removes it from its bundle and eventually deletes the private part. | Server hands out each one-time key once (atomic claim). Client deletes the private part after use. | server done; client stage 3 |
| 1.6 | A new device id is checked for collisions before first publish. | Server keeps device ids unique per UIN; the client retries on conflict. | server done; client stage 4 |
| 1.7 | Device labels, if any, are signed; an unsigned label is ignored. | Include the label in what the account key signs, or drop labels. | open |

## 2. Sessions (XEP-0384 §4.3, §6)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 2.1 | Build a session only right before sending, not when a device appears (avoids two sides claiming the same one-time key). | Lazy session creation in the client. | stage 3 |
| 2.2 | After accepting a key exchange, answer with an empty message so the sender stops sending key-exchange messages. | Empty (content-less) control message. | stage 3 |
| 2.3 | Heartbeat: if a device has only received for a while, send an empty message so the ratchet advances (break-in recovery). | Same, from the client. | stage 3 |
| 2.4 | Skipped message keys: keep at most ~1000 per session, FIFO; limit how many one message may skip (~1000). | vodozemac has its own limits - check and document them. | stage 3 |
| 2.5 | Decryption errors must NOT start new sessions automatically (an attacker could force it). Tell the user instead. | Show "could not be read on this device"; no auto re-key. | stage 3 |
| 2.6 | A message without a key for this device: show a warning, not garbage. | Same. | stage 3 |

## 3. Message format and content protection (XEP-0384 §4.4-4.5, §5.5; XEP-0420)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 3.1 | Encrypt the payload once with a fresh key; wrap that key for every recipient device and every other device of the sender (not the sending device itself). | `wraps[]` in the container (`DESIGN.md` §7). | stage 3 (one device), stage 4 (many) |
| 3.2 | Encrypt the whole content, not only plain text: formatting (our HTML), smileys (`<FONT sml=...>`), anything the message carries. | Encrypt the full text fragment as the client produced it. | stage 3 |
| 3.3 | Random padding inside the ciphertext: pad to a minimum size, then add 0-200 random units, so length leaks nothing. Longer padding than expected must be accepted. | Padding field inside the encrypted envelope. | stage 3 |
| 3.4 | The sender's identity inside the ciphertext (`<from/>`), checked by the receiver against who the server says sent it. | Sender UIN inside the envelope; mismatch = alert and reject. | stage 3 |
| 3.5 | A timestamp inside the ciphertext (`<time/>`), checked against the delivery time within a margin (replay of old messages). | Send time inside the envelope; offline messages have the server's stamp to compare with. | stage 3 |
| 3.6 | The recipient inside the ciphertext (`<to/>`) where the server could redirect (group vs private). | Include the recipient UIN too - cheap, and it stops the server from re-addressing a message. | stage 3 |
| 3.7 | Each message is marked with the scheme it uses, so a client that cannot read it says so instead of showing noise (XEP-0380). | Capability GUID + a readable one-line hint before the container for clients without the add-on. | stage 2-3 |
| 3.8 | Key material ride in empty messages; these are exempt from the trust rule (4.1). | Control messages carry no content. | stage 3 |
| 3.9 | An encrypted message, longer than the plain one, still fits what the recipient's client takes. | The server announces `MaxIncomingICBMLen` 8000 and enforces it: it refuses a longer ICBM (`REQUEST_DENIED`), and one longer than any of the recipient's clients set with `ICBMAddParameters` (`REFUSED_BY_CLIENT`). Measured on the message TLV (`0x0002`, channels 1 and 3) or the data TLV (`0x0005`, others). The add-on keeps a container within the limit or splits it. | server done; client stage 3 |
| 3.10 | Messages the server translates between client generations are left alone: tZers (channel 1 with the 0x10 fragment carrying the tZer capability, from ICQ 7.2; the "Send Tzer" plugin message on channel 2, from ICQ 6.5) are neither rewritten nor encrypted. | Known break since stage 2: the add-on rewrites 7.2's channel 1 tZer, so the server (`foodgroup/icbm_tzer.go`) no longer recognises it and 7.2 -> 6.5 tZers fail; 6.5 -> 7.2 works. Owner's decision: fix once, after the encryption stages. Workaround: `ICQE2E_MODE=observe`. | open - after stage 5 |

## 4. Trust (XEP-0384 §8)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 4.1 | Do not send to a device before it is trusted; a fake device would get copies of everything. Untrusted sessions may decrypt, but the message is marked as untrusted. | Account-signed devices remove the fake-device attack by the server; the account key itself follows trust-on-first-use, then verification. | stage 3-4 |
| 4.2 | Show a fingerprint to compare (hex groups, QR) when asking for a trust decision. | One safety number per UIN pair on the management page. | stage 5 |
| 4.3 | Warn when a contact's key changes. | Key directory keeps the account key history. | server done; client stage 5 |
| 4.4 | BTBV/TOFU are allowed trust models (0.9.0 wording). | We use TOFU for the account key, then explicit verification. | decided |

## 5. Device lists and notifications (XEP-0060/0163, XEP-0384 §5.2-5.3.1)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 5.1 | The device list is readable by anyone (people without a presence subscription must still be able to start a session). | Public `GET` endpoints of the key directory. | done |
| 5.2 | Contacts are notified when a device list changes, and newly online clients get the latest list (PEP "last published item"). | Server has no push yet - clients poll. Consider a notification over OSCAR or a change counter in the directory. | open |
| 5.3 | Clients cache the latest device list per contact. | Client cache with the directory's change marker. | stage 3 |
| 5.4 | Stale devices: stop encrypting for devices not seen for a long time. | `last_seen` in the directory; client policy. | stage 4 |

## 6. Several devices of one account (XEP-0280)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 6.1 | Incoming messages reach every device of the recipient. | The server relays to every session instance of a UIN. | done |
| 6.2 | Your sent messages reach your other devices too (carbons), encrypted for them. | OSCAR has no carbons; old ICQ clients cannot show a copy of their own sent message. Decide: server-side copy of sent messages to the sender's other instances + the add-on shows them, or accept partial history. | open |
| 6.3 | A sender may exclude a message from copies (private). | Only relevant if 6.2 is done. | open |
| 6.4 | Linking a new device is approved on an existing one; the server relays only ciphertext. | Link relay in the key directory. | server done; client stage 4 |

## 7. Transport security and sign-in

Today nothing between the clients and the server is encrypted: messages, contact
lists, addresses and the key directory token travel in clear (the token no longer
suffices to set an account key, see 7.1). Sign-in is weak too:
ICQ 2003b sends a XOR-"roasted" password (reversible at once); ICQ 6.5 and 7.2 send
an MD5 challenge digest (no clear password, but a captured digest can be
brute-forced offline, and the server must store MD5 of the password, which is
password-equivalent). References for the target shape: RFC 7677 (SCRAM-SHA-256),
XEP-0388 (SASL2), XEP-0440 (channel binding), XEP-0474 (SCRAM downgrade protection),
XEP-0484 (FAST sign-in tokens). The stock clients cannot speak any of them; a
client-side layer can.

| # | Requirement | Ours | Status |
|---|---|---|---|
| 7.1 | **Must be fixed before the key directory is deployed:** the key directory token must not be exposed in clear. Anyone who sniffs it can publish the first account key for a UIN that has not enrolled yet and so hijack trust-on-first-use. | The token still travels in clear, but it no longer suffices to set a key: a first publish or a reset needs the key announced on the token's own BOS connection (TLV `0x0E2E` in `LocateSetInfo`, added in place by the add-on), and revoking a device needs some key announced there. A sniffer can read the connection but not write into it. A password proof was rejected: 2003b sends the password reversibly roasted, and 6.5/7.2 send `StrongMD5Pass`, which is the same at every sign-in (fixed salt), so a sniffer already holds a password-equivalent. Left to an active attacker on the path: 7.2. `KEY-DIRECTORY-API.md` 3.3. | server done; client stage 3 (announce the key) |
| 7.2 | The connection to the server is encrypted with modern TLS (1.3). | The server already has TLS ports; the old clients' own TLS is missing or outdated (off for ICQ 7.2). A client-side layer that wraps the client's connection in TLS 1.3 - naturally the same component as the message encryption. | open |
| 7.3 | Sign-in does not expose a password-equivalent secret. | Inside TLS the old sign-in is protected in transit. With a client-side layer, the layer can sign in with SCRAM-SHA-256 and channel binding instead of MD5. | open |
| 7.4 | The server does not store password-equivalent values where avoidable. | Old sign-in methods force MD5 storage; keep them, but add SCRAM verifiers for clients that can use them, and allow turning off the weakest method (2003b's XOR) per server. | open |
| 7.5 | No downgrade: a client that can use the strong method is not tricked into the weak one. | Once a UIN has used the strong method, the server can refuse the weak ones for it (opt-in). | open |

## 8. Related features to keep in mind

| # | XEP | What it covers | Ours | Status |
|---|---|---|---|---|
| 8.1 | 0450 Automatic Trust Management | Trust decisions made on one device reach the account's other devices securely. | Needed with several devices. | stage 4-5 |
| 8.2 | 0454 OMEMO Media Sharing | Files: encrypted with a one-off AES-GCM key, uploaded; key and link travel inside an encrypted message. | If file transfer is ever encrypted. | open |
| 8.3 | 0334 Message Processing Hints | "Do not store / do not copy" for control messages. | Empty control messages (2.2, 2.3, 3.8) should not sit in the offline store. | stage 3 |
| 8.4 | 0184 / 0333 Receipts, Chat Markers | Delivery and read receipts. | They reveal when a message is read; decide whether receipts of encrypted messages are sent at all, and in clear or encrypted. | open |
| 8.5 | 0392 Consistent Color Generation | Colouring fingerprints so people compare them more reliably. | Management page. | stage 5 |
| 8.6 | 0045 MUC, 0313 MAM | Group chats; server archive and history sync. | Only if groups or history sync are ever in scope. | open |

## 9. Not covered (same as OMEMO)

- Metadata and traffic analysis: the server still sees who talks to whom and when.
- A device an attacker controls permanently.
- Denial of service.
- Group chats (OMEMO handles them with extra rules on membership) - a later stage if
  ever; `<to/>` (3.6) is already in the envelope for it.
