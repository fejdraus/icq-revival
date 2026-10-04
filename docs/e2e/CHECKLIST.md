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
| 1.2 | The pool holds about 100 one-time keys and never fewer than 25; the client refills it. | Server caps the pool (`E2E_MAX_ONE_TIME_KEYS`, 100). The client must watch the count and refill below 25. | done (stage 3) |
| 1.3 | Every key exchange uses a one-time key; exchanges without one are rejected. | vodozemac falls back to the fallback key when the pool is empty - decide whether to accept that (Olm's design) or require a one-time key (OMEMO). | open |
| 1.4 | The signed key is rotated every week to month; the old private part is kept one more period for late messages. | Fallback key rotation on the client; the server stores the current one. | done (stage 3) |
| 1.5 | A one-time key is used once: the receiver removes it from its bundle and eventually deletes the private part. | Server hands out each one-time key once (atomic claim). Client deletes the private part after use. | done (stage 3) |
| 1.6 | A new device id is checked for collisions before first publish. | Server keeps device ids unique per UIN; the client retries on conflict. | server done; client stage 4 |
| 1.7 | Device labels, if any, are signed; an unsigned label is ignored. | Include the label in what the account key signs, or drop labels. | open |

## 2. Sessions (XEP-0384 §4.3, §6)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 2.1 | Build a session only right before sending, not when a device appears (avoids two sides claiming the same one-time key). | Lazy session creation in the client. | done (stage 3) |
| 2.2 | After accepting a key exchange, answer with an empty message so the sender stops sending key-exchange messages. | Empty (content-less) control message. | stage 3 |
| 2.3 | Heartbeat: if a device has only received for a while, send an empty message so the ratchet advances (break-in recovery). | Same, from the client. | stage 3 |
| 2.4 | Skipped message keys: keep at most ~1000 per session, FIFO; limit how many one message may skip (~1000). | vodozemac has its own limits - check and document them. | done (stage 3) |
| 2.5 | Decryption errors must NOT start new sessions automatically (an attacker could force it). Tell the user instead. | Show "could not be read on this device"; no auto re-key. | done (stage 3) |
| 2.6 | A message without a key for this device: show a warning, not garbage. | Same. | done (stage 3) |

## 3. Message format and content protection (XEP-0384 §4.4-4.5, §5.5; XEP-0420)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 3.1 | Encrypt the payload once with a fresh key; wrap that key for every recipient device and every other device of the sender (not the sending device itself). | `wraps[]` in the container (`DESIGN.md` §7). | stage 3 (one device), stage 4 (many) |
| 3.2 | Encrypt the whole content, not only plain text: formatting (our HTML), smileys (`<FONT sml=...>`), anything the message carries. | Encrypt the full text fragment as the client produced it. | done (stage 3) |
| 3.3 | Random padding inside the ciphertext: pad to a minimum size, then add 0-200 random units, so length leaks nothing. Longer padding than expected must be accepted. | Padding field inside the encrypted envelope. | done (stage 3) |
| 3.4 | The sender's identity inside the ciphertext (`<from/>`), checked by the receiver against who the server says sent it. | Sender UIN inside the envelope; mismatch = alert and reject. | stage 3 |
| 3.5 | A timestamp inside the ciphertext (`<time/>`), checked against the delivery time within a margin (replay of old messages). | Send time inside the envelope; offline messages have the server's stamp to compare with. | done (stage 3) |
| 3.6 | The recipient inside the ciphertext (`<to/>`) where the server could redirect (group vs private). | Include the recipient UIN too - cheap, and it stops the server from re-addressing a message. | done (stage 3) |
| 3.7 | Each message is marked with the scheme it uses, so a client that cannot read it says so instead of showing noise (XEP-0380). | Capability GUID + a readable one-line hint before the container for clients without the add-on. | stage 2-3 |
| 3.8 | Key material ride in empty messages; these are exempt from the trust rule (4.1). | Control messages carry no content. | stage 3 |
| 3.9 | An encrypted message, longer than the plain one, still fits what the recipient's client takes. | The server announces `MaxIncomingICBMLen` 8000 and enforces it: it refuses a longer ICBM (`REQUEST_DENIED`), and one longer than any of the recipient's clients set with `ICBMAddParameters` (`REFUSED_BY_CLIENT`). Measured on the message TLV (`0x0002`, channels 1 and 3) or the data TLV (`0x0005`, others). The add-on keeps a container within the limit or splits it. | server done; client stage 3 |
| 3.10 | Messages the server translates between client generations are left alone: tZers (channel 1 with the 0x10 fragment carrying the tZer capability, from ICQ 7.2; the "Send Tzer" plugin message on channel 2, from ICQ 6.5) are not encrypted, so the server can translate them. | Done (sixth audit): a tZer goes as it is and is announced over the Olm session (IQT1); one from a protected contact is shown only when announced, so the server cannot fake it, but it sees which tZer was sent. 7.2 -> 6.5 works again. Idea kept for later (owner, 2026-10-03): hide even that - the sending add-on puts the tZer id in an encrypted message and the receiving add-on builds its own client's form (6.5 plugin or 7.2 channel 1); the server then sees an ordinary encrypted message. About 1-2 days plus a live test both ways; a peer without the add-on keeps the server's translation. | done; idea open |
| 3.11 | Text never goes from client to client past the encryption. | While encrypting, the add-on leaves `CapDirectICBM` out of the client's capabilities, drops direct-IM rendezvous both ways (answering the client with a cancel) and zeroes the address and port of the ICQ DC info, own and contacts' (`core/src/direct.rs`, audit 2026-10 second part, finding 5). File transfer and calls are untouched. | done (2026-10-03); live test in `tools/icq-e2e/README.md` ("Direct IM and direct connections") still to run |

## 4. Trust (XEP-0384 §8)

| # | Requirement | Ours | Status |
|---|---|---|---|
| 4.1 | Do not send to a device before it is trusted; a fake device would get copies of everything. Untrusted sessions may decrypt, but the message is marked as untrusted. | Account-signed devices remove the fake-device attack by the server; the account key itself follows trust-on-first-use, then verification. | stage 3-4 |
| 4.2 | Show a fingerprint to compare (hex groups, QR) when asking for a trust decision. | One safety number per UIN pair: Signal's numeric fingerprint (version 0) over both account keys and UINs, 60 digits in twelve groups of five, shown by `/e2e safety` in the chat; `/e2e verify` records it (10.10). The management page (stage 5) may show it too; a QR code is not planned. | done (2026-10-02) in the chat; page stage 5 |
| 4.3 | Warn when a contact's key changes. | Key directory keeps the account key history; the add-on pins each contact's account key and says "Your safety number with <uin> has changed" once per change (10.10). | done (2026-10-02) |
| 4.4 | BTBV/TOFU are allowed trust models (0.9.0 wording). | We use TOFU for the account key, then explicit verification. | decided |
| 4.5 | (Ours, beyond XEP-0384.) Keys are checked automatically, as Signal does with key transparency. | The directory appends every change to a signed append-only Merkle log; the add-on keeps a copy, refuses a contact's account key the log does not show, leaves out devices it does not show, and tells the user about any device or key in their own account they did not add (KEY-TRANSPARENCY.md). An auditor (`cmd/e2e-kt-auditor`), as Signal has, checks every entry against the directory's rules and cosigns the checkpoints; the add-on takes the log only with a recent cosignature that agrees with its copy, which catches a server showing users different logs. | done (2026-10-02); an auditor run by someone other than the operator still to find |

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

The plan for 7.2-7.5 (owner's decision, 2026-10-02), in this order:

1. ICQ 6.5 and 7.2: a TLS 1.3 + SCRAM-SHA-256 sign-in layer in the E2E add-on,
   which already sits on the client's socket.
2. ICQ 2003b and QIP: the same layer as a DLL of its own, loaded as a proxy
   DLL the way the add-on's loaders are; how to get one loaded into QIP is
   still to be researched.
3. Miranda NG: the same layer built into our ICQ plugin.
4. The server: a setting to refuse the weakest sign-in (2003b's XOR-roasted
   password) for clients that do not have the layer (7.4).

## 8. Related features to keep in mind

| # | XEP | What it covers | Ours | Status |
|---|---|---|---|---|
| 8.1 | 0450 Automatic Trust Management | Trust decisions made on one device reach the account's other devices securely. | Needed with several devices. | stage 4-5 |
| 8.2 | 0454 OMEMO Media Sharing | Files: encrypted with a one-off AES-GCM key, uploaded; key and link travel inside an encrypted message. | If file transfer is ever encrypted. | open |
| 8.3 | 0334 Message Processing Hints | "Do not store / do not copy" for control messages. | Empty control messages (2.2, 2.3, 3.8) should not sit in the offline store. | stage 3 |
| 8.4 | 0184 / 0333 Receipts, Chat Markers | Delivery and read receipts. | They reveal when a message is read; decide whether receipts of encrypted messages are sent at all, and in clear or encrypted. | open |
| 8.5 | 0392 Consistent Color Generation | Colouring fingerprints so people compare them more reliably. | Management page. | stage 5 |
| 8.6 | 0045 MUC, 0313 MAM | Group chats; server archive and history sync. | Only if groups or history sync are ever in scope. | open |

## 9. Towards Signal level - after the planned stages

What the design takes: Signal's trust model (one account key signs every device;
one safety number per pair of accounts; a last-resort key so a drained pool cannot
block a conversation), OMEMO's rules of behaviour and SCE's envelope, and Matrix's
vodozemac for the ratchet. What Signal has and the planned stages (1-5) do not:

| # | Gap | What it takes | Status |
|---|---|---|---|
| 9.1 | Post-quantum key agreement (PQXDH: X25519 + ML-KEM-768). | vodozemac has no post-quantum key agreement (checked 0.11.1, 2026-09-30: no ML-KEM/Kyber/PQXDH; its HPKE is X25519 only). But 0.11.0 added a hazmat constructor `Session::from_root_key_material` (feature `low-level-api`), made for protocols that run their own handshake - including post-quantum KEMs - and put vodozemac's audited Double Ratchet on top; it replaces only Olm's 3DH. **It covers the sender only** (checked in the 0.11.1 source, 2026-10-01): it builds an active sending chain, and its companion `ActiveSendingState` is a read-out for tests, not a receiver. The receiving side - a session from a remote root key and the sender's ratchet key, which Olm builds internally (`DoubleRatchet::inactive_from_prekey_data`, crate-private) - has no public constructor. Before 9.1: get one upstream (a small PR mirroring `from_root_key_material`), or build the receiver through `Session::from_libolm_pickle` from a pickle we write (public, but a hack to avoid). So: implement the handshake exactly per Signal's published PQXDH specification (RustCrypto `ml-kem`) as a second `keys::Handshake` variant feeding those constructors; container scheme 2 (reserved); post-quantum one-time and last-resort keys in the key directory (plan in KEY-DIRECTORY-API.md section 10); state version 2 for the sessions it makes. **Key exchange as its own control message (owner's plan, preferred):** the PQXDH part (ML-KEM ciphertext 1088 bytes, key ids, the sender's base key) goes in a control container of its own - a wrap type of its own per recipient device, no text, hidden like the other control messages (2.2, 2.3, 3.8) - sent immediately before the user's message, which then travels at normal size. It scales to several devices (about four 1.1 KB wraps fit one 7000-byte frame; more devices take more control frames), where one message with one ciphertext per device would not fit. What it needs: (a) order - live messages from one sender arrive in order over the recipient's connection, and stored offline messages are returned in the order they were stored (`ORDER BY rowid` in `RetrieveMessages`, added 2026-10-01; before, SQLite promised no order); the control frame must be sent store-if-offline like the text, and it takes one of the 10 offline slots per sender (`offlineInboxLimit`); (b) the receiver holds a scheme-2 message whose session is not there yet - a few per contact, for some minutes, in memory - and opens it when the key exchange arrives, rather than showing "cannot be read" at once; only when the hold ends is the note shown; (c) the sender repeats the same key exchange (same session, same ciphertext, not a new handshake) ahead of each message until the contact answers (2.2), as Olm repeats its pre-key message; the receiver takes a repeat of a session it holds as a no-op. A key exchange that does not verify, or a message without one, never starts a session (2.5): nothing re-keys silently. Watch the hazmat API across vodozemac releases; 9.7 review covers our PQXDH. Watch the hazmat API across vodozemac releases; 9.7 review covers our PQXDH. Readiness checked now so this is an addition, not a rewrite (see 9.8). | open - after the other security gaps |
| 9.2 | Post-quantum ratchet (Signal's newer triple ratchet). | Follows 9.1; a separate step. | open - after 9.1 |
| 9.3 | Metadata hiding (Signal's sealed sender). | The server sees who writes to whom and when. Hiding the sender from the server needs its own delivery scheme; OSCAR routes by screen name. | open - research |
| 9.4 | Transport security for the old clients (7.2 above). | TLS 1.3 in a client-side layer; until then an active attacker on the path remains. | open |
| 9.5 | Group chats. | Membership and per-member device keys (8.6). | open - if ever |
| 9.6 | Device linking convenience (Signal: scan a QR code). | **Owner's decision: for the first versions the management page in an ICQ Xtra window plus entering a short code is good enough.** A QR flow can come later. | decided for v1 |
| 9.7 | Independent review. | Each part is proven, the combination is ours: have the scheme and the code reviewed independently before calling it Signal-grade to users. | open - before release |
| 9.8 | Post-quantum readiness, so 9.1 needs no rewrite: the container scheme field is read and honoured; the key directory can take a new key kind without breaking current clients (new endpoints or API version); the message size budget leaves room for a larger first message; session set-up in the add-on is one replaceable step in front of the ratchet; the state file is versioned. | **Ready (2026-10-01).** (1) Container: version and scheme are read first (`container::parse`); any other pair is `Unsupported` and never parsed with the scheme-1 layout - the frame is dropped and the user gets "uses a newer format ... update the add-on" once (`Crypto::unsupported`). Scheme 2 is reserved as `SCHEME_PQXDH`. Tests `an_unknown_version_or_scheme_is_never_read_as_scheme_one`, `a_container_of_a_newer_scheme_is_said_to_be_unreadable_not_misread`. (2) Session set-up is `keys::Handshake` (one variant now, `Olm3Dh`) with `start_outbound` / `start_inbound` in front of the ratchet; wraps, container, ratchet and the stored session pickles are the same for any variant, since each ends in a vodozemac `Session`. Scheme 1 is unchanged on the wire. (3) State file: `version` in the JSON (`store::STATE_VERSION` = 1; a file without it is version 0 and brought up by `store::migrate`); unknown fields are ignored; a file of a newer version is refused and left untouched, so an older build never saves it back without the sessions it cannot see. Tests in `store.rs`. (4) Size: a first message to one device has 466 bytes besides the text (with the most padding) and carries up to 4727 bytes of text under the add-on's 7000-byte wire limit (`rewrite::MAX_TEXT`; the server's is 8000). With the ML-KEM ciphertext and framing in the same message (+1152 bytes, about 1.5 KB armoured) it would be 3575, and one more ciphertext per further new device - so the key exchange goes in a control message of its own (9.1), and the user's message keeps its full size. Test `a_first_message_leaves_room_for_a_post_quantum_key_exchange`. Offline messages now come back in the order they were stored (`ORDER BY rowid`), which that plan needs. (5) Key directory: the add-on ignores reply fields it does not know and calls only the v1 endpoints it knows, so PQ keys go in new endpoints and new tables without touching current clients; the strict request decoding stays. Plan, sizes and limits in KEY-DIRECTORY-API.md section 10. **Remains, with 9.1:** a public receiver-side constructor in vodozemac; the PQ endpoints, migration and signed-message purposes on the server; the key-exchange control message, the receiver's short hold and the sender's repeat (9.1); downgrade protection - a server could hide a device's PQ keys, so the device's PQ support must be signed by the account key and, once seen, pinned like the rules of section 10. | ready - the rest goes with 9.1 |

## 10. User control, visibility and downgrade protection (owner's rules)

Owner's decisions (2026-10-01). Until now the add-on encrypts silently; the user
must see and control it, and a server must not be able to switch a conversation
to clear text unnoticed. All of it is add-on logic; the server needs no change.

| # | Rule | Where | Status |
|---|---|---|---|
| 10.1 | One setting per contact: encryption **on** or **off** for outgoing messages, remembered across restarts (in the add-on's state). Default for a new chat: on, if the contact can receive encrypted messages (10.6). | add-on | done (stage 3) |
| 10.2 | Commands typed in the chat and never sent to the contact: `/e2e on`, `/e2e off`, `/e2e status`, and `/e2e plain` to send one message in clear after a downgrade warning (10.7). | add-on | done (stage 3); also `/e2e auto` - back to the default, the seen-encrypting flag kept; `/e2e status` shows auto/on/off, whether the contact was seen encrypting and whether they are verified; `/e2e safety`, `/e2e verify`, `/e2e unverify`, `/e2e accept` (10.10) |
| 10.3 | Status shown in the chat as a note: when the chat is first used in a session, on every change ("Encryption is on in this chat" / "off" / "the contact has no encryption"), and on automatic switch-on (10.5). | add-on | done (stage 3); also a key publication that leaves encryption not working is said in the chat once per sign-on per kind of failure, with its reason, and one "Encryption is ready" after it; success says nothing |
| 10.4 | Incoming encrypted messages are **always** decrypted, whatever the setting - the setting governs only what the user sends. The reader can tell an encrypted chat from a clear one. | add-on | done (stage 3): always decrypted; the chat's notes (10.3) and `/e2e status` say whether it is encrypted. A mark before each decrypted message (`🔒 `) was tried and dropped (owner's decision, 2026-10-02): ICQ 6.5 and 7.2 draw it as `??`, and the add-on now shows the message exactly as written (tools/icq-e2e/README.md, "No lock in the window") |
| 10.5 | Automatic switch-on: an incoming encrypted message turns encryption on for that contact, with a note - **unless the user switched it off by hand**; then only a hint ("the contact encrypts; /e2e on to answer encrypted"). An encrypted message cannot be forged without keys, so this cannot be abused by the server. | add-on | done (stage 3) |
| 10.6 | Whether a contact can receive encrypted messages is decided by the **key directory** (signed devices of the account) and the add-on's remembered state - and, while the contact is online, by **the client they are signed in with now** (owner's decision, 2026-10-04, resolving the question of an account with the add-on on one device and a client without it on another). The current client is the capability list of the latest "buddy arrived" or user info for the contact on this connection, forgotten when they sign off; a user info with no capability list at all (ICQ 99b through the legacy bridge) counts as "without the add-on". **Online without `CAP_E2E`, `/e2e auto`:** messages go as ordinary text and incoming unencrypted messages are shown - automatic, seen encrypting and verified contacts alike; calls, files and tZers go as they would without the add-on. The chat says so once per change of the contact's client per sign-on ("X is signed in with a client without end-to-end encryption; this message went unencrypted"; "A message from X arrived unencrypted: X is using a client without end-to-end encryption"); for a verified contact both are a WARNING and raise the security box. **Online without `CAP_E2E`, `/e2e on`:** strict, as 10.8, until the user types `/e2e auto` or `/e2e off` (the owner's refinement, 2026-10-04): every message is held, not sent, with a note saying why and that `/e2e auto` or `/e2e off` lets it go unencrypted (`/e2e plain` does nothing under `/e2e on`); unencrypted messages in the contact's name are not shown (the fifth audit's warning, naming the contact and the reason); calls and files only encrypted; tZers only when announced. **`/e2e off`:** never encrypted, shown. **With `CAP_E2E`, presence unknown, or offline:** as before - encrypted to the directory's keys (an offline contact reads them when back on a client with the add-on), and unencrypted text from a protected contact is not shown. Trade-off: a server that strips `CAP_E2E` from a contact's presence can downgrade any contact under `/e2e auto`, verified ones included, but never silently - the note comes each time the client changes, and the box for verified contacts. Under `/e2e on` it can only hold messages back. `/e2e off` stays the user's own switch. | add-on | done (stage 3); current client 2026-10-04 (`Engine::presence`, `Engine::follows_client`, `Held::OtherClient`, `caps::contacts` / `user_info_reply` / `departed`; tests `a_seen_contact_on_a_client_without_the_add_on_gets_plain_text_with_one_note`, `a_seen_contact_whose_client_announces_the_add_on_is_encrypted_and_protected`, `verified_on_a_client_without_the_add_on_is_warned_and_alerted`, `on_by_hand_on_a_client_without_the_add_on_holds_and_drops`, `verified_and_on_by_hand_on_a_client_without_the_add_on_is_held`, `an_offline_or_unknown_contact_is_encrypted_to_the_directory`, `a_change_of_client_mid_session_is_said_each_time`) |
| 10.7 | **Downgrade protection (sticky):** once a contact has been seen with signed devices or has exchanged an encrypted message, the add-on remembers it. If the server later shows no encryption for that contact (no keys in the directory; a current client without the add-on is 10.6: in clear with a note under `/e2e auto`, held under `/e2e on`), nothing is sent in clear silently: the message is held and the chat says encryption was seen before and is missing now; the user sends in clear only with `/e2e plain`. A contact never seen encrypting stays trust-on-first-use (closed only by comparing safety numbers, 4.2). | add-on | done (stage 3) |
| 10.8 | With encryption switched on by hand for a contact, nothing ever goes to that contact in clear: no keys - the message is not sent and the chat says why. | add-on | done (stage 3) |
| 10.9 | A button with a lock in the message window of ICQ 6.5 and 7.2, showing the state and opening the management page for that contact (status, on/off, safety number). Until stage 5 the commands of 10.2 do the job. | patches (client markup) + management page | dropped (owner's decision, 2026-10-02): a lock button was tried in both clients and taken out again. The window's markup does not expose which contact a chat is with, so it could show no state, and sending `/e2e status` from its script was unreliable - it sent the user's draft live instead of the command. The patches now remove it from installs that have it, and the add-on removes the per-contact state files it wrote for it. The state is said in the chat instead (10.3, `/e2e status`); the management page stays a stage-5 item |
| 10.10 | **Safety-number verification, the Signal way** (owner's decision, 2026-10-02). The number is Signal's `NumericFingerprintGenerator`, fingerprint version 0, exactly as libsignal computes it: per party SHA-512 over `0x0000 || key || id || key`, then 5199 rounds of `SHA-512(hash || key)`; the first 30 bytes as six 5-byte chunks mod 100000; the two 30-digit halves joined smaller first, so both sides see the same 60 digits. Inputs: the account key (raw 32 bytes, Ed25519) and the UIN in ident form. Nothing is shown at first contact (trust on first use). A changed account key: "Your safety number with <uin> has changed", once per change; an unverified contact goes on encrypted to the new key. A verified contact: the verification is cleared and every message is held until `/e2e verify` of the new number (after `/e2e safety`) or `/e2e accept` (send on unverified); no control message goes to the new key meanwhile. | add-on | done (2026-10-02): `safety.rs` (tested against libsignal's own vector `300354477692869396892869876765458257569162576843440918079131` and a vector of ours, derived independently in Python and documented in the test), `keys::PinnedKey::verified` (the key verified, so a verification never carries over to another key) and `held`, state file version 2 (`store::migrate`; a version-1 build refuses the file rather than dropping the verification). `/e2e verify` takes only the key behind the number shown last by `/e2e safety` in this sign-on, so a number that changed in between is never verified unseen. `/e2e plain` keeps its meaning (one message in clear) and is not the way past this hold. Not done: the management page and a QR code (stage 5, 9.6). |

## 11. Not covered (same as OMEMO)

- Metadata and traffic analysis: the server still sees who talks to whom and when.
- A device an attacker controls permanently.
- Denial of service.
- Group chats (OMEMO handles them with extra rules on membership) - a later stage if
  ever; `<to/>` (3.6) is already in the envelope for it.
