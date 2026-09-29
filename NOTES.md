# Our own ICQ server on <lan-host>

A deployed [Open OSCAR Server](https://github.com/mk6i/open-oscar-server) for friends and
colleagues: retro ICQ and AIM clients work with it the same way they once worked
with the real Mirabilis servers.

This repository holds the server source with our changes, the deployment files and
tools for the clients. The `deploy/` directory was collected from the live machine,
so its contents match what actually runs.

---

## What is deployed where

Host `<lan-host>` (SSH host `<lan-host>`, `<lan-ip>`, on the tailnet `<tailnet-host>`,
`<tailnet-ip>`).

| what | where | port |
|---|---|---|
| Open OSCAR Server | `/opt/open-oscar-server/` | OSCAR 5190, TOC 9898, legacy ICQ UDP 4000 |
| management API | same place | `127.0.0.1:8090` (8080 is taken by an unrelated service) |
| WebAPI | same place | 8082 |
| registration page | `/opt/oscar-register/` | 8099, from outside HTTPS 8444 |
| admin panel | `/opt/oscar-admin/` | 8100 |
| TLS front (nginx in a container) | `/etc/oscar-nginx/` | 1443, 3143, 5193, 8443 |

Database: `/var/lib/open-oscar-server/oscar.sqlite`, owned by the system user `oscar`.

### Ports for clients

- **5190** - no encryption; ICQ 2000b-5.1, ICQ Pro 2003b, QIP, Pidgin;
- **5193** - OSCAR over TLS with a Let's Encrypt certificate from Tailscale, for Miranda NG
  and other modern clients;
- **3143** - the same OSCAR over TLS, but with our own RSA root certificate: AIM
  6.2-7.x needs it, because its 2011 NSS libraries do not understand ECDSA;
- **1443** - Kerberos/UAS, which AIM 6.2+ uses to sign in.

Encryption for clients without SSL comes from Tailscale: no ports are exposed to the
outside, and the traffic runs inside WireGuard.

---

## Our server change: registering a number from the client

The "Get an ICQ Number" button in ICQ Pro 2003b now works - the server hands out a
number and creates the account.

The finished diff: `patches/icq-registration.diff`; the script that applies it to a
clean tree: `patches/patch-register.py`.

**What happens in the protocol.** The client opens a separate connection to the same
port 5190 and sends `SNAC(0x17,0x04)` - `BUCPRegisterRequest`. Inside `TLV(0x0001)`
is the ICQ registration block, **entirely in reversed byte order** (unlike the SNACs
themselves):

```
offset 0   dword 0
offset 4   word 0x0028 (block length 40), word 0x0003 (version)
offset 16  dword cookie          <- the server must return it in the reply
offset 40  word password length, then the password with a terminating zero
```

The password is sent **in plain text** - the format was worked out from a live capture
(`tcpdump -i any -w /tmp/reg.pcap 'tcp port 5190'`), not from documentation.

The reply is `SNAC(0x17,0x05)` with `TLV(0x0001)` holding a service block and the
assigned number, followed by an empty channel 4 FLAP as the signal to close the
connection. The reply layout is taken from the
[protocol description](https://kingant.net/oscar/?family=0x0017&subtype=0x0005);
it is marked unfinished, but the client accepted a reply built from it right away.

**Changed files:**

- `wire/snacs.go` - the constants `BUCPRegisterResponse` and `ICQTLVTagsRegistration`;
- `foodgroup/auth.go` - the method `AuthService.BUCPRegister`, picking a free number
  (`nextFreeUIN`, counting up from 100000 and checking whether each is taken), building
  the reply (`icqRegistrationReply`);
- `server/oscar/server.go` - the `BUCPRegisterRequest` branch in the login phase parser;
- `server/oscar/types.go` - the method in the `AuthService` interface.

**Build.** `go.mod` requires Go 1.26, `<lan-host>` has 1.24, so the build runs in a container:

```bash
sudo docker run --rm -v ~/oscar-src:/src \
  -v /tmp/gocache:/root/.cache/go-build -v /tmp/gomod:/go/pkg/mod \
  -w /src golang:1.26 go build -buildvcs=false -o /src/open_oscar_server_new ./cmd/server
```

The previous binary is kept as `/opt/open-oscar-server/open_oscar_server.before-register`.

Limitation: `nextFreeUIN` goes through numbers one by one with a database query for
each. With a dozen accounts this is unnoticeable; for thousands it has to be rewritten
to find the first gap in a single query.

---

## Our server change: signing in with an e-mail address

In the sign-in window of old clients the field is labelled "ICQ#/Email" - the real
server accepted an e-mail address instead of the number. The strings in `Icq.exe`
itself show it:

```
ICQ#/Email:
Login By Email Options (Web)
You have tried to login using an incorrect password, ICQ number, or an email
address that was not validated.
```

There is no separate protocol for this: the client sends whatever was typed in the
name field, and the server finds the number by the address. So the change is purely
on the server; the clients need no changes.

**Which address lets you sign in.** Any address tied to the account. There are three
sources, all of them equal:

- the ICQ profile, `users.icq_basicInfo_emailAddress` (edited from the client);
- the AIM account, `users.emailAddress` (edited from the client through ADMIN);
- the password recovery address - `oscar-register`'s own database, mirrored into the
  `loginEmail` table of the main database (migrations `0044`, `0045`).

Confirming the address by e-mail has nothing to do with signing in: an address can only
be tied to an account by someone who knows the account's current password, so an
address that is not tied to it lets nobody in anyway. The confirmation is needed for
password recovery itself - so that the link goes to a mailbox the person actually reads.

The address is **optional**. Without it everything works as before: sign-in by number,
and a forgotten password is reset by the administrator.

**One address - one account.** Otherwise the address does not tell who to let in. The
check sits on every write path, not in one place in a form:

- `SQLiteUserStore.emailFree` - inside `SetBasicInfo` (ICQ profile) and
  `UpdateEmailAddress` (AIM address), that is on every profile save, wherever it
  comes from;
- the client gets the refusal through the protocol, not by a dropped connection: ICQ
  gets `ICQStatusCodeFail` in the reply to the profile save, AIM gets
  `AdminInfoErrorInvalidEmail`;
- `oscar-register` checks the same thing when the address is tied (`409 mail_taken`)
  and once more when the link from the e-mail is followed: someone else could have
  taken the address in between. If the main database is unavailable, the service
  refuses rather than risk giving the address out twice;
- `EmailOwner` returns nothing for an ambiguous address and lets nobody in - in case
  the two records drift apart after all.

`DeleteUser` erases the row in `loginEmail`: numbers are handed out again, and a
leftover row would let the previous owner into someone else's account.

**Changed files:**

- `state/migrations/0044_verified_email.*.sql`, `0045_login_email.*.sql`;
- `state/user_store.go` - `EmailOwner`, `emailFree`, the checks in `SetBasicInfo`
  and `UpdateEmailAddress`, the cleanup in `DeleteUser`;
- `foodgroup/types.go` - the `EmailOwner` method in the `UserManager` interface;
- `foodgroup/auth.go` - replacing the address with the number in `login()`; an address
  that belongs to nobody gets the ICQ error, not the AIM one (only ICQ has the
  "ICQ#/Email" field);
- `foodgroup/icq.go` - the refusal in the reply to the profile save (`reqAckStatus`);
- `foodgroup/admin.go` - the refusal in the reply to an AIM address change;
- `deploy/oscar-register/server.js` - `syncLoginEmail`, `emailOwner`, texts;
- `deploy/oscar-legacy-web/topics.json` - the `/e` page in the client.

---

## Web services

Both are written without external dependencies, on bare Node (`node:sqlite`, `node:http`),
in the retro look of Windows 98 windows, with ru/en/uk support by `Accept-Language`.

### Registration page - `deploy/oscar-register/`

`https://<tailnet-host>:8444/` (inside the tailnet; the HTTP port 8099 answers too).

Sections:

- `/` - registering a number: picking a free one, checking whether it is taken, an
  optional e-mail for recovery;
- `/password` - changing the password and tying an e-mail;
- `/recover` - recovery by e-mail, a one-time link valid for 30 minutes;
- `/account` - changing the number and deleting the account;
- `/verify` - confirming the address from the e-mail.

**Changing the password** is needed because the management API can only change a
password, not check the current one. The service checks the hash itself, opening
`oscar.sqlite` read-only; the algorithm repeats `wire/user.go`:

```
weakMD5Pass   = MD5(authKey + password + "AOL Instant Messenger (SM)")
strongMD5Pass = MD5(authKey + MD5(password) + "AOL Instant Messenger (SM)")
```

**Recovery by e-mail.** Addresses and one-time links live in a separate database,
`/var/lib/oscar-register/recovery.sqlite`; the address must not go into the ICQ profile,
because that field is searchable through the directory and would become public. Only
the SHA-256 of the token is stored. The SMTP client is written by hand (`mail.js`):
EHLO, STARTTLS, AUTH LOGIN, subject in RFC 2047, body in base64. Mailbox settings are in
`/etc/oscar-register/mail.env` (mode 640, template: `deploy/config/mail.env.example`);
while `SMTP_HOST` is empty, the page honestly says that sending is not set up.

**Changing the number.** The server cannot rename a number - there is no such route, and
`identScreenName` is the primary key. So: create a new one, carry over the password,
profile and contact list, delete the old one - in exactly this order, so that the old
one stays intact if something fails.

**Management API pitfall:** `DELETE /user` cleans only the `users` table. `feedbag`,
`profile`, `buddyListMode` and `clientSideBuddyList` have no foreign keys, and their
rows are left orphaned - a freed number would go to a new owner together with someone
else's contact list. The service cleans up these four tables itself.

### Pages in place of vanished services - `deploy/oscar-legacy-web/`

The `oscar-legacy-web.service` service, `/opt/oscar-legacy-web`, port 8101, from outside
through nginx with TLS on 8102. `ExecReload` sends `SIGHUP`: `services.json` and
`topics.json` are re-read without a restart.

The parent unit keeps it up with `Upholds=` - the same as the registration page.
Without that, `PartOf=` would stop it together with the server but never start it again.

Topic pages are built from `topics.json`. A topic has either `use` - a list of
instructions on what to do - or `here`, a single sentence for when there is nothing to
do: the service is gone and there is nothing to replace it with. There is no separate
"on this server" box: if something works, the page simply says how to use it.

The `now` flag marks topics whose subject still works today - a feature of the client
or of our server. Their description is written in the present tense, and their header
caption reads "як це працює" ("how it works") instead of "що це було" ("what it was").
22 of the 42 topics are like that; for the rest the past tense is honest - those
services are gone.

### Profile page - `deploy/oscar-register/profile.js`

`/profile` - sign in with the number and the current password, then the whole ICQ
profile in one place. It is a separate file because the markup is large.

There are no cookies and no session: the password lives only in the tab's memory and
signs every action - the same as on the other pages of this service.

The profile is read and written **through the management API** (`GET`/`PUT
/user/{uin}/icq`), not directly in the database. That way edits from the page go
through the same checks as edits from the client - including "one address - one
account". A taken address comes back as `409 mail_taken` (before, this case looked like
an "internal error").

**Drop-down lists** - countries, languages, occupation, interest categories, past
background, organizations - are built from the client's own files, not made up:
`DataFiles/countries.fld`, `languages.fld`, `Interest.fld`, `Occupation.txt`,
`PastBG.txt`, `Group.txt`. The result is in `deploy/oscar-register/icq-codes.json`,
the parsing script is `tools/icq2003b/codes/extract-icq-codes.py` (the format is simple:
`<item><code=100><name="Art"></item>` or `code<TAB>name`).

**Privacy** - the native ICQ flags and only those: publish the address
(`PublishEmail`), require authorization, status visible on the web, receive mailings.
The protocol had no separate visibility for the other fields.

**Changing the password moved here**, `/password` answers with a redirect to `/profile`,
and the old page is removed. Changing the number and deleting the account stayed on
`/account`.

**What the form does not have, and why:**

- time zone (`GMTOffset`) - the server code does not show in what form ICQ stores it,
  and writing it at a guess would spoil the profile. The client still sets it;
- "originally from" (`OriginallyFrom*`) - the management API returns these, but
  `SetBasicInfo` in the store does not update those columns, so there is nothing to
  write them with.

The `/user/{screenname}/icq` route the page relies on is described in `api.yml`
(before, it was implemented but not documented): `GET`/`PUT`, the schemas of the
profile sections and the refusal codes, including `409` for a taken address.

### Admin panel - `deploy/oscar-admin/`

`http://<lan-ip>:8100`, HTTP Basic, the password is in `/etc/oscar-admin/secret.env`
(not in the repository). It can: list accounts with their sessions, create an account,
reset a password, suspend, end a session, delete.

**Pitfall:** lifting a suspension is `PATCH /user/{name}/account` with
`{"suspended_status": ""}` (an empty string). For `null` the server answers
`304 Not Modified`: `null` is treated as "field not sent".

---

## TLS and certificates

`tailscale cert <tailnet-host>` issues a real Let's Encrypt certificate; it is renewed
once a week by the `oscar-cert-renew` timer (`deploy/scripts/oscar-cert-renew.sh`).

For AIM we had to create **our own RSA root CA**: the Tailscale certificate is signed
with ECDSA, and the 2011 NSS libraries do not understand it. The certificate is put into
the client's NSS database (`%APPDATA%\acccore\nss`, dbm format, not sqlite).

nginx is a story of its own: AIM 6.2-7.x start the handshake with an SSLv2-format hello,
and parsing it was dropped from OpenSSL starting with 1.1.0. So the TLS front is built
with OpenSSL 1.0.2u (`ras-nginx:1.28.0-openssl-1.0.2u`).

**Pitfall:** the config and certificates are mounted into the container as individual
files, and replacing a file with a new inode (`install`, `mv`, `sed -i`) is invisible to
the container. You need `cp` over the existing file, or `docker restart oscar-nginx`.
`nginx -t` meanwhile honestly checks the old contents and notices nothing.

---

## Clients

| client | status |
|---|---|
| ICQ Pro 2003b | works fully, including registration from the client and search |
| Miranda NG | works, including search by UIN and profiles |
| QIP 2005 build 8092 | works fully |
| ICQ 6.5 | works: profiles, search, messaging. No SSL support at all |
| AIM 7.5.14.8 | works over TLS through Kerberos (1443 -> 3143) |
| ICQ 7.x | sign-in not achieved: it gets as far as `getChallenge` but does not accept the reply |
| R&Q after 2019 | not suitable: OSCAR was removed from it, only WIM is left |

---

---

## Server address in ICQ 6.5

The address is set in the client itself: "Options -> Connection -> Manual settings ->
ICQ Server", the "Host" and "Port" fields (`idIcqServerHost`, `idIcqServerPort` in
`OPrefsPanelConnection.box`). This is the path for the user; nothing needs patching.

The default there is `login.icq.com` - it is hard-coded as a UTF-16 string in
`MCore.dll`. It can be replaced in place if you want the client to go to our server
straight away without any setup: the length must match exactly, `login.icq.com` is 13
characters, and an address like `<tailnet-ip>` fits as it is. The original file is then
kept next to it (`MCore.dll.oscar-backup`). Neither hosts nor DNS is needed in either
variant.

---

---

## ICQ 6.5 patch - `tools/icq65/patch/`

`ICQ-6.5-Patch.exe` is what a user runs: one window, the same kind as the 2003b
patch. It finds the client, takes the server address (remembered in
`HKCU\Software\OpenOSCAR\Icq6Patch`), and in one pass removes the Xtraz,
advertising, tZers, SMS and phone parts of the interface, patches the
"SMS & Phone" entry out of `MUICore.dll`, points the ICQ.com pages at the
server and whitelists it, and empties the advertising, teaser and SMS carrier
lists. The sign-in server is left to the user: Options -> Connection -> ICQ
server. `-Apply`/`-Restore` with `-Root` and `-Server` run it without the
window.

It is checked against a pristine copy of build 2024: applied, it matches what
the two Python tools below produced byte for byte, apart from the byte order
marks those tools wrongly added to files that had none; restored, it matches
the pristine copy exactly; applied twice, the second run changes nothing. It
also restores files backed up by the Python tools, so a client patched the old
way can be returned to the original with it.

The sections below describe the findings it is built on.

## Dead ICQ 6.5 web services - the ICQ 6.5 patch (`tools/patcher/Icq65`)

Besides signing in, ICQ 6 fetches over HTTP from services that are long gone:
Xtraz on `xtraz.icq.com` and `df.icq.com`, help and guides on `labs.icq.com`,
updates and emoticon packs on `update.icq.com`. The addresses sit in plain text
in `ConfigFiles\*.xml`, so the tool rewrites the host and keeps the path: the
`oscar-legacy-web` routes match the original ICQ 6 paths.

**Only pages are moved.** What the client parses itself stays on the dead hosts
on purpose - `Master.xml`, `Packages.xml`, `tzer.xml`, `Searches.xml`,
`adConfig.xml`. Answering those at all is worse than not answering: with a dead
host the request times out and the client keeps its built-in defaults, while any
prompt reply - even a 404 - makes it treat the list as empty and drop that part
of the interface. That is how the tab strip, the hint in the search box and the
bottom panel disappeared during the first attempt.

**The client checks where content comes from.** `XtraConfig.xml` carries a
`WhiteDomainList` key and `tzer.xml` a `<whitelist>` block; a host that is not
listed is refused together with everything it feeds. Our host has to be added to
both, which the tool does.

**The interface itself is editable markup.** Everything the client draws lives
under `services/icqApp/ver1/` as Boxely files - `.box` markup, `.style.box`
styles, `.dtd` strings - not compiled into the binaries. A widget is removed by
marking it `collapsed="true"`, which is how the client hides its own optional
parts, and the ICQ 6.5 patch (`Icq65Client.cs`) does that for the frames left behind by the
dead services: the Xtraz strip above the contact list (`idXtrazBarArea`), the
entertainment panel below it with its ad slot (`idMainEntertainmentBox`), the
banner under the message window (`idBottomBannerContainer`), the SMS and phone
buttons of the message toolbar (`btnSMS`, `btnPhone`) and the "My Xtraz" item of
the main menu.

Not everything is in the markup: the "Free SMS" button of the message window and
the "SMS & Phone" entry of the preferences list are built in code, so only their
strings live in the `.dtd` files and neither can be collapsed.

The entry comes from a table of 16-byte records in `MUICore.dll` - panel loader,
name, label key, icon - written by a run of `mov` instructions at file offset
`0x258CDA`, where the SMS record sits between "Connection" and "Advanced".
Zeroing its four fields does remove the entry and takes the whole preferences
dialog with it: the code walks the table by a count rather than stopping at an
empty record. Removing the record for real means moving every later one up and
correcting that count, which is a code change rather than a substitution. So the
entry stays and its panel is taken away instead, leaving it to open an empty
page.

Two more things the client draws by code, whatever the markup says: the ad
element and the Xtraz buttons. The ad element cannot be dropped - the code looks
it up and the emoticon and formatting panels stop opening without it - and
collapsing it does not last, because the code shows it a few seconds after the
window opens; zeroing its size in the style sheet is what works. Xtraz add-ons
installed under `packages/` are loaded from disk and keep their buttons however
the Xtraz list is answered, so such a package is disabled by renaming its
directory.

**Xtraz and the advertising are now removed, not stubbed.** The client draws
the Xtraz strip, the teaser row and the ad slots only while something describes
them: the slots come from the `<spot>` entries of `adConfig.xml`, the teasers
from the `<tz>` entries of `tzer.xml`, both local files, and the strip from the
Xtraz list fetched over HTTP. Emptying the two local lists and answering the
list request with a list that holds nothing but the welcome entry removes all
three from the interface for good. The welcome entry has to stay: "Welcome to
ICQ" in the main menu opens an entry from this same list, and an entirely empty
list takes that with it. Note the container element is `<xtraz>`, not `<xtras>`
- with the wrong name the client reads the list and finds no entries in it. A 404 is not enough for the list: the client then keeps the
copy it cached earlier and goes on drawing the buttons that copy describes.
`--keep-xtraz` leaves them in place, and the notes below describe what that
takes.

**The Xtraz gallery is fed by a list, not by a page.** `XtrazListUrl` points at
`xtrazlist.xml`, and the client fills its own window from it, so a stub page
cannot stand in. The service now serves a minimal list in the original schema
(`xtrazList / groups / xtraz`) holding one `dhtml` item that opens our "coming
later" page inside the client.

Only `type="dhtml"` opens a remote address. Most of the original entries are
`localDhtml` (a package the client unpacks on disk first) or `boxely` (its own
XUL-like runtime); such an entry fetches a page served to it and then drops it,
which looks exactly like the fetch never happening. Serving the archived list
keeps the client's own categories, so every entry in it is rebuilt into the
plain `dhtml` shape, keeping its id - the buttons find entries by id - and its
window size.

**A DTD is required.** Before parsing the list the client fetches
`XtrazStringsUrl` + `/<lang>/xtraz_list.dtd`. The original declared entities for
the translated names; ours needs none, but the fetch has to succeed - on a 404
the parse fails and the window only reports "a problem opening Xtra".

**The list is cached for `ReloadTimeout`** (21600 seconds out of the box), so
a change only takes effect after the client restarts or the timer runs out, not
after the window is reopened. The patch sets it to 600 seconds (see
`XtrazReloadSeconds` in `Icq65Client.cs`).

Backups are kept next to the originals with the `.icq6patch-backup` suffix, and
"Restore original" puts them back (it also restores the `.icq6-retarget-backup`
and `.icq6-declutter-backup` files the older Python tools left). The sign-in
server is changed in `MCore.dll` itself, so the default `login.icq.com` points at
your server; a server typed under Options → Connection → Manual stays the user's
choice.

`MXtraz.dll` is only a string inside `MISB.dll`, not a missing file - the Xtraz
engine itself is `MISB.dll`, listed in `ICQ.exe.csassembly` and exporting
`XtraApi`, `XtraManager`, `DownloadManager` and `CacheManager`.

The request log in `oscar-legacy-web` (off with `LOG_REQUESTS=0`) is what settled
every one of these: three times in a row it showed what the client actually asks
for, where guessing had failed.

---

## Saving the profile from QIP 2012 - six separate faults

QIP writes the profile **in two requests in a row**: first the classic `SetFullInfo`
(`0x0C3A`), then the directory update (`0x0FD2`). The second one wins, and both had to
be dealt with. What was found, in order:

1. **A parse error dropped the connection.** Any error in an ICQ request handler ends
   the session; the client silently signed in again and re-read the old profile -
   from the outside it looked like "saved, and everything got cleared". An unreadable
   field is now skipped (`readICQField`) instead of failing the whole save.
2. **E-mail without the publish flag.** With an empty address QIP cuts the value off
   right after the string, and parsing ran into EOF. It is now parsed in two steps.
3. **Phone numbering was off by one.** In the protocol `1` is home, `2` work, `3`
   mobile, `4` fax, `5` work fax (`fam_15icqserver.cpp`, `getRecordByTLV(0x6E, 1..5)`).
   Counting from zero put the home phone into work, mobile into fax, and fax into
   work fax.
4. **The phone list was written on top of the old one.** The client sends it whole, so
   the list replaces all five fields: otherwise a number erased in the client stayed
   in the profile forever.
5. **Numeric codes arrive as four bytes.** Country, industry, interest type: QIP puts
   them in four bytes, and reading the first two gave zero. We read 1, 2 and 4 bytes
   and write four - Miranda's `getNumber` understands any of these lengths (`tlv.cpp`),
   so this does not bother older clients.
6. **Place of birth did not reach the database.** The directory save writes through
   `SetBasicInfo`, and its `UPDATE` lacked three columns: `originCity`,
   `originState`, `originCountryCode`. Parsing worked correctly - the values simply had
   nowhere to go.

**The length of numeric fields has to follow the client.** We read leniently -
1, 2 or 4 bytes - and write in the length the client itself sends for that field:
QIP sends the country as four bytes and does not read a two-byte one, while industry,
languages and interest type go as two bytes, and it does not read four-byte ones
either. Miranda and ICQ 6 do not care: their `getNumber` understands all three lengths
(`tlv.cpp`).

**Marital status** (tag `0x012C`) had nowhere to be stored - added the column
`icq_moreInfo_maritalStatus` (migration `0046`), a field in `ICQMoreInfo`, parsing in
the directory dialect and `marital_status` in the management API. The codes come from
the client's list: 10 - single, 11 - in a relationship, 12 - engaged, 20 - married,
30 - divorced, 31 - separated, 40 - widowed, 50 - open relationship.

**The code lists differ between versions.** The profile stores a number, and each
client has its own list of names: occupation code `18` is shown by ICQ 6.5 as
"Transportation", while the list from the ICQ 2003b files (`DataFiles`, from which
`deploy/oscar-register/icq-codes.json` is built) has "Military" in that slot, and has
no "Transportation" at all. The server cannot help here - it passes a number; no
translation table between the lists exists. The White Pages use the 2003b list.

**The directory dialect has no occupation.** In its place is "industry" (`0x0082`), a
different concept; occupation lives only in the classic request, tag `0x01CC`. QIP
sends both requests, and the zero industry from the second one erased the occupation
saved by the first. So a zero from there no longer overwrites anything. In Miranda the
same spot is marked in the code as `// Lost In Conversion` - its authors ran into the
same hole and simply turned off sending the occupation.

## ICQ Pro 2003b client patch - `tools/icq2003b/patch/`

Removes the advertising in the contact list and in the message window, the Google
search bar and the empty space under them. Four targeted changes, each one
flipping a branch that already exists in the client's code:

| file | offset | before -> after | what it does |
|---|---|---|---|
| `icqmutl.dll` | `0x20626` | `B8 96 9B 22 20` -> `31 C0 C2 04 00` | `MCCLBannerDialog::CreatTheCLBannerCtrl` -> false |
| `ICQProLib.dll` | `0x1217B` | `B8 BA 7D 89 24` -> `31 C0 C3` | `MCProBannersUtils::IsOKToDispalyBanner` -> false |
| `ICQTicker.dll` | `0x750` | `53 55 8B 6C 24 14 56` -> `B8 11 01 04 80 C2 0C 00` | `DllGetClassObject` -> `CLASS_E_CLASSNOTAVAILABLE` |
| `Icq.exe` | `0x39AA2` | `74 41` -> `EB 41` | the layout no longer adds 22 px for the ticker bar |
| `ICQMessagePlugin.dll` | `0x7B63`, `0x7B84` | `83 C0 05` -> `31 C0 90`, `83 C7 05` -> `31 FF 90` | the ICQ / SMS / Email check boxes in the message window are hidden |
| `Icq.exe` | `0x1C489C` | `Send By:` -> spaces | the caption above them |
| `Skin\IcqPro.skn` | `0x41750`, `0x41782` | `-341` -> `-133`, `136` -> `344` | the frame is pulled up to the `Send` button |

**About "Send By".** SMS and Email there are not features of the client but calls to
ICQ.com gateways that no longer exist: the e-mail and the SMS would go nowhere, and the
server would answer "user is offline". There is no point keeping a choice that has only
one working option.

**The bar is made of three layers, and they know nothing about each other** - this is
the main lesson, and it cost three failed attempts:

1. **the check boxes** are controls of the plug-in's dialog, but their visibility is set
   **not by the template** but by the layout routine: it calls `ShowWindow` itself,
   computing the argument as `neg eax; sbb eax,eax; and al,0xFB; add eax,5` - that is 5
   (`SW_SHOW`) or 0. Zeroing the result makes the client hide them with its own call.
   The controls stay in the dialog and the ICQ box stays checked, so the code reads it
   as before and `Send` works;
2. **the caption** has no control behind it at all (querying the open window shows that
   `1007` is never created): the skin draws it from string 8727 in `Icq.exe`. It is
   overwritten with spaces of the same length - the string table stores the length
   separately;
3. **the frame** is the `RgnFrame` object in `Skin/IcqPro.skn`. Its position is computed
   from anchors and offsets, not from a rectangle, so it is `m_Offset` that has to move;
   the rectangle is corrected afterwards so the file does not contradict itself. The
   object cannot be hidden entirely: it takes part in the window shape, and without it
   the right edge cuts off the send pointer.

The number 344 is the limit down to which the skin draws the curve of the left edge: it
is part of a stretched image and gets visibly squashed below this width.

**Lesson for the future:** in this client visibility is decided by the code and the
skin, not by the resources. A change has to be checked by running the client and
querying the live window (a script for it, `inspect-window.ps1`, is in the history
before commit `b654961`), not by
reading templates - twice in a row reading them gave a confident but wrong answer.

The checksums in the entries for `Icq.exe` refer to the file with the other changes
already applied, so the state is determined by comparing bytes at the offset, and the
checksum serves as a shortcut.

Files: `IcqAntibanner.exe` (a window; finds the client folder itself), `IcqAntibanner.ps1`
(the source), `icq-antibanner.py` (the same from the command line).

**How it was found.** The ICQ modules export decorated C++ names, so every class is
labelled. The analysis tools are in `tools/icq2003b/analysis/`:

- `exports.py` - find exported functions by a name mask;
- `disasm.py` - disassemble an export by name;
- `dis_at.py` - disassemble at a file offset;
- `xref.py` - who references a string;
- `impxref.py` - who calls an imported function;
- `callers.py` - who calls a function by RVA;
- `bytepatch.py` - replace bytes, checking the expected contents;
- `skinmap.py` - parse the geometry of the `IcqPro.skn` skin.

Requires `pip install capstone pefile`.

---

## The two ICQ profile dialects - and moods

Clients request the profile in two incompatible ways, and the client picks the way, not
the server: the protocol has no negotiation. So the server has to understand both.

**Classic**, from ICQ 99-2003: request `0x07D0` with subtype `0x04B2`, `0x04BA` or
`0x04D0`, reply `0x07DA` in flat blocks (`0x00C8` basic, `0x00DC` more, and so on).
Lives in `foodgroup/icq.go`.

**Directory**, from ICQ 6 (Miranda calls it MDir): subtypes `0x0FA0` (request and
search) and `0x0FD2` (saving your own profile), fields in TLVs, UTF-8 strings. Lives in
`foodgroup/icq_directory.go` and `wire/icq_directory.go`.

**Encoding.** The classic dialect knows nothing of Unicode: the client sends and expects
bytes in its Windows code page, and the protocol does not say which one. The directory
dialect and the registration page send UTF-8. The server stores UTF-8 and converts at the
edge of the classic dialect (`foodgroup/icq_classic_text.go`): incoming text that is not
UTF-8 is read in the `ICQ_CLASSIC_CODEPAGE` code page (`windows-1251` by default),
outgoing text is written in it, and what it lacks becomes `?`. Cyrillic in 1251 almost
never happens to form valid UTF-8, so the two are told apart reliably. Without this, a
Cyrillic name typed in ICQ 6.5 showed up in ICQ 2003b as mojibake (its UTF-8 bytes read
as windows-1251), and the other way round.

**Pitfalls:**

- **The profile request, search and save differ in more than the subcommand.** They
  have three different body layouts: in the request the block flag is followed by a
  four-byte counter, in search by a page number and a counter of two bytes each, in the
  save directly by the data length. Search and the profile request even use the same
  subcommand `0x0002` and differ only in the block flag (`0x03` versus `0x02`).
- **The reply subtype decides whether the wait ends.** The client parses both `0x0FAA`
  ("data") and `0x0FB4` ("reply"), but sends the acknowledgement that closes the
  details window and the search only for `0x0FB4`. With `0x0FAA` the window hangs
  forever - there is no timeout. "Data" is used only for intermediate packets of the
  results.
- **Search results go one record per packet,** and the continuation flag must be set
  both in the SNAC and inside the directory block - the client checks both. Empty
  results are a separate packet with a zero block counter.

**ICQ 6 moods are not xStatus.** The plug-in's `capXStatus` table has 86 slots, but only
32 are real GUIDs; the numbers above that are moods, and they have no capability. They
travel as a separate item `0x0E` in tag `0x1D`, as a string like `0icqmood65`, next to
the status text (item `0x02`). The server reads both in `SetUserInfoFields` and puts them
back into the contact's info; without this the mood icon would change for nobody. The
type is defined as `BARTTypesMood` in `wire`.

---

## ICQ plug-in for Miranda NG - `tools/miranda-icq/`

The ICQ protocol was removed from Miranda NG and sits there as
`NotWorkingStuff/Deprecated/IcqOscarJ` - it does not build against the current API.
`IcqOscarJ.diff` ports it to the current headers and replaces the hard-coded icq.com
addresses with the `ICQ/WebBase` setting, for which a field was added to the
`Network -> ICQ -> Features` tab. Empty - the old addresses stay. The paths
`/icq/register`, `/icq/password`, `/icq/whitepages` are served by `oscar-legacy-web`.

The built libraries are in `build/x32` and `build/x64`, for core 0.96.7. Details on
building, picking the source snapshot and installing are in `tools/miranda-icq/README.md`.

**Pitfall:** both checks on the core side are silent.

- `dll_sniffer.cpp` compares the product version from the plug-in's resource with
  `MIRANDA_VERSION_COREVERSION`. If they differ, the file is not considered a plug-in at
  all: it is not in the list, not loaded, and there is not a single message. So the
  plug-in is built strictly for its own core version.
- `newplugins.cpp` keeps `pluginBannedList`, where the UUID of the original `icqoscar8`
  is listed explicitly. The port has its own UUID.

**Translation.** Strings in Miranda are tied to a plug-in by a `#muuid` tag, and current
packs have no section for the ICQ protocol - it was removed together with the plug-in.
`langpack_russian_icq.txt` brings it back: it goes into `Languages\`, and
`#include langpack_russian_icq.txt` is appended at the **very end** of the main pack. At
the end, precisely - our file sets `#muuid`, and everything that comes after this line in
the pack would otherwise be attributed to our plug-in. It is built by
`make-langpack.py`; the current pack covers 59% of the strings, the rest comes from a
pack from the Miranda IM days, where the `IcqOscarJ` section is still intact.

**The file must not be named `ICQ.dll`.** `PluginUpdater` compares the MD5 of each file
with a list on the server and ignores the version number. Our own build will never
match, so it is always shown as "Deprecated!", and "Update" replaces it with the
server's build - with the banned UUID, after which the plug-in silently stops loading.

---

## Pitfalls that cost time

**The ICQ 2003b user database must not be edited.** Any edit to `2003b\<UIN>\O<UIN>.fpt`,
even a byte-for-byte replacement of the same length, sooner or later breaks it: the
client crashes at start-up with "The operation cannot be completed at this time" (codes
259 and 257). All changes go into the code only.

**ICQ must not be killed with `Stop-Process -Force`.** The client does not finish
writing the contact list cache `CL\<UIN>.fb`, after which it hangs on "Logging in…"
forever, even though sign-in succeeds on the server (`login_ok=true`, `user signed on`,
the session lives for minutes). Fix: delete `CL\<UIN>.fb`. Close it only the normal way:
tray -> Exit; the close button only minimizes it.

**Windows Defender blocks PowerShell scripts that patch a DLL's entry point** (AMSI).
The same changes in Python go through - hence `bytepatch.py`.

**`AOLDiag\tbdiag.dll` crashes AIM and ICQ 7.** A 2010 diagnostics module installed by
the AIM installer: after a few launches the client starts crashing with an access
violation a second after a successful sign-in. Fix: rename the folder
`Common Files\AOL\AOLDiag`.

**Dead ends not worth returning to:** the `UpBanner` flag in the database has no effect
on the panel; the skin element `StatTyping` is the status line, and turning it off
removes the connection indicator and looks like "the client does not sign in"; the pair
of getters 60/62 in `icqwutl.dll` are the character codes of `<` and `>` from HTML entity
parsing, not sizes.

---

## Deploying from scratch

1. Build the server (see above) and put it in `/opt/open-oscar-server/`.
2. Copy the units from `deploy/systemd/` to `/etc/systemd/system/`, and the config from
   `deploy/config/settings.env` to `/etc/open-oscar-server/`.
3. Web services: `deploy/oscar-register/` and `deploy/oscar-admin/` into `/opt/`,
   the admin panel password into `/etc/oscar-admin/secret.env` (mode 600), mail settings
   into `/etc/oscar-register/mail.env` (mode 640, template in `deploy/config/`).
4. TLS front: `deploy/nginx/nginx.conf` into `/etc/oscar-nginx/`, the certificates next to
   it, the container with `--network host`.
5. `systemctl enable --now open-oscar-server oscar-register oscar-admin oscar-cert-renew.timer oscar-backup.timer`.
