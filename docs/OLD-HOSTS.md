# Old hosts in the clients

Every place the classic clients still reach for an old ICQ/AOL/Mail.ru host or
a third party, and what the patches now do about it. "Ours" means pointed at
the self-host server over HTTPS on 8102 (pages, Xtraz, tZers, the web API on
8082 for ICQ 7's sign-in, STUN on the server for calls); "nowhere" means a
closed local target so nothing leaves the machine - `http://127.0.0.1:9` for a
URL (port 9 discards), `127.0.0.1` for a bare host, `203.0.113.0` (RFC 5737
TEST-NET-3) where a string must stay a bare IPv4; "hidden" means the UI entry
that opens it is collapsed or dropped.

The decisions follow one rule: if the server can serve the feature simply and
safely, point there; otherwise neutralise so nothing ever goes to an old host.
Addresses in code are written over in place in their own encoding, no longer
than the original, the tail zeroed (`tools/patcher/Common/CodeStrings.cs`);
addresses in configuration/markup are rewritten as text. Every file is
identified by the checksum of its original before a byte is written and rebuilt
from that original on each Apply, so Restore is byte-identical and a second
Apply changes nothing. The Boxely clients' update manifests are re-signed so
the client keeps the patched files (`UpdateManifests.Sync`).

Patch rows used (no new rows were added): **services-gone** (SMS/Xtraz/tZers/
Zlango/tabs), **ads**, **links** ("the pages the client opens point at your
server ... nothing goes to the old ICQ hosts"), **sign-in** ("automatic
connection and voice calls use your server").

## ICQ 7.2 (builds 3143 and 3525)

Configuration/markup (text; row in brackets):

| Where | Host | Feature | Trigger | Decision |
|---|---|---|---|---|
| `System.xml` CountryCodeUrl | xtraz.icq.com | country lookup | startup | ours `/xtraz/srv/...` |
| `System.xml` StatsUrl | cb.icq.com | stats report | periodic | nowhere |
| `System.xml` UpdateEmailUrl | www.icq.com | e-mail activation | on click | ours |
| `System.xml` DownloadEmoticonGalleriesUrl | www.icq.com | emoticons page | on click | ours |
| `Packages.xml` | update.icq.com, aopenxtraz.icq.com, aicq.openxtraz.com | add-on package lists | periodic | nowhere |
| `Master.xml` | cb.icq.com | config bundle base | startup | nowhere |
| `links.xml` page links | www.icq.com, cf.icq.com, download.icq.com, gallery.aim.com | help/about/terms/search/skins/moods/emoticons/Xtraz | on click | ours `/icq/...` (links) |
| `links.xml` sign-on & feeds | ICQ.IcqOpenAuth, Wim.BuddyListBase (api.oscar.aol.com), XtraController.UserXtraInstalHitUrl (gallery.aim.com) | fetched by the client | background | nowhere (links) |
| `links.xml` dead services | profiles.aim.com, lifestream.icq.com, www.facebook.com, chat.icq.com, www.zlango.com, www.kampyle.com | AIM profile, Lifestream, Facebook, chat, Zlango tips, feedback | on click | ours stub page (links) |
| `adConfig*.xml` (21 files) | ad.mail.ru, ar.atwola.com, im.adtech.de | ad slots + servers | periodic | slots removed, servers nowhere (ads) |
| `tzer.xml`, `tzerDe.xml` | xtraz.icq.com, c.icq.com, update.icq.com | tZer list | on open | ours `/icq/tzers` (tZers player) or nowhere |
| `XtraConfig.xml`, `zlango7/XtraConfig.xml` | df.icq.com, c.icq.com, openxtraz hosts | Xtraz list | startup | ours + server whitelisted (links); Zlango list → empty (`xtrazempty`) |
| `PushStatusServices.xml` | o.icqcdn.com / o.aolcdn.com | Lifestream service icons | on display | nowhere (links) |
| `SMSXtra.xml` | www.icq.com | SMS activation help | on click | ours stub (links) |
| `ExternalDomains.xml` | chat.facebook.com (MFacebook) | Facebook chat (XMPP) | startup | integration disabled (links) |
| `data.dtd`, `Errors.dtd`, `connect.htm` | www.macromedia.com, (fp)download.macromedia.com | "install Flash" link / Flash control auto-download | on click / when Flash missing | ours download page / nowhere |
| `AboutDlg/MsgSessionPanel/SMS/common` sentence DTDs (+ language packs) | www.icq.com, icq.rambler.ru | legal/download/SMS links | on click | ours |
| `AppConfig.xml` ACC | api.screenname.aol.com, api.oscar.aol.com, turn.oscar.aol.com, ars, http.proxy.icq.com | web login, BOS redirect, STUN, relays | sign-in / call / fallback | web+BOS+STUN → ours; ars+tunnel → nowhere (sign-in) |

Code (written over in place; `MCore.dll` relocation for the sign-in host is the
pre-existing sign-in patch):

| File | Host | Feature | Trigger | Decision (row) |
|---|---|---|---|---|
| `MCore.dll` | login.icq.com (relocated), cb.icq.com srp, update.icq.com, www.icq.com, http.proxy.icq.com | sign-in host; stats; config update; e-mail; tunnel | sign-in/periodic | ours / nowhere (sign-in) |
| `MReport.dll` + `install_dll/MReport.dll` | cb.icq.com | crash/stats report (SRP) | on crash/periodic | nowhere (links) |
| `MUICore.dll` | update.icq.com, openxtraz.icq.com, ad.mail.ru, ar.atwola.com | package-list & ad-server code defaults | periodic | nowhere (links) |
| `MUICoreLib.dll` | lifestream.icq.com | Lifestream settings default | on click | nowhere (links) |
| `acccore.dll` | api.icq.net/buddyfeed, buddyupdates.aim.com, api.login.icq.net, login.icq.com, ars.icq.com, http.proxy.icq.com, turn.icq.com, api.icq.net (3525); api.oscar.aol.com, ars/aimhttp/turn.oscar.aol.com (3143) | buddy feed/updates (Lifestream); auth/relay/STUN defaults | poll / sign-in / call | feeds nowhere (links); auth/relay/STUN nowhere (sign-in) |
| `coolcore59.dll` | sq.mediator.icq.com / .aol.com, snatmap.mac.com, http.proxy.icq.com, api.login.aol.com, my.screenname.aol.com, start.aimpages.com, startpage.aol.com, aimhttp.oscar.aol.com | SIP voice-quality server, NAT lookup, tunnel, AOL web sign-in/portal | call / sign-in | nowhere (sign-in) |
| `ICQ.exe` | www.icq.com/legal/privacy.html | privacy link of the crash dialog | on crash | nowhere (links) |
| `MCUpdateController`/`MCConfigFilesService` (AppConfig propDefaults) | update.icq.com (ManifestUrl/UpdateUrl) | self-update & config-update defaults | periodic | nowhere (links) |

Left as-is (safe): `MUICore.dll` `http://icq.com` is the tracking-cookie domain
(no fetch); `aol.com/boxely/*.xsd` schema identifiers; `www.aim.com/avtrack`
and `developer.aim.com/xsd` XML namespaces; `xprt6.dll` cookie-domain table
(`aol.com`, `aim.com`, ...); `aoldiag.dll` → supportsoft.com and `aolload.exe`
→ www.aol.com (only reached if `aolload.exe` runs; the AOL Diagnostics module
`tbdiag.dll` is already renamed by the **fix** row); `sipXtapi/sipXmediaLib`
SIP format templates and SSDP 239.255.255.250; `install_config/*.ini` and
`text_install.ini` (Mail.ru/Rambler bundleware - the installer's files, not run
by an installed client); version-number strings that look like IPs.

## ICQ 6.5 (build 2024)

Configuration/markup is handled by the existing patch: `System.xml`
(CountryCodeUrl → ours, StatsUrl/ConfigFiles → nowhere, email/emoticons →
ours), `links.xml` compad/legal pages → ours, `Master.xml`/`Packages.xml`/
`adConfig.xml`/`tzer.xml` dead hosts → nowhere, `data.dtd` + language DTDs →
ours, whitelists get the server. Advertising/Xtraz/tZers/SMS/Zlango UI is
removed by their rows. The sign-in patch relocates `login.icq.com` in
`MCore.dll`, repoints the STUN server (turn.oscar.aol.com) to ours and the
relays (ars.oscar.aol.com, http.proxy.icq.com) to nowhere.

Added here (code, files the rest of the patch did not touch):

| File | Host | Feature | Trigger | Decision (row) |
|---|---|---|---|---|
| `MReport.dll` | cb.icq.com | crash/stats report (SRP) | on crash/periodic | nowhere (links) |
| `coolcore49.dll` | sq.mediator.aol.com, snatmap.mac.com, aimhttp.oscar.aol.com, my.screenname.aol.com, start.aimpages.com, startpage.aol.com | SIP voice-quality server, NAT lookup, AOL relay, web sign-in/portal | call / sign-in | nowhere (sign-in) |

Left as-is: `MCore.dll` code defaults for master.xml (cb.icq.com), ConfigFiles
update (update.icq.com), e-mail activation (www.icq.com) and im2email
(labs.icq.com) - the files that drive these are already dead-hosted or
retargeted, so the code defaults are a never-reached fallback; `MUICore.dll`
package-list/preloader defaults (same - `Packages.xml` is dead-hosted) and the
`icq.com` cookie domain; `boxelyToolkit` `aolSearch.js` (search.aol.com, in a
gadget ICQ 6.5 does not open); www.macromedia.com in the "install Flash"
sentences (low value, could be pointed at the download page later); license
texts.

## ICQ Pro 2003b (build 3916)

Links in the data files (`icqlinks.xml`, `channels.xml`, `atelink.xml`,
`icqacc.xml`, `psearch.xml`, `WebSearch.fld`) and the four help links built into
`Icq.exe` are pointed at the server by the existing **links** row; dead hosts
with no page become a `/stub` page. Sign-in is the registry Default Server Host
→ the domain. Banners, the Google bar and the Send-By strip are removed by their
rows.

Added here (code, files the rest of the patch did not touch):

| File | Host | Feature | Trigger | Decision (row) |
|---|---|---|---|---|
| `ICQCool.dll` | 205.188.147.46 | hardcoded fallback login IP | sign-in | → 203.0.113.0 (sign-in) |
| `ICQCool.dll` | pager.icq.com | Email Express `@pager.icq.com` | on send | nowhere (links) |
| `DBAdmin.exe` | 205.188.252.121 | hardcoded fallback login IP | sign-in | → 203.0.113.0 (sign-in) |
| `DBAdmin.exe` | cb.icq.com | datafile bundles (banners, channels) | periodic | nowhere (links) |
| `ICQFTLib.dll` | rars.oscar.aol.com | file-transfer rendezvous relay | on transfer | nowhere (sign-in) |
| `ICQSmLib.dll` | a.root-servers.net | hardcoded DNS probe | startup | nowhere (sign-in) |
| `icqsrp.exe` | web.icq.com/download | upgrade link in the stats tool | periodic | nowhere (links) |

Left as-is (entangled with the offset-based code patches on `Icq.exe` and
`icqmutl.dll`, and low-value because the feature code is already removed or the
host just fails): `Icq.exe` cb.icq.com datafile URLs and `ads.web.aol.com`
banner HTML (the banner code is patched out), `ar.atwola.com` (ad server;
`icqmutl.dll` banner code is patched out, and the name resolves to 0.0.0.0),
`http.proxy.icq.com` in `ICQProLib.dll` (HTTP tunnel fallback; sign-in goes to
the server), `mail.icqmail.com`/`icqswatch` (ICQmail, gone), `icq.mirabilis.com`
in `Defaults/Server.dat`, and the static help/bookmark HTML under `DataFiles\`,
`Bookmark\`, `Help\` (opened only on explicit user action; they point at dead
cf.icq.com/web.icq.com pages that simply fail). `icqsrp.exe` SRP posts go to the
configured server (`%s`), not an old host.

## How to verify live

1. Clear the DNS client cache (`ipconfig /flushdns`), sign in on a patched
   client and use the features (open menus/help/About, send a message, place a
   call, let it sit for the periodic stats/update polls).
2. `ipconfig /displaydns` should show only the self-host domain (and, during a
   call, STUN/TURN on it) - no `*.icq.com`, `*.aol.com`, `*.aim.com`,
   `*.mail.ru`, `atwola`, `icqcdn`, `mediator`, `snatmap`, `screenname`,
   `aimpages`.
3. `netstat -b` (or a packet capture) during use should show connections only
   to the self-host and to `127.0.0.1`/refused local ports - never to an old
   host. A connection to `127.0.0.1:9`, `203.0.113.0` or a bare `127.0.0.1`
   failing at once is the intended "nowhere".

## Rebuilding the patches

The patch sources changed, so rebuild the three exes with
`tools/common/Build-Patches.ps1` (it also builds the gitignored player and E2E
add-on DLLs it ships beside them). Apply to a copy of each client and confirm a
second Apply reports no changes and Restore is byte-identical.


## Correction (2026-10-04)

ICQ 7.2's sign-in hosts are no longer overwritten: `api.login.aol.com` in
`coolcore59.dll` and `api.login.icq.net`, `api.icq.net`, `login.icq.com`,
`api.oscar.aol.com`, `my.screenname.aol.com` in `acccore.dll`/`coolcore59.dll`.
With them overwritten, a sign-in with a typed password stopped after
`getChallenge` and never sent `clientLogin` (a saved token still worked): the
client builds its web sign-in requests from these names and the AppConfig.xml
host. The client does not connect to them itself (the DNS cache after normal
use showed only the server's own name).
