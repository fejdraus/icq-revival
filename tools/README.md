# Client tools

One folder per client. Each tool keeps a backup next to every file it changes
and can put everything back.

| Folder | Client | What it is |
|---|---|---|
| `icq2003b/patch/` | ICQ Pro 2003b | **The patch to hand out.** `ICQ-2003b-Patch.exe` - removes the banners and the Google bar, points the ICQ.com menu items at our server. Built from the C# project in `patcher/Icq2003b`. |
| `icq2003b/translate/` | ICQ Pro 2003b | The Ukrainian interface: `uk-UA.json` holds every text of the client's menus, dialogs and string tables (programs, libraries and ActiveX controls) with its translation, and under `inplace` the few texts that live in a program's data or in the skin. `extract.py` brings it up to date from the client, `build.py` turns it into `patch/ICQ-2003b-uk-UA.json`, a readable text recipe of what to change - the replaced strings, menu items and control captions, and the widths the controls are fitted to - which the patch carries and follows, rebuilding each translated resource from the client's own English one, when "Ukrainian interface" is ticked. `build.py` also widens the controls a longer text needs where the dialog has room (`fit.py`), and lists what still does not fit in `overflow.json`; `check_fit.py` tries shorter wordings against it. |
| `icq2003b/analysis/` | ICQ Pro 2003b | Disassembly and cross-reference helpers used to find the code patches, plus a map of the skin file. |
| `icq2003b/codes/` | ICQ Pro 2003b | Extracts the profile code lists (countries, interests, ...) from the client's `DataFiles` into `deploy/oscar-register/icq-codes.json`. |
| `icq65/patch/` | ICQ 6.5 (build 2024) | **The patch to hand out.** `ICQ-6.5-Patch.exe` - removes Xtraz, advertising, tZers, SMS and phone from the interface and points the ICQ.com pages at our server. Built from the C# project in `patcher/Icq65`. With `FlashPlayerControl-Ruffle.dll` next to it (built there by `common/Build-Patches.ps1`, not kept in git) it can instead bring tZers back: "tZers without Flash", off until ticked. |
| `icq65/flashplayer/` | ICQ 6.5 | `FlashPlayerControl.dll` on Ruffle, the tZers player without Adobe Flash (Rust; see its README). |
| `icq65/tzers/` | ICQ 6.5 | `make_tzers.py` - rebuilds the twelve tZers the server hands out (`deploy/oscar-legacy-web/tzers/`) from the Wayback Machine, and copies their thumbnails from the client. |
| `icq72/patch/` | ICQ 7.2 (build 3143, or 3525 it updates itself to) | **The patch to hand out.** `ICQ-7.2-Patch.exe` - removes SMS, the games and Zones buttons, Xtraz, Zlango, the tab strip of the main window with its Lifestream and "My box" tabs (only the contact list stays) and advertising from the interface, takes the AOL Diagnostics module that crashes ICQ 7 (`tbdiag.dll`) out of the way, and points the ICQ.com pages and the sign-in at our server. Text files only: markup, configuration and DTDs, each checked by its checksum first. Built from the C# project in `patcher/Icq72`. The SMS entry of the settings list is built in code and stays. With `FlashPlayerControl-Ruffle.dll` next to it (as for ICQ 6.5) it can also bring back tZers and Flash avatars: "tZers and Flash avatars without Flash", off until ticked.  The client puts back from update.icq.com (which still answers) every file its update manifests (`updates\manifest` in its folder and in each package) list with another checksum; the patch keeps those manifests listing the files as it leaves them, and "Restore original" puts the manifests back too. The ICQ 6.5 patch does the same. |
| `patcher/` | every patch | The patches as C# WinForms programs (.NET Framework 4.8, one exe each): `Common/` - the window, the icon, the job list, backups and the command line all patches share, compiled into each exe as source; `Icq65/`, `Icq72/` and `Icq2003b/` - the patches for ICQ 6.5, ICQ 7.2 and ICQ Pro 2003b. |
| `patcher-cpp/` | ICQ Pro 2003b | The same 2003b patch in C++ on the plain Win32 API, for Windows XP SP3 to 11 with nothing to install (`Build.ps1`, toolset v141_xp). It carries the same text recipe of the translation and builds the translated resources from it the same way. |
| `common/` | every patch | `Build-Patches.ps1` - builds every patch's exe from `patcher/` (the .NET SDK); `Check-VirusTotal.ps1` - checks the built exes on VirusTotal (key in `VT_API_KEY`). |
| `miranda-icq/` | Miranda NG | The ICQ protocol plugin brought back to the current Miranda NG API: the patch, build output and language pack. |

The patches also point the client's sign-in at the server, where the client allows it (see the rules below).

## Rules for every client patch

These hold for the patches above and for any new one, for whatever client:

- **Only the server's domain is asked for** - `icq.example.org`, nothing
  else. Ports, schemes and paths are the same on every ICQ Revival server
  (`deploy/VM-SPEC.md`, section 3), so the patch fills them in itself for each
  kind of link its client has: the HTTPS pages on 8102 (under `/icq` for ICQ
  2003b), plain HTTP on 8101 only for what a client fetches with a loader that
  cannot do HTTPS, the short paths `/p`, `/e`, `/u`, `/m`, and so on. Whatever
  is typed is reduced to the domain - a scheme, a port or a path after it are
  dropped - and a saved value from an older version is read the same way.
- **The sign-in server is set too**, as the default the client starts from,
  never inside its own database: ICQ 6.5 in `MCore.dll`, where the built-in
  `login.icq.com` lives, ICQ 7.2 in the default connection settings of
  `packages\ICQ\ConfigFiles\AppConfig.xml`, ICQ 2003b in `Default Server
  Host` in the registry and in the connection settings the client copied it
  into on its first run.
  A server the user typed in the client's own settings stays theirs.
- **Moving to another server is applying again** with the new domain; links
  pointed at the previous server move without a restore first.
- **The server's own name is never built in.** No default domain in the code or
  the exe - the field starts empty and remembers what was typed.
- **Everything changed is backed up first**, and "Restore original" puts back
  exactly the files as they were, byte for byte.
- **Every change can be picked.** Each row has a tick, with "Select all" above
  the list, and Apply makes the client match the ticks: a cleared change that
  is in place is taken out again, from the backup, and a file with several
  changes is rebuilt from its original with the ticked ones only. The list
  offers jobs, not files: "Xtraz", "advertising", "links to your server",
  each one row with one tick however many files and places it takes, grouped
  by what they are for (`patcher/Common/PatchItems.cs`). The ticks can only be changed on a client with nothing applied;
  once anything is, they stay as it was applied with, and choosing again
  starts from "Restore original". The cleared rows are remembered; a scripted
  run takes them as `-Skip`.
- **Binaries are recognised by checksum** before a byte is written; another
  build of the client is refused rather than patched at the wrong offsets.
- **One look, one name pattern.** A patch describes its window through
  `patcher/Common/PatchWindow.cs` - title, badge, colour, columns - and does
  not draw its own. Its exe is named `ICQ-<client version>-Patch.exe`, the
  exe's description names the client and build, and the icon carries the
  version, so a patch is never mistaken for another client's. A new patch is
  a project under `patcher/`, with an `app.ico` written by `PatchIcon.WriteFile`
  with its badge and colour, and a line in `common/Build-Patches.ps1`.
