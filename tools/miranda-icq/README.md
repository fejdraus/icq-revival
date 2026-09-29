# ICQ plugin for Miranda NG

The ICQ protocol (`IcqOscarJ`) was removed from Miranda NG and sits in its repository
as `NotWorkingStuff/Deprecated/IcqOscarJ`; it does not build against the current API.
`IcqOscarJ.diff` ports it to the current headers and points the hard-coded links at
our server. The changes are minimal: only what it will not build without, plus the
address substitution.

## What is here

| File | What it is |
|------|---------|
| `IcqOscarJ.diff` | patch for `NotWorkingStuff/Deprecated/IcqOscarJ`, 41 files |
| `IcqOscarJ/` | the plugin source as built: `NotWorkingStuff/Deprecated/IcqOscarJ` of [miranda-ng/deprecated](https://github.com/miranda-ng/deprecated) (commit `eba42656`) with `IcqOscarJ.diff` applied, byte for byte (`-text` in `.gitattributes`); the GPLv2 source of `build/*/IcqOscarJ.dll` |
| `build/x32/IcqOscarJ.dll` | built for core 0.96.7, for `miranda32.exe` |
| `build/x64/IcqOscarJ.dll` | the same for `miranda64.exe` |
| `IcqRevivalFlash/` | source of the plugin for ICQ 6 animated avatars and tZers (`FlashAvatars` before 1.1), see below |
| `build/x32/IcqRevivalFlash.dll`, `build/x64/IcqRevivalFlash.dll` | the same plugin, built for core 0.96.7 |
| `translations/` | the translations of both plugins, `langpack_<language>_<plugin>.txt`, merged into Miranda's main language pack (see "Translation") |
| `langpack-extra-ru.txt`, `langpack-extra-uk.txt` | strings that are in no pack at all; input for the builder |
| `make-langpack.py` | rebuilds the translation |
| `make-update-packages.py` | packages and hashes for `PluginUpdater` on our server, see "Updates through our server" |
| `Install-IcqRevival.ps1` | installs into a Miranda folder with a backup: plugins, translations (merged into the main packs), skin patch |
| `ieview-mirandafinal/` | patch for the IEView skin "MirandaFinal": message text outside JavaScript, tZer pictures, see its README |

## Installation

Put the build of the right bitness into `Plugins\` next to the others. Or, with
Miranda closed, run `Install-IcqRevival.ps1 -Miranda <folder>`: it puts in both
builds of the right bitness and the Flash engine, merges the plugins' translations
into the installed main language packs, patches the MirandaFinal skin (if it is
there), and saves everything it replaces into `_revival-backup\<time>\` with a
`MANIFEST.txt`.

The file name is deliberately not `ICQ.dll`. `PluginUpdater` compares **the hash of
every file** with the list on the update server (`DlgUpdate.cpp`,
`CalculateModuleHash`) and does not look at the version number at all. The Miranda NG
list does not know our build, so under the name `ICQ.dll` it always shows as
"Deprecated!", and "Update" replaces it with the server's build, that is, the version
with the banned UUID, after which the plugin silently stops loading.

### Updates through our server

The sign-in server serves the same Miranda NG list, but with our files
(`deploy/oscar-legacy-web/miranda-updates.js`, address
`https://<server>:8102/miranda/stable/x32` and `/x64`). On startup IcqOscarJ points
`PluginUpdater` there: the "custom address" mode (`PluginUpdater/UpdateMode` = 0),
`UpdateURL` = `https://<host from OscarServer of the first enabled ICQ
account>:8102/miranda/stable/x%platform%`; `PluginUpdater` itself replaces
`%platform%` with 32 or 64 according to its bitness. The domain is not hard-coded;
the plugin fills in the port and path. The address it wrote is remembered in
`IcqRevival/UpdateURL`:

- the address has not been set yet, but `PluginUpdater` already has its own address:
  that one is the user's, leave it alone;
- it was set, and `PluginUpdater` still points to the same place: update it if the
  sign-in server has changed;
- it was set, but the user later chose something else (their own address or
  "stable"): do not touch it again.

The hidden `IcqRevival/UpdateBase` (the full address without `/x..`) overrides the
derived one, for testing on your own test setup.

The server's list is built so that `PluginUpdater` updates our files with our own
builds and never with someone else's:

- the lines for `Plugins\IcqOscarJ.dll`, `Plugins\IcqRevivalFlash.dll` and
  `Libs\FlashPlayerControl.dll` are ours, with the hashes of our builds; the other
  lines are as in Miranda NG. There are no Miranda NG lines under our names,
  including the old ones, even when our packages are missing from the server;
- the `rules.txt` rules that would delete our files or move them elsewhere, and the
  dependencies of our modules, are dropped; a rule that leaves a file where it is
  (`"langpack_*.txt": "Languages\\*"` in Miranda NG) stays;
- our renames of old names come before the rules (see below), and so do our
  delete rules for the separate translation files of earlier builds
  (`"langpack_*_icq.txt": null` and the like, one per plugin, see "Translation");
- a main language pack `Languages\langpack_<language>.txt` for which
  `translations/` has files is served with our sections merged into its end, and
  its line carries the hash and crc of the merged file; packs of other languages
  are Miranda NG's as they are. If a pack to merge could not be downloaded, there
  is no line for it at all, the file stays as it is, and the delete rules are
  left out of that list, so an old setup keeps its separate files until the merge
  goes through;
- other packages are served byte for byte from the Miranda NG server, and only those
  that are in its current list.

The hash in the list is not the file's MD5 but `CalculateModuleHash` from
`checksum.cpp`: the MD5 of the PE section data after zeroing the timestamps (debug,
export, resources) and rebasing the relocations to 0; for translations it is the MD5
of the whole file. `make-update-packages.py` computes it; on 125 files (x86 and x64,
PE and text) it matched `checksum.cpp` itself, built separately for both bitnesses.

While `PluginUpdater` takes the list from our server, it should update our files as
well. Otherwise they are excluded: module `PluginUpdaterFiles`, setting name is the
file path relative to the Miranda folder in lower case (`plugins\icqoscarj.dll`; the
key is `wszBuf + cbBaseLen`, without a leading slash), type BYTE, value `2`.
`PluginUpdater` does not update or delete such a file (`ScanFolder`, after the rules
are parsed) and does not unpack it (`unzipfile.cpp`, `IsFilteredFile`). The plugins
set `2` when the list is someone else's and clear it when the list is ours; they
write only when the value changes. IcqOscarJ is responsible for itself and the
IcqRevivalFlash files; IcqRevivalFlash for itself and `libs\flashplayercontrol.dll`.
A module under a different name (say, `ICQ.dll`) is always protected: the list would
bring someone else's file under that name.

The translations have no file of their own to protect any more: they live in the
main pack. Earlier builds marked `languages\langpack_russian_icq.txt`,
`languages\langpack_russian_icqrevivalflash.txt` (and the old
`..._flashavatars.txt`), and a mark would keep our delete rules off those files. So
on every start both plugins remove any `PluginUpdaterFiles` setting matching
`languages\langpack_*_icq.txt`, `languages\langpack_*_icqrevivalflash.txt` or
`languages\langpack_*_flashavatars.txt` (IcqRevivalFlash: its own two), whatever
the language and whichever list is in use: Miranda NG's list does not name those
files, and its `"langpack_*.txt": "Languages\\*"` rule leaves them where they are.

### Old name: FlashAvatars.dll

Before 1.1 the Flash plugin was called `FlashAvatars.dll`, and that name is taken:
the Miranda NG `rules.txt` (x32 and x64) contains `"flashavatars.dll": null`, which
is how it deletes its own plugin of the same name, removed in 2014. A regular
`PluginUpdater` would erase ours. So it is now `IcqRevivalFlash.dll`, the settings
module and the log user are `IcqRevivalFlash`; the UUID and capability are
unchanged (so the translation section is the same), and so are the contact settings (`FlashAvatarHash`/`FlashAvatarUrl` in the ICQ account
module).

How old installations move over:

- **through our list.** `PluginUpdater` only updates files that are in place, so the
  server puts the rename `"FlashAvatars.dll": "Plugins\\IcqRevivalFlash.dll"` at the
  start of `rules.txt` (only if a package under the new name exists). The old
  translation, `langpack_russian_flashavatars.txt`, is deleted by the rule
  `"langpack_*_flashavatars.txt": null`, and its `#include` is dropped from the
  main pack the server merges (see "Translation").
  `PluginUpdater` takes the first matching rule, compares the old file with the line
  for the new name, and on "Update" moves the old file into the backup and unpacks
  the new one (`DlgUpdate.cpp`, `ApplyUpdates`). It checks the `PluginUpdaterFiles`
  mark by the old path; builds 2e228c7 clear it while the list is ours;
- **by hand**: put in the new files, remove the old ones, and run
  `Install-IcqRevival.ps1` (or remove `#include langpack_russian_flashavatars.txt`
  from `langpack_russian.txt` yourself).

The new plugin and IcqOscarJ clear the marks from the old paths when the list is ours
or the old file is already gone; with someone else's list the old file stays
protected, otherwise Miranda NG would delete it. Once, on startup, the settings of
the `FlashAvatars` module (including the log) are moved to `IcqRevivalFlash`
(anything already set under the new name is left alone), together with the position
of the tZers button on the message window toolbar (`SRMM_Toolbar`/`TabSRMM_Toolbar`,
`FlashAvatars_1`) and the custom tZers icon (`SkinIcons/FlashAvatars_tzer`).

Tested (before the translations were merged into the main pack) on a copy of
0.96.7 with builds 2e228c7 installed (`FlashAvatars.dll`, its translation, the
`#include` of the old name) and the real Miranda NG stable x32 lists
(with only the `langpack_russian.txt` line replaced: its package is not here, it was
built from the copy's translation): `PluginUpdater` offered `IcqOscarJ.dll`,
`FlashAvatars.dll`, `langpack_russian_flashavatars.txt` and `langpack_russian.txt`;
after "Update" and a restart `FlashAvatars.dll` and the old translation were gone,
`IcqRevivalFlash.dll` and the new translation were in place, the hashes matched the
list, `langpack_russian.txt` had only the new `#include` lines, and the plugin loaded
(engine, capability). Settings migration: `FlashAvatars/NLlog` and
`SRMM_Toolbar/FlashAvatars_1` ended up under the new names, and the `FlashAvatars`
module was deleted.

Builds released before this always set `2`, so `PluginUpdater` will not update them
until the current ones are installed by hand once.

Tested on a copy of 0.96.7 with the server on a local machine and a substituted
Miranda NG server (a list with a foreign hash for `IcqOscarJ.dll`, rules deleting our
files, and a newer `Dummy.dll`):

- `PluginUpdater` picked up our address by itself and requested
  `/miranda/stable/x32/hashes.zip`;
- it offered `FlashAvatars.dll` (that is what the Flash plugin was called then;
  build 0.9 was installed, the server had 1.0), `Dummy.dll` from the Miranda NG
  server, `langpack_russian.txt` and our translation; it did not offer
  `IcqOscarJ.dll`;
- after "Update" and a restart all files matched the list, `FlashAvatars.dll` was
  byte for byte equal to the build, and `langpack_russian.txt` ended with the
  `#include` lines;
- with the user's own address (someone else's list) the `2` marks came back, none of
  our files were offered, and the delete rules did not fire; choosing "stable" after
  our address survived two restarts.

HTTPS: by default `PluginUpdater` does not check the certificate at all, and with the
check enabled ("Network → PluginUpdater → Validate SSL certificates",
`NLValidateSSL`) it accepts the Let's Encrypt chain (tested on `valid-isrgrootx1.letsencrypt.org`) and rejects a
self-signed one (`800b0109`). Port 8102 is nginx with the same certificate as for
Miranda and browsers.

### Packages for the server

```
python make-update-packages.py <directory>
```

takes `build/x32`, `build/x64` and both engines from
`tools/icq65/flashplayer/target/*/release`, and puts into `<directory>/x32` and `/x64`
the packages in the form `PluginUpdater` downloads them (`Plugins/IcqOscarJ.zip` with
`Plugins/IcqOscarJ.dll` inside, and so on), plus `manifest.json` with the hashes and
crc32; into `<directory>/translations` it copies every
`translations/langpack_<language>_<plugin>.txt`, which the server merges into the
main packs. This directory is copied to the server
into `deploy/miranda-updates` (it is not in git: the engine is 15 MB) and is reread on
`SIGHUP` or when `legacy-web` restarts. `--hash <files>` prints the `PluginUpdater`
hashes, for comparison.

## Links to your own server

The hard-coded icq.com addresses are replaced with your own through `IcqWebUrl()`: it
reads the `ICQ/WebBase` setting and appends the path to it. Empty means the old
addresses stay, that is, the behaviour does not change until the setting is filled
in.

Its field is under `Options → Network → ICQ → Features`, group **Web Pages**.

| Place in the client | Path |
|-----------------|------|
| "Create a new ICQ account" in the options and on first start | `/icq/register` |
| "Retrieve a lost password" | `/icq/password` |
| "Open ICQ profile" in the contact menu | `/icq/whitepages?icq=<number>` |

These paths are served by `oscar-legacy-web` (see
`deploy/oscar-legacy-web/services.json`), so the setting's value is the address of
that service, for example `http://192.168.1.43:8101`.

## Translation

Miranda ties translations to a plugin with a `#muuid` marker:
`LangPackTranslateString` looks for the section with the plugin's UUID and, if it
does not find one, falls back to strings not tied to any plugin. The current packs
have no section for the ICQ protocol, it was removed together with the plugin, so
only about half of the strings get translated, and in a haphazard mix.

`translations/` brings that section back, and the Flash plugin's, as one file per
plugin and language: `langpack_<language>_<plugin>.txt`, where `<language>` is as in
the name of Miranda's main pack, `langpack_<language>.txt`, and `<plugin>` (no `_`
in it) is `icq` for IcqOscarJ and `icqrevivalflash` for IcqRevivalFlash. There are
Russian and Ukrainian files so far. Another language needs only its files there:
nothing in the code, the scripts or the server names a language.

The files are not installed as files of their own. Miranda reads one pack, the main
one; an `#include` line in it would pull in a separate file, but updating the pack
from the Miranda NG server drops that line, and the separate file shows up in the
language list as if it were a language. So our sections go into the main pack
itself, at its very end, between two comment lines:

```
;### ICQ Revival translations: begin
...
;### ICQ Revival translations: end
```

- our update server does it whenever it serves a `Languages\langpack_<language>.txt`
  it has files for (`deploy/oscar-legacy-web/miranda-updates.js`,
  `mergeTranslations`): `PluginUpdater` pointed at it offers the pack as an update,
  and every later update of the pack brings the sections again;
- `Install-IcqRevival.ps1` does the same, byte for byte, to the main packs installed
  in the Miranda folder.

When merging, each file loses its BOM and its own header (`Miranda Language Pack
Version 1`, `Language:`, `Locale:`: the loader reads a header only at the top of the
main pack, and anywhere else those lines would be taken for a translation of the key
before them) and takes the main pack's line endings; the main pack keeps its BOM
(the loader skips one only at the start of a file). What was between the marker lines
before is replaced, so merging again gives the same file, and `#include` lines naming
our separate files of earlier builds (`langpack_*_<plugin>.txt`, including the old
`langpack_*_flashavatars.txt`) are dropped.

It must be the end: `#muuid` holds until the next one (`LoadLangPackFile` in
`src/mir_core/src/Windows/langpack.cpp`), so everything after our sections would be
assigned to our plugin.

Earlier builds shipped the files separately into `Languages\` and hooked them up
with `#include` lines at the end of the main pack. Through our server,
`PluginUpdater` deletes them (the `"langpack_*_<plugin>.txt": null` rules) in the
same run in which it replaces the main pack with the merged one;
`Install-IcqRevival.ps1` removes them too. The plugins clear the marks earlier
builds set on them (see "Updates through our server"), so that the rules can act.
Without our server or the script, the separate files and `#include` lines stay and
keep working as before.

### Switching Miranda to Ukrainian

Our download (`icq-revival-miranda.zip`) carries no translations: Miranda NG's main
packs come with Miranda or from its update server, and ours are merged into them.
To get the Ukrainian one:

1. main menu → "Available components list" (`PluginUpdater`), group "Languages",
   tick `Languages\langpack_ukrainian.txt`, "Download". With `PluginUpdater`
   pointed at our server (IcqOscarJ does that, see "Updates through our server")
   the file comes with our sections already in it. Without `PluginUpdater`: take
   `langpacks/ukrainian/Langpack_ukrainian.txt` from the `0_96_7` branch of the
   miranda-ng repository, save it as `Languages\langpack_ukrainian.txt` and run
   `Install-IcqRevival.ps1`, which merges our sections into it;
2. "Options" → "Customize" → "Languages": in the list pick
   `Українська [langpack_ukrainian.txt]`, then "OK".

Miranda reloads the pack at once; restart it so that every window picks up the new
language. The IcqRevivalFlash avatar gallery then shows the Ukrainian avatar names
(it goes by the pack's `Locale: 0422`).

### Building the translation

```
python make-langpack.py <plugin-directory> translations/langpack_russian_icq.txt \
    langpack-extra-ru.txt <current langpack> [<old langpack>]
python make-langpack.py --lang uk <plugin-directory> translations/langpack_ukrainian_icq.txt \
    langpack-extra-uk.txt <Deprecated/ICQ.txt> <Langpack_ukrainian.txt>
```

`--lang` (`ru` by default, or `uk`) only sets the header of the result: the
language name, the locale and the heading of the untranslated part.

The Ukrainian sources are both in the miranda-ng repository, branch `0_96_7`:
`langpacks/ukrainian/Deprecated/ICQ.txt`, the Ukrainian section of the ICQ
protocol as it was when the plugin was removed, and
`langpacks/ukrainian/Langpack_ukrainian.txt`, the current full pack (version
0.96.7, the one `PluginUpdater` delivers). The ICQ section goes first here: its
wording is the ICQ one (the moods, for example, read as ICQ's first-person
phrases rather than the generic adjectives other plugins use), and the full pack
only fills in what it lacks. With
`langpack-extra-uk.txt` in front, 912 of 914 strings are translated; the two left
are `ICQ` and `Slider1`, as in Russian. The third-party packs are not kept in git.

The script extracts the translatable strings from the source (`Translate*`,
`LPGEN*`) and from the resource, then looks for an existing translation for them in
the given packs, in order. Matching is exact first, then relaxed: without the `&`
accelerator, case-insensitive, ignoring a trailing colon or ellipsis.

The current pack alone covers 59% of the strings. The rest was found in a pack from
the Miranda IM days, where the `ICQ.dll / IcqOscarJ protocol` section is still there,
and with it coverage is 100%: of 907 strings only two stay untranslated, `ICQ` (same
as the original) and `Slider1` (an internal control name). If no such pack is at
hand, the untranslated strings are written, commented out, at the end of the file.

Two format details that are easy to trip over:

- in the source a quote inside a string is escaped (`\"`), but in the pack it is
  written plain: the loader parses escape sequences itself, and the key must match
  what the program sees after compilation. `\n` and `\t`, on the other hand, stay in
  the file as they are;
- a translation cannot start with `#`: the check for a directive comes first, and
  such a line will be skipped.

## Build

You need the miranda-ng source **of the same version as the installed core**. This is
not a suggestion but a hard requirement, see below.

```
git clone --filter=blob:none https://github.com/miranda-ng/miranda-ng
cd miranda-ng
git checkout cc32e4168    # tip of 0_96_7: core 0.96.7.28845, see below
build\make_ver_stable.bat
cp -r <this-repo>/tools/miranda-icq/IcqOscarJ protocols/    # already patched
MSBuild.exe protocols/IcqOscarJ/icqoscar8.vcxproj \
  -p:Configuration=Release -p:Platform=Win32 -p:PlatformToolset=v143
```

`IcqOscarJ/` is the same as the upstream folder with the diff applied:
```
git clone --filter=blob:none https://github.com/miranda-ng/deprecated
cp -r deprecated/NotWorkingStuff/Deprecated/IcqOscarJ protocols/
patch --binary -p1 -d protocols/IcqOscarJ < IcqOscarJ.diff
```

`--binary` is required: the Miranda source is stored with CRLF, and without it
`patch` rejects every hunk with "different line endings". Tested: the patch applies
without rejects, and the result matches byte for byte the tree the libraries in
`build/` were built from.

`include/m_version.h` is not kept in git; `build/make_ver.bat` generates it from
`build/build.no`. The version numbers must match the core: the file sets
`MIRANDA_VERSION_COREVERSION`, and `version.rc` takes the plugin's `PRODUCTVERSION`
from it.

### How to find the matching source snapshot

Third-party builds (FinalPack and the like) are built from their own tree, and their
commit hash will not be found in miranda-ng. The snapshot is found by a fingerprint:
the number of entries in the export tables:

```python
# how many exports the installed core has
pe = pefile.PE(r'...\libs\mir_app.mir'); pe.parse_data_directories([0])
len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
```

and the same number for `mir_core.mir`. Then look for the commit with the same number
of lines of the form `name @ordinal` in `src/mir_app/src/mir_app.def` and
`src/mir_core/src/mir_core.def`. Miranda assigns the ordinals explicitly and never
reuses them, so matching counts mean a matching "ordinal → function" mapping, and
plugins import the core by ordinal only.

For a copy of `D:\MirandaFinal` (0.96.7 #28845, `cc32e41`) this is `mir_app` = 1026,
`mir_core` = 1595, which gives commit `9e8deb06` of 22.06.2026. There,
`build/build.no` is already `0 96 8`, and the version had to be set to `0 96 7` by
hand, since the pack keeps its own number.

Simpler: `cc32e41` is the tip of the `0_96_7` branch (`cc32e4168`), and
`build/make_ver_stable.bat` on it writes exactly `0.96.7.28845.cc32e41` into
`include/m_version.h`. The `v0.96.7` tag is older: `mir_core` has 1592 exports there.
For IcqRevivalFlash a sparse checkout of `build/`, `include/`, `libs/` (the prebuilt
`mir_app.lib`, `mir_core.lib`, `libjson.lib`), `src/mir_app/`, `src/mir_core/`,
`utils/`, `plugins/ExternalAPI/` and `*.props` is enough. A build from this snapshot
(MSBuild VS 2022 Build Tools, v143) gave `PluginUpdater` hashes equal to those of the
files in `build/x32` and `build/x64`.

## ICQ 6 animated avatars ("devils")

ICQ 6 keeps a Flash avatar for the user: BART item type 8, a small XML
`<DOCUMENT><RESSET><URL>…swf</URL>`, whose `face` clip changes expression by the
`emotion` property (`stam`, `smile`, `sad`, `laugh`, `mad`, `cry`, `love`, `busy`,
`offline`). In Miranda they were shown by the FlashAvatars plugin (Big Muscle, 2006)
through Adobe Flash; it was removed from Miranda NG in 2014
(`NotWorkingStuff/Deprecated/FlashAvatars` in the `miranda-ng/deprecated`
repository), its UUID was put into `pluginBannedList`, and PluginUpdater deleted a
renamed `flashavatars.dll` (the rule is still in the stable `rules.txt` today, which
is why our plugin has a different name, see "Old name").

**Who called its services.** `FlashAvatar/Make`, `/Destroy`, `/Resize`, `/SetPos`,
`/GetInfo`, `/SetEmoFace`, `/SetBkColor` (`m_flash.h`) were called by the AVS avatar
control, the message windows and the contact list. In the 0.96.7 source and in the
FinalPack binaries (`AVS.dll`, `TabSRMM.dll`, `Clist_modern.dll`, the core) not one
of these calls remains; only the stub `plugins/Popup/src/avatars_flash.h` is left.
So bringing back the old services is pointless: nobody would call them.

**How it is done now.** `IcqRevivalFlash/` ("ICQ Revival Flash", `FlashAvatars.dll`
before 1.1) is a new plugin modelled on the old one:

- It replaces the window procedure of the `MAvatarControlClass` class (the AVS
  avatar control, `SetClassLongPtr` when modules load). This control shows avatars
  almost everywhere: in tabSRMM (the top panel and the picture by the input field),
  in Scriver, in the plain message window, in the info window. If the contact has a
  Flash avatar, the control draws the movie instead of the picture (windowless,
  `IViewObject::Draw` into its own buffer over the parent's background), and the
  previous picture until the movie has loaded. The contact list and popups still
  show the picture: they draw avatars themselves, not through the control.
- The movie is played by our Ruffle-based engine, `Libs\FlashPlayerControl.dll`
  (`tools/icq65/flashplayer`); the ShockwaveFlash object is created directly through
  its `DllGetClassObject`, without the registry, so the ICQ 6.5 registration is not
  touched. If the file is missing, the ShockwaveFlash registered in the system is
  used.
- The movie is downloaded once through Netlib (proxy settings apply) into
  `<avatar cache>\Flash\<md5 of the address>.swf`; http/https only, no more than
  4 MB, only files with the SWF signature.
- Facial expression: a smiley in an incoming message goes to the contact's avatar,
  in an outgoing one to your own (the code table from the old plugin plus `:D`,
  `:(`, `<3`, `*LOL*`…); status: `stam` when online, `busy` in other statuses,
  `offline` when offline. Messages older than 5 minutes (history, offline messages
  at sign-in) are not counted.
- The smiley face is held for 9 seconds, as long as on the devils test page from the
  ICQ set (`devils.zip`), and then the status face comes back. A new smiley restarts
  the countdown; a status change sets its face at once. The duration is the hidden
  setting `IcqRevivalFlash/SmileyFaceSeconds` (WORD, seconds; `0` means the smiley
  face stays until the next smiley or status). The movie itself does not return: the
  expression animation plays once and stops on its last frame. The engine can return
  the face by itself (for ICQ 6.5, which does not do it, see the engine's README),
  but the plugin turns that off (`FPCSetFaceReturn(0)`) and counts itself; the same
  goes for the system ShockwaveFlash.
- For each ICQ account the plugin announces, through `/IcqAddCapability`, the
  capability `{B9E03A0C-B33E-4B18-BC0B-7BB5903129AE}` ("ICQ Revival: Flash
  avatars"). The server (`wire.CapFlashAvatarPlayer`, `HasFlashAvatarCaps`) sends
  items 8 and 12 only to ICQ 6 and to clients with this capability; Miranda without
  the plugin does not send it and gets only the picture. The short `0x134C`
  (devils) will not do: IcqOscarJ always sends it when avatars are enabled.

**What changed in IcqOscarJ.** Previously the plugin chose one of the BART items and
preferred Flash to the picture, so AVS got XML it cannot draw. Now item 8 is handled
separately (`handleFlashAvatarHash` in `icq_avatar.cpp`): types 1/12 remain the
picture, and the XML is requested from the avatar server with a separate request;
`<URL>` is taken from it and written into the contact setting `FlashAvatarUrl` (next
to `FlashAvatarHash`); when the avatar is removed, both are erased. Tracking of
pending requests is split into "picture" and "Flash"; otherwise a second request for
the same contact was dropped as a duplicate. The MD5 check (`StrictAvatarCheck`) is
not applied to the XML.

The account's own Flash avatar (set, for example, from ICQ 6.5) is shown too: when
the server-side list is parsed, BART item `8` from group 0 is no longer taken as "own
avatar" (its id used to be remembered in `SrvAvatarID`, and updating your own picture
would overwrite this item with the picture), and its hash goes to the same
`handleFlashAvatarHash` for `hContact = 0`. After sending the capabilities the plugin
requests its own profile once more (SNAC 1,0E), in which the server now lists type 8,
and item 8 in the session data (SNAC 1,21) is handled the same way and never passed
off as the picture. The result is `FlashAvatarUrl` on the account itself;
IcqRevivalFlash draws it in its own avatar controls (your own picture in the message
window). The exception is the AVS page "User info for Owner → Avatar": the picture
for all protocols is chosen there, and it shows the picture as it would without the
plugin (controls created by AVS's own dialogs do not draw the movie for your own
avatar). The picture uploaded to the server (type 1) remains Miranda's local picture:
the Flash display does not touch it.

The contact's picture: when there is a Flash avatar, type 1 is used (a frame the
server keeps in step with the current Flash), not type 12, since the large icon may
be left over from the previous avatar. And when a picture arrives, `AvatarSaved`
records the hash of the picture received, not the current `AvatarHash`: if the
contact changed their picture while the request was in flight (a second request for
the same contact is dropped as a duplicate during that time), the old picture is no
longer passed off as the new one; the new one is requested at once
(`requestCurrentAvatar`).

**Deleting a contact.** When a contact is deleted, TabSRMM clears the contact data of
the message window (`CContactCache::deletedHandler`, `m_cache = nullptr`) and closes
the window later, with a deferred `WM_CLOSE`. Any repaint of the window in between
crashes in `CInfoPanel::RenderIPNickname` (the info panel paints the window
background and reads `m_cache`). This is a bug in TabSRMM itself; in the crash,
CrashDumper shows the read address `0000015C`. To stay clear of it:

- IcqRevivalFlash, on `ME_DB_CONTACT_DELETED`, immediately hides that contact's
  message window (a hidden window is not repainted) and stops its movies; the
  background under the movie is taken from the parent once per size, not on every
  frame;
- IcqOscarJ remembers contacts being deleted (`OnContactDeleted`) and does not look
  them up, cache them or write settings for them from network threads while the
  contact is still in the database.

### Your own animated avatar: choosing one

You can choose or remove your own animated avatar in the ICQ account menu (status
menu → account → "Animated avatar..."). IcqOscarJ itself adds the item
(`OnBuildProtoMenu`) as long as IcqRevivalFlash offers the
`IcqRevivalFlash/AvatarPicker` service; neither plugin touches the AVS "Avatar" page.
The window (`IcqRevivalFlash/src/avatars.cpp`):

- the server gallery, as on the `avatar.html` page: "Official" and "User created"
  tabs, thumbnails, names from the gallery's `avatars.json`, in Ukrainian with the
  Ukrainian language pack and in English otherwise (the avatars have no Russian
  names; ICQ never named them in Russian);
- a preview of the selected one: our engine, the same one that draws avatars, with a
  facial gesture every 4 seconds, as on the gallery card;
- "Set" and "Remove animated avatar"; the "Now set: ..." line shows what the account
  has.

The gallery is taken from the sign-in server's web pages, like the tZers:
`http://<sign-in server>:8101/icq/avatars/list.json` (the hidden account setting
`AvatarBase` replaces the folder address for testing). The format is `avatars.json`
without the extras: `{"avatars": [{"file", "thumb", "author": "icq"|"user",
"title": {"en", "uk"}}]}`.

IcqOscarJ sets the avatar, through the `/SetFlashAvatar` service (`m_icq.h`,
`PS_ICQ_SETFLASHAVATAR`), the same way the ICQ 6.5 gallery does: the movie address is
wrapped in `<DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>…</URL></RESSET></DOCUMENT>`, the
document's MD5 becomes item `8` of the server-side list (its own id,
`SrvFlashAvatarID`, separate from the picture's `SrvAvatarID`), and when the server
replies that it does not have such a document (flag `0x40` in SNAC 1,21), the
document is uploaded to the avatar server as BART type 8. The document is built from
the address, so it can be uploaded after a restart too. "Remove" sets the item to the
standard "no icon" hash (`02 01 D2 04 72`). Your own `FlashAvatarUrl` changes at once,
and your own avatar controls switch without waiting for the server. This service does
not touch the picture (type 1); the address must be http(s), printable ASCII, without
`< > " ' &`.

What contacts see: ICQ 6.5 sees the movie itself (type 8; it does not get a
placeholder picture); Miranda with IcqRevivalFlash sees the movie and the picture;
the rest see the picture (the owner's own picture, or without one, a still frame of
the gallery avatar, `-still.jpg`, which the server substitutes).

### Installation

Three files, plus the translations; Miranda must be closed:

| File | Where |
|------|------|
| `build/x32/IcqOscarJ.dll` (or x64) | `Plugins\IcqOscarJ.dll`, over the old one |
| `build/x32/IcqRevivalFlash.dll` (or x64) | `Plugins\IcqRevivalFlash.dll` |
| `FlashPlayerControl.dll` from `tools/icq65/flashplayer`, same bitness | `Libs\FlashPlayerControl.dll` |
| `translations/langpack_<language>_icqrevivalflash.txt` | merged into the main pack of that language (see "Translation"; `Install-IcqRevival.ps1` does it) |

If the plugin was installed under the old name, delete `Plugins\FlashAvatars.dll` and
`Languages\langpack_russian_flashavatars.txt`, and remove the `#include` of the old
translation from `langpack_russian.txt` (see "Old name: FlashAvatars.dll").

The engine is not in git (15 MB); it is built with `cargo build --release` in
`tools/icq65/flashplayer` (32-bit, `target\i686-pc-windows-msvc\release`), and for
`miranda64.exe` with `--target x86_64-pc-windows-msvc`, see the engine's README.
There is no need to register it (`regsvr32`) for Miranda.

The plugin is built the same way as IcqOscarJ, in a miranda-ng tree of the same
version:

```
cp -r IcqRevivalFlash <miranda-ng>/plugins/
MSBuild.exe <miranda-ng>/plugins/IcqRevivalFlash/IcqRevivalFlash.vcxproj   -p:Configuration=Release -p:Platform=Win32 -p:PlatformToolset=v143
```

`src/flash.tlb` is a copy of `tools/icq65/flashplayer/typelib/flash.tlb`; `#import`
takes `IShockwaveFlash` from it.

Checking: "Options → Plugins" shows "ICQ Revival Flash"; the log is under "Options →
Network → Log", user "ICQ Revival Flash", or in the file named by the
`ICQREVIVALFLASH_LOG` environment variable. To remove it, delete
`IcqRevivalFlash.dll`: the pictures stay, and the server stops sending the Flash items
after the next sign-in.

## tZers

A tZer is a short Flash clip with sound that ICQ 6.5 plays over the message window.
The format was taken from a real tZer sent by ICQ 6.5:

- channel 2 (rendezvous) with the "ICQ server relay" capability `{09461349-…}`, and
  in TLV 0x2711 an extended ICQ message of type `MTYPE_PLUGIN` (0x1A);
- plugin header: length `0x30`, GUID `{4FA6F34C-09B7-FD48-9208-7E857AE07330}`,
  function 0, name `Send Tzer`, 17 zero bytes; then two lengths (dword, little
  endian: "to the end" = body + 4, and the body) and the body itself:
  `<tzerRoot id="cantH" url="http://…/icq/tzers/canthearu.swf" thumb="http://…/icq/tzers/canthearu.png" name=" Can't Hear U" freeData=""/>\r\n`;
- `id` comes from ICQ 6.5's `ConfigFiles\tzer.xml` (gangSh, cantH, scratch, boo,
  kisses, rasta, arakiri, laugh, da, beback, ilikeu, `sorry ` with a space); `name`
  is in UTF-8, in the sender's language (it may start with a space). The recipient
  plays the clip from `url`.

**IcqOscarJ** (`src/icq_tzer.cpp`) recognizes this plugin and writes an ordinary
message "tZer: <name>" into the history, without a link, so the built-in tabSRMM log,
IEView and History++ all show it the same way, including without the IcqRevivalFlash
plugin. The clip address is passed on through the `<account>/Tzer` event
(`ME_ICQ_TZER`, `m_icq.h`). Sending is the `<account>/SendTzer` service
(`PS_ICQ_SENDTZER`) with the same format (the 0x2711 header is the usual Miranda one,
as for Xtraz requests; the plugin part and the body match ICQ 6.5 byte for byte); a
sent tZer is written into the history too.

**IcqRevivalFlash** (`src/tzer.cpp`) plays a tZer the same way ICQ 6.5 does: a window
of our engine's `FlashPlayerControl` class (layered, transparent, with sound) covering
the whole visible frame of the window that holds the message window (for tabSRMM, the
container; without the invisible resize borders that Windows 10/11 adds to
`GetWindowRect` on the left, right and bottom, going by
`DWMWA_EXTENDED_FRAME_BOUNDS`), as in ICQ 6.5 (`MUIMessage`: `GetWindowRect` of the
window it plays over, and `CreateWindowEx` of the class with exactly that rectangle
and that window as owner). The engine fits the whole 755×560 stage (ShowAll),
centred and without bars at the edges, so whatever is drawn beyond the stage edge (a
figure coming in from the side) is visible rather than cut off. The window is not
always on top: it is an ordinary window owned by the container, so another window
over the conversation covers the tZer too, a minimized container hides it, and when
the container is moved or resized the tZer follows it. It closes when the clip ends
(`fscommand("animEnd")`), on a click, or after 40 seconds. If a tZer arrives and there
is no window, it plays when the window opens (within two minutes). Clips are cached
together with the avatars (`<avatar cache>\Flash\`), with the same limits: http/https,
up to 4 MB, SWF signature.

To send one, use the button on the message window toolbar (ICQ contacts only): a
menu of our server's twelve tZers with pictures; the chosen one plays for the sender
too. Nothing needs to be filled in: the address is built, as in ICQ 6.5, from the
account's sign-in server (`ICQ/OscarServer`, without the port):
`http://<server>:8101/icq/tzers/<file>.swf` and `.png`; the domain is not hard-coded
in the code, and an IP address or localhost works too. The hidden setting
`ICQ/TzerBase` (the full folder address, for example
`http://127.0.0.1:18101/icq/tzers`) overrides it for a test setup. `ICQ/WebBase` is
used only if the sign-in server is not set: it may be a local network address the
recipient cannot reach. The plugin announces the tZers capability
`{B2EC8F16-7C6F-451B-BD79-DC58497888B9}`, by which ICQ 6 offers tZers to the contact.

Why in the same plugin and not a separate one: the engine, the loader and the clip
cache, the network user and the log are shared; a second plugin would load the same
engine again and share the cache with the first.

The Russian tZer names, taken from ICQ 6.5's `TzerLabels.dtd`, are in
`translations/langpack_russian_icqrevivalflash.txt`. ICQ 6.5 has no Ukrainian
resources, so the Ukrainian names in
`translations/langpack_ukrainian_icqrevivalflash.txt` are our own, made after the
Russian ones; as there, Gangsta', Booooo, Akitaka and L8R stay in English. Both
reach Miranda inside its main pack (see "Translation").

## Why two checks break the plugin silently

**Product version.** `src/mir_app/src/dll_sniffer.cpp`, `GetPluginInterfaces()`,
compares `dwProductVersion` from the file's resource with the core's
`MIRANDA_VERSION_COREVERSION`. If they do not match, `bIsPlugin = false`, and the
file is no longer considered a plugin at all: it is not in the plugin list, it is not
loaded, and no message is shown.

**Banned UUIDs.** `src/mir_app/src/newplugins.cpp` holds `pluginBannedList`, and the
UUID of the original `icqoscar8` (`{73A9615C-7D4E-4555-BADB-EE05DC928EFF}`) is listed
there explicitly. `checkAPI()` reaches `isPluginBanned()`, marks the plugin as failed
and unloads the library. That is why the port has its own UUID,
`{A5B4A32D-D2A8-4925-AE3E-1480E41A07B3}`.

On top of that, `OpenPlugin()` inserts an entry into `pluginList` without checking
for duplicates, and `Plugin_Uninit()` removes it through `List_RemovePtr`, a binary
search **by file name**, not by pointer. If you tick a plugin that is already in the
list, two entries with the same name appear: the core removes one from the list but
frees the other, and crashes on exit on the dangling pointer that remains. Hence the
advice not to toggle the check box but to put the file in place and restart.

## Changes for 0.96.7

The patch is made for this core. If you build for a newer one, `db_add_contact` will
differ: in 0.96.7 it is `db_add_contact(void)`, and from 0.96.8 on it is
`db_add_contact(const char *szModule, int flags = 0)`. There are two places in
`src/utilities.cpp`; `Proto_AddToContact` is called right next to them in both cases.

The `PROTO_INTERFACE` virtual function table did not change between these versions.

## Receiving files

Core 0.96 receives an incoming file as `DB::FILE_BLOB`, and passes the transfer
pointer back to `FileAllow`/`FileDeny`/`FileCancel` only from
`FILE_BLOB::setUserInfo` (previously `PROTORECVFILE.lParam`). The port lost this, and
"Accept" on any incoming file ended with "Unable to initiate transfer.": `FileAllow`
got a null pointer and silently returned an error, and it never got as far as
connecting. The original 0.95.8.1 does not work on this core either, for the same
reason. Now the transfer is stored in the event (`oscar_filetransfer.cpp`,
`icq_filerequests.cpp`).

Connecting: first to the sender's addresses, all the ones in the proposal: TLV 2 (the
proposed address, if it is not a proxy), TLV 3 (the client's own address; our server
puts the external one there when the two ends reach it from different addresses) and
TLV 4 (the address the server saw); local ones (10/8, 172.16/12, 192.168/16,
100.64/10, 169.254/16) first, 3 seconds each, external ones 6 seconds each. Matching
external addresses no longer decides where the peer is: a VPN or a CGNAT pool gives
one local network different external addresses. If that fails, the reverse
connection is tried (Miranda listens on a port and sends a proposal with request
number 2; ICQ 6.5 supports this). The AOL file proxy (`ars.oscar`) is gone, and our
server does not have one either: the proxy stages are not tried; if neither a direct
nor a reverse connection is possible, or the peer asks for its own proxy (request
3/4), the transfer fails at once and a cancel is sent to the peer.

**The request while the window is open.** For an incoming file the core sets a
contact list event keyed by the database event; through it the "Incoming file" window
opens. IEView, when drawing the log, removes all events with that key
(`DB::EventInfo::wipeNotify` in `HTMLBuilder.cpp`, for every message and file, on
every log redraw). With the conversation window open, the request remained only a
line in the log, and there was no way to accept it. The built-in TabSRMM log does not
remove file events. Now IcqOscarJ immediately replaces the core's event with its own
(`TakeOverFileRequestNotify`, `oscar_filetransfer.cpp`) with a key the logs do not
touch: it flashes the same way, opens the same "Incoming file" window, and goes away
when the request is accepted, declined or cancelled.

Description: ICQ 6.5 sends no text with a file, so instead of "No description given"
the size is shown (TLV 2711/2713), for example "240.5 KB".

## User info pages

The core no longer creates the "Details" and "Account" tabs from an
`OPTIONSDIALOGPAGE` with a window procedure: `USERINFOPAGE` requires a
`CUserInfoPageDlg` object. Both of our procedures (`IcqDlgProc`,
`ChangeInfoDlgProc`) are kept as they are, and between them and the core sits the
`CIcqUserInfoPage` adapter in `src/userinfotab.cpp`. It passes messages to the
procedure unchanged and adds what the new core does not send:

- the protocol pointer in `lParam` of `WM_INITDIALOG`; it used to come in a separate
  `PSN_PARAMCHANGED` notification, which the core no longer has;
- `PSN_INFOCHANGED` from `OnRefresh()`; the info window calls it after creating the
  page and on `PSM_FORCECHANGED`. `PSN_INFOCHANGED` itself is not forwarded to the
  procedure, otherwise the page would be filled twice.

`m_autoClose = 0`: otherwise `CDlgBase` would close the page on `IDCANCEL`, whereas
Esc must close the whole info window; the procedure itself does that by forwarding
the command to the parent.

`Resizer()` is required: the info window stretches the page to its own size, but only
this handler recalculates the template layout; without it the contents stay in the
top left corner as a fixed frame. The settings list on "Account" stretches in both
directions, the "Save changes" button sticks to the bottom right corner, and on
"Details" the labels stay in place while the values stretch across the width.

**The core does not request your own profile.** The info window calls `PS_GETINFO`
through `CallContactService`, which, for `hContact == 0`, does not find the account
(`Proto_GetContactAccount(0) == nullptr`) and silently returns "success". The window
starts waiting for an acknowledgement that nobody will send: hence the endless
scrolling "Updating" caption and the greyed-out "Update" button. The plugin requests
its own profile itself from `OnUserInfoInit`, and if the request was not sent, it
ends the wait with a deferred
`ProtoBroadcastAsync(0, ACKTYPE_GETINFO, ACKRESULT_FAILED, nullptr, 0)`. Deferred
because a synchronous failure would arrive before the window even starts waiting. The
"Update" button still does nothing for your own profile: `onClick_Update` in the core
skips the null contact.

`PSN_KILLACTIVE` and `PSN_APPLY` go to the procedure directly: the core reads the
page's answer as the result of `SendMessage`, and `DefDlgProc` returns
`DWLP_MSGRESULT`, so `PSNRET_INVALID_NOCHANGEPAGE` from "Account" works as before.

## What is still open

- The plugin's own version number in `src/version.h` is the old one, `0.95.8.1`.
