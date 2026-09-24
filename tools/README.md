# Client tools

One folder per client. Each tool keeps a backup next to every file it changes
and can put everything back.

| Folder | Client | What it is |
|---|---|---|
| `icq2003b/patch/` | ICQ Pro 2003b | **The patch to hand out.** `IcqPatch.exe` - removes the banners and the Google bar, points the ICQ.com menu items at our server. `IcqPatch.ps1` is its source. |
| `icq2003b/retarget/` | ICQ Pro 2003b | Moves the client's ICQ.com links to our server from `icq-services.json`, from the command line. |
| `icq2003b/analysis/` | ICQ Pro 2003b | Disassembly and cross-reference helpers used to find the code patches, plus a map of the skin file. |
| `icq2003b/codes/` | ICQ Pro 2003b | Extracts the profile code lists (countries, interests, ...) from the client's `DataFiles` into `deploy/oscar-register/icq-codes.json`. |
| `icq65/patch/` | ICQ 6.5 (build 2024) | **The patch to hand out.** `Icq6Patch.exe` - removes Xtraz, advertising, tZers, SMS and phone from the interface and points the ICQ.com pages at our server. `Icq6Patch.ps1` is its source. |
| `icq65/declutter/` | ICQ 6.5 | Superseded by `icq65/patch`. The interface half of it, from the command line. |
| `icq65/retarget/` | ICQ 6.5 | Superseded by `icq65/patch`. The links half of it, from the command line. |
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
  `login.icq.com` lives, ICQ 2003b in `Default Server Host` in the registry. A
  server the user typed in the client's own settings stays theirs.
- **Moving to another server is applying again** with the new domain; links
  pointed at the previous server move without a restore first.
- **The server's own name is never built in.** No default domain in the code or
  the exe - the field starts empty and remembers what was typed.
- **Everything changed is backed up first**, and "Restore original" puts back
  exactly the files as they were, byte for byte.
- **Binaries are recognised by checksum** before a byte is written; another
  build of the client is refused rather than patched at the wrong offsets.
