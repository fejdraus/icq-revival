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

The sign-in server is set in each client itself, not by these tools.
