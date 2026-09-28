# Patch for the IEView skin "MirandaFinal"

The `Skins\IEView\MirandaFinal` skin comes with the MirandaFinal build; who made it
and under what license is unknown. So this directory holds not the skin but only a
patch for it, which `..\Install-IcqRevival.ps1` applies in place after saving the
previous files into `_revival-backup\<time>\`. `PluginUpdater` does not look into
`Skins\`, so only the installer delivers it.

| File | What it is |
|------|---------|
| `Patch-MirandaFinal.ps1` | edits `MirandaFinal.ivt`, puts in the script and the pictures; standalone: `-Miranda <folder> -Backup <folder>` |
| `revival-tzers.js` | the tZer picture next to the "tZer: <name>" message |
| `tzers\*.png` | 12 ICQ 6.5 tZer pictures (the same as `deploy/oscar-legacy-web/tzers/`), placed into the skin's `images\tzers\` |

## What was dangerous

IEView substitutes `%text%` already escaped for HTML (`& < > "`, line breaks →
`<br>`), but **not for JavaScript**. The skin, however, passed the text of every
message straight into code, in twelve places in the template:

```
<script>getitall('%\text%','%\name%','%\uin%','%\base%',meldungsart[0]);</script><script>mailru('%\text%');</script>
```

- The contact's text became a string literal inside `<script>`. The `%\text%` form
  escapes only `\ ' " \n \r \t \b \f`; it does not touch U+2028/U+2029, which old
  JavaScript engines treat as a line end, and the protection rests entirely on
  IEView having missed nothing.
- Then `getitall()` and its helpers from `!tools\skripte\` (tzerausgabe, convert,
  videos, parser) parsed this text and **built markup from it as strings**:
  addresses, attributes, handlers, and the insertion of Flash objects (ActiveX) from
  links in the message. `mailru()` likewise inserted a Flash object when it found
  `id=flash_NN` in the text.
- The IEView page is `about:blank` in the "My Computer" zone: scripts and ActiveX
  are allowed there. Any mistake in this chain means running code from a message
  with Miranda's privileges.

In our tests (quotes, `\`, `</script>`, `<img onerror>`, line breaks, U+2028/2029,
`javascript:`, the same in a nickname) the original skin executed nothing, but only
because the escaping happened to line up; the attack surface was there.

## What the patch changes

In each of the 12 message bodies:

```
<span class="rt-text">%text%</span><script>revivalTzers()</script>
```

and in the header `<script src="mailru.js"></script>` → `<script src="revival-tzers.js"></script>`,
plus one CSS rule for the picture.

- The text stays HTML that IEView has already made safe, and nothing else parses it.
  Links and smileys work as before; IEView itself builds them.
- `revivalTzers()` is called **without arguments**: it reads the `innerText` of new
  `span.rt-text` elements and, if the text is exactly "tZer: <name>" and the name is
  in the table (12 English ones, as ICQ 6.5 sends them, and the Russian ones from its
  ru-RU `TzerLabels.dtd`), adds `<img src="images/tzers/<id>.png">`. The picture
  address comes from the table, nothing from the message. No network access.
- An unknown name stays plain text.
- The look is unchanged: the same headers, times and colours.

The files `!tools\skripte\*`, `config.js`, `mailru.js` are not touched: after the
patch nothing calls their text-parsing functions.

## Installation and rollback

`Install-IcqRevival.ps1 -Miranda <folder>` with Miranda closed. Running it again
changes nothing. If there is no skin, or the template is not the one the patch knows,
it prints a `SKIPPED` line and changes nothing. It does not touch the log setting
(IEView or another). Rollback follows `MANIFEST.txt` in the backup folder: restore
`MirandaFinal.ivt`, delete `revival-tzers.js` and `images\tzers\`.
