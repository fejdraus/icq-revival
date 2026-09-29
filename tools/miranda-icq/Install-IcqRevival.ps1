# Installs the ICQ Revival plugins (IcqOscarJ, IcqRevivalFlash and the Flash
# engine) into a Miranda folder, backing up everything it replaces or removes,
# merges the plugins' translations into Miranda's main language packs, and
# patches the MirandaFinal IEView skin if it is there (PluginUpdater does not
# look at Skins\; see ieview-mirandafinal\README.md). The logger setting is not
# touched. Miranda must be closed. Idempotent: a second run changes nothing
# and makes no backup. Undo: see MANIFEST.txt in the backup folder.
#
#   Install-IcqRevival.ps1 -Miranda <Miranda folder>
#
# The Flash plugin was FlashAvatars.dll up to 1.0; that name is taken
# (Miranda NG's update list deletes "flashavatars.dll"), so the old file is
# removed here.
#
# Translations: translations\langpack_<language>_<plugin>.txt, one #muuid
# section each. For every language that has such files and whose main pack
# Languages\langpack_<language>.txt is installed, the sections are put at the
# end of that pack between two marker lines, as our update server does it
# (deploy/oscar-legacy-web/miranda-updates.js, mergeTranslations); a later run
# replaces them. The separate files of before (Languages\langpack_*_<plugin>.txt)
# and the #include lines of the main packs that named them are removed. No
# language is named here: a new one is a new file in translations\.
param([Parameter(Mandatory)] [string]$Miranda)
$ErrorActionPreference = 'Stop'
if (Get-Process Miranda32, Miranda64 -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Miranda*" }) { throw 'Close Miranda first' }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here '..\..')).Path
$bits = if (Test-Path (Join-Path $Miranda 'Miranda64.exe')) { 'x64' } else { 'x32' }
$triple = if ($bits -eq 'x64') { 'x86_64-pc-windows-msvc' } else { 'i686-pc-windows-msvc' }
$files = [ordered]@{
  'Plugins\IcqOscarJ.dll'       = "$repo\tools\miranda-icq\build\$bits\IcqOscarJ.dll"
  'Plugins\IcqRevivalFlash.dll' = "$repo\tools\miranda-icq\build\$bits\IcqRevivalFlash.dll"
  'Libs\FlashPlayerControl.dll' = "$repo\tools\icq65\flashplayer\target\$triple\release\FlashPlayerControl.dll"
}
$remove = @('Plugins\FlashAvatars.dll')

# Our translations by language: langpack_<language>_<plugin>.txt, the plugin
# part without "_" (the server reads the names the same way).
$namePattern = '^langpack_(.+)_([^_.]+)\.txt$'
$translations = @(Get-ChildItem -LiteralPath (Join-Path $here 'translations') -File |
  Where-Object { $_.Name -match $namePattern } | Sort-Object Name)
if (-not $translations.Count) { throw "no translations in $here\translations" }
# The separate files of before, one mask per plugin; flashavatars is the old
# name of the Flash plugin's translation.
$plugins = @('flashavatars') + @($translations | ForEach-Object { ($_.Name -replace $namePattern, '$2').ToLowerInvariant() }) |
  Sort-Object -Unique
$masks = @($plugins | ForEach-Object { "langpack_*_$_.txt" })
$mergeBegin = ';### ICQ Revival translations: begin'
$mergeEnd = ';### ICQ Revival translations: end'

$backup = Join-Path $Miranda ('_revival-backup\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$manifest = [System.Collections.Generic.List[string]]::new()
function Save-Backup([string]$rel) {
  $src = Join-Path $Miranda $rel
  $bak = Join-Path $backup $rel
  New-Item -ItemType Directory -Force (Split-Path $bak) | Out-Null
  Copy-Item -LiteralPath $src $bak
}
function Get-Md5([string]$path) { (Get-FileHash -LiteralPath $path -Algorithm MD5).Hash }
function Test-Mask([string]$name) { foreach ($m in $masks) { if ($name -like $m) { return $true } }; $false }

foreach ($rel in $files.Keys) {
  $src = $files[$rel]
  if (-not (Test-Path -LiteralPath $src)) { throw "missing build: $src" }
  $dst = Join-Path $Miranda $rel
  if (Test-Path -LiteralPath $dst) {
    if ((Get-Md5 $dst) -eq (Get-Md5 $src)) { continue }
    Save-Backup $rel
    $manifest.Add("REPLACED $rel (md5 $(Get-Md5 $dst)) -> undo: copy $rel from this folder back")
  } else {
    $manifest.Add("ADDED    $rel -> undo: delete it")
  }
  New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
  Copy-Item -LiteralPath $src $dst -Force
}

$languages = Join-Path $Miranda 'Languages'
if (Test-Path -LiteralPath $languages) {
  foreach ($f in Get-ChildItem -LiteralPath $languages -File | Where-Object { Test-Mask $_.Name }) {
    $remove += "Languages\$($f.Name)"
  }
}
foreach ($rel in $remove) {
  $dst = Join-Path $Miranda $rel
  if (-not (Test-Path -LiteralPath $dst)) { continue }
  Save-Backup $rel
  Remove-Item -LiteralPath $dst -Force -Confirm:$false
  $manifest.Add("REMOVED  $rel (old file) -> undo: copy $rel from this folder back")
}

# One translation file as lines of a section: its own header (the version
# line, Language:, Locale:) and trailing empty lines left out; the core reads
# a header only at the top of the main pack.
function Get-SectionLines([string]$path) {
  $lines = [IO.File]::ReadAllText($path, [Text.UTF8Encoding]::new($false)).TrimStart([char]0xFEFF) -split "`r?`n"
  $i = 0
  while ($i -lt $lines.Count -and $lines[$i] -notmatch '^[;#\[]') { $i++ }
  $out = [System.Collections.Generic.List[string]]($lines | Select-Object -Skip $i)
  while ($out.Count -and $out[$out.Count - 1].Trim() -eq '') { $out.RemoveAt($out.Count - 1) }
  $out
}

# Merge into every installed main pack of a language we have. The pack is
# edited as UTF-8, keeping its BOM (or its lack of one) and line endings.
foreach ($group in $translations | Group-Object { ($_.Name -replace $namePattern, '$1').ToLowerInvariant() }) {
  $packRel = "Languages\langpack_$($group.Name).txt"
  $pack = Join-Path $Miranda $packRel
  if (-not (Test-Path -LiteralPath $pack)) { continue }
  $bytes = [IO.File]::ReadAllBytes($pack)
  $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
  $skip = if ($bom) { 3 } else { 0 }
  $text = [Text.UTF8Encoding]::new($false).GetString($bytes, $skip, $bytes.Length - $skip)
  $eol = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
  $kept = [System.Collections.Generic.List[string]]::new()
  $inside = $false
  $includes = 0
  foreach ($line in $text -split "`r?`n") {
    $t = $line.Trim()
    if ($inside) { if ($t -eq $mergeEnd) { $inside = $false }; continue }
    if ($t -eq $mergeBegin) { $inside = $true; continue }
    if ($t -match '^#include\s+(.+)$' -and (Test-Mask $Matches[1].Trim())) { $includes++; continue }
    $kept.Add($line)
  }
  while ($kept.Count -and $kept[$kept.Count - 1].Trim() -eq '') { $kept.RemoveAt($kept.Count - 1) }
  $kept.Add('')
  $kept.Add($mergeBegin)
  $first = $true
  foreach ($f in $group.Group) {
    if (-not $first) { $kept.Add('') }
    $first = $false
    foreach ($l in @(Get-SectionLines $f.FullName)) { $kept.Add($l) }
  }
  $kept.Add($mergeEnd)
  $new = ($kept -join $eol) + $eol
  if ($new -ceq $text) { continue }
  Save-Backup $packRel
  $out = [Text.UTF8Encoding]::new($bom).GetPreamble() + [Text.UTF8Encoding]::new($false).GetBytes($new)
  [IO.File]::WriteAllBytes($pack, $out)
  $names = ($group.Group | ForEach-Object { $_.Name }) -join ', '
  $manifest.Add("CHANGED  $packRel (merged $names; $includes old #include lines removed) -> undo: copy it from this folder back")
}

# The MirandaFinal IEView skin: message text out of JavaScript, tZer pictures.
# Skipped cleanly when the skin is not installed.
$skinLines = & (Join-Path $here 'ieview-mirandafinal\Patch-MirandaFinal.ps1') -Miranda $Miranda -Backup $backup
$skinSkipped = @($skinLines | Where-Object { $_ -like 'SKIPPED*' })
foreach ($l in $skinLines) { if ($l -notlike 'SKIPPED*') { $manifest.Add($l) } }
$skinSkipped | ForEach-Object { Write-Output $_ }

if ($manifest.Count -eq 0) {
  Write-Output "Nothing to do: $Miranda already has these builds."
  return
}
$manifest.Insert(0, '')
$manifest.Insert(0, "ICQ Revival install ($bits) $(Get-Date -Format s). Close Miranda before undoing.")
$manifest.Add('Profile settings written by Miranda itself: netlib user and module IcqRevivalFlash (moved once from FlashAvatars); contact settings FlashAvatarHash/FlashAvatarUrl in the ICQ module; AvatarCache\Flash\ with downloaded movies.')
New-Item -ItemType Directory -Force $backup | Out-Null
$manifest | Set-Content (Join-Path $backup 'MANIFEST.txt') -Encoding UTF8
Get-Content (Join-Path $backup 'MANIFEST.txt')
