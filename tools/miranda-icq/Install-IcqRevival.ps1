# Installs the ICQ Revival plugins (IcqOscarJ, IcqRevivalFlash and the Flash
# engine) into a Miranda folder, backing up everything it replaces or removes,
# and patches the MirandaFinal IEView skin if it is there (PluginUpdater does
# not look at Skins\; see ieview-mirandafinal\README.md). The logger setting
# is not touched. Miranda must be closed. Idempotent: a second run changes
# nothing and makes no backup. Undo: see MANIFEST.txt in the backup folder.
#
#   Install-IcqRevival.ps1 -Miranda <Miranda folder>
#
# The Flash plugin was FlashAvatars.dll up to 1.0; that name is taken
# (Miranda NG's update list deletes "flashavatars.dll"), so the old file and
# its translation are removed here and the #include line is switched over.
param([Parameter(Mandatory)] [string]$Miranda)
$ErrorActionPreference = 'Stop'
if (Get-Process Miranda32, Miranda64 -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Miranda*" }) { throw 'Close Miranda first' }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here '..\..')).Path
$bits = if (Test-Path (Join-Path $Miranda 'Miranda64.exe')) { 'x64' } else { 'x32' }
$triple = if ($bits -eq 'x64') { 'x86_64-pc-windows-msvc' } else { 'i686-pc-windows-msvc' }
$files = [ordered]@{
  'Plugins\IcqOscarJ.dll'                         = "$repo\tools\miranda-icq\build\$bits\IcqOscarJ.dll"
  'Plugins\IcqRevivalFlash.dll'                   = "$repo\tools\miranda-icq\build\$bits\IcqRevivalFlash.dll"
  'Libs\FlashPlayerControl.dll'                   = "$repo\tools\icq65\flashplayer\target\$triple\release\FlashPlayerControl.dll"
  'Languages\langpack_russian_icqrevivalflash.txt' = "$repo\tools\miranda-icq\langpack_russian_icqrevivalflash.txt"
  'Languages\langpack_russian_icq.txt'            = "$repo\tools\miranda-icq\langpack_russian_icq.txt"
  'Languages\langpack_ukrainian_icqrevivalflash.txt' = "$repo\tools\miranda-icq\langpack_ukrainian_icqrevivalflash.txt"
  'Languages\langpack_ukrainian_icq.txt'          = "$repo\tools\miranda-icq\langpack_ukrainian_icq.txt"
}
$remove = @('Plugins\FlashAvatars.dll', 'Languages\langpack_russian_flashavatars.txt')
# Per main pack: the #include lines our translations need, and the old ones to
# take out. There was no Ukrainian translation under the old name.
$includes = [ordered]@{
  'Languages\langpack_russian.txt' = @{
    Add  = @('#include langpack_russian_icq.txt', '#include langpack_russian_icqrevivalflash.txt')
    Drop = @('#include langpack_russian_flashavatars.txt')
  }
  'Languages\langpack_ukrainian.txt' = @{
    Add  = @('#include langpack_ukrainian_icq.txt', '#include langpack_ukrainian_icqrevivalflash.txt')
    Drop = @()
  }
}

$backup = Join-Path $Miranda ('_revival-backup\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$manifest = [System.Collections.Generic.List[string]]::new()
function Save-Backup([string]$rel) {
  $src = Join-Path $Miranda $rel
  $bak = Join-Path $backup $rel
  New-Item -ItemType Directory -Force (Split-Path $bak) | Out-Null
  Copy-Item -LiteralPath $src $bak
}
function Get-Md5([string]$path) { (Get-FileHash -LiteralPath $path -Algorithm MD5).Hash }

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

foreach ($rel in $remove) {
  $dst = Join-Path $Miranda $rel
  if (-not (Test-Path -LiteralPath $dst)) { continue }
  Save-Backup $rel
  Remove-Item -LiteralPath $dst -Force -Confirm:$false
  $manifest.Add("REMOVED  $rel (old name) -> undo: copy $rel from this folder back")
}

# The Russian and Ukrainian strings of the plugins: included at the end of the
# main pack of that language, if it is installed. The file is edited as UTF-8,
# keeping its BOM (or its lack of one) and CRLF.
foreach ($packRel in $includes.Keys) {
  $includeAdd = $includes[$packRel].Add
  $includeDrop = $includes[$packRel].Drop
  $pack = Join-Path $Miranda $packRel
  if (-not (Test-Path -LiteralPath $pack)) { continue }
  $bytes = [IO.File]::ReadAllBytes($pack)
  $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
  $text = [Text.UTF8Encoding]::new($false).GetString($bytes, $(if ($bom) { 3 } else { 0 }), $bytes.Length - $(if ($bom) { 3 } else { 0 }))
  $eol = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
  $lines = [System.Collections.Generic.List[string]]($text -split "`r?`n")
  $dropSet = $includeDrop | ForEach-Object { $_.ToLowerInvariant() }
  $kept = [System.Collections.Generic.List[string]]($lines | Where-Object { $dropSet -notcontains $_.Trim().ToLowerInvariant() })
  $have = $kept | ForEach-Object { $_.Trim().ToLowerInvariant() }
  $missing = @($includeAdd | Where-Object { $have -notcontains $_.ToLowerInvariant() })
  $dropped = $lines.Count - $kept.Count
  if ($dropped -or $missing.Count) {
    # drop the empty tail, add what is missing, end with a line break
    while ($kept.Count -and $kept[$kept.Count - 1] -eq '') { $kept.RemoveAt($kept.Count - 1) }
    foreach ($l in $missing) { $kept.Add($l) }
    $new = ($kept -join $eol) + $eol
    Save-Backup $packRel
    $out = [Text.UTF8Encoding]::new($bom).GetPreamble() + [Text.UTF8Encoding]::new($false).GetBytes($new)
    [IO.File]::WriteAllBytes($pack, $out)
    $manifest.Add("CHANGED  $packRel (includes: $dropped old removed, $($missing.Count) added) -> undo: copy it from this folder back")
  }
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
