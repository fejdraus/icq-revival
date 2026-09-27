# Patches the MirandaFinal IEView skin (Skins\IEView\MirandaFinal of a
# Miranda folder) in place:
#
#   - message text no longer goes into JavaScript: the template's
#     <script>getitall('%\text%',...)</script><script>mailru('%\text%');</script>
#     becomes <span class="rt-text">%text%</span>, i.e. the text as IEView has
#     already made it safe HTML, and nothing re-parses it;
#   - mailru.js (mail.ru Flash stickers) is no longer loaded; revival-tzers.js
#     is, and after each message revivalTzers() (no arguments) adds the tZer
#     thumbnail from images\tzers\ when the text is exactly "tZer: <name>".
#
# Backs up every file it changes into -Backup first. Idempotent: an already
# patched skin is left alone. Without the skin it does nothing.
#
#   Patch-MirandaFinal.ps1 -Miranda <folder> -Backup <folder>
#   returns the list of lines for the manifest
param(
	[Parameter(Mandatory)] [string]$Miranda,
	[Parameter(Mandatory)] [string]$Backup
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$skin = Join-Path $Miranda 'Skins\IEView\MirandaFinal'
$ivt = Join-Path $skin 'MirandaFinal.ivt'
$out = [System.Collections.Generic.List[string]]::new()
if (-not (Test-Path -LiteralPath $ivt)) {
	$out.Add('SKIPPED  Skins\IEView\MirandaFinal: not installed')
	return $out
}

# The skin's files are cp1251/ASCII: handled byte for byte as Latin-1.
$latin1 = [Text.Encoding]::GetEncoding(28591)
$text = [IO.File]::ReadAllText($ivt, $latin1)

$oldBody = "<script>getitall('%\text%','%\name%','%\uin%','%\base%',meldungsart[0]);</script><script>mailru('%\text%');</script>"
$newBody = '<span class="rt-text">%text%</span><script>revivalTzers()</script>'
$oldHead = '<script src="mailru.js"></script>'
$newHead = '<script src="revival-tzers.js"></script>' + "`r`n`t" +
	'<style type="text/css">.revival-tzer { vertical-align: middle; margin-left: 6px; width: 60px; height: 46px; }</style>'

function Save-Backup([string]$rel) {
	$src = Join-Path $skin $rel
	$dst = Join-Path $Backup ('Skins\IEView\MirandaFinal\' + $rel)
	New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
	Copy-Item -LiteralPath $src $dst
}

$patched = $text.Contains('revival-tzers.js') -and -not $text.Contains('getitall(')
if (-not $patched) {
	if (-not $text.Contains($oldBody) -and -not $text.Contains($oldHead)) {
		$out.Add('SKIPPED  Skins\IEView\MirandaFinal\MirandaFinal.ivt: not the template this patch knows')
		return $out
	}
	$count = ([regex]::Matches($text, [regex]::Escape($oldBody))).Count
	Save-Backup 'MirandaFinal.ivt'
	$text = $text.Replace($oldBody, $newBody).Replace($oldHead, $newHead)
	[IO.File]::WriteAllText($ivt, $text, $latin1)
	$out.Add("CHANGED  Skins\IEView\MirandaFinal\MirandaFinal.ivt ($count message bodies: text as HTML, no script; mailru.js -> revival-tzers.js) -> undo: copy it from this folder back")
}

# the script and the pictures: added or replaced when they differ
$files = @(@{ Src = Join-Path $here 'revival-tzers.js'; Rel = 'revival-tzers.js' })
Get-ChildItem (Join-Path $here 'tzers') -Filter *.png | ForEach-Object {
	$files += @{ Src = $_.FullName; Rel = 'images\tzers\' + $_.Name }
}
foreach ($f in $files) {
	$dst = Join-Path $skin $f.Rel
	if (Test-Path -LiteralPath $dst) {
		if ((Get-FileHash -LiteralPath $dst -Algorithm MD5).Hash -eq (Get-FileHash -LiteralPath $f.Src -Algorithm MD5).Hash) { continue }
		Save-Backup $f.Rel
		$out.Add("REPLACED Skins\IEView\MirandaFinal\$($f.Rel) -> undo: copy it from this folder back")
	}
	else {
		$out.Add("ADDED    Skins\IEView\MirandaFinal\$($f.Rel) -> undo: delete it")
	}
	New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
	Copy-Item -LiteralPath $f.Src $dst -Force
}
return $out
