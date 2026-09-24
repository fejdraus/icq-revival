# Patch for ICQ 6.5 (build 2024) - a windowed tool, the same kind as the one
# for ICQ Pro 2003b in ../../icq2003b/patch.
#
# One pass does everything the client needs to live on a private server:
#
#   1. Interface. The frames left behind by services that are gone - the Xtraz
#      strip and panel, the advertising, tZers, SMS and phone buttons - are
#      taken out of the client's own markup (services\icqApp\ver1, Boxely .box
#      files, plain XML), and the "SMS & Phone" entry of the preferences list,
#      which is built in code, out of MUICore.dll.
#   2. Links. The pages the client opens on ICQ.com - help, the legal notice,
#      e-mail confirmation, the Xtraz list - are pointed at our server, which is
#      also added to the client's content whitelists.
#   3. Advertising and teasers. Their local descriptors are emptied, which is
#      what makes the client stop drawing them at all.
#
# The sign-in server is not this tool's business: the user sets it in ICQ
# itself, under Options -> Connection -> ICQ server.
#
# Every file is backed up next to itself before the first change, and
# "Restore original" puts them all back. The user's profile is never touched.
#
# The folder is found on its own: next to this tool first (dropped into the ICQ
# folder), then from the registry, then the standard path.
#
# Without arguments the window opens. For a scripted run:
#   Icq6Patch.ps1 -Apply   [-Root <folder>] [-Server <domain>]
#   Icq6Patch.ps1 -Restore [-Root <folder>]
#
# Built into an exe with ps12exe, under Windows PowerShell 5.1:
#   ps12exe .\Icq6Patch.ps1 .\Icq6Patch.exe -App @{Windowed=$true} -Os @{Admin=$true}
#     -Build @{Target='Framework4.0'; Apartment='STA'}
#     -Resources @{Title='ICQ 6.5 Patch'; Product='ICQ Revival'}

param(
    [switch]$Apply,
    [switch]$Restore,
    [string]$Root,
    [string]$Server
)

$Headless = $Apply -or $Restore

$Suffix = '.icq6patch-backup'
# Suffixes left by the Python tools this patch replaces. Restore puts those
# back too, so a client patched the old way can be returned to the original.
$OlderSuffixes = @('.icq6-declutter-backup', '.icq6-retarget-backup')

# Only the server's domain is asked for. Ports and paths are the same on every
# ICQ Revival server (deploy/VM-SPEC.md, section 3), so the patch fills them in
# itself; nobody has to know which port serves what.
$PagesPortHttp = 8101   # the pages ICQ 6.5 opens, plain HTTP
$SettingsKey = 'HKCU:\Software\OpenOSCAR\Icq6Patch'

$Content = 'services\icqApp\ver1\content'
$Theme = 'services\icqApp\ver1\theme'

# --- code patches -------------------------------------------------------------
#
# The preferences list is built in code: each group is described in .data by a
# pointer to its records and a count, and the records - name, label key, icon,
# panel loader, 16 bytes each - are filled in by a run of mov instructions. The
# "Advanced" group holds Connection, SMS, Advanced. The SMS record is
# overwritten with the one after it and the count drops to two, which leaves
# Connection and Advanced. Blanking the record instead only leaves an empty row,
# and zeroing a loader takes the whole dialog down.

$CodePatches = @(
    [pscustomobject]@{
        File = 'MUICore.dll'
        Size = 3359744
        Sha256From = 'EA095362283BD56BEB5015DF0C56CA8EE1687A5A254775EDDA05203A33CC9F86'
        Sha256To   = 'C2AA9B7578690BA53F2A6B60540D25276AF61B454AF8F80F868411264C2BEDB0'
        What = 'the "SMS & Phone" entry of the preferences list'
        Edits = @(
            @{ Offset = 0x258CE4; From = [byte[]](0x40,0xC9,0xA6,0x33); To = [byte[]](0x28,0xFD,0xA7,0x33) }  # name
            @{ Offset = 0x258CEE; From = [byte[]](0xC4,0xF1,0xA7,0x33); To = [byte[]](0x38,0xF1,0xA7,0x33) }  # label key
            @{ Offset = 0x258CF8; From = [byte[]](0x3C,0xFD,0xA7,0x33); To = [byte[]](0x10,0xFD,0xA7,0x33) }  # icon
            @{ Offset = 0x258D02; From = [byte[]](0xF0,0x5C,0x92,0x33); To = [byte[]](0x70,0x5E,0x92,0x33) }  # loader
            @{ Offset = 0x2F0190; From = [byte[]](0x03,0x00,0x00,0x00); To = [byte[]](0x02,0x00,0x00,0x00) }  # count
        )
    }
)

# --- interface ---------------------------------------------------------------
#
# Kinds of change:
#   collapse  mark the element with this id collapsed="true" - how the client
#             hides its own optional parts;
#   dropline  remove the line holding this fragment;
#   replace   swap one exact piece of text for another.
#
# Some things may not be removed although they look removable: the ad element
# of the message window is looked up by the code, and without it the emoticon
# and formatting panels stop opening, so it is given no size instead; the empty
# band at the foot of that window holds the same panels, and the buttons above
# it sit on a spacer that keeps them out of its way.

function Edit-Collapse($file, $id, $what) {
    [pscustomobject]@{ File = $file; Kind = 'collapse'; Key = $id; New = $null; What = $what }
}
function Edit-DropLine($file, $fragment, $what) {
    [pscustomobject]@{ File = $file; Kind = 'dropline'; Key = $fragment; New = $null; What = $what }
}
function Edit-Replace($file, $from, $to, $what) {
    [pscustomobject]@{ File = $file; Kind = 'replace'; Key = $from; New = $to; What = $what }
}

$MarkupEdits = @(
    Edit-Collapse "$Content\MUICore\MainDlgPanelOwner.box" 'idXtrazBarArea' 'the Xtraz strip above the contact list'
    Edit-Collapse "$Content\MUICore\MainDlgPanelOwner.box" 'idMainEntertainmentBox' 'the Xtraz panel below the contact list'
    Edit-Collapse "$Content\MUIMessage\MsgSessionPanel.box" 'idBottomBannerContainer' 'the banner under the message window'
    Edit-Collapse "$Content\MUIMessage\MsgSessionPanel.box" 'idbtnTzers' 'the tZers button of the message window'
    Edit-Collapse "$Content\MUIMessage\CommToolbar.box" 'btnSMS' 'the SMS button of the message window'
    Edit-Collapse "$Content\MUIMessage\CommToolbar.box" 'btnPhone' 'the phone button of the message window'
    Edit-Collapse "$Content\MUICore\Preferences\OPrefsPanelNotifications.box" 'idXtrazInvitation' 'the "Xtraz invitations" option'
    Edit-Collapse "$Content\MUICore\Preferences\OPrefsPanelMessage.box" 'idAutoPlayTzers' 'the "play tZers automatically" option'
    Edit-Collapse "$Content\MUICore\ContactList\DataBoundCL.box" 'sms' 'the SMS icon on a contact row'
    Edit-Collapse "$Content\MUICore\ContactList\DataBoundCL.box" 'phone' 'the phone icon on a contact row'
    Edit-Collapse "$Content\MUICore\ContactList\MiniUserProfileDlg.gadgets.box" 'miniUserDetails.autoSmsContainer' 'the auto-SMS line of the contact card'
    Edit-Collapse "$Content\MUICore\PopupMenus.box" 'idCommSendSMS' 'the "Send SMS" item of the contact menu'
    Edit-Collapse "$Content\MUICore\PopupMenus.box" 'idXtrazMenu' 'the Xtraz submenu of the contact menu'
    Edit-Collapse "$Content\MUICore\Preferences\OPrefsPanelGeneral.box" 'idAutoSmsGroup' 'the auto-SMS section of the options'
    Edit-Collapse "$Content\MUICore\Preferences\OPrefsPanelHistory.box" 'idSaveXtrazInvitations' 'the "save Xtraz invitations" option'
    Edit-Collapse "$Content\MUICore\Preferences\OPrefsPanelSkin.box" 'IncomingSMS' 'the incoming-SMS sound'
    Edit-Collapse "$Content\MUICore\Preferences\OPrefsPanelSkin.box" 'OutgoingSMS' 'the outgoing-SMS sound'
    Edit-Collapse "$Content\MUICore\Preferences\OPrefsPanelSkin.box" 'IncomingTzer' 'the incoming-tZer sound'
    Edit-Collapse "$Content\MUICore\Preferences\OPrefsPanelSkin.box" 'IncomingXtra' 'the incoming-Xtraz sound'
    Edit-Collapse "$Content\MUICore\HistorySearchDlg.box" 'idMsgTypeSMS' 'the SMS filter of the history search'
    Edit-Collapse "$Content\MUICore\HistorySearchDlg.box" 'idMsgTypeXtrazInvitation' 'the Xtraz filter of the history search'
    Edit-DropLine "$Content\MUICore\MainDlg.box" 'cmdMyXtraz' 'the "My Xtraz" item of the main menu'
    Edit-Replace "$Theme\MUIMessage\MsgSessionDlg.style.box" `
        '<style id="bannerStyle" width="468" height="60"' `
        '<style id="bannerStyle" width="0" height="0"' `
        'the ad box of the message window'
    Edit-Replace "$Theme\MUIMessage\MsgSessionDlg.style.box" `
        '<part name="idBottomBannerContainer" flex="1" hAlign="center" fill="url(#image.MessageDlgXtra.window.background)"' `
        '<part name="idBottomBannerContainer" flex="1" hAlign="center"' `
        'the white frame at the foot of the message window'
    Edit-Replace "$Theme\MUICore\MainDlgPanelOwner.style.box" `
        '<style id="adBoxStyle" width="120" height="90" />' `
        '<style id="adBoxStyle" width="0" height="0" />' `
        'the ad box of the contact list'
    # The tab list of the "Advanced" group was 98 high inside a box of 90, and
    # the overflow covered the rounded bottom of the box. Predates the SMS entry.
    Edit-Replace "$Theme\MUICore\Preferences\OwnerPrefsDlg.style.box" `
        '<style id="advancedTabStyle" height="98"' `
        '<style id="advancedTabStyle" height="56"' `
        'the cut-off bottom of the "Advanced" group'
)

# Taken out of the way whole, renamed with the backup suffix.
$Removals = @(
    [pscustomobject]@{ Path = "$Content\MUICore\Preferences\OPrefsPanelSMS.box"; What = 'the page of the "SMS & Phone" preferences' }
    # Loaded from disk rather than from the Xtraz list, so its buttons in the
    # message window survive whatever the server answers.
    [pscustomobject]@{ Path = 'packages\zlango'; What = 'the Zlango add-on and its message window buttons' }
)

# --- links, whitelists, advertising -------------------------------------------
#
# Only the addresses the client opens as a page are moved. The ones it parses
# itself - package lists, search providers, ad configuration - must keep timing
# out on the dead hosts: any quick reply, even a 404, makes the client treat the
# list as empty and drop part of its interface.

$DeadHosts = @(
    'xtraz.icq.com', 'openxtraz.icq.com', 'icq.openxtraz.com', 'labs.icq.com',
    'update.icq.com', 'www.icq.com', 'cb.icq.com', 'df.icq.com', 'c.icq.com'
)
$PagePaths = @(
    '/xtraz/srv/', '/compad/', '/legal', '/sms', '/ibs/icq6/', '/download/icq6/',
    '/register/email_activation/', '/xtraz2/global/'
)
# Any host in front of those paths, not only the dead ICQ.com ones: the paths
# belong to ICQ.com services and nothing else, so a match is either still
# ICQ.com or a server this patch pointed them at before. Moving to another
# server is then just applying again with the new domain.
$LinkPattern = 'https?://[A-Za-z0-9.-]+(?::\d+)?' +
               '(?=(?:' + (($PagePaths | ForEach-Object { [regex]::Escape($_) }) -join '|') + '))'

# What the links are pointed at, for a given domain.
function Get-PagesBase([string]$domain) { return "http://${domain}:$PagesPortHttp" }

# The client draws the ad slots and the teaser strip only while these list
# something, and without SMS carriers it has nowhere to send a text.
$Strips = @(
    [pscustomobject]@{ File = 'ConfigFiles\adConfig.xml'; Pattern = '[ \t]*<spot\b[^>]*/>[ \t]*\r?\n?'; What = 'advertising slots' }
    [pscustomobject]@{ File = 'ConfigFiles\tzer.xml'; Pattern = '[ \t]*<tz\b[^>]*/>[ \t]*\r?\n?'; What = 'the teaser strip' }
    [pscustomobject]@{ File = 'ConfigFiles\SMSConfig.xml'; Pattern = '[ \t]*<i n="operator"[^>]*/>[ \t]*\r?\n?'; What = 'SMS carriers' }
)

# --- text files ---------------------------------------------------------------
#
# Read and written as bytes so nothing changes but the edit itself: the line
# endings stay, and a byte order mark stays where there was one. The markup is
# UTF-8; a few configuration files are Windows-1251.

$Utf8Strict = New-Object Text.UTF8Encoding($false, $true)
$Cp1251 = [Text.Encoding]::GetEncoding(1251)

function Read-Text([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $start = if ($bom) { 3 } else { 0 }
    try {
        $text = $Utf8Strict.GetString($bytes, $start, $bytes.Length - $start)
        return @{ Text = $text; Encoding = 'utf8'; Bom = $bom }
    } catch {
        return @{ Text = $Cp1251.GetString($bytes); Encoding = 'cp1251'; Bom = $false }
    }
}

function Write-Text([string]$path, $file) {
    $body = if ($file.Encoding -eq 'utf8') { $Utf8Strict.GetBytes($file.Text) } else { $Cp1251.GetBytes($file.Text) }
    if ($file.Bom) { $body = [byte[]](0xEF, 0xBB, 0xBF) + $body }
    [IO.File]::WriteAllBytes($path, $body)
}

function Backup-Once([string]$path) {
    $backup = $path + $Suffix
    if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $path -Destination $backup }
}

# --- the edits themselves -----------------------------------------------------

function Find-Tag([string]$text, [string]$id) {
    return [regex]::Match($text, '<[A-Za-z][^<>]*\bid="' + [regex]::Escape($id) + '"[^<>]*>')
}

# Returns the changed text, or $null when there is nothing to change.
function Invoke-Edit($edit, [string]$text) {
    switch ($edit.Kind) {
        'collapse' {
            $tag = Find-Tag $text $edit.Key
            if (-not $tag.Success) { return $null }
            $old = $tag.Value
            if ($old -match '\bcollapsed="true"') { return $null }
            $new = [regex]::Replace($old, '\bcollapsed="[^"]*"', '')
            $new = $new.TrimEnd('>').TrimEnd('/').TrimEnd()
            $new += ' collapsed="true"' + $(if ($old.TrimEnd().EndsWith('/>')) { '/>' } else { '>' })
            return $text.Substring(0, $tag.Index) + $new + $text.Substring($tag.Index + $tag.Length)
        }
        'dropline' {
            $lines = $text -split "`n"
            $keep = @($lines | Where-Object { -not $_.Contains($edit.Key) })
            if ($keep.Count -eq $lines.Count) { return $null }
            return ($keep -join "`n")
        }
        'replace' {
            $at = $text.IndexOf($edit.Key, [StringComparison]::Ordinal)
            if ($at -lt 0) { return $null }
            return $text.Substring(0, $at) + $edit.New + $text.Substring($at + $edit.Key.Length)
        }
    }
    return $null
}

function Get-EditState($edit) {
    $path = Join-Path $script:IcqRoot $edit.File
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    $text = (Read-Text $path).Text
    switch ($edit.Kind) {
        'collapse' {
            $tag = Find-Tag $text $edit.Key
            if (-not $tag.Success) { return 'unknown' }
            if ($tag.Value -match '\bcollapsed="true"') { return 'patched' } else { return 'original' }
        }
        'dropline' { if ($text.Contains($edit.Key)) { return 'original' } else { return 'patched' } }
        'replace' {
            # The original first: where the change only trims the end of a
            # line, the new text is a prefix of the old one and is found inside
            # the untouched file too.
            if ($text.Contains($edit.Key)) { return 'original' }
            if ($text.Contains($edit.New)) { return 'patched' }
            return 'unknown'
        }
    }
}

function Get-RemovalState($r) {
    $path = Join-Path $script:IcqRoot $r.Path
    $gone = -not (Test-Path -LiteralPath $path)
    $saved = Test-Path -LiteralPath ($path + $Suffix)
    foreach ($s in $OlderSuffixes) { if (Test-Path -LiteralPath ($path + $s)) { $saved = $true } }
    if ($gone -and $saved) { return 'patched' }
    if (-not $gone) { return 'original' }
    return 'missing'
}

# --- code patch state ---------------------------------------------------------

# .NET rather than Get-FileHash: the cmdlet is missing from old PowerShell.
function Get-Sha256([string]$path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try { $bytes = $sha.ComputeHash($fs) } finally { $fs.Close(); $sha.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '')
}

# The offsets are only right for this build, so the whole file is identified by
# its checksum before a byte is written.
function Get-CodeState($patch) {
    $path = Join-Path $script:IcqRoot $patch.File
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    $hash = Get-Sha256 $path
    if ($hash -eq $patch.Sha256To) { return 'patched' }
    if ($hash -eq $patch.Sha256From) { return 'original' }
    return 'other version'
}

# --- configuration state ------------------------------------------------------

# The domain out of whatever was typed: a scheme, a port or a path after it -
# habits from older versions of this patch - are dropped.
function Get-Domain([string]$value) {
    $v = "$value".Trim()
    $v = $v -replace '^[A-Za-z][A-Za-z0-9+.-]*://', ''
    $v = ($v -split '[/?#]')[0]
    $v = ($v -split ':')[0]
    return $v.ToLowerInvariant()
}

function Test-Domain([string]$value) {
    return $value -match '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
}

# Whether a host is already on a whitelist. The lists themselves are checked,
# not the whole file: by the time they are, the links in the same file already
# point at the host, and a plain search would find those instead.
function Test-Whitelisted([string]$name, [string]$text, [string]$h) {
    if ($name -eq 'XtraConfig.xml') {
        $m = [regex]::Match($text, 'Key="WhiteDomainList" Value="([^"]*)"')
        return $m.Success -and (@($m.Groups[1].Value -split '\s+') -contains $h)
    }
    $m = [regex]::Match($text, '(?s)<whitelist>(.*?)</whitelist>')
    return $m.Success -and $m.Groups[1].Value.Contains('<u>' + $h + '</u>')
}

function Get-LinkState([string]$domain) {
    $dir = Join-Path $script:IcqRoot 'ConfigFiles'
    if (-not (Test-Path -LiteralPath $dir)) { return @{ State = 'missing'; Info = '' } }
    $base = Get-PagesBase $domain
    $other = 0
    foreach ($f in Get-ChildItem -LiteralPath $dir -Filter *.xml -File) {
        foreach ($m in [regex]::Matches((Read-Text $f.FullName).Text, $LinkPattern, 'IgnoreCase')) {
            if ($m.Value -ne $base) { $other++ }
        }
    }
    $state = if ($other -gt 0) { 'original' } else { 'patched' }
    return @{ State = $state; Info = "$other not on your server" }
}

function Get-WhitelistState([string]$domain) {
    $h = $domain
    $missing = 0
    foreach ($name in 'XtraConfig.xml', 'tzer.xml') {
        $path = Join-Path $script:IcqRoot "ConfigFiles\$name"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if (-not (Test-Whitelisted $name (Read-Text $path).Text $h)) { $missing++ }
    }
    if ($missing -gt 0) { return 'original' } else { return 'patched' }
}

function Get-StripState($s) {
    $path = Join-Path $script:IcqRoot $s.File
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    if ([regex]::IsMatch((Read-Text $path).Text, $s.Pattern)) { return 'original' } else { return 'patched' }
}

# --- applying -----------------------------------------------------------------

function Invoke-ApplyAll([string]$domain) {
    $report = New-Object System.Collections.Generic.List[string]

    foreach ($p in $CodePatches) {
        $state = Get-CodeState $p
        if ($state -eq 'other version') { throw "$($p.File) is not the one from ICQ 6.5 build 2024; nothing was changed." }
    }

    foreach ($p in $CodePatches) {
        if ((Get-CodeState $p) -ne 'original') { continue }
        $path = Join-Path $script:IcqRoot $p.File
        Backup-Once $path
        $bytes = [IO.File]::ReadAllBytes($path)
        foreach ($e in $p.Edits) { [Array]::Copy($e.To, 0, $bytes, $e.Offset, $e.To.Length) }
        [IO.File]::WriteAllBytes($path, $bytes)
        $report.Add($p.What)
    }

    foreach ($group in ($MarkupEdits | Group-Object File)) {
        $path = Join-Path $script:IcqRoot $group.Name
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $file = Read-Text $path
        $changed = $false
        foreach ($edit in $group.Group) {
            $new = Invoke-Edit $edit $file.Text
            if ($null -eq $new) { continue }
            $file.Text = $new
            $changed = $true
            $report.Add($edit.What)
        }
        if ($changed) { Backup-Once $path; Write-Text $path $file }
    }

    foreach ($r in $Removals) {
        if ((Get-RemovalState $r) -ne 'original') { continue }
        $path = Join-Path $script:IcqRoot $r.Path
        Rename-Item -LiteralPath $path -NewName ((Split-Path $path -Leaf) + $Suffix)
        $report.Add($r.What)
    }

    $dir = Join-Path $script:IcqRoot 'ConfigFiles'
    $base = Get-PagesBase $domain
    $moved = 0
    foreach ($f in Get-ChildItem -LiteralPath $dir -Filter *.xml -File) {
        $file = Read-Text $f.FullName
        $count = @([regex]::Matches($file.Text, $LinkPattern, 'IgnoreCase') | Where-Object { $_.Value -ne $base }).Count
        if ($count -eq 0) { continue }
        $file.Text = [regex]::Replace($file.Text, $LinkPattern, $base, 'IgnoreCase')
        Backup-Once $f.FullName
        Write-Text $f.FullName $file
        $moved += $count
    }
    if ($moved) { $report.Add("$moved links pointed at $domain") }

    # The client refuses content from a host that is not on these lists, and
    # drops the part of the interface that host would have fed.
    $h = $domain
    $xtra = Join-Path $dir 'XtraConfig.xml'
    if (Test-Path -LiteralPath $xtra) {
        $file = Read-Text $xtra
        if (-not (Test-Whitelisted 'XtraConfig.xml' $file.Text $h)) {
            $new = [regex]::Replace($file.Text, '(Key="WhiteDomainList" Value=")([^"]*)(")',
                { param($m) $m.Groups[1].Value + $m.Groups[2].Value + ' ' + $h + $m.Groups[3].Value }, 'None')
            if ($new -ne $file.Text) { $file.Text = $new; Backup-Once $xtra; Write-Text $xtra $file; $report.Add("$h allowed in XtraConfig.xml") }
        }
    }
    $tzer = Join-Path $dir 'tzer.xml'
    if (Test-Path -LiteralPath $tzer) {
        $file = Read-Text $tzer
        if (-not (Test-Whitelisted 'tzer.xml' $file.Text $h)) {
            $at = $file.Text.IndexOf('</whitelist>')
            if ($at -ge 0) {
                $file.Text = $file.Text.Substring(0, $at) + "   <u>$h</u>`n   " + $file.Text.Substring($at)
                Backup-Once $tzer; Write-Text $tzer $file; $report.Add("$h allowed in tzer.xml")
            }
        }
    }

    foreach ($s in $Strips) {
        $path = Join-Path $script:IcqRoot $s.File
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $file = Read-Text $path
        $n = [regex]::Matches($file.Text, $s.Pattern).Count
        if ($n -eq 0) { continue }
        $file.Text = [regex]::Replace($file.Text, $s.Pattern, '')
        Backup-Once $path; Write-Text $path $file
        $report.Add("$($s.What): $n removed")
    }

    return $report
}

function Invoke-RestoreAll {
    $count = 0
    $suffixes = @($Suffix) + $OlderSuffixes
    $items = Get-ChildItem -LiteralPath $script:IcqRoot -Recurse -Force |
        Where-Object { $n = $_.Name; @($suffixes | Where-Object { $n.EndsWith($_) }).Count -gt 0 }
    foreach ($item in $items) {
        $s = @($suffixes | Where-Object { $item.Name.EndsWith($_) })[0]
        $orig = $item.FullName.Substring(0, $item.FullName.Length - $s.Length)
        if ($item.PSIsContainer) {
            if (-not (Test-Path -LiteralPath $orig)) { Rename-Item -LiteralPath $item.FullName -NewName (Split-Path $orig -Leaf); $count++ }
        } else {
            Copy-Item -LiteralPath $item.FullName -Destination $orig -Force
            Remove-Item -LiteralPath $item.FullName -Force
            $count++
        }
    }
    return $count
}

# --- finding the client -------------------------------------------------------

function Test-IcqFolder([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return $false }
    foreach ($f in 'ICQ.exe', 'MUICore.dll', $Content) {
        if (-not (Test-Path -LiteralPath (Join-Path $path $f))) { return $false }
    }
    return $true
}

function Get-SelfFolder {
    # Compiled, $PSScriptRoot is empty, so the process path is used instead.
    if ($PSScriptRoot) { return $PSScriptRoot }
    return [IO.Path]::GetDirectoryName([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}

function Find-IcqRoot {
    $candidates = New-Object System.Collections.Generic.List[string]
    $self = Get-SelfFolder
    if ($self) { $candidates.Add($self) }

    foreach ($key in @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\ICQ.exe',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ICQ.exe')) {
        try {
            $exe = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($exe) { $candidates.Add([IO.Path]::GetDirectoryName($exe.Trim('"'))) }
        } catch { }
    }

    foreach ($key in @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path $key)) { continue }
        foreach ($sub in (Get-ChildItem $key -ErrorAction SilentlyContinue)) {
            $d = Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue
            if ($d.DisplayName -notmatch '(?i)^icq\s*6') { continue }
            if ($d.InstallLocation) { $candidates.Add($d.InstallLocation) }
        }
    }

    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($base) { $candidates.Add((Join-Path $base 'ICQ6.5')) }
    }

    foreach ($c in $candidates) {
        try { $full = [IO.Path]::GetFullPath($c) } catch { continue }
        if (Test-IcqFolder $full) { return $full }
    }
    return $null
}

# Older versions saved host:port here; only the domain is kept now.
function Get-SavedServer {
    try { return Get-Domain (Get-ItemProperty -LiteralPath $SettingsKey -ErrorAction Stop).Server } catch { return $null }
}

function Save-Server([string]$value) {
    try {
        if (-not (Test-Path $SettingsKey)) { New-Item -Path $SettingsKey -Force | Out-Null }
        Set-ItemProperty -LiteralPath $SettingsKey -Name Server -Value $value
    } catch { }
}

function Test-ClientRunning {
    return [bool](Get-Process ICQ -ErrorAction SilentlyContinue)
}

# --- scripted run -------------------------------------------------------------

if ($Headless) {
    $script:IcqRoot = if ($Root) { [IO.Path]::GetFullPath($Root) } else { Find-IcqRoot }
    if (-not (Test-IcqFolder $script:IcqRoot)) { Write-Error "ICQ 6.5 folder not found: $($script:IcqRoot)"; exit 1 }
    if ($Restore) {
        $n = Invoke-RestoreAll
        Write-Output "files restored: $n"
        exit 0
    }
    $domain = if ($Server) { Get-Domain $Server } else { Get-SavedServer }
    if (-not (Test-Domain $domain)) { Write-Error "not a domain: '$Server' - pass -Server icq.example.org"; exit 1 }
    try {
        $done = Invoke-ApplyAll $domain
    } catch {
        Write-Error $_.Exception.Message
        exit 1
    }
    foreach ($line in $done) { Write-Output "changed: $line" }
    Write-Output "changes made: $($done.Count)"
    exit 0
}

# --- window -------------------------------------------------------------------

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

$script:IcqRoot = Find-IcqRoot

function Get-Server { return Get-Domain $txtServer.Text }

function Test-Ready {
    if (-not $script:IcqRoot) {
        [Windows.Forms.MessageBox]::Show(
            "ICQ 6.5 folder not found.`n`nPut this tool into the ICQ folder, or pick the folder manually.",
            'Client not found', 'OK', 'Error') | Out-Null
        return $false
    }
    if (Test-ClientRunning) {
        [Windows.Forms.MessageBox]::Show(
            "ICQ is running, and it keeps its own files open.`n`nClose it first: tray icon -> Exit.",
            'Close ICQ first', 'OK', 'Warning') | Out-Null
        return $false
    }
    return $true
}

function Invoke-Apply {
    if (-not (Test-Ready)) { return }
    $server = Get-Server
    if (-not (Test-Domain $server)) {
        [Windows.Forms.MessageBox]::Show(
            "Type your server's domain, nothing else:`n`n  icq.example.org`n`nThe ports and paths are filled in by the patch.",
            'Server', 'OK', 'Warning') | Out-Null
        return
    }
    $txtServer.Text = $server
    Save-Server $server
    try {
        $done = Invoke-ApplyAll $server
    } catch {
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Wrong client version', 'OK', 'Error') | Out-Null
        Update-View
        return
    }
    Update-View
    $msg = if ($done.Count) { "Changes made: $($done.Count)." } else { 'Everything was already in place.' }
    $msg += "`n`nSet the sign-in server in ICQ itself: Options -> Connection -> ICQ server.`n`nYou can start ICQ now."
    [Windows.Forms.MessageBox]::Show($msg, 'Done', 'OK', 'Information') | Out-Null
}

function Invoke-Restore {
    if (-not (Test-Ready)) { return }
    $n = Invoke-RestoreAll
    Update-View
    [Windows.Forms.MessageBox]::Show("Files restored: $n.", 'Done', 'OK', 'Information') | Out-Null
}

function Select-Folder {
    $dlg = New-Object Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Select the ICQ 6.5 folder (the one with ICQ.exe)'
    if ($script:IcqRoot) { $dlg.SelectedPath = $script:IcqRoot }
    if ($dlg.ShowDialog() -ne 'OK') { return }
    if (Test-IcqFolder $dlg.SelectedPath) {
        $script:IcqRoot = $dlg.SelectedPath
        Update-View
    } else {
        [Windows.Forms.MessageBox]::Show(
            "This folder does not look like ICQ 6.5.`n`nExpected: ICQ.exe, MUICore.dll and $Content",
            'Wrong folder', 'OK', 'Warning') | Out-Null
    }
}

$form = New-Object Windows.Forms.Form
$form.Text = 'ICQ 6.5 Patch'
$form.Size = New-Object Drawing.Size(720, 600)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$header = New-Object Windows.Forms.Label
$header.Text = 'Removes what is left of the ICQ.com services - Xtraz, advertising, tZers, SMS and phone - and points the pages the client opens at your own server. Your profile and history are left untouched.'
$header.Location = New-Object Drawing.Point(12, 10)
$header.Size = New-Object Drawing.Size(680, 34)
$form.Controls.Add($header)

$pathLabel = New-Object Windows.Forms.Label
$pathLabel.Location = New-Object Drawing.Point(12, 50)
$pathLabel.Size = New-Object Drawing.Size(540, 20)
$pathLabel.Font = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold)
$form.Controls.Add($pathLabel)

$btnFolder = New-Object Windows.Forms.Button
$btnFolder.Text = 'Change folder...'
$btnFolder.Location = New-Object Drawing.Point(572, 46)
$btnFolder.Size = New-Object Drawing.Size(120, 26)
$btnFolder.Add_Click({ Select-Folder })
$form.Controls.Add($btnFolder)

$serverLabel = New-Object Windows.Forms.Label
$serverLabel.Text = 'Server:'
$serverLabel.Location = New-Object Drawing.Point(12, 82)
$serverLabel.Size = New-Object Drawing.Size(90, 20)
$form.Controls.Add($serverLabel)

$txtServer = New-Object Windows.Forms.TextBox
$txtServer.Location = New-Object Drawing.Point(104, 79)
$txtServer.Size = New-Object Drawing.Size(588, 22)
$saved = Get-SavedServer
$txtServer.Text = if ($saved) { $saved } else { '' }
$form.Controls.Add($txtServer)

$serverHint = New-Object Windows.Forms.Label
$serverHint.Text = 'Just the domain, e.g. icq.example.org - the patch fills in ports and paths itself. Remembered for next time. The sign-in server is set in ICQ: Options -> Connection -> ICQ server.'
$serverHint.Location = New-Object Drawing.Point(104, 103)
$serverHint.Size = New-Object Drawing.Size(588, 30)
$serverHint.ForeColor = [Drawing.Color]::DimGray
$form.Controls.Add($serverHint)

$list = New-Object Windows.Forms.ListView
$list.Location = New-Object Drawing.Point(12, 138)
$list.Size = New-Object Drawing.Size(680, 364)
$list.View = 'Details'
$list.FullRowSelect = $true
$list.GridLines = $true
[void]$list.Columns.Add('Item', 380)
[void]$list.Columns.Add('Where', 190)
[void]$list.Columns.Add('State', 90)
$form.Controls.Add($list)

function Add-Group([string]$title) {
    $g = New-Object Windows.Forms.ListViewItem($title)
    $g.Font = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold)
    [void]$list.Items.Add($g)
}

function Add-Row($what, $where, $state) {
    $item = New-Object Windows.Forms.ListViewItem($what)
    [void]$item.SubItems.Add($where)
    [void]$item.SubItems.Add($state)
    if ($state -eq 'patched')      { $item.ForeColor = [Drawing.Color]::DarkGreen }
    elseif ($state -eq 'original') { $item.ForeColor = [Drawing.Color]::Black }
    else                           { $item.ForeColor = [Drawing.Color]::Firebrick }
    [void]$list.Items.Add($item)
}

function Update-View {
    $list.Items.Clear()
    if (-not $script:IcqRoot) {
        $pathLabel.Text = 'Client folder not found - use "Change folder..."'
        $pathLabel.ForeColor = [Drawing.Color]::Firebrick
        return
    }
    $pathLabel.Text = 'Client folder: ' + $script:IcqRoot
    $pathLabel.ForeColor = [Drawing.Color]::Black

    Add-Group 'CODE'
    foreach ($p in $CodePatches) { Add-Row $p.What $p.File (Get-CodeState $p) }

    Add-Group 'INTERFACE'
    foreach ($e in $MarkupEdits) { Add-Row $e.What (Split-Path $e.File -Leaf) (Get-EditState $e) }
    foreach ($r in $Removals) { Add-Row $r.What (Split-Path $r.Path -Leaf) (Get-RemovalState $r) }

    Add-Group 'LINKS AND ADVERTISING'
    $l = Get-LinkState (Get-Server)
    Add-Row ('pages the client opens, ' + $l.Info) 'ConfigFiles' $l.State
    Add-Row 'your server in the content whitelists' 'XtraConfig.xml, tzer.xml' (Get-WhitelistState (Get-Server))
    foreach ($s in $Strips) { Add-Row $s.What (Split-Path $s.File -Leaf) (Get-StripState $s) }
}

$buttons = @(
    @{ Text = 'Apply';            Action = { Invoke-Apply } }
    @{ Text = 'Restore original'; Action = { Invoke-Restore } }
    @{ Text = 'Re-check';         Action = { Update-View } }
    @{ Text = 'Close';            Action = { $form.Close() } }
)
$x = 12
foreach ($b in $buttons) {
    $btn = New-Object Windows.Forms.Button
    $btn.Text = $b.Text
    $btn.Location = New-Object Drawing.Point($x, 512)
    $btn.Size = New-Object Drawing.Size(160, 34)
    $btn.Add_Click($b.Action)
    $form.Controls.Add($btn)
    $x += 173
}

Update-View
[void]$form.ShowDialog()
