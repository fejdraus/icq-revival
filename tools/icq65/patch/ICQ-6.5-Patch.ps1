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
#   4. Sign-in server. The domain replaces login.icq.com as the server the
#      client signs in to with automatic connection settings; a server typed
#      under Options -> Connection -> manual stays the user's choice.
#
# Every file is backed up next to itself before the first change, and
# "Restore original" puts them all back. The user's profile is never touched.
#
# In the window each change has a tick, and Apply makes the client match the
# ticks: what is ticked is put in, what is cleared and in place is taken out
# again. A file with several changes is rebuilt from its backup with the
# ticked ones only, so taking one out leaves exactly the original behind.
#
# The folder is found on its own: next to this tool first (dropped into the ICQ
# folder), then from the registry, then the standard path.
#
# Without arguments the window opens. For a scripted run:
#   ICQ-6.5-Patch.ps1 -Apply   [-Root <folder>] [-Server <domain>] [-Skip <keys>]
#   ICQ-6.5-Patch.ps1 -Restore [-Root <folder>]
#
# The window is the one all client patches share, ../../common/PatchWindow.ps1.
# Built into ICQ-6.5-Patch.exe, with its icon, by ../../common/Build-Patches.ps1.

param(
    [switch]$Apply,
    [switch]$Restore,
    [string]$Root,
    [string]$Server,
    # Jobs to leave out - or take out, if in place - by their keys in $Jobs.
    [string[]]$Skip
)

$Headless = $Apply -or $Restore

$Suffix = '.icq6patch-backup'
# Suffixes left by the Python tools this patch replaces. Restore puts those
# back too, so a client patched the old way can be returned to the original.
$OlderSuffixes = @('.icq6-declutter-backup', '.icq6-retarget-backup')

# Only the server's domain is asked for. Ports and paths are the same on every
# ICQ Revival server (deploy/VM-SPEC.md, section 3), so the patch fills them in
# itself; nobody has to know which port serves what.
$PagesPortHttps = 8102  # pages the client opens in a window or the browser
$PagesPortHttp = 8101   # what the client fetches with its own loader
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
# Every page path, and whether the client can reach it over HTTPS. Tried on a
# real client: whatever it opens in a window or hands to the browser - the Xtraz
# list and its DTD, the welcome and picture windows, help and registration -
# works over HTTPS. What it fetches with its own loader does not: that loader
# drops an https:// address without even connecting. Those stay on plain HTTP.
$PageLinks = [ordered]@{
    '/xtraz2/global/'             = $true    # the Xtraz list and its DTD
    '/compad/'                    = $true    # help, registration, password, report
    '/legal'                      = $true    # the legal notice
    '/download/icq6/'             = $true    # the emoticon download page
    '/xtraz/srv/'                 = $false   # country lookup the client fetches itself
    '/register/email_activation/' = $false   # the client posts the activation itself
    '/sms'                        = $false   # SMS carriers (their entries are removed)
    '/ibs/icq6/'                  = $false   # SMS number check
}
$PagePaths = @($PageLinks.Keys)
# Any host in front of those paths, not only the dead ICQ.com ones: the paths
# belong to ICQ.com services and nothing else, so a match is either still
# ICQ.com or a server this patch pointed them at before. Moving to another
# server is then just applying again with the new domain.
$LinkPattern = 'https?://[A-Za-z0-9.-]+(?::\d+)?' +
               '(?=(?<path>' + (($PagePaths | ForEach-Object { [regex]::Escape($_) }) -join '|') + '))'

# What a link is pointed at, for a given domain and the path that follows it.
function Get-PagesBase([string]$domain, [string]$path) {
    if ($PageLinks[$path]) { return "https://${domain}:$PagesPortHttps" }
    return "http://${domain}:$PagesPortHttp"
}

# The links in a text that do not point where they should yet.
function Get-StrayLinks([string]$text, [string]$domain) {
    return @([regex]::Matches($text, $LinkPattern, 'IgnoreCase') |
        Where-Object { $_.Value -ne (Get-PagesBase $domain $_.Groups['path'].Value) })
}

# The client draws the ad slots and the teaser strip only while these list
# something, and without SMS carriers it has nowhere to send a text.
$Strips = @(
    [pscustomobject]@{ File = 'ConfigFiles\adConfig.xml'; Pattern = '[ \t]*<spot\b[^>]*/>[ \t]*\r?\n?'; What = 'advertising slots' }
    [pscustomobject]@{ File = 'ConfigFiles\tzer.xml'; Pattern = '[ \t]*<tz\b[^>]*/>[ \t]*\r?\n?'; What = 'the teaser strip' }
    [pscustomobject]@{ File = 'ConfigFiles\SMSConfig.xml'; Pattern = '[ \t]*<i n="operator"[^>]*/>[ \t]*\r?\n?'; What = 'SMS carriers' }
)

# --- sign-in server ----------------------------------------------------------
#
# With automatic connection settings ICQ 6.5 signs in to ServerHostName of its
# ConnectionSettings, and the default for it is not in any configuration file:
# MCore.dll builds it in code, from a UTF-16 string "login.icq.com" that one
# instruction pushes before SysAllocString. (ConfigFiles\Defaults\App.xml holds
# defaults for the App set only; a ServerHostName there is ignored - tried.)
#
# The string cannot be replaced in place - thirteen characters is too short for
# a domain - so the domain goes into the unused tail of .rdata, the section is
# made to map that tail, and the one push is pointed at it. login.icq.com stays
# where it was, untouched. The push carries a base relocation, so the loader
# moves the new address along with the image like the old one. The DLL has no
# checksum and no signature to keep valid.

$SignIn = [pscustomobject]@{
    File       = 'MCore.dll'
    Size       = 2349568
    Sha256From = '939847F9118F8059223729BDFF7FF174C1BF45840CA2BB3A9DD4A415E669587B'
    PushImm    = 0x4572       # push offset "login.icq.com" - its 4-byte operand
    OldTarget  = 0x320B2878   # where it points out of the box
    NewTarget  = 0x32108664   # the slot below, at image base 0x31F00000
    Slot       = 0x207064     # file offset of the slot: .rdata, past its data
    SlotEnd    = 0x207200     # end of .rdata in the file
    VSizeAt    = 0x258        # VirtualSize of .rdata in the section table
    VSizeFrom  = 0x57662
    VSizeTo    = 0x57800      # all of its raw data; .data starts at 0x209000
}

function Read-SlotDomain([byte[]]$bytes) {
    $end = $SignIn.Slot
    while ($end + 1 -lt $SignIn.SlotEnd -and ($bytes[$end] -ne 0 -or $bytes[$end + 1] -ne 0)) { $end += 2 }
    return [Text.Encoding]::Unicode.GetString($bytes, $SignIn.Slot, $end - $SignIn.Slot)
}

# original / patched / another server / other version / missing
function Get-SignInState([string]$domain) {
    $path = Join-Path $script:IcqRoot $SignIn.File
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ne $SignIn.Size) { return 'other version' }
    $target = [BitConverter]::ToUInt32($bytes, $SignIn.PushImm)
    if ($target -eq $SignIn.OldTarget) {
        if ((Get-Sha256 $path) -eq $SignIn.Sha256From) { return 'original' } else { return 'other version' }
    }
    if ($target -eq $SignIn.NewTarget) {
        if ((Read-SlotDomain $bytes) -eq $domain) { return 'patched' } else { return 'another server' }
    }
    return 'other version'
}

function Get-SignInShown {
    $path = Join-Path $script:IcqRoot $SignIn.File
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ne $SignIn.Size) { return '' }
    if ([BitConverter]::ToUInt32($bytes, $SignIn.PushImm) -eq $SignIn.NewTarget) { return Read-SlotDomain $bytes }
    return 'login.icq.com'
}

# Returns a line for the report, or $null when there was nothing to do.
function Set-SignIn([string]$domain) {
    $state = Get-SignInState $domain
    if ($state -eq 'patched' -or $state -eq 'missing') { return $null }
    if ($state -eq 'other version') { return "MCore.dll is not the one from build 2024 - sign-in server left as it is" }
    $text = [Text.Encoding]::Unicode.GetBytes($domain)
    if ($text.Length + 2 -gt $SignIn.SlotEnd - $SignIn.Slot) { return "the domain is too long for MCore.dll - sign-in server left as it is" }

    $path = Join-Path $script:IcqRoot $SignIn.File
    Backup-Once $path
    $bytes = [IO.File]::ReadAllBytes($path)
    for ($i = $SignIn.Slot; $i -lt $SignIn.SlotEnd; $i++) { $bytes[$i] = 0 }
    [Array]::Copy($text, 0, $bytes, $SignIn.Slot, $text.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$SignIn.VSizeTo), 0, $bytes, $SignIn.VSizeAt, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$SignIn.NewTarget), 0, $bytes, $SignIn.PushImm, 4)
    [IO.File]::WriteAllBytes($path, $bytes)
    return "the client signs in to $domain"
}

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

# The file as the client came with it, from this patch's backup (or one left by
# the older tools); $null while the file has not been changed yet.
function Get-OriginalText([string]$path) {
    foreach ($suf in @($Suffix) + $OlderSuffixes) {
        if (Test-Path -LiteralPath ($path + $suf)) { return (Read-Text ($path + $suf)).Text }
    }
    return $null
}

function Get-WhiteDomains([string]$text) {
    $m = [regex]::Match($text, 'Key="WhiteDomainList" Value="([^"]*)"')
    if (-not $m.Success) { return @() }
    return @($m.Groups[1].Value -split '\s+' | Where-Object { $_ })
}

function Get-WhitelistHosts([string]$text) {
    $m = [regex]::Match($text, '(?s)<whitelist>(.*?)</whitelist>')
    if (-not $m.Success) { return @() }
    return @([regex]::Matches($m.Groups[1].Value, '<u>([^<]*)</u>') | ForEach-Object { $_.Groups[1].Value })
}

function Get-LinkState([string]$domain) {
    $dir = Join-Path $script:IcqRoot 'ConfigFiles'
    if (-not (Test-Path -LiteralPath $dir)) { return @{ State = 'missing'; Info = '' } }
    $other = 0
    foreach ($f in Get-ChildItem -LiteralPath $dir -Filter *.xml -File) {
        $other += (Get-StrayLinks (Read-Text $f.FullName).Text $domain).Count
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

#_if PSScript
. (Join-Path $PSScriptRoot '..\..\common\PatchItems.ps1')
#_else
#_include "$PSScriptRoot/../../common/PatchItems.ps1"
#_endif

# What a person chooses between: one row per job, whatever number of files
# and places it takes. Every change of the tables above belongs to one.
$Jobs = [ordered]@{
    'xtraz'   = @{ Group = 'Services that are gone'; What = 'Xtraz: the strip, the panel, menus, options, sounds and filter' }
    'tzers'   = @{ Group = 'Services that are gone'; What = 'tZers: the button, the teasers, the option and the sound' }
    'sms'     = @{ Group = 'Services that are gone'; What = 'SMS and phone: buttons, icons, menus, options, sounds, filter' }
    'zlango'  = @{ Group = 'Services that are gone'; What = 'the Zlango add-on and its message window buttons' }
    'ads'     = @{ Group = 'Advertising'; What = 'advertising: the ad slots and boxes, the banner and its frame' }
    'fix'     = @{ Group = 'Fixes'; What = 'the cut-off bottom of the "Advanced" preferences group' }
    'links'   = @{ Group = 'Your server'; What = 'the pages the client opens point at your server' }
    'sign-in' = @{ Group = 'Your server'; What = 'automatic connection signs in to your server' }
}
$JobOf = @{
    'the Xtraz strip above the contact list'             = 'xtraz'
    'the Xtraz panel below the contact list'             = 'xtraz'
    'the "Xtraz invitations" option'                     = 'xtraz'
    'the Xtraz submenu of the contact menu'              = 'xtraz'
    'the "save Xtraz invitations" option'                = 'xtraz'
    'the incoming-Xtraz sound'                           = 'xtraz'
    'the Xtraz filter of the history search'             = 'xtraz'
    'the "My Xtraz" item of the main menu'               = 'xtraz'
    'the tZers button of the message window'             = 'tzers'
    'the "play tZers automatically" option'              = 'tzers'
    'the incoming-tZer sound'                            = 'tzers'
    'the teaser strip'                                   = 'tzers'
    'the "SMS & Phone" entry of the preferences list'    = 'sms'
    'the page of the "SMS & Phone" preferences'          = 'sms'
    'the SMS button of the message window'               = 'sms'
    'the phone button of the message window'             = 'sms'
    'the SMS icon on a contact row'                      = 'sms'
    'the phone icon on a contact row'                    = 'sms'
    'the auto-SMS line of the contact card'              = 'sms'
    'the "Send SMS" item of the contact menu'            = 'sms'
    'the auto-SMS section of the options'                = 'sms'
    'the incoming-SMS sound'                             = 'sms'
    'the outgoing-SMS sound'                             = 'sms'
    'the SMS filter of the history search'               = 'sms'
    'SMS carriers'                                       = 'sms'
    'the Zlango add-on and its message window buttons'   = 'zlango'
    'the banner under the message window'                = 'ads'
    'the ad box of the message window'                   = 'ads'
    'the white frame at the foot of the message window'  = 'ads'
    'the ad box of the contact list'                     = 'ads'
    'advertising slots'                                  = 'ads'
    'the cut-off bottom of the "Advanced" group'         = 'fix'
    # The client refuses content from a host not on its whitelists, so the
    # links are no use without them.
    'links'                                              = 'links'
    'whitelist'                                          = 'links'
    'sign-in'                                            = 'sign-in'
}

# Every change with its current state, folded into one row per job. A row's
# key is its job: what it is chosen by.
function Get-Items([string]$domain) {
    $items = New-Object System.Collections.Generic.List[object]
    $add = { param($key, $where, $state)
        $items.Add([pscustomobject]@{ Group = ''; Key = $key; What = $key; Where = $where; State = $state })
    }
    foreach ($p in $CodePatches) { & $add $p.What $p.File (Get-CodeState $p) }
    foreach ($e in $MarkupEdits) { & $add $e.What (Split-Path $e.File -Leaf) (Get-EditState $e) }
    foreach ($r in $Removals) { & $add $r.What (Split-Path $r.Path -Leaf) (Get-RemovalState $r) }
    & $add 'links' 'ConfigFiles' (Get-LinkState $domain).State
    & $add 'whitelist' 'XtraConfig.xml' (Get-WhitelistState $domain)
    foreach ($st in $Strips) { & $add $st.What (Split-Path $st.File -Leaf) (Get-StripState $st) }
    & $add 'sign-in' ('MCore.dll, now ' + (Get-SignInShown)) (Get-SignInState $domain)
    return Merge-Jobs $items
}

# Puts back a whole file from its backup; the backup stays, as the original.
function Restore-FromBackup([string]$path) {
    foreach ($suf in @($Suffix) + $OlderSuffixes) {
        if (Test-Path -LiteralPath ($path + $suf)) {
            Copy-Item -LiteralPath ($path + $suf) -Destination $path -Force
            return $true
        }
    }
    return $false
}

# The whitelist of one configuration file with the host added, if it has one.
function Add-Whitelisted([string]$name, [string]$text, [string]$h) {
    if ($name -eq 'XtraConfig.xml') {
        if (Test-Whitelisted $name $text $h) { return $text }
        return [regex]::Replace($text, '(Key="WhiteDomainList" Value=")([^"]*)(")',
            { param($m) $m.Groups[1].Value + $m.Groups[2].Value + ' ' + $h + $m.Groups[3].Value }, 'None')
    }
    if ($name -eq 'tzer.xml') {
        if (Test-Whitelisted $name $text $h) { return $text }
        $at = $text.IndexOf('</whitelist>')
        if ($at -lt 0) { return $text }
        return $text.Substring(0, $at) + "   <u>$h</u>`n   " + $text.Substring($at)
    }
    return $text
}

# Makes the client match the selection and returns what changed, one line
# per change.
function Invoke-ApplyAll([string]$domain, $skip) {
    foreach ($p in $CodePatches) {
        if ((Test-Wanted $skip $p.What) -and (Get-CodeState $p) -eq 'other version') {
            throw "$($p.File) is not the one from ICQ 6.5 build 2024; nothing was changed."
        }
    }
    $before = Get-Items $domain

    foreach ($p in $CodePatches) {
        $path = Join-Path $script:IcqRoot $p.File
        $state = Get-CodeState $p
        if (Test-Wanted $skip $p.What) {
            if ($state -ne 'original') { continue }
            Backup-Once $path
            $bytes = [IO.File]::ReadAllBytes($path)
            foreach ($e in $p.Edits) { [Array]::Copy($e.To, 0, $bytes, $e.Offset, $e.To.Length) }
            [IO.File]::WriteAllBytes($path, $bytes)
        } elseif ($state -eq 'patched') {
            [void](Restore-FromBackup $path)
        }
    }

    # Each file is built again from the original with the wanted edits.
    foreach ($group in ($MarkupEdits | Group-Object File)) {
        $path = Join-Path $script:IcqRoot $group.Name
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $file = Read-Text $path
        $original = Get-OriginalText $path
        $text = if ($null -ne $original) { $original } else { $file.Text }
        foreach ($edit in $group.Group) {
            if (-not (Test-Wanted $skip $edit.What)) { continue }
            $new = Invoke-Edit $edit $text
            if ($null -ne $new) { $text = $new }
        }
        if ($text -cne $file.Text) { Backup-Once $path; $file.Text = $text; Write-Text $path $file }
    }

    foreach ($r in $Removals) {
        $path = Join-Path $script:IcqRoot $r.Path
        $state = Get-RemovalState $r
        if (Test-Wanted $skip $r.What) {
            if ($state -eq 'original') { Rename-Item -LiteralPath $path -NewName ((Split-Path $path -Leaf) + $Suffix) }
        } elseif ($state -eq 'patched') {
            foreach ($suf in @($Suffix) + $OlderSuffixes) {
                if (Test-Path -LiteralPath ($path + $suf)) { Rename-Item -LiteralPath ($path + $suf) -NewName (Split-Path $path -Leaf); break }
            }
        }
    }

    # The configuration files the same way: the original, then the links, the
    # whitelists and the emptied lists that are wanted. A server let in before
    # is gone with that too - the original never had it.
    #
    # The client refuses content from a host that is not on the whitelists,
    # and drops the part of the interface that host would have fed; so the
    # links and the whitelists go together.
    $dir = Join-Path $script:IcqRoot 'ConfigFiles'
    $links = Test-Wanted $skip 'links'
    $white = Test-Wanted $skip 'whitelist'
    foreach ($f in Get-ChildItem -LiteralPath $dir -Filter *.xml -File) {
        $file = Read-Text $f.FullName
        $original = Get-OriginalText $f.FullName
        $text = if ($null -ne $original) { $original } else { $file.Text }
        if ($links) {
            $text = [regex]::Replace($text, $LinkPattern,
                { param($m) Get-PagesBase $domain $m.Groups['path'].Value }, 'IgnoreCase')
        }
        if ($white) { $text = Add-Whitelisted $f.Name $text $domain }
        foreach ($s in $Strips) {
            if ((Split-Path $s.File -Leaf) -eq $f.Name -and (Test-Wanted $skip $s.What)) {
                $text = [regex]::Replace($text, $s.Pattern, '')
            }
        }
        if ($text -cne $file.Text) { Backup-Once $f.FullName; $file.Text = $text; Write-Text $f.FullName $file }
    }

    if (Test-Wanted $skip 'sign-in') {
        [void](Set-SignIn $domain)
    } elseif (@('patched', 'another server') -contains (Get-SignInState $domain)) {
        [void](Restore-FromBackup (Join-Path $script:IcqRoot $SignIn.File))
    }

    $report = New-Object System.Collections.Generic.List[string]
    $after = Get-Items $domain
    for ($i = 0; $i -lt $after.Count; $i++) {
        if ($after[$i].State -eq $before[$i].State) { continue }
        if ($after[$i].State -eq 'patched') { $report.Add('applied: ' + $after[$i].What) }
        else { $report.Add('taken out: ' + $after[$i].What) }
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
        $set = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($k in $Skip) { [void]$set.Add($k) }
        $done = Invoke-ApplyAll $domain $set
    } catch {
        Write-Error $_.Exception.Message
        exit 1
    }
    foreach ($line in $done) { Write-Output $line }
    Write-Output "changes made: $($done.Count)"
    exit 0
}

# --- window -------------------------------------------------------------------

#_if PSScript
. (Join-Path $PSScriptRoot '..\..\common\PatchWindow.ps1')
#_else
#_include "$PSScriptRoot/../../common/PatchWindow.ps1"
#_endif

$script:IcqRoot = Find-IcqRoot

$ui = New-PatchWindow -Title 'ICQ 6.5 Patch' -Badge '6.5' -AccentTop '#4CC06E' -AccentBottom '#1E8A46' `
    -ClientName 'ICQ 6.5' `
    -Subtitle 'Removes what is left of the ICQ.com services - Xtraz, advertising, tZers, SMS and phone - and points the client at your own server. Your profile and history are left untouched.' `
    -ServerHint 'Just the domain, e.g. icq.example.org. The patch fills in ports and paths, and ICQ signs in there. Remembered for next time.' `
    -Columns @(@('Change', 420), @('Where', 190))

function Get-Server { return Get-Domain $ui.Server.Text }

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
    $ui.Server.Text = $server
    Save-Server $server
    Save-PatchUnchecked $ui $SettingsKey
    try {
        $done = Invoke-ApplyAll $server $ui.Unchecked
    } catch {
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Wrong client version', 'OK', 'Error') | Out-Null
        Update-View
        return
    }
    Update-View
    $msg = if ($done.Count) { "Changes made: $($done.Count)`n`n  " + (@($done | Select-Object -First 12) -join "`n  ") } else { 'The client already matches the selection.' }
    if ($done.Count -gt 12) { $msg += "`n  ..." }
    if (Test-PatchSelected $ui 'sign-in') { $msg += "`n`nWith automatic connection settings ICQ signs in to $server." }
    $msg += "`n`nYou can start ICQ now."
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

function Update-View {
    Set-PatchFolder $ui $script:IcqRoot
    Clear-PatchList $ui
    if ($script:IcqRoot) {
        $groups = @{}
        foreach ($it in Get-Items (Get-Server)) {
            if (-not $groups.ContainsKey($it.Group)) { $groups[$it.Group] = Add-PatchGroup $ui $it.Group }
            Add-PatchRow $ui $groups[$it.Group] @($it.What, $it.Where) $it.State $it.Key
        }
    }
    Complete-PatchList $ui
}

$ui.FolderButton.Add_Click({ Select-Folder })
$saved = Get-SavedServer
if ($saved) { $ui.Server.Text = $saved }
Read-PatchUnchecked $ui $SettingsKey
$ui.Server.Add_Leave({ Update-View })

[void](Add-PatchButton $ui 'Close' { $ui.Form.Close() })
[void](Add-PatchButton $ui 'Apply' { Invoke-Apply } -Primary)
[void](Add-PatchButton $ui 'Restore original' { Invoke-Restore })
[void](Add-PatchButton $ui 'Re-check' { Update-View })

Update-View
Show-PatchWindow $ui
