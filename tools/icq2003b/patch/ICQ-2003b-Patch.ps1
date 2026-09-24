# Патч для ICQ Pro 2003b — оконное приложение.
#
# Делает две вещи разом:
#
#   1. Убирает рекламу и строку поиска Google четырьмя точечными правками в
#      коде клиента.
#   2. Перенаправляет ссылки на мёртвые службы ICQ.com: справка, «белые
#      страницы», веб-пейджер, панель после входа и поиск. Адрес своего
#      сервера задаётся в окне.
#
# База пользователя и скин не трогаются: правка базы ломает клиент насмерть.
#
# Папку клиента ищет сам: сначала рядом с собой (положили в каталог ICQ или
# взяли портативную сборку), затем в реестре, затем по стандартному пути.
#
# In the window each change has a tick, and Apply makes the client match the
# ticks: what is ticked is put in, what is cleared and in place is taken out
# again, from the backup of the file.
#
# Without arguments the window opens. For a scripted run:
#   ICQ-2003b-Patch.ps1 -Apply   [-Root <folder>] [-Server <domain>] [-Skip <jobs>] [-Include ukrainian] [-NoRegistry]
#   ICQ-2003b-Patch.ps1 -Restore [-Root <folder>] [-NoRegistry]
#
# The window is the one all client patches share, ../../common/PatchWindow.ps1.
# Built into ICQ-2003b-Patch.exe, with its icon, by ../../common/Build-Patches.ps1.

param(
    [switch]$Apply,
    [switch]$Restore,
    [string]$Root,
    [string]$Server,
    # Jobs to leave out - or take out, if in place - by their keys in $Jobs.
    [string[]]$Skip,
    # Jobs that are off unless asked for, such as ukrainian.
    [string[]]$Include,
    # Leaves the registry alone - the sign-in server lives there, for the
    # whole machine, not in the folder. For runs on a copy of the client.
    [switch]$NoRegistry
)

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

$BinSuffix  = '.antibanner-backup'
$LinkSuffix = '.icq-links-backup'
$Latin1     = [Text.Encoding]::GetEncoding(28591)

# --- правки кода -------------------------------------------------------------
#
# Имена функций взяты из таблиц экспорта самих модулей: они экспортируют
# декорированные имена C++, поэтому места найдены по именам, а не подбором.

$Patches = @(
    [pscustomobject]@{
        File = 'icqmutl.dll'; Offset = 0x20626
        From = [byte[]](0xB8,0x96,0x9B,0x22,0x20)
        To   = [byte[]](0x31,0xC0,0xC2,0x04,0x00)
        Size = 270421
        Sha256From = '7B3198D703D4AB2DAAD6A8062B0C4F885419C3BC72151BF78427D3FA32A6680A'
        Sha256To   = '4530FF4F8190DCE7D213D40BBDC3602E774A65490AE5D927CF7B77D8C245E347'
        What = 'contact list banner is never created'
        Job = 'banners'
    }
    [pscustomobject]@{
        File = 'ICQProLib.dll'; Offset = 0x1217B
        From = [byte[]](0xB8,0xBA,0x7D,0x89,0x24)
        To   = [byte[]](0x31,0xC0,0xC3)
        Size = 198739
        Sha256From = '192941271B7B50BC9298B665C2C1F0C9F3F74E2AF43FAFF3C0FE0F0E082A31A3'
        Sha256To   = '631780FABA446E9AB5598D88B45296A626F373DAFAA275D828B1920692EC139E'
        What = 'message window banner is never shown'
        Job = 'banners'
    }
    [pscustomobject]@{
        File = 'ICQTicker.dll'; Offset = 0x750
        From = [byte[]](0x53,0x55,0x8B,0x6C,0x24,0x14,0x56)
        To   = [byte[]](0xB8,0x11,0x01,0x04,0x80,0xC2,0x0C,0x00)
        Size = 37977
        Sha256From = '92058B9563288A066DC4884E68930BB67F78A6D10AD8BAB8BD0F8287FB847A39'
        Sha256To   = '2E901493EFB3914273DDD952159B3135FD959A8FC2F0DB8DD67EFDE875D031FF'
        What = 'Google search bar and its button are gone'
        Job = 'google bar'
    }
    [pscustomobject]@{
        File = 'Icq.exe'; Offset = 0x39AA2
        From = [byte[]](0x74,0x41)
        To   = [byte[]](0xEB,0x41)
        Size = 1880639
        Sha256From = '6C97F1B8045ED6E6801E0AFD97548B040819F153836B25B0F968184483F1546A'
        Sha256To   = 'BE8AEA553DCABA7108E3442EEEBAA5F00A56A2BE78653290EFFF6A83DF5F0B1B'
        What = 'no empty strip reserved for them'
        # The 22 px the layout keeps for the bar above: one job with it.
        Job = 'google bar'
    }
    [pscustomobject]@{
        # The "Send By: ICQ / SMS / Email" strip in the message window. SMS and
        # Email went through gateways on ICQ.com and there is nothing behind
        # them any more, so the strip only offers ways to fail.
        #
        # The strip is made of three layers that know nothing about each other,
        # and each needed its own change:
        #
        #   1. the three tick boxes - controls of the plugin's dialog;
        #   2. the words "Send By:"  - a string in Icq.exe, painted by the skin;
        #   3. the frame around them - an object in Skin\IcqPro.skn.
        #
        # This is the first layer. The dialog template is not where visibility
        # is decided: a layout routine calls ShowWindow itself and works out the
        # argument as 5 (SW_SHOW) or 0 (SW_HIDE):
        #
        #   neg eax ; sbb eax, eax ; and al, 0xFB ; add eax, 5
        #
        # Zeroing the result makes the client hide the boxes with its own call.
        # They stay in the dialog and the ICQ box stays ticked, so the code
        # still reads it and Send keeps working. Two places: eax for the group,
        # edi for the three boxes pushed after it.
        File = 'ICQMessagePlugin.dll'; Offset = 0x7B63
        From = [byte[]](0x83,0xC0,0x05)
        To   = [byte[]](0x31,0xC0,0x90)
        Size = 236144
        Sha256From = 'AFC36BD67D353EECA1F952C3ED56D372FE93C018D58C966F0A930EDEE5AC887B'
        Sha256To   = 'E40BEEE28D67ECACA0A10182F215CB2901F8CD4A56F85C667C0AE8E09E18E486'
        What = 'tick boxes ICQ / SMS / Email are hidden'
        Job = 'send-by'
    }
    [pscustomobject]@{
        File = 'ICQMessagePlugin.dll'; Offset = 0x7B84
        From = [byte[]](0x83,0xC7,0x05)
        To   = [byte[]](0x31,0xFF,0x90)
        Size = 236144
        Sha256From = 'AFC36BD67D353EECA1F952C3ED56D372FE93C018D58C966F0A930EDEE5AC887B'
        Sha256To   = 'E40BEEE28D67ECACA0A10182F215CB2901F8CD4A56F85C667C0AE8E09E18E486'
        What = 'the same for the group around them'
        Job = 'send-by'
    }
    [pscustomobject]@{
        # Second layer: the words. There is no control behind them - a walk of
        # the open window shows none - the skin paints them from this string,
        # string 8727 of Icq.exe, so only the string itself can be changed. It
        # is written as a resource, blank, in English or in Ukrainian - see
        # "the binaries" below; the offset is where it sits in the original.
        File = 'Icq.exe'; Offset = 0x1C489C
        Resource = 'sendBy'
        From = [Text.Encoding]::Unicode.GetBytes('Send By:')
        To   = [Text.Encoding]::Unicode.GetBytes('        ')
        Size = 1880639
        Sha256From = '85F31E2FB53366F1FCC03D16788E50E6932AE2BB3F13C10C3242F1D68AD68684'
        Sha256To   = '64EA6C32386A04D71B873522EF3A2662E074EB048AF584459F9E8492DC4F0EBA'
        What = 'the words "Send By:" are gone'
        # The three layers of the strip only make sense together.
        Job = 'send-by'
    }
    [pscustomobject]@{
        # Third layer: the frame. An object named RgnFrame in the skin, 334x32
        # from x=136 to x=470 - it used to hold the tick boxes, and with them
        # hidden its left half was empty. Its position is worked out from
        # anchors and offsets, not from the rectangle, so the offset is what
        # actually moves it; the rectangle is kept in step so the file stays
        # consistent with itself.
        #
        # 344 is as close to the Send button as the skin can draw: the curve of
        # the left end is part of a stretched image, and below this width it
        # visibly flattens. Hiding the object outright is not an option - it
        # shapes the window, and without it the right edge clips the indicator.
        File = 'Skin\IcqPro.skn'; Offset = 0x41750
        From = [byte[]](0xAB,0xFE,0xFF,0xFF)
        To   = [byte[]](0x7B,0xFF,0xFF,0xFF)
        Size = 423358
        Sha256From = 'B9E7997D2E60A5E172F09376550596B61C871A45B9804243F23F07D2B14CECD0'
        Sha256To   = '5E126B5C13CF0400FAAF43BBA6631E497F70EC7C85C41B5645BBB5F700CA2370'
        What = 'the frame is pulled up to the Send button'
        Job = 'send-by'
    }
    [pscustomobject]@{
        File = 'Skin\IcqPro.skn'; Offset = 0x41782
        From = [byte[]](0x88,0x00,0x00,0x00)
        To   = [byte[]](0x58,0x01,0x00,0x00)
        Size = 423358
        Sha256From = 'B9E7997D2E60A5E172F09376550596B61C871A45B9804243F23F07D2B14CECD0'
        Sha256To   = '5E126B5C13CF0400FAAF43BBA6631E497F70EC7C85C41B5645BBB5F700CA2370'
        What = 'its rectangle follows the offset'
        Job = 'send-by'
    }
)


# --- адреса, зашитые прямо в код --------------------------------------------
#
# Эти ссылки лежат в Icq.exe строками, файла с ними нет. Строку можно заменить
# только на не более длинную: хвост добивается нулями, сдвигать ничего нельзя.
# Поэтому на сервере заведены короткие пути /p, /u, /e, /m в корне адреса —
# они просто перенаправляют на полные страницы.

$StringPatches = @(
    [pscustomobject]@{
        File = 'Icq.exe'; Offset = 0x14269C; Path = '/p'
        Original = 'http://cf.icq.com/cf/2003b/password.html'
        What = '"Forgot your ICQ#/Password?" on the login window'
    }
    [pscustomobject]@{
        File = 'Icq.exe'; Offset = 0x14283C; Path = '/e'
        Original = 'http://cf.icq.com/cf/2003b/email_login.html'
        What = '"ICQ#/Email" help on the login window'
    }
    [pscustomobject]@{
        File = 'Icq.exe'; Offset = 0x140448; Path = '/u'
        Original = 'http://cf.icq.com/cf/2003b/unregister.html'
        What = 'help on deleting your number'
    }
    [pscustomobject]@{
        File = 'Icq.exe'; Offset = 0x142804; Path = '/m'
        Original = 'http://cf.icq.com/cf/2003b/public_private_modes.html'
        What = 'help on public and private mode'
    }
)

# --- ссылки ------------------------------------------------------------------

$LinkFiles = @(
    'DataFiles\icqlinks.xml'
    'DataFiles\channels.xml'
    'DataFiles\atelink.xml'
    'DataFiles\icqacc.xml'
    'DataFiles\psearch.xml'
    'DataFiles\WebSearch.fld'
)

$DeadHosts = @(
    'cb.icq.com','cf.icq.com','cgi.icq.com','google.icq.com','mail.icqmail.com'
    'members.icq.com','news.icqit.com','public.icq.com','search.icq.com'
    'web.icq.com','www.icq.com','www.icqit.com','wwp.icq.com'
)

# Ссылки с известным именем в icqlinks.xml ведут на свои страницы.
$NamedRoutes = [ordered]@{
    'StartPage'              = '{base}/today?uin=%icquin%'
    'WWP'                    = '{base}/center?uin=%d'
    'HowTo'                  = '{base}/howto?uin=%icquin%'
    'Main Page'              = '{base}/howto?uin=%icquin%'
    'Password'               = '{base}/password'
    'PasswordR'              = '{base}/password'
    'Registration'           = '{base}/register'
    'Fail Register'          = '{base}/register'
    'Delete User'            = '{base}/account'
    'Whitepages'             = '{base}/whitepages'
    'White Pages Update'     = '{base}/whitepages'
    'Users Lists'            = '{base}/whitepages'
    'OtherDirectories'       = '{base}/whitepages'
    'Homepage Directory'     = '{base}/whitepages'
    'Map'                    = '{base}/whitepages'
}

# Ссылки без имени опознаются по самому адресу. Порядок важен: частное раньше
# общего, иначе общее правило перехватит запрос поиска и потеряет слово.
#
# Про «=REPLACEME»: клиент подставляет введённое слово вместо этой
# последовательности вместе со знаком равенства, поэтому знаков два —
# первый остаётся в адресе.
$UrlRoutes = @(
    [pscustomobject]@{ Match = 'google\.icq\.com/search'; Target = 'https://www.google.com/search?q==REPLACEME' }
    [pscustomobject]@{ Match = 'search\.icq\.com';        Target = '{base}/whitepages' }
    [pscustomobject]@{ Match = 'google\.icq\.com';        Target = 'https://www.google.com/' }
    [pscustomobject]@{ Match = '/welcome/';               Target = '{base}/welcome?uin=%icquin%' }
)

# Only the server's domain is asked for. The port and path of the pages are the
# same on every ICQ Revival server (deploy/VM-SPEC.md, section 3), so the patch
# fills them in: 2003b opens these links in the browser, which wants HTTPS.
$PagesPortHttps = 8102
$PagesPath = '/icq'

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

function Get-PagesRoot([string]$domain) { return "https://${domain}:$PagesPortHttps" }

# Введённый адрес запоминается, чтобы не вбивать его при каждом запуске.
$SettingsKey = 'HKCU:\Software\OpenOSCAR\IcqPatch'

# Older versions saved the whole address here; only the domain is kept now.
function Get-SavedBase {
    try { return Get-Domain (Get-ItemProperty -LiteralPath $SettingsKey -ErrorAction Stop).ServerBase } catch { return $null }
}

function Save-Base([string]$value) {
    try {
        if (-not (Test-Path $SettingsKey)) { New-Item -Path $SettingsKey -Force | Out-Null }
        Set-ItemProperty -LiteralPath $SettingsKey -Name ServerBase -Value $value
    } catch { }
}

# --- sign-in server ----------------------------------------------------------
#
# ICQ 2003b keeps the server in two places. Default Server Host under HKLM is
# what a new install starts from - and what "Get an ICQ Number" connects to:
# out of the box it is login.icq.com, which is gone, so registering failed
# with "Info Number 117". On its first run the client copies it into the
# connection settings under HKCU, and from then on signs in with those; the
# default is not read again. So both are set.
#
# The connection settings are only taken over while they still hold the dead
# default, or a server this patch put there before: a server the user typed
# under Preferences -> Connection stays theirs. The port stays 5190, as it is
# there already. What each held first is saved once, for Restore original.

$DefaultPrefsKeys = @(
    'HKLM:\SOFTWARE\WOW6432Node\Mirabilis\ICQ\ICQPro\DefaultPrefs'   # 64-bit Windows
    'HKLM:\SOFTWARE\Mirabilis\ICQ\ICQPro\DefaultPrefs'               # 32-bit Windows
)
$SignInValue = 'Default Server Host'
$ConnectionKey = 'HKCU:\Software\Mirabilis\ICQ\CommonPrefs\Connection'
$ConnectionValue = 'ServerHostName'
$DeadSignIn = 'login.icq.com'

function Get-DefaultPrefsKey {
    foreach ($k in $DefaultPrefsKeys) { if (Test-Path -LiteralPath $k) { return $k } }
    return $null
}

function Get-RegValue([string]$key, [string]$name) {
    try { return (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).$name } catch { return $null }
}

function Get-SignInServer {
    $k = Get-DefaultPrefsKey
    if (-not $k) { return $null }
    return Get-RegValue $k $SignInValue
}

# The server the client signs in with; $null before its first run.
function Get-ConnectionServer { return Get-RegValue $ConnectionKey $ConnectionValue }

# Whether the connection settings are the patch's to change: the dead default,
# or the server of an earlier apply.
function Test-ConnectionOurs([string]$current, [string]$previous) {
    return $current -eq $DeadSignIn -or ($previous -and $current -eq $previous)
}

# Saves what a value held first - once, so a second apply does not save our
# own domain as the "original".
function Save-Original([string]$name, [string]$value) {
    if (-not (Test-Path $SettingsKey)) { New-Item -Path $SettingsKey -Force | Out-Null }
    if (-not (Get-RegValue $SettingsKey $name)) { Set-ItemProperty -LiteralPath $SettingsKey -Name $name -Value "$value" }
}

# original / patched / missing, for the domain.
function Get-SignInState([string]$domain, [string]$previous) {
    if (-not (Get-DefaultPrefsKey)) { return 'missing' }
    if (-not $domain -or (Get-SignInServer) -ne $domain) { return 'original' }
    $c = Get-ConnectionServer
    if ($c -and $c -ne $domain -and (Test-ConnectionOurs $c $previous)) { return 'original' }
    return 'patched'
}

function Set-SignInServer([string]$domain, [string]$previous) {
    $k = Get-DefaultPrefsKey
    if (-not $k) { return $false }
    $changed = $false
    try {
        $current = Get-SignInServer
        if ($current -ne $domain) {
            Save-Original 'OriginalServerHost' $current
            Set-ItemProperty -LiteralPath $k -Name $SignInValue -Value $domain -ErrorAction Stop
            $changed = $true
        }
        $c = Get-ConnectionServer
        if ($c -and $c -ne $domain -and (Test-ConnectionOurs $c $previous)) {
            Save-Original 'OriginalConnectionHost' $c
            Set-ItemProperty -LiteralPath $ConnectionKey -Name $ConnectionValue -Value $domain -ErrorAction Stop
            $changed = $true
        }
    } catch { }
    return $changed
}

# Puts back what was saved; a saved value is only let go once it is back in
# place.
function Restore-SignInServer {
    $done = 0
    $saved = Get-RegValue $SettingsKey 'OriginalServerHost'
    $k = Get-DefaultPrefsKey
    if ($saved -and $k) {
        try {
            Set-ItemProperty -LiteralPath $k -Name $SignInValue -Value $saved -ErrorAction Stop
            Remove-ItemProperty -LiteralPath $SettingsKey -Name OriginalServerHost -ErrorAction SilentlyContinue
            $done++
        } catch { }
    }
    $saved = Get-RegValue $SettingsKey 'OriginalConnectionHost'
    if ($saved -and (Test-Path -LiteralPath $ConnectionKey)) {
        try {
            Set-ItemProperty -LiteralPath $ConnectionKey -Name $ConnectionValue -Value $saved -ErrorAction Stop
            Remove-ItemProperty -LiteralPath $SettingsKey -Name OriginalConnectionHost -ErrorAction SilentlyContinue
            $done++
        } catch { }
    }
    return $done
}

# --- поиск папки клиента ----------------------------------------------------

function Test-IcqFolder([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return $false }
    foreach ($p in $Patches) {
        if (-not (Test-Path -LiteralPath (Join-Path $path $p.File))) { return $false }
    }
    return $true
}

function Get-SelfFolder {
    # В скомпилированном виде $PSScriptRoot пуст, поэтому берём путь процесса.
    if ($PSScriptRoot) { return $PSScriptRoot }
    return [IO.Path]::GetDirectoryName([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}

function Find-IcqRoot {
    $candidates = New-Object System.Collections.Generic.List[string]

    $self = Get-SelfFolder
    if ($self) { $candidates.Add($self) }

    foreach ($key in @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Icq.exe',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Icq.exe')) {
        try {
            $exe = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($exe) { $candidates.Add([IO.Path]::GetDirectoryName($exe)) }
        } catch { }
    }

    foreach ($key in @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path $key)) { continue }
        foreach ($sub in (Get-ChildItem $key -ErrorAction SilentlyContinue)) {
            $d = Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue
            if ($d.DisplayName -notmatch '(?i)^icq') { continue }
            if ($d.InstallLocation) { $candidates.Add($d.InstallLocation) }
            # The command line may quote the program and add arguments after it.
            if ($d.UninstallString -match '^\s*"?(?<exe>[^"]+?\.exe)') {
                try { $candidates.Add([IO.Path]::GetDirectoryName($Matches['exe'])) } catch { }
            }
        }
    }

    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($base) { $candidates.Add((Join-Path $base 'ICQ')) }
    }

    foreach ($c in $candidates) {
        try { $full = [IO.Path]::GetFullPath($c) } catch { continue }
        if (Test-IcqFolder $full) { return $full }
    }
    return $null
}

$script:IcqRoot = Find-IcqRoot

# --- the binaries -------------------------------------------------------------
#
# Every program file the patch changes is built again on each Apply, from its
# original - the backup, or the file itself while it has none - with the
# wanted changes in this order: code bytes, the links inside Icq.exe, then
# resources: the Ukrainian interface and the blanked "Send By:". Taking a
# change out is leaving it out of the build, and the result is exact.
#
# Resources are written by Windows itself (UpdateResource). It rebuilds the
# resource section and nothing before it - code and data stay where they are,
# so the offsets of the code patches hold in a translated file as well.

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class IcqRes {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibraryEx(string file, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "FindResourceExW")]
    static extern IntPtr FindResourceEx(IntPtr module, IntPtr type, IntPtr name, ushort lang);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "FindResourceExW")]
    static extern IntPtr FindResourceExNamed(IntPtr module, IntPtr type, string name, ushort lang);
    [DllImport("kernel32.dll")] static extern IntPtr LoadResource(IntPtr module, IntPtr res);
    [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr data);
    [DllImport("kernel32.dll")] static extern uint SizeofResource(IntPtr module, IntPtr res);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr BeginUpdateResource(string file, bool deleteExisting);
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "UpdateResourceW")]
    static extern bool UpdateResource(IntPtr update, IntPtr type, IntPtr name, ushort lang, byte[] data, uint size);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "UpdateResourceW")]
    static extern bool UpdateResourceNamed(IntPtr update, IntPtr type, string name, ushort lang, byte[] data, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool EndUpdateResource(IntPtr update, bool discard);

    // Names: "#123" for a number, anything else for a name.
    static bool IsId(string name, out int id) {
        id = 0;
        return name.StartsWith("#") && int.TryParse(name.Substring(1), out id);
    }

    // The data of each resource, null where the file has none.
    public static byte[][] Read(string file, int[] types, string[] names, int[] langs) {
        var result = new byte[types.Length][];
        IntPtr module = LoadLibraryEx(file, IntPtr.Zero, 0x22);  // as data file, as image resource
        if (module == IntPtr.Zero) return result;
        try {
            for (int i = 0; i < types.Length; i++) {
                int id;
                IntPtr res = IsId(names[i], out id)
                    ? FindResourceEx(module, (IntPtr)types[i], (IntPtr)id, (ushort)langs[i])
                    : FindResourceExNamed(module, (IntPtr)types[i], names[i], (ushort)langs[i]);
                if (res == IntPtr.Zero) continue;
                uint size = SizeofResource(module, res);
                IntPtr p = LockResource(LoadResource(module, res));
                var data = new byte[size];
                Marshal.Copy(p, data, 0, (int)size);
                result[i] = data;
            }
        } finally { FreeLibrary(module); }
        return result;
    }

    public static bool Same(byte[] a, byte[] b) {
        if (a == null || b == null || a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    public static void Write(string file, int[] types, string[] names, int[] langs, byte[][] data) {
        IntPtr update = BeginUpdateResource(file, false);
        if (update == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        for (int i = 0; i < types.Length; i++) {
            int id;
            bool ok = IsId(names[i], out id)
                ? UpdateResource(update, (IntPtr)types[i], (IntPtr)id, (ushort)langs[i], data[i], (uint)data[i].Length)
                : UpdateResourceNamed(update, (IntPtr)types[i], names[i], (ushort)langs[i], data[i], (uint)data[i].Length);
            if (!ok) {
                var e = new System.ComponentModel.Win32Exception();
                EndUpdateResource(update, true);
                throw e;
            }
        }
        if (!EndUpdateResource(update, false)) throw new System.ComponentModel.Win32Exception();
    }
}
'@

# The translated resources, built by ../translate/build.py: gzip, base64.
#_if PSScript
$UkPacked = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ICQ-2003b-uk-UA.txt'))
#_else
#_include_as_value UkPacked "$PSScriptRoot/ICQ-2003b-uk-UA.txt"
#_endif

function Get-Translation {
    if (-not $script:Translation) {
        $ms = New-Object IO.MemoryStream(, [Convert]::FromBase64String($UkPacked))
        $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)
        $t = $reader.ReadToEnd() | ConvertFrom-Json
        $reader.Close()
        # Decoded once: the data of every resource, and a key for each.
        foreach ($f in $t.files.PSObject.Properties) {
            foreach ($it in $f.Value.items) {
                $it | Add-Member Key ('{0}|{1}|{2}' -f $it.t, (Get-ResName $it.n), $it.l)
                $it | Add-Member Bytes ([Convert]::FromBase64String($it.d))
            }
        }
        $sb = $t.sendBy
        $sb | Add-Member Key ('{0}|{1}|{2}' -f $sb.t, (Get-ResName $sb.n), $sb.l)
        # Not En / Uk: names are not case sensitive, and those are the base64 texts.
        $sb | Add-Member BlankEn ([Convert]::FromBase64String($sb.en))
        $sb | Add-Member BlankUk ([Convert]::FromBase64String($sb.uk))
        $script:Translation = $t
    }
    return $script:Translation
}

function Get-ResName($n) { if ($n -is [string]) { return $n } else { return "#$n" } }

function Get-TranslationFiles { return @((Get-Translation).files.PSObject.Properties | ForEach-Object { $_.Name }) }

# Sum through .NET rather than Get-FileHash: old PowerShell lacks the cmdlet.
function Get-Sha256([string]$path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try { $bytes = $sha.ComputeHash($fs) } finally { $fs.Close(); $sha.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '')
}

function Get-BytesSha([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Test-SameBytes([byte[]]$a, [byte[]]$b) { return [IcqRes]::Same($a, $b) }

# The original of a program file: its backup, or the file while it has none.
function Get-OriginalPath([string]$path) {
    $backup = $path + $BinSuffix
    if (Test-Path -LiteralPath $backup) { return $backup }
    return $path
}

# Reads resources of a file by their keys "type|name|lang".
function Read-Resources([string]$path, [string[]]$keys) {
    $parts = @($keys | ForEach-Object { , ($_ -split '\|') })
    # The comma keeps the array of arrays whole: returned bare, PowerShell
    # would unroll it, and one resource would come back as its bytes.
    return , [IcqRes]::Read($path, [int[]]@($parts | ForEach-Object { [int]$_[0] }),
        [string[]]@($parts | ForEach-Object { $_[1] }), [int[]]@($parts | ForEach-Object { [int]$_[2] }))
}

# The "Send By:" words: blank in either language, or as they came.
function Get-SendByState([string]$path) {
    $sb = (Get-Translation).sendBy
    $cur = (Read-Resources $path @($sb.Key))[0]
    if ((Test-SameBytes $cur $sb.BlankEn) -or (Test-SameBytes $cur $sb.BlankUk)) { return 'patched' }
    if ($cur -and (Get-BytesSha $cur) -eq $sb.from) { return 'original' }
    $tr = @((Get-Translation).files.($sb.file).items | Where-Object { $_.Key -eq $sb.Key })
    if ($tr.Count -and (Test-SameBytes $cur $tr[0].Bytes)) { return 'original' }
    return 'unknown'
}

function Get-State($patch) {
    if (-not $script:IcqRoot) { return 'no folder' }
    $path = Join-Path $script:IcqRoot $patch.File
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    # The offsets are right for build 3916 only: the original is recognised by
    # its size, and the change by its bytes - which a translated file keeps in
    # place.
    if ((Get-Item -LiteralPath (Get-OriginalPath $path)).Length -ne $patch.Size) { return 'other version' }
    if ($patch.Resource) { return Get-SendByState $path }
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {
        $len = [Math]::Max($patch.From.Length, $patch.To.Length)
        $buf = New-Object byte[] $len
        $null = $fs.Seek($patch.Offset, 'Begin')
        $null = $fs.Read($buf, 0, $len)
    } finally { $fs.Close() }
    $same = { param($expect)
        for ($i = 0; $i -lt $expect.Length; $i++) { if ($buf[$i] -ne $expect[$i]) { return $false } }
        return $true
    }
    if (& $same $patch.To)   { return 'patched' }
    if (& $same $patch.From) { return 'original' }
    return 'unknown'
}

# Whether a file speaks Ukrainian: all its resources translated, none, or a mix.
function Get-TranslationState([string]$rel) {
    if (-not $script:IcqRoot) { return 'no folder' }
    $path = Join-Path $script:IcqRoot $rel
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    $entry = (Get-Translation).files.$rel
    if ((Get-Item -LiteralPath (Get-OriginalPath $path)).Length -ne $entry.size) { return 'other version' }
    $sb = (Get-Translation).sendBy
    $cur = Read-Resources $path @($entry.items | ForEach-Object { $_.Key })
    $done = 0; $orig = 0
    for ($i = 0; $i -lt $entry.items.Count; $i++) {
        $it = $entry.items[$i]
        $c = $cur[$i]
        $blankUk = $rel -eq $sb.file -and $it.Key -eq $sb.Key -and (Test-SameBytes $c $sb.BlankUk)
        $blankEn = $rel -eq $sb.file -and $it.Key -eq $sb.Key -and (Test-SameBytes $c $sb.BlankEn)
        if ((Test-SameBytes $c $it.Bytes) -or $blankUk) { $done++ }
        elseif ($blankEn -or ($c -and (Get-BytesSha $c) -eq $it.from)) { $orig++ }
    }
    if ($done -eq $entry.items.Count) { return 'patched' }
    if ($orig -eq $entry.items.Count) { return 'original' }
    if ($done -gt 0) { return 'partly' }
    return 'unknown'
}

# --- перенос ссылок ----------------------------------------------------------

function Get-Base([string]$domain) {
    return (Get-PagesRoot $domain) + $PagesPath
}

function Get-UrlHost([string]$url) {
    if ($url -match '^https?://([^/:]+)') { return $Matches[1].ToLower() }
    return ''
}

# Во что превратить ссылку: явное имя, образец адреса, заглушка — или никак.
function Resolve-Target([string]$name, [string]$url, [string]$base) {
    if ($name -and $NamedRoutes.Contains($name)) {
        return $NamedRoutes[$name] -replace '\{base\}', $base
    }
    foreach ($r in $UrlRoutes) {
        if ($url -match $r.Match) { return $r.Target -replace '\{base\}', $base }
    }
    if ($DeadHosts -contains (Get-UrlHost $url)) {
        $leaf = ($url -split '\?')[0].TrimEnd('/')
        $leaf = ($leaf -split '/')[-1]
        if (-not $leaf) { $leaf = 'index' }
        return "$base/stub/$leaf"
    }
    return $null
}

function Convert-LinkText([string]$text, [string]$base, [ref]$count) {
    $n = 0

    # Записи с именем: имя и адрес лежат в одном блоке <item>.
    if ($text -match '<item>') {
        $text = [regex]::Replace($text, '(?s)<item>.*?</item>', {
            param($m)
            $block = $m.Value
            $um = [regex]::Match($block, '(?is)<url>\s*([^<]*?)\s*</url>')
            if (-not $um.Success) { return $block }
            $url = $um.Groups[1].Value
            if ($url -notmatch '^https?://') { return $block }
            $nm = [regex]::Match($block, '(?is)<name>\s*([^<]*?)\s*</name>')
            $name = if ($nm.Success) { $nm.Groups[1].Value } else { '' }
            $new = Resolve-Target $name $url $base
            if (-not $new -or $new -eq $url) { return $block }
            $script:convCount++
            return $block.Substring(0, $um.Groups[1].Index) + $new +
                   $block.Substring($um.Groups[1].Index + $um.Groups[1].Length)
        })
    }

    # Всё остальное: адреса в других тегах, в атрибутах, в полях WebSearch.fld.
    # Трогаем только мёртвые хосты, поэтому чужого не заденем.
    $text = [regex]::Replace($text, 'https?://[^\s"''<>\]]+', {
        param($m)
        $url = $m.Value
        if ($DeadHosts -notcontains (Get-UrlHost $url)) { return $url }
        $new = Resolve-Target '' $url $base
        if (-not $new -or $new -eq $url) { return $url }
        $script:convCount++
        return $new
    })

    return $text
}

function Get-LinkState($rel) {
    if (-not $script:IcqRoot) { return @{ State = 'no folder'; Info = '' } }
    $path = Join-Path $script:IcqRoot $rel
    if (-not (Test-Path -LiteralPath $path)) { return @{ State = 'missing'; Info = '' } }
    $text = [IO.File]::ReadAllText($path, $Latin1)
    $urls = [regex]::Matches($text, 'https?://[^\s"''<>\]]+')
    $dead = 0
    foreach ($m in $urls) { if ($DeadHosts -contains (Get-UrlHost $m.Value)) { $dead++ } }
    $state = if ($urls.Count -eq 0) { 'no links' } elseif ($dead -gt 0) { 'original' } else { 'patched' }
    return @{ State = $state; Info = "$($urls.Count) links, $dead dead" }
}

# --- applying -----------------------------------------------------------------

function Get-StringAt([string]$path, [int]$offset, [int]$len) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {
        $buf = New-Object byte[] $len
        $null = $fs.Seek($offset, 'Begin')
        $null = $fs.Read($buf, 0, $len)
    } finally { $fs.Close() }
    $text = [Text.Encoding]::ASCII.GetString($buf)
    $z = $text.IndexOf([char]0)
    if ($z -ge 0) { $text = $text.Substring(0, $z) }
    return $text
}

function Get-StringState($sp) {
    if (-not $script:IcqRoot) { return 'no folder' }
    $path = Join-Path $script:IcqRoot $sp.File
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    $cur = Get-StringAt $path $sp.Offset $sp.Original.Length
    if ($cur -eq $sp.Original) { return 'original' }
    if ($cur -match '^https?://') { return 'patched' }
    return 'other version'
}

# Backs a program file up once, before its first change: while it has no
# backup, the file is still the original.
function Backup-Bin([string]$path) {
    $backup = $path + $BinSuffix
    if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $path -Destination $backup }
}

# Every program file the patch may change.
function Get-BinaryFiles {
    return @(@($Patches | ForEach-Object { $_.File }) + @($StringPatches | ForEach-Object { $_.File }) +
        @(Get-TranslationFiles) | Select-Object -Unique)
}

# Builds one program file from its original with the wanted changes, and
# writes it if it came out different. The links that did not fit are added to
# $tooLong.
function Build-Binary([string]$rel, [string]$domain, $skip, $tooLong) {
    $path = Join-Path $script:IcqRoot $rel
    if (-not (Test-Path -LiteralPath $path)) { return }
    $bytes = [IO.File]::ReadAllBytes((Get-OriginalPath $path))

    foreach ($p in @($Patches | Where-Object { $_.File -eq $rel -and -not $_.Resource })) {
        if ((Test-Wanted $skip $p.What) -and $bytes.Length -eq $p.Size) {
            [Array]::Copy($p.To, 0, $bytes, $p.Offset, $p.To.Length)
        }
    }

    # Для зашитых строк берём только корень адреса: место в файле ограничено
    # длиной исходной ссылки, и каждый символ на счету.
    $root = Get-PagesRoot $domain
    foreach ($sp in @($StringPatches | Where-Object { $_.File -eq $rel })) {
        if (-not (Test-Wanted $skip $sp.What)) { continue }
        $url = $root + $sp.Path
        if ($url.Length -gt $sp.Original.Length) {
            $tooLong.Add(('{0} (needs {1}, room for {2})' -f $sp.Path, $url.Length, $sp.Original.Length))
            continue
        }
        $new = [Text.Encoding]::ASCII.GetBytes($url)
        for ($i = 0; $i -lt $sp.Original.Length; $i++) {
            $bytes[$sp.Offset + $i] = if ($i -lt $new.Length) { $new[$i] } else { 0 }
        }
    }

    # The resources, by key; a later one for the same key wins.
    $res = [ordered]@{}
    $tr = Get-Translation
    $entry = $tr.files.$rel
    $ukrainian = $entry -and (Test-Wanted $skip "uk:$rel") -and $bytes.Length -eq $entry.size
    if ($ukrainian) { foreach ($it in $entry.items) { $res[$it.Key] = $it.Bytes } }
    $words = @($Patches | Where-Object { $_.Resource -eq 'sendBy' })[0]
    if ($rel -eq $tr.sendBy.file -and (Test-Wanted $skip $words.What) -and $bytes.Length -eq $words.Size) {
        $res[$tr.sendBy.Key] = if ($ukrainian) { $tr.sendBy.BlankUk } else { $tr.sendBy.BlankEn }
    }

    $tmp = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllBytes($tmp, $bytes)
        if ($res.Count) {
            $parts = @($res.Keys | ForEach-Object { , ($_ -split '\|') })
            [IcqRes]::Write($tmp, [int[]]@($parts | ForEach-Object { [int]$_[0] }),
                [string[]]@($parts | ForEach-Object { $_[1] }), [int[]]@($parts | ForEach-Object { [int]$_[2] }),
                [byte[][]]@($res.Values))
        }
        $built = [IO.File]::ReadAllBytes($tmp)
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

    if (-not (Test-SameBytes $built ([IO.File]::ReadAllBytes($path)))) {
        Backup-Bin $path
        [IO.File]::WriteAllBytes($path, $built)
    }
}

#_if PSScript
. (Join-Path $PSScriptRoot '..\..\common\PatchItems.ps1')
#_else
#_include "$PSScriptRoot/../../common/PatchItems.ps1"
#_endif

# What a person chooses between: one row per job, whatever number of files
# and places it takes.
$Jobs = [ordered]@{
    'banners'    = @{ Group = 'Advertising'; What = 'the banners of the contact list and the message window' }
    'google bar' = @{ Group = 'Advertising'; What = 'the Google search bar and the strip kept for it' }
    'send-by'    = @{ Group = 'Services that are gone'; What = 'the "Send By: ICQ / SMS / Email" strip of the message window' }
    'links'      = @{ Group = 'Your server'; What = 'ICQ.com links in menus and help point at your server' }
    'sign-in'    = @{ Group = 'Your server'; What = 'ICQ signs in to your server, "Get an ICQ Number" too' }
    # Off until chosen: not everyone wants the client in another language.
    'ukrainian'  = @{ Group = 'Language'; What = 'Ukrainian interface: menus, windows and messages'; Off = $true }
}
$JobOf = @{ 'sign-in' = 'sign-in' }
foreach ($p in $Patches) { if ($p.Job) { $JobOf[$p.What] = $p.Job } }
foreach ($f in Get-TranslationFiles) { $JobOf["uk:$f"] = 'ukrainian' }
foreach ($sp in $StringPatches) { $JobOf[$sp.What] = 'links' }
foreach ($rel in $LinkFiles) { $JobOf[$rel] = 'links' }

# Every change with its current state, in the order the window lists them,
# the parts of one job folded into one row. A row's key is what it is chosen
# by: the job, or the change itself.
function Get-Items([string]$domain) {
    $items = New-Object System.Collections.Generic.List[object]
    $add = { param($group, $key, $what, $where, $state)
        $items.Add([pscustomobject]@{ Group = $group; Key = $key; What = $what; Where = $where; State = $state })
    }
    foreach ($p in $Patches) {
        & $add 'Code' $p.What $p.What ('{0} at 0x{1:X}' -f $p.File, $p.Offset) (Get-State $p)
    }
    foreach ($sp in $StringPatches) {
        & $add 'Links inside the executable' $sp.What $sp.What ('{0} at 0x{1:X}' -f $sp.File, $sp.Offset) (Get-StringState $sp)
    }
    foreach ($rel in $LinkFiles) {
        $name = [IO.Path]::GetFileName($rel)
        & $add 'Links' $rel "menu items in $name point at your server" $name (Get-LinkState $rel).State
    }
    $shown = Get-ConnectionServer
    if (-not $shown) { $shown = Get-SignInServer }
    if (-not $shown) { $shown = '(not set)' }
    & $add 'Sign-in server' 'sign-in' 'ICQ signs in to your server' "now $shown" (Get-SignInState $domain (Get-SavedBase))
    foreach ($f in Get-TranslationFiles) { & $add 'Language' "uk:$f" "uk:$f" $f (Get-TranslationState $f) }
    return Merge-Jobs $items
}

# Makes the client match the selection. Returns what changed, one line per
# change, and the links that did not fit.
function Invoke-ApplyAll([string]$domain, [string]$previous, $skip) {
    $wrong = @($Patches | Where-Object { (Test-Wanted $skip $_.What) -and (Get-State $_) -eq 'other version' } |
        ForEach-Object { $_.File } | Select-Object -Unique)
    if ($wrong.Count -gt 0) {
        throw ("These files do not match ICQ Pro 2003b build 3916:`n`n  " + ($wrong -join "`n  ") +
            "`n`nThe code patches are tied to exact offsets in that build. Applying them to " +
            "another version would overwrite unrelated code, so nothing was changed.")
    }
    $binaries = @(Get-BinaryFiles)
    Start-PatchSteps ($binaries.Count + 4)
    Step-Patch 'Checking the client...'
    $before = Get-Items $domain

    $tooLong = New-Object System.Collections.Generic.List[string]
    foreach ($rel in $binaries) {
        Step-Patch "Building $rel..."
        Build-Binary $rel $domain $skip $tooLong
    }
    Step-Patch 'Links in DataFiles...'

    $base = Get-Base $domain
    foreach ($rel in $LinkFiles) {
        $path = Join-Path $script:IcqRoot $rel
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $backup = $path + $LinkSuffix
        if (-not (Test-Wanted $skip $rel)) {
            if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $path -Force }
            continue
        }
        if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $path -Destination $backup }
        $script:convCount = 0
        $text = [IO.File]::ReadAllText($path, $Latin1)
        # Links pointed at a previous server move to the new one as they are;
        # the rest is converted from ICQ.com as before.
        if ($previous -and $previous -ne $domain) {
            $old = Get-PagesRoot $previous
            $n = ([regex]::Matches($text, [regex]::Escape($old))).Count
            if ($n) { $text = $text.Replace($old, (Get-PagesRoot $domain)); $script:convCount += $n }
        }
        $text = Convert-LinkText $text $base ([ref]$null)
        if ($script:convCount -gt 0) { [IO.File]::WriteAllText($path, $text, $Latin1) }
    }

    Step-Patch 'Sign-in server...'
    if ($NoRegistry) {
    } elseif (Test-Wanted $skip 'sign-in') {
        [void](Set-SignInServer $domain $previous)
    } else {
        try { [void](Restore-SignInServer) } catch { }
    }

    $lines = New-Object System.Collections.Generic.List[string]
    Step-Patch 'Checking the result...'
    $after = Get-Items $domain
    for ($i = 0; $i -lt $after.Count; $i++) {
        if ($after[$i].State -eq $before[$i].State) { continue }
        if ($after[$i].State -eq 'patched') { $lines.Add('applied: ' + $after[$i].What) }
        else { $lines.Add('taken out: ' + $after[$i].What) }
    }
    return @{ Lines = $lines; TooLong = @($tooLong) }
}

function Invoke-RestoreAll {
    $done = 0
    $binaries = @(Get-BinaryFiles)
    Start-PatchSteps ($binaries.Count + $LinkFiles.Count + 1)
    foreach ($f in $binaries) {
        Step-Patch "Restoring $f..."
        $path = Join-Path $script:IcqRoot $f
        $backup = $path + $BinSuffix
        if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $path -Force; $done++ }
    }
    foreach ($rel in $LinkFiles) {
        Step-Patch "Restoring $rel..."
        $path = Join-Path $script:IcqRoot $rel
        $backup = $path + $LinkSuffix
        if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $path -Force; $done++ }
    }
    Step-Patch 'Sign-in server...'
    if (-not $NoRegistry) { $done += Restore-SignInServer }
    return $done
}

# --- scripted run -------------------------------------------------------------

if ($Apply -or $Restore) {
    $script:IcqRoot = if ($Root) { [IO.Path]::GetFullPath($Root) } else { Find-IcqRoot }
    if (-not (Test-IcqFolder $script:IcqRoot)) { Write-Error "ICQ Pro 2003b folder not found: $($script:IcqRoot)"; exit 1 }
    if ($Restore) {
        Write-Output "files restored: $(Invoke-RestoreAll)"
        exit 0
    }
    $previous = Get-SavedBase
    $domain = if ($Server) { Get-Domain $Server } else { $previous }
    if (-not (Test-Domain $domain)) { Write-Error "not a domain: '$Server' - pass -Server icq.example.org"; exit 1 }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($k in $Skip) { [void]$set.Add($k) }
    foreach ($k in $Jobs.Keys) { if ($Jobs[$k].Off -and $Include -notcontains $k) { [void]$set.Add($k) } }
    try {
        $result = Invoke-ApplyAll $domain $previous $set
    } catch {
        Write-Error $_.Exception.Message
        exit 1
    }
    foreach ($line in $result.Lines) { Write-Output $line }
    foreach ($t in $result.TooLong) { Write-Output "did not fit: $t" }
    Write-Output "changes made: $($result.Lines.Count)"
    exit 0
}

function Test-Ready {
    if (-not $script:IcqRoot) {
        [Windows.Forms.MessageBox]::Show(
            "ICQ Pro 2003b folder not found.`n`nPut this tool into the ICQ folder, or pick the folder manually.",
            'Client not found', 'OK', 'Error') | Out-Null
        return $false
    }
    $p = Get-Process Icq -ErrorAction SilentlyContinue
    if ($p) {
        [Windows.Forms.MessageBox]::Show(
            "ICQ is running. Close it properly: tray icon -> Exit.`n`n" +
            "Do not kill the process: the client leaves its contact list cache half-written and then hangs forever on ""Logging in...""",
            'Close ICQ first', 'OK', 'Warning') | Out-Null
        return $false
    }
    return $true
}

function Invoke-Apply {
    if (-not (Test-Ready)) { return }
    # Checked before anything is written.
    $domain = Get-Domain $ui.Server.Text
    if (-not (Test-Domain $domain)) {
        [Windows.Forms.MessageBox]::Show(
            "Type your server's domain, nothing else:`n`n  icq.example.org`n`nThe port and path are filled in by the patch.",
            'Server', 'OK', 'Warning') | Out-Null
        return
    }
    $ui.Server.Text = $domain
    Save-PatchUnchecked $ui $SettingsKey
    Start-PatchWork $ui 'Applying...'
    try {
        $result = Invoke-ApplyAll $domain (Get-SavedBase) $ui.Unchecked
    } catch {
        Stop-PatchWork $ui
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Wrong client version', 'OK', 'Error') | Out-Null
        Update-View
        return
    }
    Stop-PatchWork $ui
    Save-Base $domain
    Update-View

    $done = $result.Lines
    $msg = if ($done.Count) { "Changes made: $($done.Count)`n`n  " + (@($done | Select-Object -First 12) -join "`n  ") } else { 'The client already matches the selection.' }
    if ($done.Count -gt 12) { $msg += "`n  ..." }
    if ($result.TooLong.Count -gt 0) {
        $msg += "`n`nThese did not fit and were left alone:`n  " + ($result.TooLong -join "`n  ") +
                "`n`nA link stored inside the executable cannot be made longer than the original," +
                " so a shorter server address would fix it."
    }
    if ((Test-PatchSelected $ui 'sign-in') -and (Get-SignInServer) -eq $domain) {
        $c = Get-ConnectionServer
        if ($c -and $c -ne $domain) {
            $msg += "`n`nICQ is set to sign in to $c under Preferences -> Connection," +
                    " which looks like your own choice, so it was left alone. Change it there" +
                    " to $domain to sign in to this server."
        } else {
            $msg += "`n`nICQ signs in to $domain."
        }
    }
    $msg += "`n`nYou can start ICQ now."
    [Windows.Forms.MessageBox]::Show($msg, 'Done', 'OK', 'Information') | Out-Null
}

function Invoke-Restore {
    if (-not (Test-Ready)) { return }
    Start-PatchWork $ui 'Restoring...'
    try { $done = Invoke-RestoreAll } finally { Stop-PatchWork $ui }
    Update-View
    [Windows.Forms.MessageBox]::Show("Files restored: $done.", 'Done', 'OK', 'Information') | Out-Null
}

function Select-Folder {
    $dlg = New-Object Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Select the ICQ Pro 2003b folder (the one with Icq.exe)'
    if ($script:IcqRoot) { $dlg.SelectedPath = $script:IcqRoot }
    if ($dlg.ShowDialog() -ne 'OK') { return }
    if (Test-IcqFolder $dlg.SelectedPath) {
        $script:IcqRoot = $dlg.SelectedPath
        Update-View
    } else {
        [Windows.Forms.MessageBox]::Show(
            "This folder does not look like ICQ Pro 2003b.`n`nExpected files: " + (($Patches.File) -join ', '),
            'Wrong folder', 'OK', 'Warning') | Out-Null
    }
}

# --- окно -------------------------------------------------------------------

#_if PSScript
. (Join-Path $PSScriptRoot '..\..\common\PatchWindow.ps1')
#_else
#_include "$PSScriptRoot/../../common/PatchWindow.ps1"
#_endif

$ui = New-PatchWindow -Title 'ICQ Pro 2003b Patch' -Badge '2003b' -AccentTop '#4FA3E0' -AccentBottom '#1F66B0' `
    -ClientName 'ICQ Pro 2003b' `
    -Subtitle 'Removes the banners, the Google search bar and the empty strip they occupied, and points the menu items that used to open ICQ.com at your own server. The user database and the skin are left untouched.' `
    -ServerHint 'Just the domain, e.g. icq.example.org. The patch fills in the port and path, and new accounts sign in there. Remembered for next time.' `
    -Columns @(@('Change', 400), @('Where', 210))

function Update-View {
    Set-PatchFolder $ui $script:IcqRoot
    Clear-PatchList $ui
    if ($script:IcqRoot) {
        $groups = @{}
        foreach ($it in Get-Items (Get-Domain $ui.Server.Text)) {
            if (-not $groups.ContainsKey($it.Group)) { $groups[$it.Group] = Add-PatchGroup $ui $it.Group }
            Add-PatchRow $ui $groups[$it.Group] @($it.What, $it.Where) $it.State $it.Key
        }
    }
    Complete-PatchList $ui
}

$ui.FolderButton.Add_Click({ Select-Folder })
$saved = Get-SavedBase
if ($saved) { $ui.Server.Text = $saved }
Read-PatchUnchecked $ui $SettingsKey @($Jobs.Keys | Where-Object { $Jobs[$_].Off })
$ui.Server.Add_Leave({ Update-View })

[void](Add-PatchButton $ui 'Close' { $ui.Form.Close() })
[void](Add-PatchButton $ui 'Apply' { Invoke-Apply } -Primary)
[void](Add-PatchButton $ui 'Restore original' { Invoke-Restore })
[void](Add-PatchButton $ui 'Re-check' { Update-View })

Update-View
Show-PatchWindow $ui
