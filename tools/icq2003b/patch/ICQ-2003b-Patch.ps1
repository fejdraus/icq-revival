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
#   ICQ-2003b-Patch.ps1 -Apply   [-Root <folder>] [-Server <domain>] [-Skip <keys>]
#   ICQ-2003b-Patch.ps1 -Restore [-Root <folder>]
#
# The window is the one all client patches share, ../../common/PatchWindow.ps1.
# Built into ICQ-2003b-Patch.exe, with its icon, by ../../common/Build-Patches.ps1.

param(
    [switch]$Apply,
    [switch]$Restore,
    [string]$Root,
    [string]$Server,
    # Changes to leave out - or take out, if in place - by the names the
    # window lists them under (the link file's path, sign-in for that row).
    [string[]]$Skip
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
    }
    [pscustomobject]@{
        File = 'ICQProLib.dll'; Offset = 0x1217B
        From = [byte[]](0xB8,0xBA,0x7D,0x89,0x24)
        To   = [byte[]](0x31,0xC0,0xC3)
        Size = 198739
        Sha256From = '192941271B7B50BC9298B665C2C1F0C9F3F74E2AF43FAFF3C0FE0F0E082A31A3'
        Sha256To   = '631780FABA446E9AB5598D88B45296A626F373DAFAA275D828B1920692EC139E'
        What = 'message window banner is never shown'
    }
    [pscustomobject]@{
        File = 'ICQTicker.dll'; Offset = 0x750
        From = [byte[]](0x53,0x55,0x8B,0x6C,0x24,0x14,0x56)
        To   = [byte[]](0xB8,0x11,0x01,0x04,0x80,0xC2,0x0C,0x00)
        Size = 37977
        Sha256From = '92058B9563288A066DC4884E68930BB67F78A6D10AD8BAB8BD0F8287FB847A39'
        Sha256To   = '2E901493EFB3914273DDD952159B3135FD959A8FC2F0DB8DD67EFDE875D031FF'
        What = 'Google search bar and its button are gone'
    }
    [pscustomobject]@{
        File = 'Icq.exe'; Offset = 0x39AA2
        From = [byte[]](0x74,0x41)
        To   = [byte[]](0xEB,0x41)
        Size = 1880639
        Sha256From = '6C97F1B8045ED6E6801E0AFD97548B040819F153836B25B0F968184483F1546A'
        Sha256To   = 'BE8AEA553DCABA7108E3442EEEBAA5F00A56A2BE78653290EFFF6A83DF5F0B1B'
        What = 'no empty strip reserved for them'
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
        Link = 'send-by boxes'
    }
    [pscustomobject]@{
        File = 'ICQMessagePlugin.dll'; Offset = 0x7B84
        From = [byte[]](0x83,0xC7,0x05)
        To   = [byte[]](0x31,0xFF,0x90)
        Size = 236144
        Sha256From = 'AFC36BD67D353EECA1F952C3ED56D372FE93C018D58C966F0A930EDEE5AC887B'
        Sha256To   = 'E40BEEE28D67ECACA0A10182F215CB2901F8CD4A56F85C667C0AE8E09E18E486'
        What = 'the same for the group around them'
        Link = 'send-by boxes'
    }
    [pscustomobject]@{
        # Second layer: the words. There is no control behind them - a walk of
        # the open window shows none - the skin paints them from this string,
        # so only the string itself can be changed. Same length, spaces: the
        # table keeps lengths separately and nothing may shift.
        File = 'Icq.exe'; Offset = 0x1C489C
        From = [Text.Encoding]::Unicode.GetBytes('Send By:')
        To   = [Text.Encoding]::Unicode.GetBytes('        ')
        Size = 1880639
        Sha256From = '85F31E2FB53366F1FCC03D16788E50E6932AE2BB3F13C10C3242F1D68AD68684'
        Sha256To   = '64EA6C32386A04D71B873522EF3A2662E074EB048AF584459F9E8492DC4F0EBA'
        What = 'the words "Send By:" are gone'
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
        Link = 'send-by frame'
    }
    [pscustomobject]@{
        File = 'Skin\IcqPro.skn'; Offset = 0x41782
        From = [byte[]](0x88,0x00,0x00,0x00)
        To   = [byte[]](0x58,0x01,0x00,0x00)
        Size = 423358
        Sha256From = 'B9E7997D2E60A5E172F09376550596B61C871A45B9804243F23F07D2B14CECD0'
        Sha256To   = '5E126B5C13CF0400FAAF43BBA6631E497F70EC7C85C41B5645BBB5F700CA2370'
        What = 'its rectangle follows the offset'
        Link = 'send-by frame'
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
# The server ICQ 2003b gives a new account and connects to for "Get an ICQ
# Number". Out of the box it is login.icq.com, which is gone, so registering a
# number from the client failed with "Info Number 117". An account that already
# exists keeps the server in its own settings; this is only the default a new
# one starts from. The port stays 5190, as it is there already.

$DefaultPrefsKeys = @(
    'HKLM:\SOFTWARE\WOW6432Node\Mirabilis\ICQ\ICQPro\DefaultPrefs'   # 64-bit Windows
    'HKLM:\SOFTWARE\Mirabilis\ICQ\ICQPro\DefaultPrefs'               # 32-bit Windows
)
$SignInValue = 'Default Server Host'

function Get-DefaultPrefsKey {
    foreach ($k in $DefaultPrefsKeys) { if (Test-Path -LiteralPath $k) { return $k } }
    return $null
}

function Get-SignInServer {
    $k = Get-DefaultPrefsKey
    if (-not $k) { return $null }
    try { return (Get-ItemProperty -LiteralPath $k -ErrorAction Stop).$SignInValue } catch { return $null }
}

# Remembers what the client came with - once, so a second apply does not save
# our own domain as the "original" - and puts the domain in its place.
function Set-SignInServer([string]$domain) {
    $k = Get-DefaultPrefsKey
    if (-not $k) { return $false }
    $current = Get-SignInServer
    if ($current -eq $domain) { return $false }
    try {
        if (-not (Test-Path $SettingsKey)) { New-Item -Path $SettingsKey -Force | Out-Null }
        $saved = (Get-ItemProperty -LiteralPath $SettingsKey -ErrorAction SilentlyContinue).OriginalServerHost
        if (-not $saved) { Set-ItemProperty -LiteralPath $SettingsKey -Name OriginalServerHost -Value "$current" }
        Set-ItemProperty -LiteralPath $k -Name $SignInValue -Value $domain -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Restore-SignInServer {
    $k = Get-DefaultPrefsKey
    if (-not $k) { return 0 }
    try {
        $saved = (Get-ItemProperty -LiteralPath $SettingsKey -ErrorAction Stop).OriginalServerHost
    } catch { return 0 }
    if (-not $saved) { return 0 }
    # The saved original is only let go once it is back in place.
    try { Set-ItemProperty -LiteralPath $k -Name $SignInValue -Value $saved -ErrorAction Stop } catch { return 0 }
    Remove-ItemProperty -LiteralPath $SettingsKey -Name OriginalServerHost -ErrorAction SilentlyContinue
    return 1
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

# --- состояние правок кода ---------------------------------------------------

# Сумма считается средствами .NET, а не Get-FileHash: этого командлета нет
# в старых сборках PowerShell, а патч должен работать и там.
function Get-Sha256([string]$path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try { $bytes = $sha.ComputeHash($fs) } finally { $fs.Close(); $sha.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '')
}

function Get-State($patch) {
    if (-not $script:IcqRoot) { return 'no folder' }
    $path = Join-Path $script:IcqRoot $patch.File
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }

    # Сверка по контрольной сумме: смещения верны только для этой сборки, на
    # другой по тем же адресам лежит чужой код. Если сумма не сошлась, файл
    # мог быть изменён нами же — заменой зашитых адресов, — поэтому запасной
    # признак версии это размер плюс ожидаемые байты по смещению.
    $hash = Get-Sha256 $path
    if ($hash -eq $patch.Sha256To)   { return 'patched' }
    if ($hash -ne $patch.Sha256From) {
        if ((Get-Item -LiteralPath $path).Length -ne $patch.Size) { return 'other version' }
    }
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

# --- применение --------------------------------------------------------------


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

# Backs a binary up once, before its first change.
function Backup-Bin([string]$path) {
    $backup = $path + $BinSuffix
    if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $path -Destination $backup }
}

# Puts back the original bytes of one place in a binary, from its backup.
function Restore-Bytes([string]$path, [int]$offset, [int]$len) {
    $backup = $path + $BinSuffix
    if (-not (Test-Path -LiteralPath $backup)) { return $false }
    $orig = [IO.File]::ReadAllBytes($backup)
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($orig.Length -ne $bytes.Length) { return $false }
    [Array]::Copy($orig, $offset, $bytes, $offset, $len)
    [IO.File]::WriteAllBytes($path, $bytes)
    return $true
}

# Returns the addresses that did not fit into the original string.
function Set-StringPatches([string]$base, $skip) {
    $tooLong = @()
    foreach ($sp in $StringPatches) {
        if (-not (Test-Wanted $skip $sp.What)) { continue }
        $path = Join-Path $script:IcqRoot $sp.File
        if (-not (Test-Path -LiteralPath $path)) { continue }
        # Для зашитых строк берём только корень адреса: место в файле
        # ограничено длиной исходной ссылки, и каждый символ на счету.
        $root = if ($base -match '^(https?://[^/]+)') { $Matches[1] } else { $base }
        $url = $root + $sp.Path
        if ($url.Length -gt $sp.Original.Length) {
            $tooLong += ('{0} (needs {1}, room for {2})' -f $sp.Path, $url.Length, $sp.Original.Length)
            continue
        }
        if ((Get-StringAt $path $sp.Offset $sp.Original.Length) -ceq $url) { continue }
        Backup-Bin $path
        $bytes = [IO.File]::ReadAllBytes($path)
        $new = [Text.Encoding]::ASCII.GetBytes($url)
        for ($i = 0; $i -lt $sp.Original.Length; $i++) {
            $bytes[$sp.Offset + $i] = if ($i -lt $new.Length) { $new[$i] } else { 0 }
        }
        [IO.File]::WriteAllBytes($path, $bytes)
    }
    return $tooLong
}

# Whether a change is wanted: all of them, unless a key is in $skip - the
# rows cleared in the window.
function Test-Wanted($skip, [string]$key) { return -not ($skip -and $skip.Contains($key)) }

# Every change with its current state, in the order the window lists them.
# The key names a change for the selection; rows with the same Link are one
# change and are ticked together.
function Get-Items([string]$domain) {
    $items = New-Object System.Collections.Generic.List[object]
    $add = { param($group, $key, $what, $where, $state, $link)
        $items.Add([pscustomobject]@{ Group = $group; Key = $key; What = $what; Where = $where; State = $state; Link = $link })
    }
    foreach ($p in $Patches) {
        & $add 'Code' $p.What $p.What ('{0} at 0x{1:X}' -f $p.File, $p.Offset) (Get-State $p) $p.Link
    }
    foreach ($sp in $StringPatches) {
        & $add 'Links inside the executable' $sp.What $sp.What ('{0} at 0x{1:X}' -f $sp.Path, $sp.Offset) (Get-StringState $sp) ''
    }
    foreach ($rel in $LinkFiles) {
        $s = Get-LinkState $rel
        $name = [IO.Path]::GetFileName($rel)
        $where = if ($s.Info) { "$name, $($s.Info)" } else { $name }
        & $add 'Links' $rel "menu items in $name point at your server" $where $s.State ''
    }
    $current = Get-SignInServer
    $state = if (-not (Get-DefaultPrefsKey)) { 'missing' } elseif ($domain -and $current -eq $domain) { 'patched' } else { 'original' }
    $shown = if ($current) { $current } else { '(not set)' }
    & $add 'Sign-in server' 'sign-in' 'new accounts and "Get an ICQ Number" connect to your server' "Default Server Host, now $shown" $state ''
    return $items
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
    $before = Get-Items $domain

    foreach ($p in $Patches) {
        $path = Join-Path $script:IcqRoot $p.File
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $state = Get-State $p
        if (Test-Wanted $skip $p.What) {
            if ($state -ne 'original') { continue }
            Backup-Bin $path
            $bytes = [IO.File]::ReadAllBytes($path)
            [Array]::Copy($p.To, 0, $bytes, $p.Offset, $p.To.Length)
            [IO.File]::WriteAllBytes($path, $bytes)
        } elseif ($state -eq 'patched') {
            # The new code may be longer than the old; the backup has every
            # byte it covered.
            $len = [Math]::Max($p.From.Length, $p.To.Length)
            if (-not (Restore-Bytes $path $p.Offset $len) -and $p.From.Length -eq $p.To.Length) {
                $bytes = [IO.File]::ReadAllBytes($path)
                [Array]::Copy($p.From, 0, $bytes, $p.Offset, $p.From.Length)
                [IO.File]::WriteAllBytes($path, $bytes)
            }
        }
    }

    # Зашитые в код адреса — до правки ссылок: обе части пишут в Icq.exe.
    $base = Get-Base $domain
    $tooLong = Set-StringPatches $base $skip
    foreach ($sp in $StringPatches) {
        if ((Test-Wanted $skip $sp.What) -or (Get-StringState $sp) -ne 'patched') { continue }
        $path = Join-Path $script:IcqRoot $sp.File
        $bytes = [IO.File]::ReadAllBytes($path)
        $orig = [Text.Encoding]::ASCII.GetBytes($sp.Original)
        [Array]::Copy($orig, 0, $bytes, $sp.Offset, $orig.Length)
        [IO.File]::WriteAllBytes($path, $bytes)
    }

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

    if (Test-Wanted $skip 'sign-in') {
        [void](Set-SignInServer $domain)
    } else {
        try { [void](Restore-SignInServer) } catch { }
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $after = Get-Items $domain
    for ($i = 0; $i -lt $after.Count; $i++) {
        if ($after[$i].State -eq $before[$i].State) { continue }
        if ($after[$i].State -eq 'patched') { $lines.Add('applied: ' + $after[$i].What) }
        else { $lines.Add('taken out: ' + $after[$i].What) }
    }
    return @{ Lines = $lines; TooLong = $tooLong }
}

function Invoke-RestoreAll {
    $done = 0
    foreach ($f in @($Patches.File) + @($StringPatches.File) | Select-Object -Unique) {
        $path = Join-Path $script:IcqRoot $f
        $backup = $path + $BinSuffix
        if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $path -Force; $done++ }
    }
    foreach ($rel in $LinkFiles) {
        $path = Join-Path $script:IcqRoot $rel
        $backup = $path + $LinkSuffix
        if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $path -Force; $done++ }
    }
    $done += Restore-SignInServer
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
    try {
        $result = Invoke-ApplyAll $domain (Get-SavedBase) $ui.Unchecked
    } catch {
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Wrong client version', 'OK', 'Error') | Out-Null
        Update-View
        return
    }
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
        $msg += "`n`nNew accounts and ""Get an ICQ Number"" connect to $domain." +
                " An account that exists already keeps its own server: set it under" +
                " the connection settings of that account."
    }
    $msg += "`n`nYou can start ICQ now."
    [Windows.Forms.MessageBox]::Show($msg, 'Done', 'OK', 'Information') | Out-Null
}

function Invoke-Restore {
    if (-not (Test-Ready)) { return }
    $done = Invoke-RestoreAll
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
            Add-PatchRow $ui $groups[$it.Group] @($it.What, $it.Where) $it.State $it.Key $it.Link
        }
    }
    Complete-PatchList $ui
}

$ui.FolderButton.Add_Click({ Select-Folder })
$saved = Get-SavedBase
if ($saved) { $ui.Server.Text = $saved }
Read-PatchUnchecked $ui $SettingsKey
$ui.Server.Add_Leave({ Update-View })

[void](Add-PatchButton $ui 'Close' { $ui.Form.Close() })
[void](Add-PatchButton $ui 'Apply' { Invoke-Apply } -Primary)
[void](Add-PatchButton $ui 'Restore original' { Invoke-Restore })
[void](Add-PatchButton $ui 'Re-check' { Update-View })

Update-View
Show-PatchWindow $ui
