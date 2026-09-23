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
# Собирается в exe: Invoke-ps2exe .\IcqPatch.ps1 .\IcqPatch.exe
#                    -noConsole -requireAdmin -title 'ICQ Pro 2003b Patch'

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
    }
    [pscustomobject]@{
        File = 'ICQMessagePlugin.dll'; Offset = 0x7B84
        From = [byte[]](0x83,0xC7,0x05)
        To   = [byte[]](0x31,0xFF,0x90)
        Size = 236144
        Sha256From = 'AFC36BD67D353EECA1F952C3ED56D372FE93C018D58C966F0A930EDEE5AC887B'
        Sha256To   = 'E40BEEE28D67ECACA0A10182F215CB2901F8CD4A56F85C667C0AE8E09E18E486'
        What = 'the same for the group around them'
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
    }
    [pscustomobject]@{
        File = 'Skin\IcqPro.skn'; Offset = 0x41782
        From = [byte[]](0x88,0x00,0x00,0x00)
        To   = [byte[]](0x58,0x01,0x00,0x00)
        Size = 423358
        Sha256From = 'B9E7997D2E60A5E172F09376550596B61C871A45B9804243F23F07D2B14CECD0'
        Sha256To   = '5E126B5C13CF0400FAAF43BBA6631E497F70EC7C85C41B5645BBB5F700CA2370'
        What = 'its rectangle follows the offset'
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

$DefaultBase = 'https://chat.example.ts.net:8102/icq'

# Введённый адрес запоминается, чтобы не вбивать его при каждом запуске.
$SettingsKey = 'HKCU:\Software\OpenOSCAR\IcqPatch'

function Get-SavedBase {
    try { return (Get-ItemProperty -LiteralPath $SettingsKey -ErrorAction Stop).ServerBase } catch { return $null }
}

function Save-Base([string]$value) {
    try {
        if (-not (Test-Path $SettingsKey)) { New-Item -Path $SettingsKey -Force | Out-Null }
        Set-ItemProperty -LiteralPath $SettingsKey -Name ServerBase -Value $value
    } catch { }
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
            if ($d.UninstallString) { $candidates.Add([IO.Path]::GetDirectoryName($d.UninstallString.Trim('"'))) }
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

function Get-Base {
    $b = $txtBase.Text.Trim().TrimEnd('/')
    if ($b) { return $b }
    return $DefaultBase
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

# Возвращает список адресов, которые не влезли в исходную строку.
function Set-StringPatches([string]$base) {
    $tooLong = @()
    foreach ($sp in $StringPatches) {
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
        $bytes = [IO.File]::ReadAllBytes($path)
        $new = [Text.Encoding]::ASCII.GetBytes($url)
        for ($i = 0; $i -lt $sp.Original.Length; $i++) {
            $bytes[$sp.Offset + $i] = if ($i -lt $new.Length) { $new[$i] } else { 0 }
        }
        [IO.File]::WriteAllBytes($path, $bytes)
        $script:stringsDone++
    }
    return $tooLong
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

    $wrong = @()
    foreach ($p in $Patches) {
        if ((Get-State $p) -eq 'other version') { $wrong += $p.File }
    }
    if ($wrong.Count -gt 0) {
        [Windows.Forms.MessageBox]::Show(
            "These files do not match ICQ Pro 2003b build 3916:`n`n  " + ($wrong -join "`n  ") +
            "`n`nThe code patches are tied to exact offsets in that build. Applying them to " +
            "another version would overwrite unrelated code, so nothing was changed.",
            'Wrong client version', 'OK', 'Error') | Out-Null
        return
    }

    $bin = 0
    foreach ($p in $Patches) {
        $path = Join-Path $script:IcqRoot $p.File
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if ((Get-State $p) -ne 'original') { continue }
        $backup = $path + $BinSuffix
        if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $path -Destination $backup }
        $bytes = [IO.File]::ReadAllBytes($path)
        [Array]::Copy($p.To, 0, $bytes, $p.Offset, $p.To.Length)
        [IO.File]::WriteAllBytes($path, $bytes)
        $bin++
    }

    $base = Get-Base
    Save-Base $base

    # Зашитые в код адреса — до правки ссылок: обе части пишут в Icq.exe.
    $script:stringsDone = 0
    $tooLong = Set-StringPatches $base

    $script:convCount = 0
    $files = 0
    foreach ($rel in $LinkFiles) {
        $path = Join-Path $script:IcqRoot $rel
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $backup = $path + $LinkSuffix
        if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $path -Destination $backup }
        $before = $script:convCount
        $text = [IO.File]::ReadAllText($path, $Latin1)
        $text = Convert-LinkText $text $base ([ref]$null)
        if ($script:convCount -ne $before) {
            [IO.File]::WriteAllText($path, $text, $Latin1)
            $files++
        }
    }

    Update-View
    $msg = "Code patches applied: $bin`nLinks redirected: $($script:convCount) in $files files" +
           "`nLinks inside the executable: $($script:stringsDone)"
    if ($tooLong.Count -gt 0) {
        $msg += "`n`nThese did not fit and were left alone:`n  " + ($tooLong -join "`n  ") +
                "`n`nA link stored inside the executable cannot be made longer than the original," +
                " so a shorter server address would fix it."
    }
    $msg += "`n`nYou can start ICQ now."
    [Windows.Forms.MessageBox]::Show($msg, 'Done', 'OK', 'Information') | Out-Null
}

function Invoke-Restore {
    if (-not (Test-Ready)) { return }
    $done = 0
    foreach ($p in $Patches) {
        $path = Join-Path $script:IcqRoot $p.File
        $backup = $path + $BinSuffix
        if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $path -Force; $done++ }
    }
    foreach ($rel in $LinkFiles) {
        $path = Join-Path $script:IcqRoot $rel
        $backup = $path + $LinkSuffix
        if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $path -Force; $done++ }
    }
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

$form = New-Object Windows.Forms.Form
$form.Text = 'ICQ Pro 2003b Patch'
$form.Size = New-Object Drawing.Size(700, 520)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$header = New-Object Windows.Forms.Label
$header.Text = 'Removes the banners, the Google search bar and the empty strip they occupied, and points the menu items that used to open ICQ.com at your own server. The user database and the skin are left untouched.'
$header.Location = New-Object Drawing.Point(12, 10)
$header.Size = New-Object Drawing.Size(660, 34)
$form.Controls.Add($header)

$pathLabel = New-Object Windows.Forms.Label
$pathLabel.Location = New-Object Drawing.Point(12, 50)
$pathLabel.Size = New-Object Drawing.Size(520, 20)
$pathLabel.Font = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold)
$form.Controls.Add($pathLabel)

$btnFolder = New-Object Windows.Forms.Button
$btnFolder.Text = 'Change folder...'
$btnFolder.Location = New-Object Drawing.Point(552, 46)
$btnFolder.Size = New-Object Drawing.Size(120, 26)
$btnFolder.Add_Click({ Select-Folder })
$form.Controls.Add($btnFolder)

$baseLabel = New-Object Windows.Forms.Label
$baseLabel.Text = 'Server pages:'
$baseLabel.Location = New-Object Drawing.Point(12, 82)
$baseLabel.Size = New-Object Drawing.Size(90, 20)
$form.Controls.Add($baseLabel)

$txtBase = New-Object Windows.Forms.TextBox
$txtBase.Location = New-Object Drawing.Point(104, 79)
$txtBase.Size = New-Object Drawing.Size(568, 22)
$saved = Get-SavedBase
$txtBase.Text = if ($saved) { $saved } else { $DefaultBase }
$form.Controls.Add($txtBase)

$baseHint = New-Object Windows.Forms.Label
$baseHint.Text = 'Address of the pages that replace the dead ICQ.com services. Change it to your own server; it is remembered for next time.'
$baseHint.Location = New-Object Drawing.Point(104, 103)
$baseHint.Size = New-Object Drawing.Size(568, 16)
$baseHint.ForeColor = [Drawing.Color]::DimGray
$form.Controls.Add($baseHint)

$list = New-Object Windows.Forms.ListView
$list.Location = New-Object Drawing.Point(12, 126)
$list.Size = New-Object Drawing.Size(660, 286)
$list.View = 'Details'
$list.FullRowSelect = $true
$list.GridLines = $true
[void]$list.Columns.Add('Item', 170)
[void]$list.Columns.Add('Detail', 120)
[void]$list.Columns.Add('State', 80)
[void]$list.Columns.Add('Effect', 280)
$form.Controls.Add($list)

function Add-Row($col1, $col2, $state, $effect) {
    $item = New-Object Windows.Forms.ListViewItem($col1)
    [void]$item.SubItems.Add($col2)
    [void]$item.SubItems.Add($state)
    [void]$item.SubItems.Add($effect)
    if ($state -eq 'patched')      { $item.ForeColor = [Drawing.Color]::DarkGreen }
    elseif ($state -eq 'original') { $item.ForeColor = [Drawing.Color]::Black }
    elseif ($state -eq 'no links') { $item.ForeColor = [Drawing.Color]::Gray }
    else                           { $item.ForeColor = [Drawing.Color]::Firebrick }
    [void]$list.Items.Add($item)
}

function Update-View {
    if ($script:IcqRoot) {
        $pathLabel.Text = 'Client folder: ' + $script:IcqRoot
        $pathLabel.ForeColor = [Drawing.Color]::Black
    } else {
        $pathLabel.Text = 'Client folder not found - use "Change folder..."'
        $pathLabel.ForeColor = [Drawing.Color]::Firebrick
    }
    $list.Items.Clear()

    $g1 = New-Object Windows.Forms.ListViewItem('CODE PATCHES')
    $g1.Font = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold)
    [void]$list.Items.Add($g1)
    foreach ($p in $Patches) {
        Add-Row $p.File ('0x{0:X}' -f $p.Offset) (Get-State $p) $p.What
    }

    $g2 = New-Object Windows.Forms.ListViewItem('LINKS INSIDE THE EXECUTABLE')
    $g2.Font = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold)
    [void]$list.Items.Add($g2)
    foreach ($sp in $StringPatches) {
        Add-Row $sp.Path ('0x{0:X}' -f $sp.Offset) (Get-StringState $sp) $sp.What
    }

    $g3 = New-Object Windows.Forms.ListViewItem('LINKS')
    $g3.Font = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold)
    [void]$list.Items.Add($g3)
    foreach ($rel in $LinkFiles) {
        $s = Get-LinkState $rel
        Add-Row ([IO.Path]::GetFileName($rel)) $s.Info $s.State 'menu items point at your server'
    }
}

$btnApply = New-Object Windows.Forms.Button
$btnApply.Text = 'Apply'
$btnApply.Location = New-Object Drawing.Point(12, 418)
$btnApply.Size = New-Object Drawing.Size(150, 34)
$btnApply.Add_Click({ Invoke-Apply })
$form.Controls.Add($btnApply)

$btnRestore = New-Object Windows.Forms.Button
$btnRestore.Text = 'Restore original'
$btnRestore.Location = New-Object Drawing.Point(172, 418)
$btnRestore.Size = New-Object Drawing.Size(150, 34)
$btnRestore.Add_Click({ Invoke-Restore })
$form.Controls.Add($btnRestore)

$btnRefresh = New-Object Windows.Forms.Button
$btnRefresh.Text = 'Re-check'
$btnRefresh.Location = New-Object Drawing.Point(332, 418)
$btnRefresh.Size = New-Object Drawing.Size(150, 34)
$btnRefresh.Add_Click({ Update-View })
$form.Controls.Add($btnRefresh)

$btnClose = New-Object Windows.Forms.Button
$btnClose.Text = 'Close'
$btnClose.Location = New-Object Drawing.Point(522, 418)
$btnClose.Size = New-Object Drawing.Size(150, 34)
$btnClose.Add_Click({ $form.Close() })
$form.Controls.Add($btnClose)

Update-View
[void]$form.ShowDialog()
