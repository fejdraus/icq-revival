# Антибаннер для ICQ Pro 2003b — оконное приложение.
#
# Убирает рекламу и строку поиска Google четырьмя точечными правками в коде
# клиента. База пользователя, скин и настройки не трогаются.
#
# Папку клиента ищет сам: сначала рядом с собой (положили в каталог ICQ или
# взяли портативную сборку), затем в реестре, затем по стандартному пути.
# Если не нашёл — можно указать вручную.
#
# Собирается в exe: Invoke-ps2exe .\IcqAntibanner.ps1 .\IcqAntibanner.exe
#                   -noConsole -requireAdmin -title 'ICQ Pro 2003b Antibanner'

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

$Suffix = '.antibanner-backup'

# Каждая правка: файл, смещение, исходные байты, новые байты, назначение.
# Имена функций взяты из таблиц экспорта самих модулей — они экспортируют
# декорированные имена C++, поэтому места найдены по именам, а не подбором.
$Patches = @(
    [pscustomobject]@{
        File = 'icqmutl.dll'; Offset = 0x20626
        From = [byte[]](0xB8,0x96,0x9B,0x22,0x20)
        To   = [byte[]](0x31,0xC0,0xC2,0x04,0x00)
        What = 'contact list banner is never created'
        Func = 'MCCLBannerDialog::CreatTheCLBannerCtrl'
    }
    [pscustomobject]@{
        File = 'ICQProLib.dll'; Offset = 0x1217B
        From = [byte[]](0xB8,0xBA,0x7D,0x89,0x24)
        To   = [byte[]](0x31,0xC0,0xC3)
        What = 'message window banner is never shown'
        Func = 'MCProBannersUtils::IsOKToDispalyBanner'
    }
    [pscustomobject]@{
        File = 'ICQTicker.dll'; Offset = 0x750
        From = [byte[]](0x53,0x55,0x8B,0x6C,0x24,0x14,0x56)
        To   = [byte[]](0xB8,0x11,0x01,0x04,0x80,0xC2,0x0C,0x00)
        What = 'Google search bar and its button are gone'
        Func = 'DllGetClassObject -> CLASS_E_CLASSNOTAVAILABLE'
    }
    [pscustomobject]@{
        File = 'Icq.exe'; Offset = 0x39AA2
        From = [byte[]](0x74,0x41)
        To   = [byte[]](0xEB,0x41)
        What = 'no empty strip reserved for them'
        Func = 'contact list layout, add eax,0x16'
    }
)

# --- поиск папки клиента ----------------------------------------------------

# Папка считается подходящей, если в ней лежат все файлы, которые мы правим.
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

    # 1. рядом с собой — портативная сборка или файл положили в папку клиента
    $self = Get-SelfFolder
    if ($self) { $candidates.Add($self) }

    # 2. реестр: путь к Icq.exe
    foreach ($key in @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Icq.exe',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Icq.exe')) {
        try {
            $exe = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($exe) { $candidates.Add([IO.Path]::GetDirectoryName($exe)) }
        } catch { }
    }

    # 3. запись об удалении программы
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

    # 4. обычные места установки
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

# --- работа с файлами -------------------------------------------------------

function Get-State($patch) {
    if (-not $script:IcqRoot) { return 'no folder' }
    $path = Join-Path $script:IcqRoot $patch.File
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {
        $len = [Math]::Max($patch.From.Length, $patch.To.Length)
        $buf = New-Object byte[] $len
        $null = $fs.Seek($patch.Offset, 'Begin')
        $null = $fs.Read($buf, 0, $len)
    } finally { $fs.Close() }

    $matches = { param($expect)
        for ($i = 0; $i -lt $expect.Length; $i++) { if ($buf[$i] -ne $expect[$i]) { return $false } }
        return $true
    }
    if (& $matches $patch.To)   { return 'patched' }
    if (& $matches $patch.From) { return 'original' }
    return 'unknown'
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
    $done = 0
    foreach ($p in $Patches) {
        $path = Join-Path $script:IcqRoot $p.File
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if ((Get-State $p) -ne 'original') { continue }
        $backup = $path + $Suffix
        if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $path -Destination $backup }
        $bytes = [IO.File]::ReadAllBytes($path)
        [Array]::Copy($p.To, 0, $bytes, $p.Offset, $p.To.Length)
        [IO.File]::WriteAllBytes($path, $bytes)
        $done++
    }
    Update-View
    [Windows.Forms.MessageBox]::Show("Patches applied: $done.`nYou can start ICQ now.", 'Done', 'OK', 'Information') | Out-Null
}

function Invoke-Restore {
    if (-not (Test-Ready)) { return }
    $done = 0
    foreach ($p in $Patches) {
        $path = Join-Path $script:IcqRoot $p.File
        $backup = $path + $Suffix
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
$form.Text = 'ICQ Pro 2003b Antibanner'
$form.Size = New-Object Drawing.Size(660, 390)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$header = New-Object Windows.Forms.Label
$header.Text = 'Removes the banners in the contact list and the message window, the Google search bar and the empty strip they used to occupy. The user database and client settings are left untouched.'
$header.Location = New-Object Drawing.Point(12, 10)
$header.Size = New-Object Drawing.Size(620, 32)
$form.Controls.Add($header)

$pathLabel = New-Object Windows.Forms.Label
$pathLabel.Location = New-Object Drawing.Point(12, 46)
$pathLabel.Size = New-Object Drawing.Size(490, 20)
$pathLabel.Font = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold)
$form.Controls.Add($pathLabel)

$btnFolder = New-Object Windows.Forms.Button
$btnFolder.Text = 'Change folder...'
$btnFolder.Location = New-Object Drawing.Point(512, 42)
$btnFolder.Size = New-Object Drawing.Size(120, 26)
$btnFolder.Add_Click({ Select-Folder })
$form.Controls.Add($btnFolder)

$list = New-Object Windows.Forms.ListView
$list.Location = New-Object Drawing.Point(12, 74)
$list.Size = New-Object Drawing.Size(620, 200)
$list.View = 'Details'
$list.FullRowSelect = $true
$list.GridLines = $true
[void]$list.Columns.Add('File', 110)
[void]$list.Columns.Add('Offset', 80)
[void]$list.Columns.Add('State', 90)
[void]$list.Columns.Add('Effect', 320)
$form.Controls.Add($list)

function Update-View {
    if ($script:IcqRoot) {
        $pathLabel.Text = 'Client folder: ' + $script:IcqRoot
        $pathLabel.ForeColor = [Drawing.Color]::Black
    } else {
        $pathLabel.Text = 'Client folder not found — use "Change folder..."'
        $pathLabel.ForeColor = [Drawing.Color]::Firebrick
    }
    $list.Items.Clear()
    foreach ($p in $Patches) {
        $item = New-Object Windows.Forms.ListViewItem($p.File)
        [void]$item.SubItems.Add(('0x{0:X}' -f $p.Offset))
        $st = Get-State $p
        [void]$item.SubItems.Add($st)
        [void]$item.SubItems.Add($p.What)
        if ($st -eq 'patched')     { $item.ForeColor = [Drawing.Color]::DarkGreen }
        elseif ($st -eq 'original') { $item.ForeColor = [Drawing.Color]::Black }
        else                        { $item.ForeColor = [Drawing.Color]::Firebrick }
        [void]$list.Items.Add($item)
    }
}

$btnApply = New-Object Windows.Forms.Button
$btnApply.Text = 'Apply'
$btnApply.Location = New-Object Drawing.Point(12, 290)
$btnApply.Size = New-Object Drawing.Size(140, 32)
$btnApply.Add_Click({ Invoke-Apply })
$form.Controls.Add($btnApply)

$btnRestore = New-Object Windows.Forms.Button
$btnRestore.Text = 'Restore original'
$btnRestore.Location = New-Object Drawing.Point(162, 290)
$btnRestore.Size = New-Object Drawing.Size(140, 32)
$btnRestore.Add_Click({ Invoke-Restore })
$form.Controls.Add($btnRestore)

$btnRefresh = New-Object Windows.Forms.Button
$btnRefresh.Text = 'Re-check'
$btnRefresh.Location = New-Object Drawing.Point(312, 290)
$btnRefresh.Size = New-Object Drawing.Size(140, 32)
$btnRefresh.Add_Click({ Update-View })
$form.Controls.Add($btnRefresh)

$btnClose = New-Object Windows.Forms.Button
$btnClose.Text = 'Close'
$btnClose.Location = New-Object Drawing.Point(492, 290)
$btnClose.Size = New-Object Drawing.Size(140, 32)
$btnClose.Add_Click({ $form.Close() })
$form.Controls.Add($btnClose)

Update-View
[void]$form.ShowDialog()
