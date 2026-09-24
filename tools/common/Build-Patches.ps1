# Builds the exe of every client patch, each with its own icon.
#
# Run under Windows PowerShell 5.1:
#
#   powershell -ExecutionPolicy Bypass -File tools\common\Build-Patches.ps1
#
# The patches written in C# (tools\patcher) are built with the .NET SDK
# (dotnet build); their icon is the app.ico next to each project, drawn once
# by New-PatchIconFile of PatchWindow.ps1. The ones still written in PowerShell
# are compiled with ps12exe (Install-Module ps12exe), which gets its icon drawn
# here, by the same PatchWindow.ps1 - the same picture the window shows - so
# badge and colours here are the ones each patch passes to New-PatchWindow.
# Explorer shows the title as the file description, hence the client version.

$ErrorActionPreference = 'Stop'
$tools = Split-Path $PSScriptRoot -Parent

# Each exe is built in the temp folder and copied into place after: a failed
# build then leaves the one there as it was, and a scanner holding the file
# just made - which happened - only delays the copy.
function Copy-IntoPlace([string]$from, [string]$to) {
    for ($try = 1; ; $try++) {
        try { Copy-Item -LiteralPath $from -Destination $to -Force -ErrorAction Stop; break }
        catch { if ($try -ge 5) { throw "could not write $to (open, or held by a scanner): $($_.Exception.Message)" } }
        Start-Sleep -Seconds 2
    }
    Write-Output ("built {0} ({1:N0} bytes)" -f $to, (Get-Item -LiteralPath $to).Length)
}

# --- C# projects ---------------------------------------------------------------

$Projects = @(
    @{ Project = 'patcher\Icq65\Icq65Patch.csproj'; Exe = 'icq65\patch\ICQ-6.5-Patch.exe' }
)

foreach ($p in $Projects) {
    $project = Join-Path $tools $p.Project
    $exe = Join-Path $tools $p.Exe
    $out = Join-Path ([IO.Path]::GetTempPath()) ('patch-build-' + [Guid]::NewGuid().ToString('N'))
    try {
        $said = & dotnet build $project -c Release -o $out --nologo -v q
        $built = Join-Path $out ([IO.Path]::GetFileName($exe))
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $built)) { throw ("not built: $exe`n" + ($said | Out-String)) }
        Copy-IntoPlace $built $exe
    } finally {
        Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- PowerShell scripts, compiled with ps12exe ---------------------------------

. (Join-Path $PSScriptRoot 'PatchWindow.ps1')
Import-Module ps12exe

$Patches = @(
    @{ Script = 'icq2003b\patch\ICQ-2003b-Patch.ps1'; Badge = '2003b'; Top = '#4FA3E0'; Bottom = '#1F66B0'
       Description = 'Patch for ICQ Pro 2003b (build 3916)' }
)

foreach ($p in $Patches) {
    $script = Join-Path $tools $p.Script
    $exe = [IO.Path]::ChangeExtension($script, '.exe')
    $icon = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetFileNameWithoutExtension($script) + '.ico')
    New-PatchIconFile $icon $p.Badge $p.Top $p.Bottom
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetFileName($exe))
    try {
        $said = ps12exe -inputFile $script -outputFile $tmp -NoUpdateCheck `
            -App @{ Windowed = $true; DpiAware = $true } `
            -Os @{ Admin = $true } `
            -Build @{ Target = 'Framework4.0'; Apartment = 'STA' } `
            -Resources @{ Icon = $icon; Title = $p.Description; Description = $p.Description; Product = 'ICQ Revival' } 2>&1
    } finally {
        Remove-Item -LiteralPath $icon -Force -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path -LiteralPath $tmp)) { throw ("not built: $exe`n" + ($said | Out-String)) }
    Copy-IntoPlace $tmp $exe
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($exe)) -Filter '*.win32manifest' | Remove-Item -Force -ErrorAction SilentlyContinue
}
