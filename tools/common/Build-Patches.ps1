# Builds the exe of every client patch, each with its own icon.
#
# Run under Windows PowerShell 5.1 with ps12exe installed
# (Install-Module ps12exe):
#
#   powershell -ExecutionPolicy Bypass -File tools\common\Build-Patches.ps1
#
# The icons are drawn by PatchWindow.ps1 - the same picture the window shows -
# so badge and colours here are the ones each patch passes to New-PatchWindow.
# Explorer shows the title as the file description, hence the client version.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PatchWindow.ps1')
Import-Module ps12exe

$tools = Split-Path $PSScriptRoot -Parent
$Patches = @(
    @{ Script = 'icq65\patch\ICQ-6.5-Patch.ps1'; Badge = '6.5'; Top = '#4CC06E'; Bottom = '#1E8A46'
       Description = 'Patch for ICQ 6.5 (build 2024)' }
    @{ Script = 'icq2003b\patch\ICQ-2003b-Patch.ps1'; Badge = '2003b'; Top = '#4FA3E0'; Bottom = '#1F66B0'
       Description = 'Patch for ICQ Pro 2003b (build 3916)' }
)

foreach ($p in $Patches) {
    $script = Join-Path $tools $p.Script
    $exe = [IO.Path]::ChangeExtension($script, '.exe')
    $icon = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetFileNameWithoutExtension($script) + '.ico')
    New-PatchIconFile $icon $p.Badge $p.Top $p.Bottom
    # Now and then the build does not write the exe - a scanner holding the
    # file, most likely - and an old exe left in place looks built. Only one
    # written after the start counts, and a failed try shows what ps12exe said.
    $start = Get-Date
    try {
        for ($try = 1; $try -le 3; $try++) {
            $said = ps12exe -inputFile $script -outputFile $exe -NoUpdateCheck `
                -App @{ Windowed = $true; DpiAware = $true } `
                -Os @{ Admin = $true } `
                -Build @{ Target = 'Framework4.0'; Apartment = 'STA' } `
                -Resources @{ Icon = $icon; Title = $p.Description; Description = $p.Description; Product = 'ICQ Revival' } 2>&1
            if ((Test-Path -LiteralPath $exe) -and (Get-Item -LiteralPath $exe).LastWriteTime -ge $start) { break }
            Write-Warning ("try $try did not write $exe`n" + ($said | Out-String))
            Start-Sleep -Seconds 2
        }
    } finally {
        Remove-Item -LiteralPath $icon -Force -ErrorAction SilentlyContinue
    }
    if (-not ((Test-Path -LiteralPath $exe) -and (Get-Item -LiteralPath $exe).LastWriteTime -ge $start)) { throw "not built: $exe" }
    Write-Output ("built {0} ({1:N0} bytes)" -f $exe, (Get-Item -LiteralPath $exe).Length)
}
