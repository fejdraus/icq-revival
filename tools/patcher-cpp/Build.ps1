# Builds the native (C++) client patches into tools\patcher-cpp\out.
#
#   powershell -ExecutionPolicy Bypass -File tools\patcher-cpp\Build.ps1
#
# Needs Visual Studio 2022 (or its Build Tools) with the XP toolset of Visual
# Studio 2017: the components Microsoft.VisualStudio.Component.VC.v141.x86.x64
# and Microsoft.VisualStudio.Component.WinXP. With them the exe runs on
# Windows XP SP3 through 11 and needs nothing installed. -Toolset v143 builds
# with the current toolset instead, for trying things out only: that exe does
# not start on XP.
#
# Only ICQ Pro 2003b is ported so far. The exes in tools\*\patch are still the
# C# ones, built by tools\common\Build-Patches.ps1; this script leaves them
# alone.

param(
    [string]$Toolset = 'v141_xp'
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$out = Join-Path $here 'out'

$Projects = @(
    @{ Project = 'icq2003b\ICQ-2003b-Patch.vcxproj'; Exe = 'ICQ-2003b-Patch.exe' }
)

# MSBuild of the newest Visual Studio that has the toolset: a newer Visual
# Studio next to it may well lack the XP one.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw "Visual Studio is not installed (no $vswhere)" }
$requires = @('Microsoft.VisualStudio.Component.VC.Tools.x86.x64')
if ($Toolset -eq 'v141_xp') { $requires = @('Microsoft.VisualStudio.Component.VC.v141.x86.x64', 'Microsoft.VisualStudio.Component.WinXP') }
$msbuild = & $vswhere -latest -products * -requires $requires -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw "no Visual Studio with the $Toolset toolset (components: $($requires -join ', '))" }

[void](New-Item -ItemType Directory -Force -Path $out)
foreach ($p in $Projects) {
    $project = Join-Path $here $p.Project
    $said = & $msbuild $project /nologo /v:minimal /t:Rebuild /p:Configuration=Release /p:Platform=Win32 "/p:PlatformToolset=$Toolset"
    $built = Join-Path $here ("obj\$Toolset\bin\" + $p.Exe)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $built)) { throw ("not built: $($p.Exe)`n" + ($said | Out-String)) }
    $exe = Join-Path $out $p.Exe
    # A scanner holding the file just made - which happened with the C#
    # patches - only delays the copy.
    for ($try = 1; ; $try++) {
        try { Copy-Item -LiteralPath $built -Destination $exe -Force -ErrorAction Stop; break }
        catch { if ($try -ge 5) { throw "could not write $exe (open, or held by a scanner): $($_.Exception.Message)" } }
        Start-Sleep -Seconds 2
    }
    Write-Output ("built {0} with {1} ({2:N0} bytes)" -f $exe, $Toolset, (Get-Item -LiteralPath $exe).Length)
}
