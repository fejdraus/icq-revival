# Builds the exe of every client patch.
#
# Run under Windows PowerShell 5.1 or PowerShell 7, with the .NET SDK:
#
#   powershell -ExecutionPolicy Bypass -File tools\common\Build-Patches.ps1 [-NoPlayer]
#
# The patches are C# projects under tools\patcher, built with dotnet build;
# the same sources give the same exe. Each carries its icon as the app.ico
# next to its project, written once by PatchIcon.WriteFile (patcher\Common) -
# the same picture the window shows. Explorer shows the title as the file
# description, hence the client version in it.
#
# The ICQ 6.5 and 7.2 patches also have a file next to them:
# FlashPlayerControl-Ruffle.dll, the tZers player they put into the client,
# as FlashPlayerControl.dll, when "tZers without Flash" is ticked. It has a
# name of its own so that a patch dropped into the ICQ folder never takes it
# for the client's original. It is built from tools\icq65\flashplayer with
# Rust (cargo, see its README.md) and copied to tools\icq65\patch and
# tools\icq72\patch, so each folder is a release: the exe and the DLL side by
# side. -NoPlayer leaves it out; without cargo it
# is left out with a warning, and the patch shows that row as not available.

param([switch]$NoPlayer)

$ErrorActionPreference = 'Stop'
$tools = Split-Path $PSScriptRoot -Parent

$Projects = @(
    @{ Project = 'patcher\Icq65\Icq65Patch.csproj'; Exe = 'icq65\patch\ICQ-6.5-Patch.exe' }
    @{ Project = 'patcher\Icq2003b\Icq2003bPatch.csproj'; Exe = 'icq2003b\patch\ICQ-2003b-Patch.exe' }
    @{ Project = 'patcher\Icq72\Icq72Patch.csproj'; Exe = 'icq72\patch\ICQ-7.2-Patch.exe' }
)

# Copies a built file into place; a scanner holding the file just made - which
# happened - only delays the copy.
function Copy-Built($built, $to) {
    for ($try = 1; ; $try++) {
        try { Copy-Item -LiteralPath $built -Destination $to -Force -ErrorAction Stop; break }
        catch { if ($try -ge 5) { throw "could not write $to (open, or held by a scanner): $($_.Exception.Message)" } }
        Start-Sleep -Seconds 2
    }
    Write-Output ("built {0} ({1:N0} bytes)" -f $to, (Get-Item -LiteralPath $to).Length)
}

foreach ($p in $Projects) {
    $project = Join-Path $tools $p.Project
    $exe = Join-Path $tools $p.Exe
    # The exe is built in the temp folder and copied into place after: a
    # failed build then leaves the one there as it was.
    $out = Join-Path ([IO.Path]::GetTempPath()) ('patch-build-' + [Guid]::NewGuid().ToString('N'))
    try {
        $said = & dotnet build $project -c Release -o $out --nologo -v q
        $built = Join-Path $out ([IO.Path]::GetFileName($exe))
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $built)) { throw ("not built: $exe`n" + ($said | Out-String)) }
        Copy-Built $built $exe
    } finally {
        Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not $NoPlayer) {
    $crate = Join-Path $tools 'icq65\flashplayer'
    $dlls = @('icq65\patch\FlashPlayerControl-Ruffle.dll', 'icq72\patch\FlashPlayerControl-Ruffle.dll') | ForEach-Object { Join-Path $tools $_ }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Warning "cargo not found - $($dlls -join ', ') not built (tools\icq65\flashplayer\README.md)"
    } else {
        # cargo takes the 32-bit target from the crate's .cargo\config.toml,
        # which it reads from the working folder.
        # cargo reports its progress on stderr, which Windows PowerShell would
        # take for a failure under 'Stop'; the exit code tells.
        Push-Location $crate
        $ErrorActionPreference = 'Continue'
        try {
            $said = & cargo build --release 2>&1
            if ($LASTEXITCODE -ne 0) { throw ("not built: FlashPlayerControl.dll`n" + ($said | Out-String)) }
        } finally {
            $ErrorActionPreference = 'Stop'
            Pop-Location
        }
        foreach ($dll in $dlls) {
            Copy-Built (Join-Path $crate 'target\i686-pc-windows-msvc\release\FlashPlayerControl.dll') $dll
        }
    }
}
