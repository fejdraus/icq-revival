# Builds the exe of every client patch.
#
# Run under Windows PowerShell 5.1 or PowerShell 7, with the .NET SDK:
#
#   powershell -ExecutionPolicy Bypass -File tools\common\Build-Patches.ps1
#
# The patches are C# projects under tools\patcher, built with dotnet build;
# the same sources give the same exe. Each carries its icon as the app.ico
# next to its project, drawn once by New-PatchIconFile of PatchWindow.ps1 -
# the same picture the window shows. Explorer shows the title as the file
# description, hence the client version in it.

$ErrorActionPreference = 'Stop'
$tools = Split-Path $PSScriptRoot -Parent

$Projects = @(
    @{ Project = 'patcher\Icq65\Icq65Patch.csproj'; Exe = 'icq65\patch\ICQ-6.5-Patch.exe' }
    @{ Project = 'patcher\Icq2003b\Icq2003bPatch.csproj'; Exe = 'icq2003b\patch\ICQ-2003b-Patch.exe' }
)

foreach ($p in $Projects) {
    $project = Join-Path $tools $p.Project
    $exe = Join-Path $tools $p.Exe
    # The exe is built in the temp folder and copied into place after: a
    # failed build then leaves the one there as it was, and a scanner holding
    # the file just made - which happened - only delays the copy.
    $out = Join-Path ([IO.Path]::GetTempPath()) ('patch-build-' + [Guid]::NewGuid().ToString('N'))
    try {
        $said = & dotnet build $project -c Release -o $out --nologo -v q
        $built = Join-Path $out ([IO.Path]::GetFileName($exe))
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $built)) { throw ("not built: $exe`n" + ($said | Out-String)) }
        for ($try = 1; ; $try++) {
            try { Copy-Item -LiteralPath $built -Destination $exe -Force -ErrorAction Stop; break }
            catch { if ($try -ge 5) { throw "could not write $exe (open, or held by a scanner): $($_.Exception.Message)" } }
            Start-Sleep -Seconds 2
        }
        Write-Output ("built {0} ({1:N0} bytes)" -f $exe, (Get-Item -LiteralPath $exe).Length)
    } finally {
        Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
    }
}
