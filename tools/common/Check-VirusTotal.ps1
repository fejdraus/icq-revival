# Checks files on VirusTotal and prints what the engines say about each.
#
#   pwsh -File tools\common\Check-VirusTotal.ps1 <file> [<file> ...] [-Rescan]
#
# The API key comes from the VT_API_KEY environment variable only, so it is
# never in the repository or on a command line. A free key allows 4 requests
# a minute; the script waits between them.
#
# A file VirusTotal already knows is not uploaded again: its last report is
# shown, or with -Rescan it is analysed again. Uploading shares the file with
# VirusTotal and the vendors behind it, as the web page does - send only what
# is meant to be public, such as the patch executables.

param(
    [Parameter(Mandatory, ValueFromRemainingArguments)]
    [string[]]$Path,
    [switch]$Rescan
)

$ErrorActionPreference = 'Stop'
$key = $env:VT_API_KEY
if (-not $key) { $key = [Environment]::GetEnvironmentVariable('VT_API_KEY', 'User') }
if (-not $key) { throw 'set VT_API_KEY to your VirusTotal API key' }
$api = 'https://www.virustotal.com/api/v3'
$headers = @{ 'x-apikey' = $key }

# The free API allows 4 requests a minute.
$script:last = [DateTime]::MinValue
function Invoke-Vt([string]$method, [string]$uri, $form) {
    $wait = 15.5 - ((Get-Date) - $script:last).TotalSeconds
    if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
    $script:last = Get-Date
    $req = @{ Method = $method; Uri = $uri; Headers = $headers; SkipHttpErrorCheck = $true; StatusCodeVariable = 'code' }
    if ($form) { $req.Form = $form }
    $body = Invoke-RestMethod @req
    return [pscustomobject]@{ Code = $code; Body = $body }
}

function Wait-Analysis([string]$id) {
    for ($i = 0; $i -lt 40; $i++) {
        $r = Invoke-Vt GET "$api/analyses/$id"
        if ($r.Code -eq 200 -and $r.Body.data.attributes.status -eq 'completed') { return }
    }
    throw "analysis $id did not finish in time"
}

foreach ($p in $Path) {
    $file = Get-Item -LiteralPath $p
    $sha = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $known = Invoke-Vt GET "$api/files/$sha"
    if ($known.Code -eq 404) {
        $up = Invoke-Vt POST "$api/files" @{ file = $file }
        if ($up.Code -ne 200) { throw "upload failed ($($up.Code)): $($up.Body | ConvertTo-Json -Depth 5 -Compress)" }
        Wait-Analysis $up.Body.data.id
    } elseif ($known.Code -eq 200 -and $Rescan) {
        $re = Invoke-Vt POST "$api/files/$sha/analyse"
        if ($re.Code -ne 200) { throw "rescan failed ($($re.Code))" }
        Wait-Analysis $re.Body.data.id
    } elseif ($known.Code -ne 200) {
        throw "lookup failed ($($known.Code)): $($known.Body | ConvertTo-Json -Depth 5 -Compress)"
    }

    $report = (Invoke-Vt GET "$api/files/$sha").Body.data.attributes
    $stats = $report.last_analysis_stats
    $total = $stats.malicious + $stats.suspicious + $stats.undetected + $stats.harmless
    $flagged = $report.last_analysis_results.PSObject.Properties |
        Where-Object { $_.Value.category -in 'malicious', 'suspicious' } |
        ForEach-Object { '    {0}: {1}' -f $_.Name, $_.Value.result }
    Write-Output ('{0}  {1}/{2}  {3}' -f $file.Name, ($stats.malicious + $stats.suspicious), $total, $file.FullName)
    Write-Output "    https://www.virustotal.com/gui/file/$sha"
    $flagged
}
