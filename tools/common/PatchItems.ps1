# The list of changes a client patch offers, shared by every patch and used
# with and without the window.
#
# A patch keeps its changes as small as the files need - one byte run, one
# line of markup - but a person chooses what they get: no Xtraz, no
# advertising, links to their own server. So every change belongs to a job,
# and the window shows one row per job, with one tick and one state.
#
# Pulled in like PatchWindow.ps1:
#
#   #_if PSScript
#   . (Join-Path $PSScriptRoot '..\..\common\PatchItems.ps1')
#   #_else
#   #_include "$PSScriptRoot/../../common/PatchItems.ps1"
#   #_endif
#
# Filled in by the patch:
#   $JobOf = @{ 'change one' = 'job'; 'change two' = 'job' }
#   $Jobs  = [ordered]@{ 'job' = @{ Group = 'window group'; What = 'what the row says' } }
# in the order the window lists them.

# The key a change is chosen by: its job, or the change itself.
function Get-JobKey([string]$part) {
    if ($JobOf -and $JobOf.ContainsKey($part)) { return $JobOf[$part] }
    return $part
}

# Whether a change is wanted: all of them, unless its job is in $skip - the
# rows cleared in the window, or -Skip of a scripted run.
function Test-Wanted($skip, [string]$part) {
    return -not ($skip -and $skip.Contains((Get-JobKey $part)))
}

# One state for a job out of the states of its changes.
function Join-States([string[]]$states) {
    $s = @($states | Where-Object { $_ -ne 'missing' })
    if ($s.Count -eq 0) { return 'missing' }
    foreach ($bad in 'other version', 'unknown') { if ($s -contains $bad) { return $bad } }
    $distinct = @($s | Select-Object -Unique)
    if ($distinct.Count -eq 1) { return $distinct[0] }
    return 'partly'
}

# Folds the changes into one row per job, in the order of $Jobs. Items have
# Key (the change's name), Where (a file, maybe "file at offset") and State.
# A change no job claims keeps a row of its own at the end.
function Merge-Jobs($items) {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($job in $Jobs.Keys) {
        $parts = @($items | Where-Object { (Get-JobKey $_.Key) -eq $job })
        if ($parts.Count -eq 0) { continue }
        $files = @($parts | ForEach-Object { ($_.Where -split ' at ')[0] } | Select-Object -Unique)
        $where = if ($files.Count -le 2) { $files -join ', ' } else { "$($parts.Count) changes in $($files.Count) files" }
        $out.Add([pscustomobject]@{
            Group = $Jobs[$job].Group; Key = $job; What = $Jobs[$job].What; Where = $where
            State = (Join-States @($parts | ForEach-Object { $_.State }))
        })
    }
    foreach ($it in $items) {
        if (-not $Jobs.Contains((Get-JobKey $it.Key))) { $out.Add($it) }
    }
    return $out
}
