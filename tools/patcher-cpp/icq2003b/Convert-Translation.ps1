# Turns the Ukrainian interface of ICQ Pro 2003b into the two resources the
# C++ patch carries.
#
#   Convert-Translation.ps1 -Source ...\ICQ-2003b-uk-UA.txt -OutDir <folder>
#
# ICQ-2003b-uk-UA.txt stays the source: JSON, gzip, base64, as
# tools\icq2003b\translate\build.py writes it. It is decoded here, at build
# time, so the exe holds nothing packed or encoded - scanners took the packed
# blob of the C# exe for something that unpacks itself. Written to OutDir:
#
#   translation.idx  a UTF-8 text index, one record per line, fields split
#                    by tabs (see Translation.cpp for the records)
#   translation.dat  the raw bytes of every item, one after another
#
# Runs under Windows PowerShell 5.1 and PowerShell 7. Reads the JSON the way
# the C# patch did: members in the order of the file, a single value where a
# list is expected taken as a list of one.

param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$OutDir
)

$ErrorActionPreference = 'Stop'
$inv = [Globalization.CultureInfo]::InvariantCulture

$packed = [IO.File]::ReadAllText($Source, [Text.Encoding]::UTF8).Trim()
$gz = New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(, [Convert]::FromBase64String($packed))), [IO.Compression.CompressionMode]::Decompress)
$reader = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)
$json = $reader.ReadToEnd()
$reader.Dispose()
$t = $json | ConvertFrom-Json

$data = New-Object IO.MemoryStream
$index = New-Object Text.StringBuilder

# A list as the C# patch read one: none as none, an array as it is, anything
# else as a list of one.
function ListOf($value) {
    if ($null -eq $value) { return , @() }
    if ($value -is [array]) { return , $value }
    return , @($value)
}

# Appends bytes to the data and gives "offset<TAB>length".
function Blob([string]$base64) {
    $bytes = [Convert]::FromBase64String($base64)
    $at = $data.Position
    $data.Write($bytes, 0, $bytes.Length)
    return "$at`t$($bytes.Length)"
}

# One field of a record: tabs and line breaks would split it.
function Field($value) {
    $s = [Convert]::ToString($value, $inv)
    if ($s -match "[`t`r`n]") { throw "a field of the translation holds a tab or a line break: $s" }
    return $s
}

# "type|name|lang"; the name is "#123" for a number.
function KeyOf($o) {
    $name = if ($o.n -is [string]) { $o.n } else { '#' + [Convert]::ToString($o.n, $inv) }
    return Field ([string]::Format($inv, '{0}|{1}|{2}', $o.t, $name, $o.l))
}

function Line([string[]]$fields) {
    [void]$index.Append(($fields -join "`t")).Append("`n")
}

[void]$index.Append("# The Ukrainian interface of ICQ Pro 2003b, from ICQ-2003b-uk-UA.txt. Generated; do not edit.`n")
Line @('language', (Field $t.language))
foreach ($f in $t.files.PSObject.Properties) {
    $v = $f.Value
    Line @('file', (Field $f.Name), (Field ([Convert]::ToInt64($v.size, $inv))))
    foreach ($it in (ListOf $v.items)) {
        Line @('item', (KeyOf $it), (Field $it.from), (Blob $it.d))
    }
    foreach ($it in (ListOf $v.inplace)) {
        if ($it -isnot [Management.Automation.PSCustomObject]) { continue }
        Line @('place', (Field ([Convert]::ToInt32($it.o, $inv))), (Blob $it.d), (Blob $it.from))
    }
    if ($v.whole -is [Management.Automation.PSCustomObject]) {
        Line @('whole', (Field $v.whole.from), (Blob $v.whole.d))
    }
}
$sb = $t.sendBy
Line @('sendby', (Field $sb.file), (KeyOf $sb), (Field $sb.from), (Blob $sb.en), (Blob $sb.uk))

[void](New-Item -ItemType Directory -Force -Path $OutDir)
$utf8 = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $OutDir 'translation.idx'), $index.ToString(), $utf8)
[IO.File]::WriteAllBytes((Join-Path $OutDir 'translation.dat'), $data.ToArray())
