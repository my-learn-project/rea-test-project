[CmdletBinding()]
param([string]$UpxExe = (Join-Path (Split-Path $PSScriptRoot -Parent) '.tools\upx\upx-5.2.1-win64\upx.exe'))
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$source = Join-Path $root 'dist\client'
if (!(Test-Path $UpxExe)) { throw 'Install UPX with scripts/install-upx.ps1, or pass -UpxExe.' }
if (!(Test-Path (Join-Path $source 'CardGuard.exe'))) { throw 'Build the client first.' }
$secrets = Get-ChildItem $source -Recurse -File | Where-Object { $_.Name -match 'issuer|private|passphrase|demo-card|\.dpapi$|\.pfx$|\.key$' }
if ($secrets) { throw 'Unexpected signing material or issuer found in client distribution. Inspect it before packing.' }
$destination = Join-Path $root ('dist\packed-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory $destination | Out-Null
Copy-Item -Path "$source\*" -Destination $destination -Recurse
$results = @()
foreach ($name in @('CardGuard.exe','license-client.exe')) {
    $target = Join-Path $destination $name
    $before = (Get-Item $target).Length
    # Never use --force: UPX must preserve the hardened build's mitigations.
    $message = & $UpxExe --best --no-progress $target 2>&1 | Out-String
    $code = $LASTEXITCODE
    $packed = $code -eq 0
    if ($packed) {
        & $UpxExe --test $target
        if ($LASTEXITCODE -ne 0) { throw "UPX verification failed: $name" }
    } else {
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination $target -Force
    }
    $results += [pscustomobject]@{name=$name; packed=$packed; bytesBefore=$before; bytesAfter=(Get-Item $target).Length; message=$message.Trim()}
}
$results | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $destination 'packing-report.json') -Encoding utf8
$results | Format-List
if ($results.packed -contains $false) {
    Write-Warning 'UPX could not pack every hardened executable. The report records why; original mitigations were retained.'
}
Write-Host "Output: $destination"
