#Requires -Version 7.2
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/upx/upx/releases/tags/v5.2.1' -TimeoutSec 60
$asset = $release.assets | Where-Object name -eq 'upx-5.2.1-win64.zip'
if (!$asset -or $asset.digest -notmatch '^sha256:([0-9a-f]{64})$') { throw 'Official release has no SHA256 digest.' }
$expectedHash = $Matches[1]
$directory = Join-Path $root '.tools\upx'
New-Item -ItemType Directory -Force $directory | Out-Null
$archive = Join-Path $directory $asset.name
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archive -TimeoutSec 120
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) { throw 'UPX SHA256 mismatch.' }
Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force
@{version='5.2.1';sha256=$asset.digest;url=$asset.browser_download_url} | ConvertTo-Json | Set-Content (Join-Path $directory 'release.json') -Encoding utf8
Write-Host ('UPX ready: ' + (Join-Path $directory 'upx-5.2.1-win64\upx.exe'))
