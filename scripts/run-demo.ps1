[CmdletBinding()]
param()
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root 'dist\client\CardGuard.exe'
if (!(Test-Path $exe)) { throw 'Run scripts/build.ps1 first.' }
Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe -Parent)
