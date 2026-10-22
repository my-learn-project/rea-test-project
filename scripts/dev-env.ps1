#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
$script:ProjectRoot = Split-Path $PSScriptRoot -Parent
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
$helperBin = Join-Path $script:ProjectRoot '.tools\python\Scripts'
$env:Path = "$cargoBin;$helperBin;$env:Path"
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path $vswhere)) { throw 'MSVC missing. Run scripts/setup-dev.ps1 -Phase Toolchain.' }
$vsPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vsPath) { throw 'MSVC C++ toolchain not found.' }
Import-Module (Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
$envFile = Join-Path $script:ProjectRoot '.tools\environment.json'
if (Test-Path $envFile) { $script:DevEnvironment = Get-Content $envFile -Raw | ConvertFrom-Json }
function Assert-NativeExit([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit $LASTEXITCODE)." }
}
