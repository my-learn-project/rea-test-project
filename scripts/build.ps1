#Requires -Version 7.2
[CmdletBinding()]
param([switch]$SkipTests)
. (Join-Path $PSScriptRoot 'dev-env.ps1')
Set-Location $ProjectRoot
if (!$DevEnvironment -or !(Test-Path $DevEnvironment.qtRoot)) { throw 'Run scripts/setup-dev.ps1 -Phase Qt first.' }
if (!(Test-Path 'config\trusted-public-key.hex')) { throw 'Run scripts/init-demo.ps1 first to initialize the signing identity.' }
if (!$SkipTests) {
    & cargo fmt --all -- --check
    Assert-NativeExit 'Rust formatting'
    & cargo clippy --locked --workspace --all-targets -- -D warnings
    Assert-NativeExit 'Rust Clippy'
    & cargo test --locked --workspace
    Assert-NativeExit 'Rust tests'
}
& cargo build --locked --release --workspace
Assert-NativeExit 'Rust release build'
& cmake -S . -B build/gui -G Ninja '-DCMAKE_BUILD_TYPE=Release' "-DCMAKE_PREFIX_PATH=$($DevEnvironment.qtRoot)"
Assert-NativeExit 'Qt CMake configure'
& cmake --build build/gui
Assert-NativeExit 'Qt build'
$clientDir = Join-Path $ProjectRoot 'dist\client'
New-Item -ItemType Directory -Force $clientDir | Out-Null
Copy-Item -LiteralPath 'build\gui\CardGuard.exe' -Destination $clientDir -Force
Copy-Item -LiteralPath 'target\release\license-client.exe' -Destination $clientDir -Force
foreach ($extra in @('generic','networkinformation','tls','imageformats','Qt6Network.dll')) {
    $candidate = [IO.Path]::GetFullPath((Join-Path $clientDir $extra))
    if (!$candidate.StartsWith($clientDir + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Deployment cleanup path escaped client directory.' }
    if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Recurse -Force }
}
& (Join-Path $DevEnvironment.qtRoot 'bin\windeployqt.exe') --release --no-patchqt --no-translations --no-system-d3d-compiler --no-opengl-sw --skip-plugin-types generic,networkinformation,tls,imageformats (Join-Path $clientDir 'CardGuard.exe')
Assert-NativeExit 'Qt deployment'
Copy-Item -LiteralPath (Join-Path $DevEnvironment.qtRoot 'plugins\platforms\qoffscreen.dll') -Destination (Join-Path $clientDir 'platforms') -Force
[IO.File]::WriteAllText((Join-Path $clientDir 'qt.conf'),"[Paths]`nPrefix=.`nPlugins=.`n",[Text.UTF8Encoding]::new($false))
$licenseDir = Join-Path $clientDir 'licenses'
New-Item -ItemType Directory -Force $licenseDir | Out-Null
Copy-Item -LiteralPath 'docs\THIRD_PARTY.md' -Destination $licenseDir -Force
Copy-Item -Path 'docs\licenses\*' -Destination $licenseDir -Force
$sbom = Join-Path $DevEnvironment.qtRoot 'sbom\qtbase-6.12.0.spdx.json'
if (Test-Path $sbom) { Copy-Item -LiteralPath $sbom -Destination $licenseDir -Force }
$qtLicenseSource = Join-Path $DevEnvironment.qtRoot 'licenses'
if (Test-Path $qtLicenseSource) { Copy-Item -Path "$qtLicenseSource\*" -Destination $licenseDir -Recurse -Force }
& $DevEnvironment.python (Join-Path $PSScriptRoot 'collect-notices.py')
Assert-NativeExit 'Rust dependency notices'
Write-Host "Built client: $clientDir\CardGuard.exe"
Write-Host 'Issuer and private keys remain in the development workspace.'
