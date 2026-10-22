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
$toolManifest = Join-Path $ProjectRoot '.tools\xollvm\toolchain.json'
if (!(Test-Path -LiteralPath $toolManifest)) { & (Join-Path $PSScriptRoot 'install-xollvm.ps1') }
$protectionTools = Get-Content -LiteralPath $toolManifest -Raw | ConvertFrom-Json
$policyDir = Join-Path $ProjectRoot 'build\protection\windows-x64'
& $DevEnvironment.python (Join-Path $PSScriptRoot 'build-policy.py') --target windows-x64 --output $policyDir --clang $protectionTools.clang --opt $protectionTools.opt
Assert-NativeExit 'Open-source policy virtualization'
$metadata = (& cargo metadata --locked --offline --filter-platform x86_64-pc-windows-msvc --format-version 1 | ConvertFrom-Json)
Assert-NativeExit 'Locked Rust dependency metadata'
$windowsPackage = @($metadata.packages | Where-Object { $_.name -eq 'windows_x86_64_msvc' })
if ($windowsPackage.Count -ne 1) { throw 'Expected exactly one locked Windows import package.' }
$windowsImport = Join-Path (Split-Path $windowsPackage[0].manifest_path -Parent) 'lib\windows.0.52.0.lib'
& cmake -S . -B build/gui -G Ninja '-DCMAKE_BUILD_TYPE=Release' "-DCMAKE_PREFIX_PATH=$($DevEnvironment.qtRoot)" "-DCARDGUARD_RUST_LIBRARY=$ProjectRoot/target/release/license_client.lib" "-DCARDGUARD_POLICY_OBJECT=$policyDir/authorization_policy.obj" "-DCARDGUARD_WINDOWS_IMPORT_LIBRARY=$windowsImport"
Assert-NativeExit 'Qt CMake configure'
& cmake --build build/gui
Assert-NativeExit 'Qt build'
& ctest --test-dir build/gui --output-on-failure -C Release
Assert-NativeExit 'Virtualized authorization policy regression'
$clientDir = Join-Path $ProjectRoot 'dist\client'
New-Item -ItemType Directory -Force $clientDir | Out-Null
Copy-Item -LiteralPath 'build\gui\CardGuard.exe' -Destination $clientDir -Force
Copy-Item -LiteralPath 'target\release\license-client.exe' -Destination $clientDir -Force
Copy-Item -LiteralPath (Join-Path $policyDir 'protection.json') -Destination $clientDir -Force
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

# Keep the CMake output usable when opened directly during development.
# Reuse the deployed runtime without copying the full distribution or removing files.
$guiDir = Join-Path $ProjectRoot 'build\gui'
$requiredRuntimeFiles = @('Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll', 'qt.conf', 'platforms\qwindows.dll')
$missingRuntimeFiles = @($requiredRuntimeFiles | Where-Object {
    !(Test-Path -LiteralPath (Join-Path $clientDir $_) -PathType Leaf)
})
if ($missingRuntimeFiles.Count -gt 0) {
    throw "Qt 运行依赖部署不完整，无法同步开发运行目录：$($missingRuntimeFiles -join ', ')。请检查 Qt SDK 并重新运行 scripts/build.ps1。"
}
Get-ChildItem -LiteralPath $clientDir -File -Filter '*.dll' | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $guiDir -Force
}
Copy-Item -LiteralPath (Join-Path $clientDir 'qt.conf'), (Join-Path $clientDir 'license-client.exe') -Destination $guiDir -Force
foreach ($pluginType in @('platforms', 'styles')) {
    $pluginSource = Join-Path $clientDir $pluginType
    if (Test-Path -LiteralPath $pluginSource -PathType Container) {
        $pluginDestination = Join-Path $guiDir $pluginType
        New-Item -ItemType Directory -Force $pluginDestination | Out-Null
        Get-ChildItem -LiteralPath $pluginSource -Force | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination $pluginDestination -Recurse -Force
        }
    }
}
$runNotes = @'
CardGuard 开发运行目录

此目录中的 CardGuard.exe 可在构建完成后直接双击运行。
build.ps1 会同步 Qt DLL、平台/样式插件、qt.conf 和最新 license-client.exe。

推荐使用项目 dist\client\CardGuard.exe；dist\client 是包含第三方许可通知的完整客户端目录。
开发输出目录 build\gui 仅同步本机运行所需文件，不包含完整包的 licenses 或运行时安装程序。

如果提示缺少 Qt6Core.dll 等文件，请在项目根目录执行：
  pwsh -File .\scripts\build.ps1

移动程序时请复制完整 dist\client 目录，保留其 DLL 和插件子目录结构。
'@
[IO.File]::WriteAllText((Join-Path $guiDir 'README-运行说明.txt'), $runNotes, [Text.UTF8Encoding]::new($true))
$archivePath = Join-Path $ProjectRoot 'dist\CardGuard-windows-x64.zip'
$unexpectedFiles = Get-ChildItem -LiteralPath $clientDir -Recurse -File | Where-Object {
    $_.Name -match 'issuer|private|passphrase|demo-card|invalid-card|\.dpapi$|\.pfx$|\.p12$|\.key$'
}
if ($unexpectedFiles) { throw 'Unexpected signing material or issuer found in client distribution. Inspect it before creating the ZIP.' }
Compress-Archive -LiteralPath $clientDir -DestinationPath $archivePath -Force
Write-Host "Built client: $clientDir\CardGuard.exe"
Write-Host "Development executable is also ready: $guiDir\CardGuard.exe"
Write-Host "Distribution archive: $archivePath"
Write-Host 'Issuer and private keys remain in the development workspace.'
