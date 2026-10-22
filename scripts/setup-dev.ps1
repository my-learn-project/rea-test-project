[CmdletBinding()]
param(
    [ValidateSet('Toolchain', 'Qt', 'All')][string]$Phase = 'All',
    [string]$PythonExe,
    [string]$QtVersion = '6.12.0',
    [ValidatePattern('^(stable|\d+\.\d+\.\d+)$')][string]$RustVersion = '1.98.0'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tools = Join-Path $root '.tools'
$downloads = Join-Path $tools 'downloads'
New-Item -ItemType Directory -Force $downloads | Out-Null

function Download-File([string]$Url, [string]$Destination) {
    if (!(Test-Path -LiteralPath $Destination)) {
        Write-Host "Downloading $Url"
        Invoke-WebRequest -Uri $Url -OutFile $Destination
    }
}
function Assert-Publisher([string]$File, [string]$Publisher) {
    $signature = Get-AuthenticodeSignature -LiteralPath $File
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch $Publisher) {
        throw "Invalid Authenticode signature: $File"
    }
}
function Assert-Exit([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed: $LASTEXITCODE" }
}

if ($Phase -in @('Toolchain','All')) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vsPath = if (Test-Path $vswhere) { & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath }
    $vsProcess = $null
    if (!$vsPath) {
        $installer = Join-Path $downloads 'vs_buildtools.exe'
        Download-File 'https://aka.ms/vs/17/release/vs_buildtools.exe' $installer
        Assert-Publisher $installer 'Microsoft Corporation'
        Write-Host 'Installing MSVC 2022 and Windows SDK (this can take several minutes).'
        $vsProcess = Start-Process -FilePath $installer -ArgumentList @('--quiet','--wait','--norestart','--installPath','C:\BuildTools','--add','Microsoft.VisualStudio.Workload.VCTools','--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','--add','Microsoft.VisualStudio.Component.Windows11SDK.26100') -WindowStyle Hidden -PassThru
    }
    $rustup = Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe'
    if (!(Test-Path $rustup)) {
        $installer = Join-Path $downloads 'rustup-init.exe'
        Download-File 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' $installer
        $checksumUrl = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe.sha256'
        Invoke-WebRequest -Uri $checksumUrl -OutFile "$installer.sha256"
        $expectedHash = ((Get-Content -LiteralPath "$installer.sha256" -Raw).Trim() -split '\s+')[0]
        if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Rustup SHA256 mismatch.' }
        Write-Host "Installing Rust $RustVersion, Cargo, rustfmt and Clippy."
        & $installer -y --default-host x86_64-pc-windows-msvc --default-toolchain $RustVersion --profile default --no-modify-path
        Assert-Exit 'rustup installation'
    }
    & $rustup default "$RustVersion-x86_64-pc-windows-msvc"
    Assert-Exit 'Default stable MSVC toolchain'
    & $rustup component add --toolchain "$RustVersion-x86_64-pc-windows-msvc" rustfmt clippy rust-analyzer
    Assert-Exit 'rustup components'
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    $userPath = [Environment]::GetEnvironmentVariable('Path','User')
    if (($userPath -split ';') -notcontains $cargoBin) {
        [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $cargoBin), 'User')
    }
    if ($vsProcess) {
        $vsProcess.WaitForExit()
        if ($vsProcess.ExitCode -notin @(0,3010)) { throw "Visual Studio installer failed: $($vsProcess.ExitCode); inspect %TEMP%/dd_* logs" }
        if ($vsProcess.ExitCode -eq 3010) { Write-Warning 'Windows restart requested by the Build Tools installer.' }
    }
    & (Join-Path $cargoBin 'rustc.exe') --version
    & (Join-Path $cargoBin 'cargo.exe') --version
}

if ($Phase -in @('Qt','All')) {
    $python = Join-Path $tools 'python\Scripts\python.exe'
    if (!(Test-Path $python)) {
        if (!$PythonExe) {
            $command = Get-Command python -ErrorAction SilentlyContinue
            if (!$command) { throw 'Pass -PythonExe with the path to Python 3.10+.' }
            $PythonExe = $command.Source
        }
        & $PythonExe -m venv (Join-Path $tools 'python')
        Assert-Exit 'Python virtual environment'
    }
    & $python -m pip install --disable-pip-version-check 'aqtinstall==3.3.0' 'cmake==4.4.4' 'ninja==1.13.2'
    Assert-Exit 'Build helpers'
    if (!$QtVersion) {
        $versions = & $python -m aqt list-qt windows desktop --spec '>=6.8,<7'
        Assert-Exit 'Qt version discovery'
        $QtVersion = ($versions -split '\s+' | Where-Object { $_ -match '^6\.\d+\.\d+$' } | Sort-Object { [version]$_ } | Select-Object -Last 1)
        if (!$QtVersion) { throw 'No stable Qt 6 version returned by the official repository.' }
    }
    $qtRoot = Join-Path $tools 'Qt'
    if (!(Test-Path (Join-Path $qtRoot 'bin\qmake.exe'))) {
        & $python (Join-Path $PSScriptRoot 'install-qt.py') --version $QtVersion --output (Join-Path $tools 'Qt')
        Assert-Exit 'Qt SDK installation'
    }
    @{ qtRoot = $qtRoot; qtVersion = $QtVersion; python = $python } | ConvertTo-Json | Set-Content (Join-Path $tools 'environment.json') -Encoding utf8
    Write-Host "Qt SDK: $qtRoot"
}
