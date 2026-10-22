#Requires -Version 7.2
[CmdletBinding()]
param([string]$PythonExe)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$configuration = Get-Content -LiteralPath (Join-Path $root 'config\xollvm-toolchain.json') -Raw | ConvertFrom-Json
# Require the reviewed release even if a local config file is accidentally edited.
$expectedHash = '762eec5f8274ad45705d3294606c7e7de83c76969db57741b1789aaaa726d1f1'
$officialUrl = 'https://github.com/und3ath/xollvm/releases/download/v0.11.1/xollvm-windows-llvm22-Release.7z'
if ($configuration.version -ne '0.11.1' -or $configuration.llvm_major -ne 22 -or
    $configuration.sha256 -ne $expectedHash -or $configuration.url -ne $officialUrl) {
    throw 'xollvm toolchain config does not match the reviewed fixed release.'
}

function Assert-Within([string]$Path, [string]$Base) {
    $absolute = [IO.Path]::GetFullPath($Path)
    $basePath = [IO.Path]::GetFullPath($Base).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (!$absolute.StartsWith($basePath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Tool installation path escaped its intended directory.'
    }
    # Reject existing reparse points instead of allowing a junction to redirect writes.
    $cursor = $absolute
    while ($cursor.Length -gt $basePath.Length) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Tool installation path contains a reparse point.'
            }
        }
        $cursor = Split-Path $cursor -Parent
    }
    return $absolute
}

function Assert-ClangReady([string]$ClangExe, [string]$ProbeDirectory) {
    $clangVersion = (& $ClangExe --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $clangVersion -notmatch 'clang version 22\.') {
        throw 'Pinned xollvm clang is not an executable LLVM 22 toolchain on this Windows host.'
    }
    # Use the official compiler's built-in pipeline. opt.exe is not needed and
    # may be disallowed by application control; never change policy or rename it.
    $probeName = 'readiness-' + [Guid]::NewGuid().ToString('N')
    $probePath = Assert-Within (Join-Path $ProbeDirectory ($probeName + '.cpp')) $ProbeDirectory
    $probeIrPath = Assert-Within (Join-Path $ProbeDirectory ($probeName + '.ll')) $ProbeDirectory
    try {
        $probeSource = @'
extern "C" __attribute__((annotate("obf: vm(encBytecode=0,antiDebug=0,bindAntiDebug=0)"), noinline))
int cardguard_xollvm_readiness(unsigned value) {
    int allowed = 0;
    if (value == 7u) { allowed = 1; }
    return allowed;
}

'@
        [IO.File]::WriteAllText($probePath, $probeSource, [Text.UTF8Encoding]::new($false))
        $diagnostic = & $ClangExe '--target=x86_64-pc-windows-msvc' '-std=c++17' '-ffreestanding' '-nostdinc' '-fno-exceptions' '-fno-rtti' '-O1' '-S' '-emit-llvm' '-mllvm' '-enable-obfuscation' '-mllvm' '-obf-verify' '-mllvm' '-obf-seed=20261022' '-mllvm' '-obf-deterministic' $probePath '-o' $probeIrPath 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "xollvm clang could not execute its built-in obfuscation pipeline: $($diagnostic.Trim())"
        }
        $probeIr = Get-Content -LiteralPath $probeIrPath -Raw
        if ($probeIr -notmatch 'vm\.bytecode' -or $probeIr -notmatch '__vm_engine') {
            throw 'xollvm clang recognized the flags but did not emit an actual virtualized readiness function.'
        }
    } finally {
        foreach ($probeFile in @($probePath, $probeIrPath)) {
            if (Test-Path -LiteralPath $probeFile -PathType Leaf) {
                Remove-Item -LiteralPath $probeFile -Force
            }
        }
    }
}

function Save-VerifiedArchive([string]$ArchivePath, [string]$PythonPath) {
    # A fresh name prevents an interrupted or concurrent download from being
    # promoted. Both transports fetch the same pinned official asset and must
    # satisfy the same reviewed digest before the file can be used.
    $temporaryDownload = Assert-Within ($ArchivePath + '.part-' + [Guid]::NewGuid().ToString('N')) $root
    try {
        $verified = $false
        try {
            Invoke-WebRequest -Uri $officialUrl -OutFile $temporaryDownload -TimeoutSec 90
            $verified = (Get-FileHash -LiteralPath $temporaryDownload -Algorithm SHA256).Hash -eq $expectedHash
            if (!$verified) { Write-Warning 'The first download was incomplete or failed its pinned digest; retrying with Python HTTPS.' }
        } catch {
            Write-Warning 'The first HTTPS download failed; retrying the same pinned asset with Python HTTPS.'
        }
        if (!$verified) {
            if (Test-Path -LiteralPath $temporaryDownload) { Remove-Item -LiteralPath $temporaryDownload -Force }
            # GitHub release redirects can be cached in an unusable state on
            # some hosts. A fixed query bypasses that cache without changing the
            # asset, certificate validation, or mandatory digest verification.
            $download = @'
import hashlib
from pathlib import Path
import sys
import time
import urllib.request

url, destination, expected = sys.argv[1:]
started = time.monotonic()
size = 0
value = hashlib.sha256()
request = urllib.request.Request(url, headers={'User-Agent': 'CardGuard-toolchain-installer/0.1'})
with urllib.request.urlopen(request, timeout=60) as response:
    if not response.url.startswith('https://'):
        raise SystemExit('Refusing a non-HTTPS release redirect')
    with Path(destination).open('xb') as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > 256 * 1024 * 1024 or time.monotonic() - started > 300:
                raise SystemExit('Pinned release download exceeded its size or time limit')
            value.update(chunk)
            output.write(chunk)
if value.hexdigest() != expected:
    raise SystemExit('Downloaded xollvm archive failed the fixed SHA-256 check')
'@
            $download | & $PythonPath - ($officialUrl + '?cardguard=20261022') $temporaryDownload $expectedHash
            if ($LASTEXITCODE -ne 0) { throw 'The fallback xollvm download failed; no downloaded tool was executed.' }
        }
        if ((Get-FileHash -LiteralPath $temporaryDownload -Algorithm SHA256).Hash -ne $expectedHash) {
            throw 'Downloaded xollvm archive failed the fixed SHA-256 check.'
        }
        Move-Item -LiteralPath $temporaryDownload -Destination $ArchivePath -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryDownload) { Remove-Item -LiteralPath $temporaryDownload -Force }
    }
}

$tools = Assert-Within (Join-Path $root '.tools') $root
$toolRoot = Assert-Within (Join-Path $tools 'xollvm') $root
$downloads = Assert-Within (Join-Path $tools 'downloads') $root
New-Item -ItemType Directory -Force $toolRoot, $downloads | Out-Null
$manifestPath = Assert-Within (Join-Path $toolRoot 'toolchain.json') $root
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    try {
        $installed = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($installed.version -ne '0.11.1' -or $installed.llvmMajor -ne 22 -or $installed.mode -ne 'clang-integrated' -or
            $installed.sha256 -ne $expectedHash -or
            $installed.clangSha256 -notmatch '^[0-9a-fA-F]{64}$' -or $installed.optSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'Cached toolchain metadata does not match the fixed release.'
        }
        $cachedClang = Assert-Within ([string]$installed.clang) $toolRoot
        $cachedOpt = Assert-Within ([string]$installed.opt) $toolRoot
        if (!(Test-Path -LiteralPath $cachedClang -PathType Leaf) -or
            !(Test-Path -LiteralPath $cachedOpt -PathType Leaf) -or
            (Split-Path $cachedClang -Leaf) -ne 'clang.exe' -or (Split-Path $cachedOpt -Leaf) -ne 'opt.exe' -or
            (Get-FileHash -LiteralPath $cachedClang -Algorithm SHA256).Hash -ne $installed.clangSha256 -or
            (Get-FileHash -LiteralPath $cachedOpt -Algorithm SHA256).Hash -ne $installed.optSha256) {
            throw 'Cached xollvm executable paths or file hashes do not match the installation manifest.'
        }
        Assert-ClangReady $cachedClang $toolRoot
        Write-Host "Reusing verified xollvm v0.11.1: $cachedClang"
        return
    } catch {
        Write-Warning 'Existing xollvm installation did not pass verification; preparing a fresh copy from the fixed archive.'
    }
}
if (!$PythonExe) {
    $PythonExe = Join-Path $tools 'python\Scripts\python.exe'
}
if (!(Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    throw 'Pass -PythonExe with an existing Python that has py7zr installed (the project Qt helper environment includes it).'
}
$archive = Assert-Within (Join-Path $downloads $configuration.archive_name) $root
if (!(Test-Path -LiteralPath $archive)) {
    Write-Host 'Downloading pinned xollvm v0.11.1 / LLVM 22 (about 125 MB).'
    Save-VerifiedArchive $archive $PythonExe
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'Cached xollvm archive failed the fixed SHA-256 check; it was not executed.'
}

$stage = Assert-Within (Join-Path $toolRoot ('v0.11.1-llvm22-' + [Guid]::NewGuid().ToString('N'))) $root
New-Item -ItemType Directory $stage | Out-Null
$extract = @'
import sys
from pathlib import Path
import py7zr
archive_path = Path(sys.argv[1]).resolve()
destination = Path(sys.argv[2]).resolve()
with py7zr.SevenZipFile(archive_path) as archive:
    for name in archive.getnames():
        if not (destination / name).resolve().is_relative_to(destination):
            raise SystemExit('Unsafe path in xollvm archive')
    archive.extractall(destination)
for path in destination.rglob('*'):
    if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
        if not path.resolve().is_relative_to(destination):
            raise SystemExit('External link in xollvm archive')
'@
$extract | & $PythonExe - $archive $stage
if ($LASTEXITCODE -ne 0) { throw 'xollvm archive extraction failed.' }
$clangCandidates = @(Get-ChildItem -LiteralPath $stage -Recurse -File -Filter clang.exe)
if ($clangCandidates.Count -ne 1) { throw 'Expected exactly one clang.exe in the official toolchain archive.' }
$clang = Assert-Within $clangCandidates[0].FullName $toolRoot
$bin = Split-Path $clang -Parent
$opt = Assert-Within (Join-Path $bin 'opt.exe') $toolRoot
if (!(Test-Path -LiteralPath $opt -PathType Leaf)) { throw 'Official toolchain archive is missing opt.exe.' }
Assert-ClangReady $clang $toolRoot
$environment = @{
    version = $configuration.version
    llvmMajor = 22
    mode = 'clang-integrated'
    archiveSha256 = $expectedHash
    sha256 = $expectedHash
    installRoot = $stage
    clang = $clang
    clangCl = $clang
    clangClDriverArgument = '--driver-mode=cl'
    opt = $opt
    optAvailable = $false
    optAvailability = 'not-executed; clang-integrated mode does not require opt.exe'
    clangSha256 = (Get-FileHash -LiteralPath $clang -Algorithm SHA256).Hash.ToLowerInvariant()
    optSha256 = (Get-FileHash -LiteralPath $opt -Algorithm SHA256).Hash.ToLowerInvariant()
    licenseUrl = $configuration.license_url
}
$environment | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Host "xollvm ready: $clang"
Write-Host 'Official archive verified; clang-integrated VM readiness passed. opt.exe was not executed; no security settings changed.'
