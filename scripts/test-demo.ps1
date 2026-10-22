#Requires -Version 7.2
[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'dev-env.ps1')
. (Join-Path $PSScriptRoot 'client-protocol.ps1')
Set-Location $ProjectRoot
$client = Join-Path $ProjectRoot 'dist\client\CardGuard.exe'
$diagnosticClient = Join-Path $ProjectRoot 'dist\client\license-client.exe'
function Invoke-Request([string]$Request) {
    return Invoke-CardGuardProtocol -Executable $client -Request $Request
}
function Assert-True([bool]$Condition, [string]$Name) {
    if (!$Condition) { throw "FAIL: $Name" }
    Write-Host "PASS: $Name"
}
$tokenOutput = & (Join-Path $PSScriptRoot 'issue-demo.ps1')
$token = @($tokenOutput)[-1]
$device = Invoke-Request '{"op":"device"}'
Assert-True ($device.ok -and $device.result.device_id -match '^[0-9a-f]{64}$') 'Machine identity'
$valid = Invoke-Request (@{op='verify';token=$token} | ConvertTo-Json -Compress)
Assert-True $valid.ok 'Issued card accepted'
$parts = $token.Split('.')
$payload = $parts[1]
$signature = $parts[2]
$replacement = if ($signature[0] -eq 'A') { 'B' } else { 'A' }
$tampered = $parts[0] + '.' + $payload + '.' + $replacement + $signature.Substring(1)
$invalid = Invoke-Request (@{op='verify';token=$tampered} | ConvertTo-Json -Compress)
Assert-True (!$invalid.ok -and $invalid.error.code -eq 'invalid_signature') 'Changed signature rejected'
foreach ($bad in @('', 'not-a-card', ('x' * 5000))) {
    $response = Invoke-Request (@{op='verify';token=$bad} | ConvertTo-Json -Compress)
    Assert-True (!$response.ok) 'Malformed or oversized token rejected'
}
foreach ($request in @('{','{"op":"device","extra":true}','{"op":"unknown"}')) {
    $response = Invoke-Request $request
    Assert-True (!$response.ok -and $response.error.code -eq 'invalid_request') 'Invalid protocol request rejected'
}
$wrongDeviceOutput = & (Join-Path $PSScriptRoot 'issue-demo.ps1') -DeviceId ('0' * 64)
$wrongDevice = @($wrongDeviceOutput)[-1]
$response = Invoke-Request (@{op='verify';token=$wrongDevice} | ConvertTo-Json -Compress)
Assert-True (!$response.ok -and $response.error.code -eq 'wrong_device') 'Card for another machine rejected'
[IO.File]::WriteAllText((Join-Path $ProjectRoot '.local\demo-card.txt'),$token,[Text.UTF8Encoding]::new($false))
$gui = Join-Path $ProjectRoot 'dist\client\CardGuard.exe'
function Invoke-GuiSmoke([string]$TokenFile, [string]$Screenshot, [string]$Executable = $gui) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new($Executable)
    $startInfo.ArgumentList.Add('--smoke-test')
    if ($TokenFile) {
        $startInfo.ArgumentList.Add('--smoke-token-file')
        $startInfo.ArgumentList.Add($TokenFile)
    }
    if ($Screenshot) {
        $startInfo.ArgumentList.Add('--screenshot')
        $startInfo.ArgumentList.Add($Screenshot)
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($startInfo)
    if (!$process.WaitForExit(15000)) { $process.Kill(); throw ('Qt smoke test timed out: ' + $process.StandardError.ReadToEnd()) }
    $diagnostics = $process.StandardError.ReadToEnd()
    if ($process.ExitCode -notin @(0,2)) { Write-Host $diagnostics }
    return $process.ExitCode
}
Assert-True ((Invoke-GuiSmoke '' '') -eq 0) 'Qt offscreen GUI and in-process Rust verification'
$tokenPath = Join-Path $ProjectRoot '.local\demo-card.txt'
Assert-True ((Invoke-GuiSmoke $tokenPath (Join-Path $ProjectRoot 'build\gui-valid.png')) -eq 0) 'Qt accepts authentic card'
$badTokenPath = Join-Path $ProjectRoot '.local\invalid-card.txt'
[IO.File]::WriteAllText($badTokenPath,$tampered,[Text.UTF8Encoding]::new($false))
Assert-True ((Invoke-GuiSmoke $badTokenPath (Join-Path $ProjectRoot 'build\gui-invalid.png')) -eq 2) 'Qt rejects tampered card'

# Modify only a complete, disposable copy; never remove or replace the shipped helper.
$boundaryBuildRoot = [IO.Path]::GetFullPath((Join-Path $ProjectRoot 'build'))
$boundaryRoot = [IO.Path]::GetFullPath((Join-Path $boundaryBuildRoot ('helper-boundary-' + [Guid]::NewGuid().ToString('N'))))
if (!$boundaryRoot.StartsWith($boundaryBuildRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Helper boundary test path escaped the build directory.'
}
New-Item -ItemType Directory -Path $boundaryRoot | Out-Null
try {
    $clientSource = Split-Path $gui -Parent
    $sourceLinks = Get-ChildItem -LiteralPath $clientSource -Force -Recurse | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }
    Assert-True (!$sourceLinks) 'Client fixture source has no reparse points'
    $boundaryClient = Join-Path $boundaryRoot 'client'
    Copy-Item -LiteralPath $clientSource -Destination $boundaryClient -Recurse
    $boundaryGui = Join-Path $boundaryClient 'CardGuard.exe'
    $boundaryHelper = Join-Path $boundaryClient 'license-client.exe'
    if (Test-Path -LiteralPath $boundaryHelper) { Remove-Item -LiteralPath $boundaryHelper -Force }
    Assert-True ((Invoke-GuiSmoke $tokenPath '' $boundaryGui) -eq 0) 'GUI accepts authentic card with diagnostic helper absent'
    Assert-True ((Invoke-GuiSmoke $badTokenPath '' $boundaryGui) -eq 2) 'GUI rejects tampered card with diagnostic helper absent'

    $fixtureSource = Join-Path $boundaryRoot 'forged-helper.cpp'
    $fixtureObject = Join-Path $boundaryRoot 'forged-helper.obj'
    $fixtureMarker = Join-Path $boundaryClient 'helper-invoked.marker'
    $fixtureCode = @'
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    std::wstring module(32768, L'\0');
    DWORD count = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
    if (count == 0 || count >= module.size()) return 4;
    module.resize(count);
    const auto separator = module.find_last_of(L"\\/");
    if (separator == std::wstring::npos) return 4;
    const auto marker = module.substr(0, separator + 1) + L"helper-invoked.marker";
    HANDLE file = CreateFileW(marker.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 5;
    CloseHandle(file);
    const char *success = R"({"ok":true,"result":{"device_id":"1111111111111111111111111111111111111111111111111111111111111111","license_id":"FORGED-TEST-FIXTURE","subject":"Forged helper test fixture","issued_at":1,"expires_at":4102444800,"product":"card-demo","version":1}})";
    std::string request;
    while (std::getline(std::cin, request)) std::cout << success << std::endl;
    return 0;
}
'@
    [IO.File]::WriteAllText($fixtureSource, $fixtureCode, [Text.UTF8Encoding]::new($false))
    $fixtureCompileOutput = & cl.exe /nologo /std:c++17 /EHsc /O2 /MT "/Fe:$boundaryHelper" "/Fo:$fixtureObject" $fixtureSource 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the controlled forged-helper test fixture.' }
    $fixtureResponse = '{"op":"verify","token":"fixture-probe"}' | & $boundaryHelper --stdio
    Assert-NativeExit 'Forged helper fixture control'
    $fixtureParsed = $fixtureResponse | ConvertFrom-Json
    Assert-True ($fixtureParsed.ok -and (Test-Path -LiteralPath $fixtureMarker)) 'Forged helper control returns success and creates its invocation marker'
    Remove-Item -LiteralPath $fixtureMarker -Force
    Assert-True ((Invoke-GuiSmoke $badTokenPath '' $boundaryGui) -eq 2) 'GUI rejects tampered card beside an always-success forged helper'
    Assert-True (!(Test-Path -LiteralPath $fixtureMarker)) 'GUI never invokes the forged diagnostic helper'
} finally {
    $boundaryCleanup = [IO.Path]::GetFullPath($boundaryRoot)
    if (!$boundaryCleanup.StartsWith($boundaryBuildRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing helper fixture cleanup outside the build directory.'
    }
    if (Test-Path -LiteralPath $boundaryCleanup) { Remove-Item -LiteralPath $boundaryCleanup -Recurse -Force }
}

$forbidden = Get-ChildItem dist/client -Recurse -File | Where-Object { $_.Name -match 'issuer|private|passphrase|demo-card|\.pdb$' }
Assert-True (!$forbidden) 'Client distribution excludes signing secrets and issuer'
foreach ($exe in @($diagnosticClient,$gui)) {
    $headers = (& dumpbin /headers $exe | Out-String)
    Assert-NativeExit 'PE mitigation inspection'
    foreach ($flag in @('Dynamic base','NX compatible','Control Flow Guard','High Entropy Virtual Addresses')) {
        Assert-True ($headers -match [regex]::Escape($flag)) ((Split-Path $exe -Leaf) + ' / ' + $flag)
    }
}
Write-Host 'Integration checks completed. Local demo card: .local/demo-card.txt'
