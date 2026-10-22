#Requires -Version 7.2
[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'dev-env.ps1')
Set-Location $ProjectRoot
$client = Join-Path $ProjectRoot 'dist\client\license-client.exe'
function Invoke-Request([string]$Request) {
    $response = $Request | & $client --stdio
    Assert-NativeExit 'Client protocol'
    if (@($response).Count -ne 1) { throw 'Protocol emitted unexpected extra lines.' }
    return $response | ConvertFrom-Json
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
function Invoke-GuiSmoke([string]$TokenFile, [string]$Screenshot) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new($gui)
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
Assert-True ((Invoke-GuiSmoke '' '') -eq 0) 'Qt offscreen GUI and Rust IPC'
$tokenPath = Join-Path $ProjectRoot '.local\demo-card.txt'
Assert-True ((Invoke-GuiSmoke $tokenPath (Join-Path $ProjectRoot 'build\gui-valid.png')) -eq 0) 'Qt accepts authentic card'
$badTokenPath = Join-Path $ProjectRoot '.local\invalid-card.txt'
[IO.File]::WriteAllText($badTokenPath,$tampered,[Text.UTF8Encoding]::new($false))
Assert-True ((Invoke-GuiSmoke $badTokenPath (Join-Path $ProjectRoot 'build\gui-invalid.png')) -eq 2) 'Qt rejects tampered card'
$forbidden = Get-ChildItem dist/client -Recurse -File | Where-Object { $_.Name -match 'issuer|private|passphrase|demo-card|\.pdb$' }
Assert-True (!$forbidden) 'Client distribution excludes signing secrets and issuer'
foreach ($exe in @($client,$gui)) {
    $headers = (& dumpbin /headers $exe | Out-String)
    Assert-NativeExit 'PE mitigation inspection'
    foreach ($flag in @('Dynamic base','NX compatible','Control Flow Guard','High Entropy Virtual Addresses')) {
        Assert-True ($headers -match [regex]::Escape($flag)) ((Split-Path $exe -Leaf) + ' / ' + $flag)
    }
}
Write-Host 'Integration checks completed. Local demo card: .local/demo-card.txt'
