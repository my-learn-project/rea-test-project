#Requires -Version 7.2
[CmdletBinding()]
param([string]$Subject = '本机演示授权', [ValidateRange(1,8760)][int]$ValidHours = 24, [string]$DeviceId)
. (Join-Path $PSScriptRoot 'dev-env.ps1')
. (Join-Path $PSScriptRoot 'client-protocol.ps1')
Set-Location $ProjectRoot
$privateKey = Join-Path $ProjectRoot '.local\demo.private.json'
$passFile = Join-Path $ProjectRoot '.local\demo-passphrase.dpapi'
if (!(Test-Path $privateKey) -or !(Test-Path $passFile)) { throw 'Run scripts/init-demo.ps1 first.' }
if (!$DeviceId) {
    $deviceResponse = Invoke-CardGuardProtocol -Executable (Join-Path $ProjectRoot 'dist\client\CardGuard.exe') -Request '{"op":"device"}'
    if (!$deviceResponse.ok) { throw $deviceResponse.error.message }
    $DeviceId = $deviceResponse.result.device_id
}
if ($DeviceId -notmatch '^[0-9a-f]{64}$') { throw 'DeviceId must be 64 lowercase hexadecimal characters.' }
$secure = ConvertTo-SecureString (Get-Content $passFile -Raw)
$password = [System.Net.NetworkCredential]::new('', $secure).Password
$startInfo = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $ProjectRoot 'target\release\license-issuer.exe'))
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
foreach ($item in @('issue','--private-key',$privateKey,'--subject',$Subject,'--device-id',$DeviceId,'--license-id',([Guid]::NewGuid().ToString()),'--valid-hours',$ValidHours.ToString(),'--passphrase-stdin')) { $startInfo.ArgumentList.Add($item) }
$process = [System.Diagnostics.Process]::Start($startInfo)
$process.StandardInput.WriteLine($password)
$process.StandardInput.Close()
$password = $null
$token = $process.StandardOutput.ReadToEnd().Trim()
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw 'Card issuance failed.' }
$outputPath = Join-Path $ProjectRoot '.local\demo-card.txt'
[IO.File]::WriteAllText($outputPath,$token,[Text.UTF8Encoding]::new($false))
Write-Host "Card saved: $outputPath"
Write-Output $token
