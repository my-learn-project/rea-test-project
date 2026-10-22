#Requires -Version 7.2
[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'dev-env.ps1')
Set-Location $ProjectRoot
$privateDir = Join-Path $ProjectRoot '.local'
New-Item -ItemType Directory -Force $privateDir | Out-Null
# Restrict development secrets to this Windows user, SYSTEM and Administrators.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
$acl.SetOwner($identity)
foreach ($sid in @($identity, [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $privateDir -AclObject $acl
$privateKey = Join-Path $privateDir 'demo.private.json'
$publicKey = Join-Path $ProjectRoot 'config\trusted-public-key.hex'
$passFile = Join-Path $privateDir 'demo-passphrase.dpapi'
if ((Test-Path $privateKey) -and (Test-Path $publicKey) -and (Test-Path $passFile)) {
    Write-Host 'Existing demo identity retained.'
    return
}
if ((Test-Path $privateKey) -or (Test-Path $publicKey) -or (Test-Path $passFile)) {
    throw 'Partial identity exists. Inspect .local and config; files will not be overwritten.'
}
& cargo build --release -p license-issuer
Assert-NativeExit 'Issuer build'
$passwordBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($passwordBytes)
$password = [Convert]::ToBase64String($passwordBytes)
[Array]::Clear($passwordBytes,0,$passwordBytes.Length)
$secure = ConvertTo-SecureString $password -AsPlainText -Force
$protected = ConvertFrom-SecureString $secure
$startInfo = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $ProjectRoot 'target\release\license-issuer.exe'))
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardInput = $true
foreach ($item in @('keygen','--private-key',$privateKey,'--public-key',$publicKey,'--passphrase-stdin')) { $startInfo.ArgumentList.Add($item) }
$process = [System.Diagnostics.Process]::Start($startInfo)
$process.StandardInput.WriteLine($password)
$process.StandardInput.Close()
$password = $null
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw 'Demo key generation failed.' }
[IO.File]::WriteAllText($passFile,$protected,[Text.UTF8Encoding]::new($false))
Write-Host 'Created a development signing identity. Its random passphrase is protected by current-user Windows DPAPI.'
Write-Host 'Use scripts/issue-demo.ps1 to issue a card for this development identity.'
