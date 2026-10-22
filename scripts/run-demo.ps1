[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$clientDir = Join-Path $root 'dist\client'
$exe = Join-Path $clientDir 'CardGuard.exe'
$requiredFiles = @('CardGuard.exe', 'license-client.exe', 'Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll', 'qt.conf', 'platforms\qwindows.dll')
$missingFiles = @($requiredFiles | Where-Object {
    !(Test-Path -LiteralPath (Join-Path $clientDir $_) -PathType Leaf)
})
if ($missingFiles.Count -gt 0) {
    $missingList = ($missingFiles | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
    throw "客户端运行文件不完整，暂时无法启动：$([Environment]::NewLine)$missingList$([Environment]::NewLine)请在项目根目录运行：pwsh -File .\scripts\build.ps1，然后重新启动。完整客户端应保留在 dist\client 目录。"
}
try {
    Start-Process -FilePath $exe -WorkingDirectory $clientDir
} catch {
    throw "无法启动 CardGuard：$($_.Exception.Message)$([Environment]::NewLine)请运行 pwsh -File .\scripts\build.ps1 恢复客户端及 Qt 运行依赖后重试。"
}
