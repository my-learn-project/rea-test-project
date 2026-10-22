#Requires -Version 7.2
# Dot-source this file; it has no initialization or process side effects.
function Invoke-CardGuardProtocol {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Request,
        [ValidateRange(1,60)][int]$TimeoutSeconds = 15
    )
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    if ($Request.Contains("`r") -or $Request.Contains("`n") -or $encoding.GetByteCount($Request) + 1 -gt 16384) {
        throw 'Protocol request must be one line within the 16 KiB input limit.'
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new($Executable)
    $startInfo.ArgumentList.Add('--stdio')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardInputEncoding = $encoding
    $startInfo.StandardOutputEncoding = $encoding
    $startInfo.StandardErrorEncoding = $encoding
    $process = [Diagnostics.Process]::Start($startInfo)
    $limit = 65536
    $stdoutBytes = [byte[]]::new($limit + 1)
    $stderrBytes = [byte[]]::new($limit + 1)
    $stdoutCount = 0
    $stderrCount = 0
    $stdoutDone = $false
    $stderrDone = $false
    $inputDone = $false
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBytes, 0, $stdoutBytes.Length)
        $stderrTask = $process.StandardError.BaseStream.ReadAsync($stderrBytes, 0, $stderrBytes.Length)
        # Explicit LF makes the byte limit independent of the host's newline convention.
        $inputTask = $process.StandardInput.WriteAsync($Request + "`n")
        while ($true) {
            if (!$inputDone -and $inputTask.IsCompleted) {
                $inputTask.GetAwaiter().GetResult()
                $process.StandardInput.Close()
                $inputDone = $true
            }
            if (!$stdoutDone -and $stdoutTask.IsCompleted) {
                $read = $stdoutTask.GetAwaiter().GetResult()
                if ($read -eq 0) { $stdoutDone = $true } else {
                    $stdoutCount += $read
                    if ($stdoutCount -gt $limit) { throw 'Protocol stdout exceeded its 64 KiB limit.' }
                    $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBytes, $stdoutCount, $stdoutBytes.Length - $stdoutCount)
                }
            }
            if (!$stderrDone -and $stderrTask.IsCompleted) {
                $read = $stderrTask.GetAwaiter().GetResult()
                if ($read -eq 0) { $stderrDone = $true } else {
                    $stderrCount += $read
                    if ($stderrCount -gt $limit) { throw 'Protocol stderr exceeded its 64 KiB limit.' }
                    $stderrTask = $process.StandardError.BaseStream.ReadAsync($stderrBytes, $stderrCount, $stderrBytes.Length - $stderrCount)
                }
            }
            if ($inputDone -and $stdoutDone -and $stderrDone -and $process.HasExited) { break }
            if ($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'CardGuard protocol process timed out.' }
            Start-Sleep -Milliseconds 10
        }
        if (!$process.WaitForExit(1000) -or $process.ExitCode -ne 0) { throw 'CardGuard protocol process failed.' }
        $stdoutText = $encoding.GetString($stdoutBytes, 0, $stdoutCount)
        $line = [regex]::Match($stdoutText, '\A(?<response>[^\r\n]+)\r?\n\z')
        if (!$line.Success) { throw 'Protocol must emit exactly one JSON response line.' }
        $response = $line.Groups['response'].Value | ConvertFrom-Json -NoEnumerate
        if ($response -isnot [pscustomobject] -or $response.ok -isnot [bool]) { throw 'Protocol response has an invalid shape.' }
        return $response
    } finally {
        if (!$process.HasExited) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
        }
        $process.Dispose()
    }
}
