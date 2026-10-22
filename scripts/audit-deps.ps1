#Requires -Version 7.2
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$auditProjectRoot = Split-Path $PSScriptRoot -Parent
$auditReportDirectory = Join-Path $auditProjectRoot '.local'
$auditReportPath = Join-Path $auditReportDirectory 'audit-report.json'
$auditEndpoint = 'https://api.osv.dev/v1/querybatch'
$auditTarget = 'x86_64-pc-windows-msvc'
$auditPackages = [System.Collections.Generic.List[object]]::new()
$auditFailure = 'Development environment initialization failed.'
$auditExitCode = 2

# The report contains dependency coordinates and OSV advisory IDs only.
# No paths, machine identifiers, environment variables, or signing material are sent.
$auditReport = [ordered]@{
    schema_version = 1
    status = 'unavailable'
    checked_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    source = $auditEndpoint
    ecosystem = 'crates.io'
    target = $auditTarget
    package_count = 0
    advisory_count = 0
    packages = @()
    message = 'Audit has not completed; vulnerability status is unknown.'
}

try {
    . (Join-Path $PSScriptRoot 'dev-env.ps1')
    Push-Location -LiteralPath $auditProjectRoot
    try {
        $auditFailure = 'The locked offline dependency tree could not be read. Restore Cargo.lock and fetch its dependencies before retrying.'
        $auditTree = @(& cargo tree --locked --offline --workspace --target $auditTarget --prefix none --format '{p}')
        if ($LASTEXITCODE -ne 0) {
            throw 'Cargo dependency tree failed.'
        }
    } finally {
        Pop-Location
    }

    $auditFailure = 'The dependency tree contained an unsupported entry; vulnerability status is unknown.'
    $auditCoordinates = @{}
    foreach ($auditLine in $auditTree) {
        $auditLine = ([string]$auditLine).Trim()
        if ([string]::IsNullOrWhiteSpace($auditLine)) { continue }
        # Local workspace packages include their filesystem path in parentheses.
        # Git dependencies also include a source URL; neither is a registry coordinate.
        if ($auditLine -match '^[A-Za-z0-9_-]+ v[0-9][0-9A-Za-z.+-]* \((?!\*\))[^)]+\)(?: \(\*\))?$') {
            continue
        }
        if ($auditLine -notmatch '^(?<name>[A-Za-z0-9_-]+) v(?<version>[0-9][0-9A-Za-z.+-]*)(?: \(\*\))?$') {
            throw 'Unexpected cargo tree output.'
        }
        $auditName = $Matches['name']
        $auditVersion = $Matches['version']
        $auditCoordinates["$auditName@$auditVersion"] = [ordered]@{
            name = $auditName
            version = $auditVersion
            advisories = @()
        }
    }
    foreach ($auditCoordinate in ($auditCoordinates.Keys | Sort-Object)) {
        $auditPackages.Add($auditCoordinates[$auditCoordinate])
    }
    if ($auditPackages.Count -eq 0) {
        $auditFailure = 'No registry dependencies were found; no audit conclusion can be made.'
        throw 'Empty registry dependency set.'
    }
    $auditReport.package_count = $auditPackages.Count

    $auditFailure = 'OSV could not be reached or returned an invalid response. Vulnerability status is unknown; retry when the service is available.'
    # Bounded batches also keep each public dependency request small.
    for ($auditOffset = 0; $auditOffset -lt $auditPackages.Count; $auditOffset += 100) {
        $auditBatchSize = [Math]::Min(100, $auditPackages.Count - $auditOffset)
        $auditQueries = [System.Collections.Generic.List[object]]::new()
        for ($auditIndex = 0; $auditIndex -lt $auditBatchSize; $auditIndex++) {
            $auditPackage = $auditPackages[$auditOffset + $auditIndex]
            $auditQueries.Add(@{
                package = @{ name = $auditPackage.name; ecosystem = 'crates.io' }
                version = $auditPackage.version
            })
        }
        $auditBody = @{ queries = $auditQueries.ToArray() } | ConvertTo-Json -Depth 8 -Compress
        $auditResponse = Invoke-RestMethod -Method Post -Uri $auditEndpoint -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($auditBody)) -TimeoutSec 60
        if ($null -eq $auditResponse -or $null -eq $auditResponse.PSObject.Properties['results'] -or $auditResponse.results -isnot [array]) {
            throw 'OSV response is missing results.'
        }
        $auditResults = @($auditResponse.results)
        if ($auditResults.Count -ne $auditBatchSize) {
            throw 'OSV response count does not match query count.'
        }
        for ($auditIndex = 0; $auditIndex -lt $auditBatchSize; $auditIndex++) {
            $auditResult = $auditResults[$auditIndex]
            if ($null -eq $auditResult -or $auditResult -isnot [pscustomobject]) {
                throw 'OSV returned an invalid result item.'
            }
            foreach ($auditResultProperty in $auditResult.PSObject.Properties.Name) {
                if ($auditResultProperty -notin @('vulns', 'next_page_token')) {
                    throw 'OSV returned an unsupported result field.'
                }
            }
            if ($null -ne $auditResult.PSObject.Properties['next_page_token'] -and ![string]::IsNullOrWhiteSpace([string]$auditResult.next_page_token)) {
                throw 'OSV returned a partial paginated result; audit is incomplete.'
            }
            $auditIds = [System.Collections.Generic.List[string]]::new()
            if ($null -ne $auditResult.PSObject.Properties['vulns']) {
                if ($auditResult.vulns -isnot [array]) {
                    throw 'OSV advisory list is malformed.'
                }
                foreach ($auditVulnerability in @($auditResult.vulns)) {
                    $auditId = [string]$auditVulnerability.id
                    if ([string]::IsNullOrWhiteSpace($auditId) -or $auditId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
                        throw 'OSV returned an invalid advisory ID.'
                    }
                    $auditIds.Add($auditId)
                }
            }
            $auditPackages[$auditOffset + $auditIndex].advisories = @($auditIds | Sort-Object -Unique)
        }
    }

    $auditAllIds = @($auditPackages | ForEach-Object { $_.advisories } | Sort-Object -Unique)
    $auditReport.advisory_count = $auditAllIds.Count
    if ($auditAllIds.Count -gt 0) {
        $auditReport.status = 'advisories_found'
        $auditReport.message = 'OSV reports advisories for one or more locked Rust dependencies. Review before release.'
        $auditExitCode = 1
        foreach ($auditPackage in $auditPackages) {
            if ($auditPackage.advisories.Count -gt 0) {
                Write-Warning ("{0} {1}: {2}" -f $auditPackage.name, $auditPackage.version, ($auditPackage.advisories -join ', '))
            }
        }
    } else {
        $auditReport.status = 'passed'
        $auditReport.message = 'OSV returned no known advisories for these locked Rust registry dependencies at the time of this check. This is not a security guarantee and does not audit Qt or other native dependencies.'
        $auditExitCode = 0
        Write-Host "OSV returned no known advisories for $($auditPackages.Count) locked Rust registry dependencies."
    }
} catch {
    $auditReport.status = 'unavailable'
    $auditReport.message = $auditFailure
    $auditExitCode = 2
    Write-Warning "Dependency audit unavailable: $auditFailure"
} finally {
    $auditReport.packages = $auditPackages.ToArray()
    try {
        New-Item -ItemType Directory -Path $auditReportDirectory -Force | Out-Null
        $auditReportJson = $auditReport | ConvertTo-Json -Depth 10
        [IO.File]::WriteAllText($auditReportPath, $auditReportJson, [Text.UTF8Encoding]::new($false))
        Write-Host 'Audit report saved to .local/audit-report.json.'
    } catch {
        Write-Warning 'The local audit report could not be saved; audit is incomplete.'
        $auditExitCode = 2
    }
}
exit $auditExitCode
