param(
    [Parameter(Mandatory=$true)][ValidateSet('russellmitchell','fox')][string]$Scene,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9_]+$')][string]$Destination,
    [switch]$ProbeOnly
)
$ErrorActionPreference = 'Stop'
$taskRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskOutput = Join-Path $taskRoot "outputs/correlation_v4_capacity/$Destination"
$taskOwner = $null
$taskIdentity = $null
$taskMinimum = [long]::MaxValue
$taskPeak = [long]0
$taskStarted = Get-Date
$taskScenePattern = '--scene\s+'+[regex]::Escape($Scene)+'(?=\s|$)'
$taskDestinationPattern = '--destination\s+'+[regex]::Escape($Destination)+'(?=\s|$)'

function Find-OwnedValidation {
    $matching = @(Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Where-Object {
        $_.CommandLine -and $_.CommandLine.Contains('verify_correlation_capacity.py') -and
        $_.CommandLine -match $taskScenePattern -and $_.CommandLine -match $taskDestinationPattern
    })
    foreach ($directory in (Get-ChildItem -LiteralPath (Join-Path $taskRoot 'data/processed') -Directory |
            Sort-Object LastWriteTime -Descending | Select-Object -First 12)) {
        $recordPath = Join-Path $directory.FullName 'run.json'
        if (-not (Test-Path -LiteralPath $recordPath)) { continue }
        try { $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json } catch { continue }
        if ($record.status -notin @('queued','running') -or $record.dataset_metadata.scene_id -ne $Scene) { continue }
        $owner = $matching | Where-Object { $_.ProcessId -eq $record.owner_pid } | Select-Object -First 1
        if ($owner) { return @{ process=$owner; analysis_id=$record.analysis_id } }
    }
    return $null
}

if ($ProbeOnly) {
    $observed = Find-OwnedValidation
    [pscustomobject]@{ available_commit_kb=(Get-CimInstance Win32_OperatingSystem).FreeVirtualMemory;
        matched_analysis_id=if ($observed) { $observed.analysis_id } else { $null };
        matched_pid=if ($observed) { $observed.process.ProcessId } else { $null }; guard_mib=512 } |
        ConvertTo-Json -Compress
    exit 0
}

while (-not $taskOwner) {
    $found = Find-OwnedValidation
    if ($found) { $taskOwner=[int]$found.process.ProcessId; $taskIdentity=$found.analysis_id; $taskCreation=$found.process.CreationDate; break }
    if ((Get-Date)-$taskStarted -gt [TimeSpan]::FromMinutes(5)) { throw 'validation_worker_not_found' }
    Start-Sleep -Seconds 2
}

$taskStatus = 'completed_without_abort'
while ($true) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $taskOwner"
    if (-not $process) { break }
    # Revalidate ownership immediately before any possible termination.
    if (-not ($process.CreationDate -eq $taskCreation -and $process.CommandLine -and $process.CommandLine.Contains('verify_correlation_capacity.py') -and
        $process.CommandLine -match $taskScenePattern -and $process.CommandLine -match $taskDestinationPattern)) {
        throw 'validation_process_identity_changed'
    }
    $live = Get-Process -Id $taskOwner -ErrorAction SilentlyContinue
    if (-not $live) { break }
    $taskPeak=[Math]::Max($taskPeak,$live.PeakWorkingSet64)
    $available=[long](Get-CimInstance Win32_OperatingSystem).FreeVirtualMemory
    $taskMinimum=[Math]::Min($taskMinimum,$available)
    if ($available -lt 524288) {
        $taskStatus='resource_stopped'
        Stop-Process -Id $taskOwner -Force -ErrorAction SilentlyContinue
        break
    }
    Start-Sleep -Seconds 2
}

$receipt=[ordered]@{ status=$taskStatus; analysis_id=$taskIdentity; owner_pid=$taskOwner;
    minimum_available_commit_kb=$taskMinimum; peak_process_rss_mb=$taskPeak/1048576;
    guard_mib=512; threshold_changed=$false; candidate_policy_changed=$false;
    started_at=$taskStarted.ToUniversalTime().ToString('o'); completed_at=(Get-Date).ToUniversalTime().ToString('o');
    reason=if ($taskStatus -eq 'resource_stopped') { 'host_available_commit_below_512_MiB' } else { $null } }
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $taskOutput 'external_resource_guard.json') -Encoding utf8
$receipt | ConvertTo-Json -Compress
