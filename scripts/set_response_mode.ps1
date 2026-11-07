#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('SIMULATION_ONLY', 'GUARDED_AUTO')]
    [string]$Mode
)
$ErrorActionPreference = 'Stop'
$taskName = 'DACN-Git-Agent'
$configPath = Join-Path $env:ProgramData 'DACN-Git\app\config\agent.json'
if (-not (Test-Path -LiteralPath $configPath)) { throw "Agent not installed: $configPath" }
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$oldMode = [string]$config.response_mode
if ($Mode -eq 'GUARDED_AUTO') {
    Write-Warning 'LIVE RESPONSE ENABLED: only corroborated, high-risk PowerShell with verified PID/path/user/start and AI approval can be terminated.'
}
# Preserve rollback file, but never print user-specific configuration values.
Copy-Item -LiteralPath $configPath -Destination "$configPath.bak" -Force
$config.response_mode = $Mode
if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName }
Start-Sleep -Seconds 2
$config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding UTF8
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
$task = Get-ScheduledTask -TaskName $taskName
if ($task.State -ne 'Running') {
    throw "Agent did not restart (state=$($task.State)). Check: C:\ProgramData\DACN-Git\app\logs\dacn_agent.log"
}
Write-Host "Mode: $oldMode -> $Mode; Task: $($task.State)"
