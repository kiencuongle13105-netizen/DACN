$ErrorActionPreference = "Stop"
$root = Join-Path $env:ProgramData "DACN-Git\app"
$task = Get-ScheduledTask -TaskName "DACN-Git-Agent" -ErrorAction SilentlyContinue
if (-not $task) { Write-Host "DACN-Git-Agent not installed"; exit 1 }
$info = Get-ScheduledTaskInfo -TaskName "DACN-Git-Agent"
Write-Host "TASK: $($task.TaskName)  STATE: $($task.State)  LAST_RESULT: $($info.LastTaskResult)"
Write-Host "Installed app: $root"
$heartbeat = Join-Path $root "data\heartbeat.json"
if (Test-Path $heartbeat) {
    Write-Host "HEARTBEAT:"
    Get-Content $heartbeat -Raw
} else { Write-Host "No heartbeat yet. Check Python dependencies, event log permissions and task log." }
$log = Join-Path $root "logs\dacn_agent.log"
if (Test-Path $log) { Write-Host "LAST LOGS:"; Get-Content $log -Tail 12 }
$legacy = Get-ScheduledTask -TaskName "DACN-*" -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -ne 'DACN-Git-Agent' -and $_.State -eq 'Running' }
if ($legacy) { Write-Warning "Other DACN tasks are running in parallel: $(($legacy.TaskName) -join ', ')" }
