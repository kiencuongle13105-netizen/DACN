#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$RestorePreviousTasks)
$ErrorActionPreference = "Stop"
$name = "DACN-Git-Agent"
$task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($task) {
    if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $name }
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
    Write-Host "Removed scheduled task: $name"
} else { Write-Host "$name is not registered." }
if ($RestorePreviousTasks) {
    $backupPath = Join-Path $env:ProgramData "DACN-Git\previous_tasks.json"
    if (Test-Path $backupPath) {
        $old = @(Get-Content $backupPath -Raw | ConvertFrom-Json)
        foreach ($entry in $old) {
            $oldTask = Get-ScheduledTask -TaskName $entry.Name -ErrorAction SilentlyContinue
            if ($oldTask -and $entry.WasEnabled) {
                Enable-ScheduledTask -TaskName $entry.Name | Out-Null
                if ($entry.WasRunning) { Start-ScheduledTask -TaskName $entry.Name }
                Write-Host "Restored: $($entry.Name)"
            }
        }
    } else { Write-Warning "No previous task backup found." }
}
Write-Host "Runtime data preserved in $env:ProgramData\DACN-Git\app"
