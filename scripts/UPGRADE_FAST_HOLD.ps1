#Requires -RunAsAdministrator
[CmdletBinding()]
param([ValidateSet('I-OWN-THIS-VM')][string]$Consent)
$ErrorActionPreference = 'Stop'
if ($Consent -ne 'I-OWN-THIS-VM') { throw 'Run only on your isolated VM with -Consent I-OWN-THIS-VM.' }
$src = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$app = Join-Path $env:ProgramData 'DACN-Git\app'
$taskName = 'DACN-Git-Agent'
if (!(Test-Path (Join-Path $app 'agent\autostart.py'))) { throw 'Week6 agent not installed.' }
$backup = Join-Path $env:ProgramData ('DACN-Git\backup_fast_hold_' + (Get-Date -Format yyyyMMdd_HHmmss))
New-Item -ItemType Directory -Path $backup -Force | Out-Null
$items = @('Sensor', 'agent', 'actuator', 'utils', 'main.py')
foreach ($item in $items) {
    $old = Join-Path $app $item
    $dst = Join-Path $backup $item
    if (Test-Path $old -PathType Container) {
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        Copy-Item -Path (Join-Path $old '*') -Destination $dst -Recurse -Force
    } elseif (Test-Path $old) {
        Copy-Item -LiteralPath $old -Destination $dst -Force
    }
}
$oldConfig = Join-Path $app 'config\agent.json'
if (Test-Path $oldConfig) { Copy-Item $oldConfig (Join-Path $backup 'agent.json') -Force }
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($task.State -eq 'Running') {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Start-Sleep -Seconds 2
}
try {
    # Installer retains local response_mode, AI URL/model, cursor, data, and logs.
    # No mode changes are forced by this upgrade.
    & (Join-Path $src 'scripts\install_autostart.ps1')
    if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') {
        throw 'Agent task not running after upgrade.'
    }
    Write-Host "FAST HOLD upgrade installed. Backup: $backup" -ForegroundColor Green
    Get-Content (Join-Path $app 'config\agent.json') -Raw
} catch {
    Write-Warning "Upgrade failed. Reverting code from $backup"
    foreach ($item in $items) {
        $old = Join-Path $backup $item
        $dst = Join-Path $app $item
        if (Test-Path $old -PathType Container) {
            New-Item -ItemType Directory -Path $dst -Force | Out-Null
            Copy-Item -Path (Join-Path $old '*') -Destination $dst -Recurse -Force
        } elseif (Test-Path $old) {
            Copy-Item -LiteralPath $old -Destination $dst -Force
        }
    }
    if (Test-Path (Join-Path $backup 'agent.json')) {
        Copy-Item (Join-Path $backup 'agent.json') $oldConfig -Force
    }
    Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    throw
}
