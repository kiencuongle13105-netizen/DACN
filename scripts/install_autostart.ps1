#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$PythonPath = "",
    [string]$AiEndpoint = "http://192.168.62.1:1236/v1",
    [string]$Model = "qwen2.5-coder-3b-instruct-awq",
    [switch]$EnableGuardedAuto,
    [switch]$DisableGuardedAuto,
    [switch]$ReplaceExistingDACN
)
$ErrorActionPreference = "Stop"
if ($EnableGuardedAuto -and $DisableGuardedAuto) {
    throw "Choose only one of -EnableGuardedAuto or -DisableGuardedAuto"
}
$taskName = "DACN-Git-Agent"
$installRoot = Join-Path $env:ProgramData "DACN-Git"
$app = Join-Path $installRoot "app"
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$legacyNames = @("DACN-Sensor-Detection", "DACN-Alert-Forwarder", "DACN-Response-Worker")
$backupPath = Join-Path $installRoot "previous_tasks.json"

if (-not (Test-Path (Join-Path $sourceRoot "agent\autostart.py"))) {
    throw "Cannot find agent\autostart.py in $sourceRoot"
}
if ($AiEndpoint -notmatch '^https?://[^/]+/v1/?$') {
    throw "AiEndpoint must look like http://192.168.62.1:1236/v1"
}

if ([string]::IsNullOrWhiteSpace($PythonPath)) {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        # Python 3.12 is the existing VM environment. Suppress launcher failures
        # without treating optional discovery as a fatal PowerShell error.
        try { $PythonPath = (& $launcher.Source -3.12 -c "import sys; print(sys.executable)" | Select-Object -First 1) } catch { $PythonPath = "" }
        if (-not $PythonPath) {
            try { $PythonPath = (& $launcher.Source -3 -c "import sys; print(sys.executable)" | Select-Object -First 1) } catch { $PythonPath = "" }
        }
    }
    if (-not $PythonPath) {
        $found = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($found) { $PythonPath = $found.Source }
    }
}
if (-not $PythonPath -or -not (Test-Path $PythonPath)) {
    throw "Could not find Python. Pass -PythonPath 'C:\Program Files\Python312\python.exe'."
}
Write-Host "Python: $PythonPath"
& $PythonPath -c "import sys; assert sys.version_info >= (3,10)"
if ($LASTEXITCODE -ne 0) { throw "Python 3.10+ is required" }
& $PythonPath -c "import psutil, win32evtlog"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing Python requirements..."
    & $PythonPath -m pip install --disable-pip-version-check -r (Join-Path $sourceRoot "requirements-vm.txt")
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
    & $PythonPath -c "import psutil, win32evtlog"
    if ($LASTEXITCODE -ne 0) { throw "Python dependencies still unavailable" }
}

try {
    $channel = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
    if (-not $channel.IsEnabled) { throw "Sysmon Operational log disabled" }
} catch {
    throw "Sysmon Operational log not available. Install/enable Sysmon before AutoStart. $($_.Exception.Message)"
}

$oldTasks = @()
foreach ($name in $legacyNames) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task) {
        $oldTasks += [PSCustomObject]@{ Name = $name; WasEnabled = ($task.State -ne 'Disabled'); WasRunning = ($task.State -eq 'Running') }
    }
}
$activeLegacy = @($oldTasks | Where-Object { $_.WasEnabled })
if ($activeLegacy.Count -gt 0 -and -not $ReplaceExistingDACN) {
    $names = ($activeLegacy | ForEach-Object { $_.Name }) -join ", "
    throw "Existing DACN tasks are active: $names. To avoid duplicate monitoring, rerun with -ReplaceExistingDACN; old tasks will be disabled and restorable."
}

New-Item -ItemType Directory -Force -Path $app, $installRoot | Out-Null
if ($oldTasks.Count -gt 0 -and $ReplaceExistingDACN -and -not (Test-Path $backupPath)) {
    $oldTasks | ConvertTo-Json -Depth 3 | Set-Content -Path $backupPath -Encoding UTF8
}

# Only copy versioned Python code. Preserve SQLite, cursor, logs, and local config.
foreach ($folder in @("Sensor", "agent", "actuator", "utils")) {
    $src = Join-Path $sourceRoot $folder
    $dst = Join-Path $app $folder
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    Copy-Item -Path (Join-Path $src "*") -Destination $dst -Recurse -Force
}
Copy-Item -LiteralPath (Join-Path $sourceRoot "main.py") -Destination (Join-Path $app "main.py") -Force
New-Item -ItemType Directory -Force -Path (Join-Path $app "config"), (Join-Path $app "data"), (Join-Path $app "logs") | Out-Null
$configPath = Join-Path $app "config\agent.json"
$config = [ordered]@{
    ai_endpoint = $AiEndpoint.TrimEnd('/')
    model = $Model
    polling_interval = 1.0
    retry_seconds = 10.0
    response_mode = "SIMULATION_ONLY"
}
if (Test-Path $configPath) {
    $existingConfig = Get-Content $configPath -Raw | ConvertFrom-Json
    # Keep a user's custom host/model during upgrades unless explicitly supplied.
    if (-not $PSBoundParameters.ContainsKey('AiEndpoint')) { $config.ai_endpoint = [string]$existingConfig.ai_endpoint }
    if (-not $PSBoundParameters.ContainsKey('Model')) { $config.model = [string]$existingConfig.model }
    if ($null -ne $existingConfig.polling_interval) { $config.polling_interval = [double]$existingConfig.polling_interval }
    if ($null -ne $existingConfig.retry_seconds) { $config.retry_seconds = [double]$existingConfig.retry_seconds }
    if ($existingConfig.response_mode -in @("SIMULATION_ONLY", "GUARDED_AUTO")) {
        $config.response_mode = [string]$existingConfig.response_mode
    }
    Write-Host "Preserving local settings unless an override was passed."
}
if ($EnableGuardedAuto) { $config.response_mode = "GUARDED_AUTO" }
if ($DisableGuardedAuto) { $config.response_mode = "SIMULATION_ONLY" }
$config | ConvertTo-Json -Depth 4 | Set-Content -Path $configPath -Encoding UTF8
& $PythonPath -m compileall -q $app
if ($LASTEXITCODE -ne 0) { throw "Python compilation failed" }
Push-Location $app
try {
    & $PythonPath -m agent.autostart --check --config $configPath
    if ($LASTEXITCODE -ne 0) { throw "Agent self-check failed" }
} finally {
    Pop-Location
}

try {
    if ($ReplaceExistingDACN) {
        foreach ($old in $oldTasks) {
            $task = Get-ScheduledTask -TaskName $old.Name -ErrorAction SilentlyContinue
            if ($task -and $task.State -eq 'Running') { Stop-ScheduledTask -TaskName $old.Name }
            if ($task) { Disable-ScheduledTask -TaskName $old.Name | Out-Null }
        }
    }

    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName }
    $arguments = '-u -m agent.autostart --config "' + $configPath + '"'
    $action = New-ScheduledTaskAction -Execute $PythonPath -Argument $arguments -WorkingDirectory $app
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 3
    $running = Get-ScheduledTask -TaskName $taskName
    if ($running.State -ne 'Running') {
        throw "Task did not remain running (state=$($running.State)). Check Task Scheduler history and Python logs."
    }
} catch {
    # Don't strand the original endpoint without its existing tasks if registration fails.
    if ($ReplaceExistingDACN) {
        foreach ($old in $oldTasks) {
            if ($old.WasEnabled) {
                Enable-ScheduledTask -TaskName $old.Name -ErrorAction SilentlyContinue | Out-Null
                if ($old.WasRunning) { Start-ScheduledTask -TaskName $old.Name -ErrorAction SilentlyContinue }
            }
        }
    }
    throw
}
Write-Host "Installed and started: $taskName"
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State
Write-Host "App: $app"
Write-Host "Log: $app\logs\dacn_agent.log"
Write-Host "Config: $configPath"
Write-Host "Mode: $($config.response_mode)"
if ($config.response_mode -eq "GUARDED_AUTO") {
    Write-Warning "LIVE KILL ENABLED (GUARDED). Only same-GUID corroborated, high-risk interactive PowerShell; requires AI HIGH/CRITICAL approval and exact process identity checks."
}
