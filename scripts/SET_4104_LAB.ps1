#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Enable,
    [switch]$Restore,
    [ValidateSet('I-OWN-THIS-VM')][string]$Consent
)
$ErrorActionPreference='Stop'
if ($Enable -and $Restore) { throw 'Choose either -Enable or -Restore, not both.' }
$key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$name='EnableScriptBlockLogging'
$backup=Join-Path $env:ProgramData 'DACN-Git\backup_4104_lab_policy.json'
if ($Enable -or $Restore) {
    if ($Consent -ne 'I-OWN-THIS-VM') { throw 'Explicit VM consent required.' }
}
if ($Enable) {
    if (Test-Path $backup) { throw "Existing policy backup found: $backup. Restore before enabling again." }
    $hadKey = Test-Path $key
    $value = Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
    $hadValue = $null -ne $value
    $old = if ($hadValue) { [int]$value.$name } else { $null }
    New-Item -ItemType Directory -Path (Split-Path $backup -Parent) -Force | Out-Null
    [pscustomobject]@{ HadKey=$hadKey; HadValue=$hadValue; OldValue=$old } |
        ConvertTo-Json | Set-Content -LiteralPath $backup -Encoding UTF8
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name $name -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Warning 'EID4104 enabled. Script content may include secrets. Use only inside isolated lab VM.'
    Write-Host "Backup: $backup"
} elseif ($Restore) {
    if (!(Test-Path $backup)) { throw 'No 4104 policy backup exists. Refusing to guess the original state.' }
    $old = Get-Content $backup -Raw | ConvertFrom-Json
    if ($old.HadValue) {
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name $name -Value ([int]$old.OldValue) -PropertyType DWord -Force | Out-Null
    } else {
        Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
        if (-not $old.HadKey -and (Test-Path $key)) {
            $remaining = @(Get-Item -Path $key | Select-Object -ExpandProperty Property)
            if ($remaining.Count -eq 0) { Remove-Item $key -ErrorAction SilentlyContinue }
        }
    }
    Remove-Item -LiteralPath $backup -Force
    Write-Host 'EID4104 policy restored from backup.' -ForegroundColor Green
} else {
    $value=Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
    Write-Host "EnableScriptBlockLogging = $(if($value){$value.$name}else{'Not configured'})"
    Write-Host "Backup exists: $(Test-Path $backup)"
}
