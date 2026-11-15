#Requires -Version 5.1
$ErrorActionPreference='Stop'
$channel='Microsoft-Windows-Sysmon/Operational'
Write-Host '=== Sysmon EID1 / EID5 diagnostics ===' -ForegroundColor Cyan
try {
  $events=Get-WinEvent -FilterHashtable @{LogName=$channel;Id=1,5;StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop
  $events | Group-Object Id | Select-Object Name,Count | Format-Table
  if(@($events | Where-Object Id -eq 5).Count -eq 0){
    Write-Warning 'No EID5 in past 24h. Completed-before-hold CANNOT be measured from these logs.'
    Write-Host 'Inspect active Sysmon configuration with: sysmon64 -s  (or sysmon -s).'
    Write-Host 'Do not overwrite production Sysmon config without reviewing the existing rules.'
  }
}catch{Write-Warning "Cannot query Sysmon log: $($_.Exception.Message)"}
try { & sysmon64 -s 2>$null | Out-Host }catch{Write-Host 'sysmon64 -s is optional; locate the installed Sysmon binary if not in PATH.'}
