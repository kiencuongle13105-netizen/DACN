#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$app=Join-Path $env:ProgramData 'DACN-Git\app'
if (-not (Test-Path (Join-Path $app 'agent\recover_holds.py'))) { throw "App missing: $app" }
Push-Location $app
try { py -3.12 -m agent.recover_holds; if ($LASTEXITCODE -ne 0) { throw 'Recovery failed' } }
finally { Pop-Location }
