#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ResultFolder)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$needed=@('cases_raw.csv','sysmon_process_events.jsonl','full_decision_audit.jsonl','labels_for_review.csv')
foreach($name in $needed){if(!(Test-Path (Join-Path $ResultFolder $name))){throw "Missing evidence: $name"}}
Push-Location $root
try {
  $args=@('-3.12','-m','verification6.final_audit','--cases',(Join-Path $ResultFolder 'cases_raw.csv'),
    '--events',(Join-Path $ResultFolder 'sysmon_process_events.jsonl'),
    '--audit',(Join-Path $ResultFolder 'full_decision_audit.jsonl'),
    '--labels',(Join-Path $ResultFolder 'labels_for_review.csv'),
    '--out',(Join-Path $ResultFolder 'final_metrics'))
  $def=Join-Path $ResultFolder 'defender_events.jsonl'
  if(Test-Path $def){$args+=@('--defender',$def)}
  & py @args
  if($LASTEXITCODE -ne 0){throw 'Final evaluation failed'}
} finally { Pop-Location }
