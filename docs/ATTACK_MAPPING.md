# ATT&CK mapping review (not automatic attribution)

| Telemetry / behavior | Candidate technique | Evidence requirement / caveat |
|---|---|---|
| Sysmon EID1 PowerShell command | T1059.001 PowerShell | Process creation evidences PowerShell execution; alone not malicious |
| PowerShell downloads a tool/payload into host | T1105 Ingress Tool Transfer | Verify actual transfer/download, not merely a URL in command |
| Obfuscated PowerShell commands | T1027.010 Command Obfuscation | EncodedCommand alone does not establish malicious intent |
| Sysmon EID8 remote thread creation | T1055 Process Injection (candidate) | EID8 alone cannot prove successful injection; correlate source/target, memory telemetry |
| Sysmon EID13 registry Run / RunOnce | T1547.001 Registry Run Keys / Startup Folder (candidate) | Confirm actual value/data and persistence intent; unrelated updates are benign |
| Sysmon EID11 executable/script in low-trust path | No automatic technique ID | File created does not prove execution or persistence |
| Normal Get-Process, Get-Service, Write-Output | None | Legitimate administration scripts are negative controls |

Important: EID1 and an obfuscated command are not enough to label a sample malicious. Do not derive ATT&CK IDs from SLM text without evidence checking.

Official references: https://attack.mitre.org/techniques/T1059/001/ ; https://attack.mitre.org/techniques/T1105/ ; https://attack.mitre.org/techniques/T1027/010/ ; https://attack.mitre.org/techniques/T1055/ ; https://attack.mitre.org/techniques/T1547/001/ .
