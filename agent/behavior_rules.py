"""Conservative, behavior-based Windows EDR fast rules.

These rules do not inspect Atomic Red Team labels, executors, test GUIDs, or
parent-process names to decide whether an action should be taken. They apply to
real Sysmon process-creation telemetry irrespective of its origin.

A match is a *reason to temporarily hold for SLM review*, not proof that a
malicious objective was completed. They intentionally do not promise to cover
all ATT&CK techniques or all Atomic Red Team tests.
"""
from __future__ import annotations

import ntpath
import re
from typing import Any, Dict

from agent.guarded_containment import high_risk_command, parse_injection_attempt
from utils.bo_giai_ma import BoGiaiMaPowerShell

# Only interactive, individually identity-verified user processes may be held.
# Protect services, Windows shell, browsers, processes with unknown identity.
CONTAINABLE_IMAGES = frozenset({
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'mshta.exe', 'regsvr32.exe',
    'rundll32.exe', 'schtasks.exe', 'reg.exe', 'wmic.exe', 'mavinject.exe',
})


def _matched(rule: str, technique: str, reason: str, image: str) -> Dict[str, Any]:
    return {'matched': True, 'rule_id': rule, 'techniques': [technique],
            'reason': reason, 'image': image}


def fast_rule(event: Dict[str, Any]) -> Dict[str, Any]:
    """Match high-confidence command patterns, never generic encoded commands."""
    if int(event.get('event_id', 0)) != 1:
        return {'matched': False, 'rule_id': 'NOT_PROCESS_CREATE', 'techniques': []}
    image = ntpath.basename(str(event.get('image', '')).replace('/', '\\')).lower()
    if image not in CONTAINABLE_IMAGES:
        return {'matched': False, 'rule_id': 'NOT_CONTAINABLE_IMAGE', 'techniques': []}
    processed = BoGiaiMaPowerShell.tien_xu_ly_su_kien(event)
    original = str(event.get('command_line', ''))
    command = str(processed.get('cleaned_command') or original).lower()
    if len(command) > 32768:
        command = command[:32768]
    # EID1-prehold of a highly specific injection command; EID8 cannot be a
    # prerequisite for HOLD because it would occur after the remote thread.
    # A separate corroboration and SLM approval are still required for KILL.
    if image == 'mavinject.exe':
        attempt, reason = parse_injection_attempt(event)
        if attempt is not None:
            return _matched('FR-INJECTION-PREHOLD-001', 'T1218.013',
                            'Mavinject /INJECTRUNNING from writable DLL path (intent only)', image)
        return {'matched': False, 'rule_id': reason, 'techniques': []}
    # PowerShell must have combined fetch+execute or in-memory execute; an
    # encoded command or common admin cmdlet alone NEVER triggers a hold.
    if image in ('powershell.exe', 'pwsh.exe') and high_risk_command(command):
        return _matched('FR-PS-INMEM-001', 'T1059.001',
                        'PowerShell combined download/execution or in-memory execution', image)
    if image == 'cmd.exe' and high_risk_command(command):
        return _matched('FR-CMD-CHAIN-001', 'T1059.003',
                        'Command interpreter launches a download/execute chain', image)
    if image == 'mshta.exe' and (re.search(r'\b(?:javascript|vbscript):', command) or
                                 re.search(r'https?://\S+\.hta\b', command)):
        return _matched('FR-MSHTA-001', 'T1218.005',
                        'HTML application host running inline script or remote HTA', image)
    if image == 'regsvr32.exe' and re.search(r'\bscrobj\.dll\b', command) and re.search(r'/i:\s*https?://', command):
        return _matched('FR-REGSVR32-001', 'T1218.010',
                        'Regsvr32 scriptlet loaded through remote /i: URL', image)
    if image == 'rundll32.exe' and 'mshtml' in command and re.search(r'\bjavascript:', command):
        return _matched('FR-RUNDLL32-001', 'T1218.011',
                        'Rundll32 invokes MSHTML JavaScript', image)
    # Persistence via Run/RunOnce is suspicious only if the new value launches
    # an additional risky script interpreter; do not hold routine reg edits.
    if image == 'reg.exe' and re.search(r'\badd\b', command) and re.search(r'\\run(?:once)?(?:\\|\s|\"|$)', command):
        if any(x in command for x in ('powershell', 'pwsh', 'mshta', 'wscript')) and any(
                x in command for x in ('http://', 'https://', '-enc', '-encoded', 'javascript:', 'vbscript:')):
            return _matched('FR-REG-RUN-001', 'T1547.001',
                            'Run-key change launching a remote or obfuscated interpreter', image)
    if image == 'schtasks.exe' and re.search(r'(?:/create)\b', command) and re.search(r'/tr\b', command):
        if ('powershell' in command or 'pwsh' in command) and high_risk_command(command):
            return _matched('FR-SCHTASK-001', 'T1053.005',
                            'Scheduled-task command executes PowerShell fetch/execute chain', image)
    if image == 'wmic.exe' and re.search(r'process\s+call\s+create', command) and high_risk_command(command):
        return _matched('FR-WMIC-001', 'T1047',
                        'WMI process creation with a download/execute chain', image)
    return {'matched': False, 'rule_id': 'NO_HIGH_CONFIDENCE_SIGNAL', 'techniques': []}
