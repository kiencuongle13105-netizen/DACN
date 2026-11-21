"""Evidence-based MITRE ATT&CK technique *observations*.

A technique observation does not prove maliciousness or authorize containment.
Only corroborated, locally verified evidence may support real process termination.
"""
from __future__ import annotations

import ntpath
import re
from typing import Any, Dict, Iterable, List

# HKCU is represented as HKU\SID by Sysmon on Windows; both share this tail.
_CANONICAL_USER_RUN_KEY = re.compile(
    r"\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\(?:run|runonce)(?:\\|$)",
    re.IGNORECASE,
)


def is_startup_run_key(target: str) -> bool:
    return bool(_CANONICAL_USER_RUN_KEY.search(str(target or "").replace("/", "\\")))


def _event_target(event: Dict[str, Any]) -> str:
    data = event.get("event_data") or {}
    # A normalized telemetry fact may use target instead of raw Sysmon fields.
    return str(data.get("TargetObject") or event.get("target") or "")


def _unique_append(ids: List[str], technique: str) -> None:
    if technique not in ids:
        ids.append(technique)


def candidates(creation: Dict[str, Any], supporting: Iterable[Dict[str, Any]] = (),
               process_tree: Iterable[Dict[str, Any]] = ()) -> List[str]:
    ids: List[str] = []
    image = ntpath.basename(str(creation.get("image") or "").lower().replace("/", "\\"))
    cmd = str(creation.get("cleaned_command") or creation.get("command_line") or "").lower()
    if image == "cmd.exe":
        _unique_append(ids, "T1059.003")
    if image in ("powershell.exe", "pwsh.exe"):
        _unique_append(ids, "T1059.001")
        if (bool(creation.get("is_obfuscated")) or re.search(r"-(?:e|enc|encodedcommand)\s+", cmd)) and (
                "downloadstring" in cmd or "frombase64string" in cmd or "iex" in cmd):
            _unique_append(ids, "T1027")
    for item in list(supporting or ()) + list(process_tree or ()):
        try:
            eid = int(item.get("event_id", 0))
        except (TypeError, ValueError, AttributeError):
            continue
        data = item.get("event_data") or {}
        if eid == 13:
            _unique_append(ids, "T1112")
            if is_startup_run_key(_event_target(item)):
                _unique_append(ids, "T1547.001")
        elif eid == 8:
            src = str(data.get("SourceProcessGUID") or data.get("SourceProcessGuid") or "").lower()
            dst = str(data.get("TargetProcessGUID") or data.get("TargetProcessGuid") or "").lower()
            img = str(data.get("TargetImage") or "").lower()
            if src and dst and src != dst and img and "<unknown" not in img:
                _unique_append(ids, "T1055")
    return ids


def _reported_observation(possible: List[str]) -> str:
    """Report the most specific observable behavior, never a malware verdict.

    Generic PowerShell execution and registry modifications are less specific
    than a confirmed Run-key value write. An observed technique can be reported
    even when a 3B model declines to name it.
    """
    for technique in ("T1547.001", "T1055", "T1027", "T1059.001", "T1059.003", "T1112"):
        if technique in possible:
            return technique
    return "N/A"


def adjudicate(creation: Dict[str, Any], verdict: Dict[str, Any], related=(),
               process_tree=()) -> Dict[str, Any]:
    suggested = str(verdict.get("mitre_technique") or "").strip().upper()
    possible = candidates(creation, related, process_tree)
    observed_run = any(
        int(e.get("event_id", 0)) == 13 and is_startup_run_key(_event_target(e))
        for e in list(related or ()) + list(process_tree or ())
        if isinstance(e, dict)
    )
    ai_match = suggested in possible
    observed = _reported_observation(possible)
    return {
        # Independent behavior mapping: never used to grant process termination.
        "reported_attack_id": observed,
        "attack_id_source": "SYSMON_OBSERVED_TECHNIQUE" if observed != "N/A" else "UNMAPPED",
        "slm_technique_match": ai_match,
        "ai_suggested_attack_id": suggested,
        "attack_mapping_candidates": possible,
        "observed_technique_candidates": possible,
        "observed_registry_run_key": observed_run,
        "attack_mapping_status": (
            "SUPPORTED_CANDIDATE" if suggested in possible else "UNSUPPORTED_OR_UNVERIFIED"
        ),
        "validated_attack_id": suggested if suggested in possible else "N/A",
    }
