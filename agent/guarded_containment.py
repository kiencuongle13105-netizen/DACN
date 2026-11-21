"""Fail-closed *real* response for explicitly enabled Windows VM deployments.

Never allow an LLM alone to choose a PID. Correlate independent Sysmon event IDs
on the same ProcessGuid, require a high-risk behavioral indicator, confirm exact
live process identity and lifetime with psutil, and audit the result.
"""
from __future__ import annotations

import ntpath
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

MAX_EVENT_AGE_SEC = 120
MAX_CORRELATION_GAP_SEC = 90
MAX_CLOCK_DELTA_SEC = 10
SHELL_EXECUTABLES = {"powershell.exe", "pwsh.exe"}
SUSPICIOUS_SUFFIX = (".exe", ".dll", ".ps1", ".vbs", ".js", ".hta")


def parse_event_time(event: Dict[str, Any]) -> Optional[datetime]:
    stamp = event.get("event_time_utc") or event.get("utc_time")
    if not stamp:
        return None
    try:
        dt = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def event_guid(event: Dict[str, Any]) -> str:
    return str(event.get("process_guid") or "").strip().lower()


def high_risk_command(cleaned: str) -> bool:
    """Strict local signal; enc/obfuscation alone is not enough."""
    s = cleaned.lower()
    fetch = any(k in s for k in ("downloadstring", "downloadfile", "invoke-webrequest", "start-bitstransfer", "http://", "https://"))
    execution = bool(re.search(r"\b(iex|invoke-expression|invoke-command)\b", s))
    in_memory = "frombase64string" in s and (
        "reflection.assembly" in s or bool(re.search(r"\b(iex|invoke-expression)\b", s))
    )
    return (fetch and execution) or in_memory


def meaningful_evidence(event: Dict[str, Any]) -> bool:
    """Only risky artifacts/registry persistence/remote-thread events corroborate."""
    data = event.get("event_data") or {}
    eid = int(event.get("event_id", 0))
    if eid == 8:
        return bool(data.get("TargetProcessGUID") or data.get("TargetProcessGuid"))
    if eid == 11:
        target = str(data.get("TargetFilename", "")).lower().replace("/", "\\")
        low_trust_dir = any(k in target for k in ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\"))
        return low_trust_dir and target.endswith(SUSPICIOUS_SUFFIX)
    if eid == 13:
        target = str(data.get("TargetObject", "")).lower().replace("/", "\\")
        return bool(re.search(r"\\(currentversion\\run|currentversion\\runonce)(\\|$)", target))
    return False


def eligible_evidence(creation: Dict[str, Any], related: Iterable[Dict[str, Any]], now: Optional[datetime] = None) -> Tuple[bool, str, List[Dict[str, Any]]]:
    now = now or datetime.now(timezone.utc)
    if int(creation.get("event_id", 0)) != 1 or not event_guid(creation):
        return False, "MISSING_CREATION_GUID", []
    if ntpath.basename(str(creation.get("image", "")).lower()) not in SHELL_EXECUTABLES:
        return False, "NOT_POWERSHELL", []
    created = parse_event_time(creation)
    if not created or not (0 <= (now - created).total_seconds() <= MAX_EVENT_AGE_SEC):
        return False, "STALE_EVENT", []
    command = str(creation.get("cleaned_command", "") or creation.get("command_line", ""))
    if not high_risk_command(command):
        return False, "NO_HIGH_RISK_COMMAND", []
    supporting = []
    for item in related:
        if event_guid(item) != event_guid(creation) or int(item.get("event_id", 0)) not in (8, 11, 13):
            continue
        event_time = parse_event_time(item)
        if not event_time or not (0 <= (event_time - created).total_seconds() <= MAX_CORRELATION_GAP_SEC):
            continue
        if meaningful_evidence(item):
            supporting.append(item)
    if not supporting:
        return False, "INSUFFICIENT_INDEPENDENT_EVIDENCE", []
    return True, "CORRELATED", supporting[:10]


def policy_approves(verdict: Dict[str, Any]) -> bool:
    return (verdict.get("is_threat") is True
            and str(verdict.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
            and str(verdict.get("action", "")).upper() == "KILL_PROCESS")


def _safe_image(path: str) -> str:
    return ntpath.normcase(path.replace("/", "\\").removeprefix("\\\\?\\").removeprefix("\\??\\"))


def terminate_verified(creation: Dict[str, Any], *, now: Optional[datetime] = None,
                       process_factory: Optional[Callable[[int], Any]] = None) -> Dict[str, Any]:
    """Terminate only the *same* interactive-user PowerShell process in Sysmon.

    Called only after eligible_evidence() and policy_approves(). Fail closed.
    """
    now = now or datetime.now(timezone.utc)
    result: Dict[str, Any] = {"executed_action": "NONE", "response_reason": "DENIED"}
    created = parse_event_time(creation)
    if not created or not (0 <= (now - created).total_seconds() <= MAX_EVENT_AGE_SEC):
        result["response_reason"] = "STALE_EVENT"; return result
    pid = creation.get("pid")
    if not isinstance(pid, int) or pid <= 4:
        result["response_reason"] = "INVALID_PID"; return result
    image = _safe_image(str(creation.get("image") or ""))
    user = str(creation.get("user") or "").lower().strip()
    if not image or ntpath.basename(image) not in SHELL_EXECUTABLES:
        result["response_reason"] = "NOT_POWERSHELL"; return result
    # Never terminate a service/SYSTEM account or an event with missing owner.
    if not user or any(x in user for x in ("system", "local service", "network service", "dwm-", "umfd-")):
        result["response_reason"] = "PROTECTED_IDENTITY"; return result
    if process_factory is None:
        import psutil
        process_factory = psutil.Process
    try:
        proc = process_factory(pid)
        actual_path = _safe_image(str(proc.exe()))
        actual_user = str(proc.username()).lower().strip()
        actual_start = float(proc.create_time())
        result["pid"] = pid
        if actual_path != image or actual_user != user:
            result["response_reason"] = "IDENTITY_MISMATCH"; return result
        if abs(actual_start - created.timestamp()) > MAX_CLOCK_DELTA_SEC:
            result["response_reason"] = "PID_REUSED_OR_TIME_MISMATCH"; return result
        if not proc.is_running():
            result["response_reason"] = "NOT_RUNNING"; return result
        # Re-read both before kill to reduce time-of-check/time-of-use races.
        if _safe_image(str(proc.exe())) != image or abs(float(proc.create_time()) - created.timestamp()) > MAX_CLOCK_DELTA_SEC:
            result["response_reason"] = "PROCESS_CHANGED"; return result
        proc.kill()
        result["executed_action"] = "KILL_PROCESS"
        try:
            proc.wait(timeout=3)
            result["response_reason"] = "POST_VERIFY_OK"
        except Exception as exc:
            # A kill was attempted; never claim verified success on timeout.
            result["response_reason"] = "POST_VERIFY_INCOMPLETE:" + type(exc).__name__
    except Exception as exc:
        result["response_reason"] = "PROCESS_ERROR:" + type(exc).__name__
    return result
