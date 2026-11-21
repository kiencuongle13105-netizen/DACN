"""Structured EDR evidence for the real SLM, never an execution or kill policy.

FAST_RULE/held state describes local containment, not malware proof.
Sysmon corroboration requires exact ProcessGuid. EID4104 is PID+time only.
"""
from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, Iterable, List
from agent.guarded_containment import event_guid, meaningful_evidence, parse_event_time


def corroborating_events(creation: Dict[str, Any], related: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    guid = event_guid(creation)
    start = parse_event_time(creation)
    if not guid or start is None:
        return out
    for ev in related:
        stamp = parse_event_time(ev)
        eid = int(ev.get("event_id", 0))
        if event_guid(ev) != guid or eid not in (8, 11, 13) or stamp is None:
            continue
        if not (0 <= (stamp - start).total_seconds() <= 90):
            continue
        if not meaningful_evidence(ev):
            continue
        data = ev.get("event_data") or {}
        target = data.get("TargetFilename") or data.get("TargetObject") or data.get("TargetProcessGUID") or ""
        out.append({"event_id": eid, "record_id": str(ev.get("record_id", "")),
                    "time_utc": ev.get("event_time_utc"), "target": str(target)[:200],
                    "correlation": "SAME_SYSMON_PROCESSGUID"})
    return sorted(out, key=lambda r: (r["event_id"], r["record_id"]))[:10]


def build_evidence_context(creation: Dict[str, Any], *, rule: Dict[str, Any],
                           hold_status: str, related: Iterable[Dict[str, Any]] = (),
                           script_blocks: Iterable[Dict[str, Any]] = ()) -> Dict[str, Any]:
    from agent.two_stage import fast_rule
    # Calculate the local FAST_RULE result again from this very same EID1.
    actual_rule = fast_rule(creation)
    matched = bool(actual_rule.get("matched"))
    verified_rule = str(actual_rule.get("rule_id", "")) if matched else ""
    sysmon = corroborating_events(creation, related)
    psblocks = list(script_blocks)[:5]
    out = {
        "source_process_guid": event_guid(creation),
        "source_pid": creation.get("pid"),
        "source_event_record_id": str(creation.get("record_id", "")),
        "source_event_time_utc": creation.get("event_time_utc"),
        "fast_rule_matched": matched,
        "local_fast_rule_id": verified_rule,
        "fast_rule_signal": actual_rule.get("reason", "") if matched else "",
        "containment_status": str(hold_status),
        "corroborating_events": sysmon,
        "powershell_4104": psblocks,
        "evidence_limits": [
            "Fast rule/hold is NOT proof of maliciousness",
            "EID4104 has no Sysmon ProcessGuid; correlated only by PID and creation time",
            "Missing EID4104 is NOT proof of benignness",
        ],
    }
    fingerprint_data = {
        "guid": out["source_process_guid"], "eid1": out["source_event_record_id"],
        "sysmon": [(r["event_id"], r["record_id"]) for r in sysmon],
        "4104": [(r.get("record_id"), r.get("script_block_id")) for r in psblocks],
    }
    out["evidence_fingerprint"] = hashlib.sha256(
        json.dumps(fingerprint_data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:24]
    return out


def prepare_for_slm(processed: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    event = processed.copy()
    event.update(context)
    return event


def audit_context(context: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "fast_rule_matched": context.get("fast_rule_matched", False),
        "local_fast_rule_id": context.get("local_fast_rule_id", ""),
        "containment_status_at_analysis": context.get("containment_status", "UNKNOWN"),
        "sysmon_corrob_count": len(context.get("corroborating_events", [])),
        "powershell_4104_count": len(context.get("powershell_4104", [])),
        "evidence_fingerprint": context.get("evidence_fingerprint", ""),
    }
