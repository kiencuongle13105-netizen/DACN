"""Read-only PowerShell EID 4104 correlation for a Windows EDR lab.

Every candidate must match source PID AND bounded Sysmon EID1 creation time.
This module never executes PowerShell or authorizes process termination. EID4104
is not independent malware attribution and must not be treated as instructions.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

LOG = logging.getLogger(__name__)
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
CHANNEL = "Microsoft-Windows-PowerShell/Operational"
MAX_BLOCKS = 5
MAX_CHARS = 1500
MAX_WINDOW_SECONDS = 90
# Cap query work so a busy PowerShell log does not consume the hold deadline.
MAX_SCANNED = 160
BATCH_SIZE = 16
EVT_TIMEOUT_MS = 100


def _datetime(value: Any):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def parse_4104_xml(xml: str) -> Dict[str, Any]:
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    if system is None or system.findtext("e:EventID", namespaces=NS) != "4104":
        raise ValueError("Not a PowerShell EID 4104 event")
    execution = system.find("e:Execution", NS)
    created = system.find("e:TimeCreated", NS)
    fields = {d.attrib.get("Name"): d.text or "" for d in root.findall("e:EventData/e:Data", NS)}
    return {
        "event_id": 4104,
        "record_id": system.findtext("e:EventRecordID", default="", namespaces=NS),
        "pid": int(execution.attrib.get("ProcessID", "0")) if execution is not None else 0,
        "time_utc": created.attrib.get("SystemTime", "") if created is not None else "",
        "script_block_id": fields.get("ScriptBlockId", ""),
        "message_number": fields.get("MessageNumber", ""),
        "message_total": fields.get("MessageTotal", ""),
        "text": fields.get("ScriptBlockText", ""),
    }


def _within_creation_window(creation: Dict[str, Any], candidate: Dict[str, Any], now=None) -> bool:
    """PID-only correlation requires source GUID, PID and bounded event timestamps."""
    created = _datetime(creation.get("event_time_utc"))
    stamp = _datetime(candidate.get("time_utc"))
    now = now or datetime.now(timezone.utc)
    if not created or not stamp or not creation.get("process_guid"):
        return False
    if type(creation.get("pid")) is not int or creation["pid"] <= 4 or candidate.get("pid") != creation["pid"]:
        return False
    return (timedelta(seconds=-1) <= stamp - created <= timedelta(seconds=MAX_WINDOW_SECONDS)
            and stamp <= now + timedelta(seconds=1)
            and timedelta(seconds=0) <= now - created <= timedelta(seconds=MAX_WINDOW_SECONDS))


def _safe_close(handle) -> None:
    """Close pywin32 PyEVT_HANDLE. pywin32 does NOT export win32evtlog.EvtClose.

    PyEVT_HANDLE.Close() invokes Windows EvtClose; destruction also closes handles.
    Cleanup failures must never discard already-correlated observations.
    """
    close = getattr(handle, "Close", None)
    if callable(close):
        try:
            close()
        except Exception as exc:
            LOG.debug("EID4104 handle close failure type=%s", type(exc).__name__)


def _read_query(evt, query: str, creation: Dict[str, Any], now: datetime):
    """Fetch bounded results. Nonzero EvtNext timeout permits asynchronous query delivery.

    Returns (matched_blocks, scanned_count, error_label). A log record can exist
    while a query sees no result yet; callers must not infer benignness.
    """
    handle = None
    out = []
    scanned = 0
    error = ""
    try:
        handle = evt.EvtQuery(CHANNEL, evt.EvtQueryChannelPath | evt.EvtQueryReverseDirection, query)
        for _ in range(MAX_SCANNED // BATCH_SIZE):
            try:
                batch = evt.EvtNext(handle, BATCH_SIZE, EVT_TIMEOUT_MS)
            except Exception as exc:
                code = getattr(exc, "winerror", None)
                if code is None:
                    args = getattr(exc, "args", ())
                    code = args[0] if args and isinstance(args[0], int) else None
                if code in (259, 1460):  # no more items, or query timed out
                    error = "NO_MORE_ITEMS" if code == 259 else "QUERY_TIMEOUT"
                    break
                raise
            if not batch:
                break
            for item in batch:
                try:
                    scanned += 1
                    try:
                        row = parse_4104_xml(evt.EvtRender(item, evt.EvtRenderEventXml))
                    except (ValueError, TypeError, ET.ParseError):
                        continue
                    if _within_creation_window(creation, row, now):
                        out.append({
                            "event_id": 4104,
                            "record_id": row["record_id"],
                            "time_utc": row["time_utc"],
                            "script_block_id": row["script_block_id"][:100],
                            "message_number": row["message_number"],
                            "message_total": row["message_total"],
                            "script_excerpt": row["text"][:MAX_CHARS],
                            "correlation": "PID_AND_CREATION_TIME_ONLY",
                        })
                finally:
                    _safe_close(item)
            if len(out) >= MAX_BLOCKS:
                break
    except Exception as exc:
        error = f"{type(exc).__name__}({getattr(exc, 'winerror', 'n/a')})"
    finally:
        if handle is not None:
            try:
                _safe_close(handle)
            except Exception:
                pass
    return out[:MAX_BLOCKS], scanned, error


def read_script_blocks(creation: Dict[str, Any], *, now=None) -> List[Dict[str, Any]]:
    """Use a PID-filtered EID4104 query, then bounded time-filtered fallback.

    Never wait for log production, poll indefinitely, or modify logging policy.
    """
    created = _datetime(creation.get("event_time_utc"))
    now = now or datetime.now(timezone.utc)
    if not created or not _within_creation_window(
        creation, {"pid": creation.get("pid"), "time_utc": created.isoformat()}, now
    ):
        LOG.info("EID4104 collection pid=%s status=INVALID_CREATION", creation.get("pid"))
        return []
    try:
        import win32evtlog  # type: ignore[import-not-found]
    except ImportError:
        LOG.info("EID4104 collection pid=%s status=PYWIN32_UNAVAILABLE", creation.get("pid"))
        return []
    pid = creation["pid"]
    # Avoid fractional timestamp XPath provider incompatibilities. Python validates
    # the time window on EVERY returned candidate even for the fallback query.
    by_pid = f"*[System[(EventID=4104) and Execution[@ProcessID={pid}]]]"
    selected, scanned, err = _read_query(win32evtlog, by_pid, creation, now)
    LOG.info("EID4104 query pid=%s mode=PID scanned=%s matched=%s status=%s",
             pid, scanned, len(selected), err or "OK")
    if selected:
        return selected
    # Fallback handles EvtQuery provider differences. This is intentionally capped
    # and cannot use a 4104 from another PID or a previous reused PID.
    since = (created - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    by_time = f"*[System[(EventID=4104) and TimeCreated[@SystemTime>='{since}']]]"
    recovered, scanned2, err2 = _read_query(win32evtlog, by_time, creation, now)
    LOG.info("EID4104 query pid=%s mode=TIME scanned=%s matched=%s status=%s",
             pid, scanned2, len(recovered), err2 or "OK")
    return recovered
