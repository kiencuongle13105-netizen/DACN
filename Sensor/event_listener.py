"""Durable Windows Sysmon EID1/8/11/13 reader for DACN.

The EventRecordID cursor is persisted *after* the consumer has accepted each
record. This avoids losing events during a restart or while the AI host is off.
An initial installation begins at the latest event instead of replaying history.
"""
from __future__ import annotations

import json
import logging
import os
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

LOG = logging.getLogger(__name__)
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}
CORRELATION_IDS = (8, 11, 13)
EVENT_XPATH = "(EventID=1 or EventID=8 or EventID=11 or EventID=13)"
DEFAULT_CURSOR_PATH = Path(__file__).resolve().parents[1] / "data" / "sysmon_cursor.json"


def parse_sysmon_event(xml_content: str) -> Dict[str, Any]:
    """Read structured EventData correctly even when XML is escaped."""
    root = ET.fromstring(xml_content)
    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("Sysmon event is missing System")
    record_text = system.findtext("e:EventRecordID", default="", namespaces=NS)
    event_id_text = system.findtext("e:EventID", default="", namespaces=NS)
    if not record_text.isdigit() or not event_id_text.isdigit():
        raise ValueError("Sysmon event is missing numeric RecordID/EventID")
    fields = {
        el.attrib["Name"]: el.text or ""
        for el in root.findall(".//e:EventData/e:Data", NS)
        if el.attrib.get("Name")
    }
    pid_text = fields.get("ProcessId", "0")
    timestamp = system.find("e:TimeCreated", NS)
    event_id = int(event_id_text)
    image = fields.get("Image", fields.get("SourceImage", ""))
    process_guid = fields.get("SourceProcessGUID", fields.get("SourceProcessGuid", "")) if event_id == 8 else fields.get("ProcessGuid", "")
    return {
        "source": f"Sysmon_EID{event_id}",
        "event_id": event_id,
        "record_id": record_text,
        "pid": int(pid_text) if pid_text.isdigit() else 0,
        "image": image,
        "command_line": fields.get("CommandLine", ""),
        "user": fields.get("User", ""),
        "parent_image": fields.get("ParentImage", ""),
        "process_guid": process_guid,
        "utc_time": fields.get("UtcTime", ""),
        "event_data": fields,
        "event_time_utc": timestamp.attrib.get("SystemTime", "") if timestamp is not None else "",
        "timestamp": time.time(),
    }


class EventSensorAgent:
    SYSMON_CHANNEL = SYSMON_CHANNEL

    def __init__(self, polling_interval: float = 1.0, state_path: Optional[Path] = None):
        self.polling_interval = max(0.2, float(polling_interval))
        self.state_path = Path(state_path) if state_path is not None else DEFAULT_CURSOR_PATH
        self.last_record_id = self._read_cursor()
        self._initialized = self.last_record_id is not None

    def _read_cursor(self) -> Optional[int]:
        try:
            if self.state_path.exists():
                value = int(json.loads(self.state_path.read_text(encoding="utf-8-sig"))["last_record_id"])
                return max(0, value)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            LOG.warning("Cannot read Sysmon cursor %s: %s", self.state_path, exc)
        return None

    def _save_cursor(self, record_id: int) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_suffix(".tmp")
        with temp.open("w", encoding="utf-8") as f:
            json.dump({"last_record_id": record_id}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, self.state_path)
        self.last_record_id = record_id

    @staticmethod
    def _win32evtlog():
        import win32evtlog  # type: ignore[import-not-found]
        return win32evtlog

    def _iter_event_xml(self, query: str, reverse: bool = False):
        event_log = self._win32evtlog()
        flags = event_log.EvtQueryChannelPath | (
            event_log.EvtQueryReverseDirection if reverse else event_log.EvtQueryForwardDirection
        )
        handle = event_log.EvtQuery(self.SYSMON_CHANNEL, flags, query)
        try:
            while True:
                try:
                    items = event_log.EvtNext(handle, 64)
                except Exception as exc:
                    # EvtNext may signal the end of the result set with ERROR_NO_MORE_ITEMS.
                    if getattr(exc, "winerror", None) == 259 or getattr(exc, "args", (None,))[0] == 259:
                        break
                    raise
                if not items:
                    break
                for item in items:
                    try:
                        yield event_log.EvtRender(item, event_log.EvtRenderEventXml)
                    finally:
                        if hasattr(event_log, "EvtClose"):
                            event_log.EvtClose(item)
        finally:
            if hasattr(event_log, "EvtClose"):
                event_log.EvtClose(handle)

    def _latest_record_id(self) -> Optional[int]:
        for xml in self._iter_event_xml(f"*[System[{EVENT_XPATH}]]", reverse=True):
            return int(parse_sysmon_event(xml)["record_id"])
        return None

    def doc_su_kien_sysmon_moi_nhat(self) -> List[Dict[str, Any]]:
        """Compatibility method: reads eligible events and advances cursor."""
        result = []
        for item in self._scan():
            result.append(item)
            self._save_cursor(int(item["record_id"]))
        return result

    def _scan(self):
        if not self._initialized:
            newest = self._latest_record_id()
            if newest is not None:
                self._save_cursor(newest)
                LOG.info("First launch: baselined Sysmon EventRecordID=%s", newest)
            self._initialized = True
            return
        last = self.last_record_id or 0
        query = f"*[System[({EVENT_XPATH}) and (EventRecordID>{last})]]"
        for xml in self._iter_event_xml(query):
            event = parse_sysmon_event(xml)
            current = int(event["record_id"])
            if current <= (self.last_record_id or 0):
                continue
            basename = event["image"].replace("/", "\\").rsplit("\\", 1)[-1].lower()
            eid = event["event_id"]
            is_shell_start = eid == 1 and basename in SHELLS
            is_shell_evidence = eid in CORRELATION_IDS and basename in {"powershell.exe", "pwsh.exe"} and bool(event["process_guid"])
            if is_shell_start or is_shell_evidence:
                # Caller must queue before resuming; cursor advances only on resume.
                yield event
            self._save_cursor(current)

    def quat_lang_nghe_lien_tuc(self) -> Generator[Dict[str, Any], None, None]:
        LOG.info("Sysmon sensor started: %s (poll %.1fs)", self.SYSMON_CHANNEL, self.polling_interval)
        while True:
            try:
                yield from self._scan()
            except Exception:
                LOG.exception("Sysmon collection failed; retrying")
            time.sleep(self.polling_interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    for event in EventSensorAgent().quat_lang_nghe_lien_tuc():
        print(event)
