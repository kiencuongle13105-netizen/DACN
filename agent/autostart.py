"""DACN Git agent: automatic, resilient Windows background monitoring.

The local AI is an analyst. Real containment is gated by local, independently
correlated Sysmon evidence and verified Windows process identity. Configurable
GUARDED_AUTO is opt-in through an Administrator installer switch.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
LOG = logging.getLogger("dacn.autostart")
DEFAULT_CONFIG = ROOT / "config" / "agent.json"


def load_config(path: Path) -> Dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict):
        raise ValueError("agent config must be a JSON object")
    url = str(raw.get("ai_endpoint", "")).rstrip("/")
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("ai_endpoint must be an HTTP(S) URL")
    if not url.endswith("/v1"):
        raise ValueError("ai_endpoint must point to the LM Studio /v1 endpoint")
    model = str(raw.get("model", "")).strip()
    if not model:
        raise ValueError("model is required")
    mode = str(raw.get("response_mode", "SIMULATION_ONLY")).upper()
    if mode not in {"SIMULATION_ONLY", "GUARDED_AUTO"}:
        raise ValueError("Invalid response_mode (choose SIMULATION_ONLY or GUARDED_AUTO)")
    return {
        "ai_endpoint": url,
        "model": model,
        "polling_interval": max(.2, float(raw.get("polling_interval", 1.0))),
        "retry_seconds": max(2, float(raw.get("retry_seconds", 10.0))),
        "response_mode": mode,
    }


def configure_logging(logs_dir: Path) -> None:
    logs_dir.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler = RotatingFileHandler(logs_dir / "dacn_agent.log", maxBytes=5_000_000, backupCount=4, encoding="utf-8")
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)


class SingleInstance:
    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        if self.path.stat().st_size == 0:
            self.handle.write(b"0")
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError):
            self.handle.close()
            raise RuntimeError("DACN Git Agent is already running") from None
        return self

    def __exit__(self, *args):
        if self.handle is not None:
            self.handle.close()


class QueueDB:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                record_id INTEGER PRIMARY KEY, payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                updated_utc TEXT NOT NULL
            )""")
            columns = {r[1] for r in db.execute("PRAGMA table_info(events)")}
            if "process_guid" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN process_guid TEXT NOT NULL DEFAULT ''")
            if "event_id" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN event_id INTEGER NOT NULL DEFAULT 0")
            # Backfill rows from the previous installation without losing any pending data.
            for rid, raw in db.execute("SELECT record_id,payload FROM events WHERE process_guid='' OR event_id=0").fetchall():
                try:
                    event = json.loads(raw)
                    db.execute("UPDATE events SET process_guid=?, event_id=? WHERE record_id=?",
                               (str(event.get("process_guid", "")).lower(), int(event.get("event_id", 0)), rid))
                except (ValueError, TypeError, KeyError):
                    pass
            db.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status, record_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_events_guid ON events(process_guid,event_id)")

    def _conn(self):
        db = sqlite3.connect(str(self.path), timeout=15)
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def put(self, event: Dict[str, Any]) -> None:
        record_id = int(event["record_id"])
        with self._conn() as db:
            db.execute(
                "INSERT OR IGNORE INTO events(record_id,payload,updated_utc,process_guid,event_id) VALUES(?,?,?,?,?)",
                (record_id, json.dumps(event, ensure_ascii=False), utc_now(),
                 str(event.get("process_guid", "")).lower(), int(event.get("event_id", 0))),
            )

    def next_pending(self) -> Optional[Dict[str, Any]]:
        with self._conn() as db:
            row = db.execute("SELECT payload FROM events WHERE status='pending' ORDER BY record_id LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def done(self, record_id: int) -> None:
        with self._conn() as db:
            db.execute("UPDATE events SET status='done', updated_utc=? WHERE record_id=?", (utc_now(), record_id))

    def failed(self, record_id: int) -> None:
        with self._conn() as db:
            db.execute("UPDATE events SET attempts=attempts+1, updated_utc=? WHERE record_id=?", (utc_now(), record_id))

    def get_creation_and_related(self, process_guid: str):
        """Correlate all local Sysmon evidence with one exact source ProcessGuid."""
        with self._conn() as db:
            rows = db.execute(
                "SELECT payload FROM events WHERE process_guid=? AND event_id IN (1,8,11,13) ORDER BY record_id DESC LIMIT 150",
                (process_guid.lower(),),
            ).fetchall()
        events = [json.loads(raw) for (raw,) in rows]
        creation = next((item for item in events if int(item.get("event_id", 0)) == 1), None)
        related = [item for item in events if int(item.get("event_id", 0)) in (8,11,13)]
        return creation, related

    def count_pending(self) -> int:
        with self._conn() as db:
            return int(db.execute("SELECT COUNT(*) FROM events WHERE status='pending'").fetchone()[0])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_atomic_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def collector_loop(db: QueueDB, interval: float, cursor_path: Path) -> None:
    from Sensor.event_listener import EventSensorAgent
    sensor = EventSensorAgent(polling_interval=interval, state_path=cursor_path)
    for event in sensor.quat_lang_nghe_lien_tuc():
        db.put(event)
        LOG.info("Queued Sysmon EID1 record=%s image=%s", event.get("record_id"), event.get("image"))


def audit_verdict(path: Path, event: Dict[str, Any], verdict: Dict[str, Any],
                  mode: str = "SIMULATION_ONLY", response: Optional[Dict[str, Any]] = None,
                  evidence: Optional[list] = None) -> None:
    allowed = {"IGNORE", "LOG_ONLY", "INVESTIGATE", "KILL_PROCESS"}
    action = str(verdict.get("action", "LOG_ONLY")).upper()
    response = response or {"executed_action": "NONE", "response_reason": "NO_ACTION"}
    entry = {
        "utc": utc_now(), "record_id": event.get("record_id"),
        "process_guid": event.get("process_guid", ""), "image": event.get("image"),
        "ai_is_threat": verdict.get("is_threat") is True,
        "ai_action": action if action in allowed else "LOG_ONLY",
        "severity": str(verdict.get("severity", "INFO")),
        "mitre_technique": str(verdict.get("mitre_technique", "N/A")),
        "reasoning": str(verdict.get("reasoning", ""))[:1000],
        "executed_action": response.get("executed_action", "NONE"),
        "response_reason": response.get("response_reason", "NO_ACTION"),
        "response_mode": mode,
        "evidence_ids": [str(item.get("record_id")) for item in (evidence or [])],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def collector_supervisor(db: QueueDB, interval: float, cursor_path: Path) -> None:
    while True:
        try:
            collector_loop(db, interval, cursor_path)
        except Exception:
            LOG.exception("Collector stopped unexpectedly; restart in 5 seconds")
            time.sleep(5)


def worker_loop(db: QueueDB, config: Dict[str, Any], data_dir: Path, stop_event: threading.Event):
    from agent.bo_nao_ai import BoNaoAIAgent
    from agent.guarded_containment import (eligible_evidence, event_guid,
                                           policy_approves, terminate_verified)
    from utils.bo_giai_ma import BoGiaiMaPowerShell

    ai = BoNaoAIAgent(base_url=config["ai_endpoint"], model=config["model"])
    log_path = data_dir / "decision_audit.jsonl"
    heartbeat_path = data_dir / "heartbeat.json"
    mode = config["response_mode"]
    recent_error = None
    last_heartbeat = 0.0
    while not stop_event.is_set():
        if time.monotonic() - last_heartbeat >= 5:
            write_atomic_json(heartbeat_path, {
                "updated_utc": utc_now(), "pid": os.getpid(),
                "pending_events": db.count_pending(),
                "ai_endpoint": config["ai_endpoint"],
                "response_mode": mode,
                "last_error": recent_error,
            })
            last_heartbeat = time.monotonic()
        event = db.next_pending()
        if event is None:
            stop_event.wait(1)
            continue
        record_id = int(event["record_id"])
        eid = int(event.get("event_id", 0))
        try:
            if eid == 1:
                processed = BoGiaiMaPowerShell.tien_xu_ly_su_kien(event)
                verdict = ai.phan_tich_su_kien(processed)
                if str(verdict.get("severity", "")).upper() == "ERROR":
                    raise RuntimeError(str(verdict.get("reasoning", "AI unavailable"))[:300])
                audit_verdict(log_path, event, verdict, mode,
                              {"response_reason": "AWAIT_CORROBORATION"})
                LOG.info("AI reviewed EID1 record=%s action=%s (no single-event termination)",
                         record_id, verdict.get("action"))
            elif eid in (8, 11, 13):
                creation, related = db.get_creation_and_related(event_guid(event))
                if creation is not None:
                    processed = BoGiaiMaPowerShell.tien_xu_ly_su_kien(creation)
                    eligible, reason, matching = eligible_evidence(processed, related)
                    if eligible:
                        processed["corroborating_events"] = [{
                            "event_id": item["event_id"],
                            "record_id": item["record_id"],
                            "target": str((item.get("event_data") or {}).get(
                                "TargetFilename", (item.get("event_data") or {}).get("TargetObject", "")))[:250],
                        } for item in matching]
                        verdict = ai.phan_tich_su_kien(processed)
                        if str(verdict.get("severity", "")).upper() == "ERROR":
                            raise RuntimeError(str(verdict.get("reasoning", "AI unavailable"))[:300])
                        response = {"executed_action": "NONE", "response_reason": "AI_DID_NOT_APPROVE"}
                        if policy_approves(verdict):
                            if mode == "GUARDED_AUTO":
                                response = terminate_verified(creation)
                            else:
                                response["response_reason"] = "SIMULATED_POLICY_APPROVAL"
                        audit_verdict(log_path, creation, verdict, mode, response, matching)
                        LOG.warning("Guarded response guid=%s action=%s reason=%s",
                                    event_guid(event), response["executed_action"], response["response_reason"])
                    else:
                        LOG.info("Evidence record=%s ignored for response: %s", record_id, reason)
            db.done(record_id)
            recent_error = None
        except Exception as exc:
            db.failed(record_id)
            recent_error = str(exc)[:300]
            LOG.warning("AI pending record=%s (retry in %.1fs): %s", record_id, config["retry_seconds"], recent_error)
            stop_event.wait(config["retry_seconds"])


def run(config_path: Path, check: bool = False):
    config = load_config(config_path)
    data_dir = ROOT / "data"
    logs_dir = ROOT / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    if check:
        db = QueueDB(data_dir / "pending_events.sqlite3")
        print("DACN Git Agent: configuration OK")
        print("AI endpoint:", config["ai_endpoint"])
        print("Model:", config["model"])
        print("Response mode:", config["response_mode"])
        print("Pending events:", db.count_pending())
        return

    configure_logging(logs_dir)
    with SingleInstance(data_dir / "agent.lock"):
        db = QueueDB(data_dir / "pending_events.sqlite3")
        LOG.info("DACN Git Agent starting; AI=%s model=%s", config["ai_endpoint"], config["model"])
        LOG.warning("Response mode %s: real termination requires corroboration, AI approval and local identity verification", config["response_mode"])
        stop_event = threading.Event()
        collector = threading.Thread(target=collector_supervisor, args=(db, config["polling_interval"], data_dir / "sysmon_cursor.json"), daemon=True, name="sysmon-collector")
        collector.start()
        try:
            worker_loop(db, config, data_dir, stop_event)
        except KeyboardInterrupt:
            LOG.info("Stopping DACN Git Agent")
        finally:
            stop_event.set()


def main():
    parser = argparse.ArgumentParser(description="DACN Git auto-starting VM agent")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    run(args.config, check=args.check)


if __name__ == "__main__":
    main()
