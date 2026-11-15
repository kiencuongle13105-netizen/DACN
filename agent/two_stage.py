"""Fast-rule hold + bounded SLM decision for the DACN Windows laboratory VM.

No shell commands from telemetry are executed. Actions verify process identity.
A dedicated watchdog resumes suspended processes on timeout or agent restart.
"""
from __future__ import annotations
import json
import ntpath
import sqlite3
from contextlib import contextmanager
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from agent.guarded_containment import parse_event_time, high_risk_command
from utils.bo_giai_ma import BoGiaiMaPowerShell

SHELLS = {'powershell.exe', 'pwsh.exe'}
MAX_EVENT_DELAY_SEC = 8
MAX_CLOCK_SKEW_SEC = 10


def fast_rule(event: Dict[str, Any]) -> Dict[str, Any]:
    """Conservative precision-first local rule: no encoded-only or admin commands."""
    if int(event.get('event_id', 0)) != 1:
        return {'matched': False, 'rule_id': 'NOT_PROCESS_CREATE', 'techniques': []}
    image = ntpath.basename(str(event.get('image', '')).replace('/', '\\')).lower()
    if image not in SHELLS:
        return {'matched': False, 'rule_id': 'NOT_POWERSHELL', 'techniques': []}
    processed = BoGiaiMaPowerShell.tien_xu_ly_su_kien(event)
    command = processed.get('cleaned_command', '')
    if high_risk_command(command):
        return {'matched': True, 'rule_id': 'FR-PS-INMEM-001', 'techniques': ['T1059.001'], 'reason': 'PowerShell combined fetch+execute or base64 in-memory execution'}
    return {'matched': False, 'rule_id': 'NO_HIGH_CONFIDENCE_SIGNAL', 'techniques': []}


def _norm(path: str) -> str:
    return ntpath.normcase(path.replace('/', '\\').removeprefix('\\\\?\\').removeprefix('\\??\\'))


def checked_process(event: Dict[str, Any], factory: Optional[Callable] = None, max_age: float = MAX_EVENT_DELAY_SEC):
    """Return (process, reason); reject stale events, reused PID, system accounts."""
    try:
        created = parse_event_time(event)
        if created is None:
            return None, 'NO_EVENT_TIMESTAMP'
        age = (datetime.now(timezone.utc) - created).total_seconds()
        if age < -MAX_CLOCK_SKEW_SEC or age > max_age:
            return None, 'EVENT_TOO_OLD'
        pid = event.get('pid')
        if type(pid) is not int or pid <= 4:
            return None, 'INVALID_PID'
        user = str(event.get('user', '')).strip().lower()
        if not user or any(x in user for x in ('system', 'local service', 'network service', 'dwm-', 'umfd-')):
            return None, 'PROTECTED_ACCOUNT'
        image = _norm(str(event.get('image', '')))
        if ntpath.basename(image) not in SHELLS:
            return None, 'NOT_POWERSHELL'
        if factory is None:
            import psutil
            factory = psutil.Process
        proc = factory(pid)
        if _norm(str(proc.exe())) != image or str(proc.username()).strip().lower() != user:
            return None, 'IDENTITY_MISMATCH'
        if abs(float(proc.create_time()) - created.timestamp()) > MAX_CLOCK_SKEW_SEC:
            return None, 'PID_REUSE_OR_TIME_MISMATCH'
        if not proc.is_running():
            return None, 'NOT_RUNNING'
        return proc, 'VERIFIED'
    except Exception as exc:
        return None, 'PROCESS_ERROR_' + type(exc).__name__


class TwoStageController:
    """SQLite holds persist across crashes. Operations synchronized with the watchdog."""
    def __init__(self, database: Path, *, timeout_sec: float = 5, process_factory=None, live: bool = False, clock=time.monotonic):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_sec = max(1., min(float(timeout_sec), 20.))
        self.process_factory = process_factory
        self.live = bool(live)
        self.clock = clock
        self.lock = threading.RLock()
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS holds (record_id INTEGER PRIMARY KEY, event_json TEXT NOT NULL, deadline_utc REAL NOT NULL, status TEXT NOT NULL)')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(str(self.database), timeout=10)
        try:
            db.execute('PRAGMA busy_timeout=10000')
            with db:
                yield db
        finally:
            db.close()

    def _get(self, rid):
        with self._db() as db:
            row = db.execute('SELECT event_json,deadline_utc,status FROM holds WHERE record_id=?', (int(rid),)).fetchone()
        return row

    def _save(self, rid, event, deadline, status):
        with self._db() as db:
            db.execute('INSERT OR REPLACE INTO holds VALUES (?,?,?,?)', (int(rid), json.dumps(event, ensure_ascii=False), deadline, status))

    def hold(self, event: Dict[str, Any]) -> Dict[str, Any]:
        matched = fast_rule(event)
        if not matched['matched']:
            return {'executed_action': 'NONE', 'response_reason': matched['rule_id'], 'rule_id': matched['rule_id']}
        rid = int(event['record_id'])
        with self.lock:
            existing = self._get(rid)
            if existing:
                return {'executed_action': 'NONE', 'response_reason': 'ALREADY_SEEN', 'rule_id': matched['rule_id']}
            if not self.live:
                self._save(rid, event, time.time(), 'SIMULATED')
                return {'executed_action': 'SIMULATED_HOLD', 'response_reason': 'SIMULATION_ONLY', 'rule_id': matched['rule_id']}
            proc, reason = checked_process(event, self.process_factory)
            if proc is None:
                self._save(rid, event, time.time(), reason)
                return {'executed_action': 'NONE', 'response_reason': reason, 'rule_id': matched['rule_id'],
                        'exited_before_hold': reason in ('NOT_RUNNING', 'PROCESS_ERROR_NoSuchProcess')}
            # Mark before suspending: on abrupt stop, recovery will attempt resume.
            self._save(rid, event, time.time() + self.timeout_sec, 'PENDING_SUSPEND')
            try:
                proc.suspend()
            except Exception as exc:
                self._save(rid, event, time.time(), 'SUSPEND_FAILED')
                return {'executed_action': 'NONE', 'response_reason': 'SUSPEND_FAILED_' + type(exc).__name__, 'rule_id': matched['rule_id']}
            self._save(rid, event, time.time() + self.timeout_sec, 'HELD')
            return {'executed_action': 'SUSPEND', 'response_reason': 'FAST_RULE', 'rule_id': matched['rule_id'],
                    'hold_utc': datetime.now(timezone.utc).isoformat(), 'time_to_hold_ms': round(max(0, (time.time()-parse_event_time(event).timestamp())*1000), 3)}

    def _resume(self, event):
        proc, reason = checked_process(event, self.process_factory, max_age=3600)
        if proc is None:
            return 'RESUME_NOT_POSSIBLE_' + reason
        try:
            proc.resume()
            return 'RESUMED'
        except Exception as exc:
            return 'RESUME_FAILED_' + type(exc).__name__

    def resolve(self, event, verdict: Dict[str, Any], *, permit_kill: bool = True):
        rid = int(event['record_id'])
        with self.lock:
            row = self._get(rid)
            if row is None or row[2] != 'HELD':
                return {'executed_action': 'NONE', 'response_reason': 'NOT_HELD_OR_EXPIRED'}
            previous, deadline, _ = row
            original = json.loads(previous)
            if time.time() >= deadline:
                status = self._resume(original)
                self._save(rid, original, deadline, status)
                return {'executed_action': 'RESUME' if status == 'RESUMED' else 'NONE', 'response_reason': 'AI_TIMEOUT_' + status}
            from agent.guarded_containment import policy_approves
            if permit_kill and policy_approves(verdict):
                proc, reason = checked_process(original, self.process_factory, max_age=3600)
                if proc is not None:
                    try:
                        proc.kill()
                        self._save(rid, original, deadline, 'TERMINATED')
                        return {'executed_action': 'KILL_PROCESS', 'response_reason': 'SLM_APPROVED'}
                    except Exception as exc:
                        reason = 'KILL_FAILED_' + type(exc).__name__
                # Fail safe: try to release if kill fails.
                resumed = self._resume(original)
                self._save(rid, original, deadline, resumed)
                return {'executed_action': 'RESUME' if resumed == 'RESUMED' else 'NONE', 'response_reason': reason + '_' + resumed}
            status = self._resume(original)
            self._save(rid, original, deadline, status)
            return {'executed_action': 'RESUME' if status == 'RESUMED' else 'NONE', 'response_reason': 'SLM_RELEASE_' + status}

    def watchdog(self, *, all_pending: bool = False):
        """On restart call all_pending=True before subscribing to new events."""
        with self.lock:
            with self._db() as db:
                rows = db.execute("SELECT record_id,event_json,deadline_utc,status FROM holds WHERE status IN ('HELD','PENDING_SUSPEND')").fetchall()
            results = []
            for rid, raw, deadline, state in rows:
                if all_pending or state == 'PENDING_SUSPEND' or time.time() >= deadline:
                    event = json.loads(raw)
                    status = self._resume(event)
                    self._save(rid, event, deadline, status)
                    results.append({'record_id': rid, 'process_guid': event.get('process_guid', ''), 'pid': event.get('pid'), 'audit_phase': 'WATCHDOG', 'executed_action': 'RESUME' if status == 'RESUMED' else 'NONE', 'response_reason': 'WATCHDOG_' + status})
            return results
