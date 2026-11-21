"""Opt-in short-lived Fast Hold for DACN Windows lab endpoints.

A fast local rule temporarily suspends an *exact, verified* interactive user
PowerShell process. SLM cannot select a PID. Every hold has a persistent lease,
a separate watchdog, a hard deadline, and an append-only audit trail.

This is not a general-purpose malware detector; never deploy across production
Windows endpoints without additional policy engineering and field validation.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
import ntpath
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from agent.guarded_containment import (MAX_CLOCK_DELTA_SEC, SHELL_EXECUTABLES,
                                       _safe_image, high_risk_command, parse_event_time)

PROTECTED_ACCOUNTS = ("system", "local service", "network service", "dwm-", "umfd-")
DEFAULT_LEASE_SEC = 6.0
MAX_LEASE_SEC = 10.0
# Independent watchdog may outlive a stalled worker; allow bounded recovery.
CLAIM_RECOVERY_GRACE_SEC = 4.0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_account(user: str) -> bool:
    user = user.lower().strip()
    return bool(user) and not any(part in user for part in PROTECTED_ACCOUNTS)


def fast_rule(event: Dict[str, Any], *, now: Optional[datetime] = None, max_age_sec: float = 4.0) -> str:
    """Evaluate only EID1 from a freshly created interactive PowerShell.

    The command must have both fetch+execution, or an explicit in-memory
    Base64+expression/reflection combination. EncodedCommand alone is benign.
    """
    if int(event.get("event_id", 0)) != 1:
        return "SKIP_NOT_CREATION"
    if not str(event.get("process_guid", "")).strip():
        return "SKIP_NO_GUID"
    if ntpath.basename(str(event.get("image", "")).lower()) not in SHELL_EXECUTABLES:
        return "SKIP_NOT_POWERSHELL"
    if not _safe_account(str(event.get("user", ""))):
        return "SKIP_PROTECTED_OWNER"
    dt = parse_event_time(event)
    age = (now or datetime.now(timezone.utc)) - dt if dt else None
    if age is None or not (0 <= age.total_seconds() <= max_age_sec):
        return "SKIP_STALE_EVENT"
    from utils.bo_giai_ma import BoGiaiMaPowerShell
    clean = BoGiaiMaPowerShell.tien_xu_ly_su_kien(event).get("cleaned_command", "")
    return "FAST_HIGH_RISK_COMMAND" if high_risk_command(clean) else "SKIP_NO_FAST_RULE"


def process_identity(event: Dict[str, Any], process_factory: Callable[[int], Any]) -> tuple[Optional[Any], str]:
    """Match PID, owner, executable and creation time; do not trust model output."""
    pid = event.get("pid")
    if not isinstance(pid, int) or pid <= 4:
        return None, "INVALID_PID"
    image = _safe_image(str(event.get("image") or ""))
    owner = str(event.get("user") or "").lower().strip()
    if ntpath.basename(image) not in SHELL_EXECUTABLES or not _safe_account(owner):
        return None, "PROTECTED_IDENTITY"
    created = parse_event_time(event)
    if created is None:
        return None, "BAD_EVENT_TIME"
    try:
        proc = process_factory(pid)
        if not proc.is_running():
            return None, "PROCESS_FINISHED_BEFORE_BLOCK"
        if (_safe_image(str(proc.exe())) != image or
                str(proc.username()).lower().strip() != owner or
                abs(float(proc.create_time()) - created.timestamp()) > MAX_CLOCK_DELTA_SEC):
            return None, "IDENTITY_MISMATCH"
        return proc, "IDENTITY_OK"
    except Exception as exc:
        # psutil.NoSuchProcess can occur with short-lived scripts.
        if type(exc).__name__ in {"NoSuchProcess", "ZombieProcess"}:
            return None, "PROCESS_FINISHED_BEFORE_BLOCK"
        return None, "IDENTITY_ERROR:" + type(exc).__name__


class LeaseStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS holds (
                guid TEXT PRIMARY KEY, event_json TEXT NOT NULL,
                state TEXT NOT NULL, expires_epoch REAL NOT NULL,
                suspended_epoch REAL, updated_utc TEXT NOT NULL
            )""")

    @contextmanager
    def _conn(self):
        con = sqlite3.connect(str(self.path), timeout=8)
        try:
            con.execute("PRAGMA busy_timeout=8000")
            with con:
                yield con
        finally:
            con.close()

    def prepare(self, event: Dict[str, Any], expires_epoch: float) -> bool:
        guid = str(event["process_guid"]).lower()
        # One atomic INSERT, never INSERT OR REPLACE. If duplicate EID1 reaches
        # two collectors, the existing lease cannot be overwritten/resuspended.
        with self._conn() as con:
            result = con.execute("""INSERT OR IGNORE INTO holds
                (guid,event_json,state,expires_epoch,suspended_epoch,updated_utc)
                VALUES(?,?, 'PREPARED', ?, NULL, ?)""",
                (guid, json.dumps(event), expires_epoch, utc_now()))
        return result.rowcount == 1

    def set_state(self, guid: str, state: str, suspended_epoch: Optional[float] = None) -> None:
        with self._conn() as con:
            if suspended_epoch is None:
                con.execute("UPDATE holds SET state=?, updated_utc=? WHERE guid=?",
                            (state, utc_now(), guid.lower()))
            else:
                con.execute("UPDATE holds SET state=?, suspended_epoch=?, updated_utc=? WHERE guid=?",
                            (state, suspended_epoch, utc_now(), guid.lower()))

    def set_suspended_epoch(self, guid: str, timestamp: float) -> None:
        with self._conn() as con:
            con.execute("UPDATE holds SET suspended_epoch=?,updated_utc=? "
                        "WHERE guid=? AND state='SUSPENDED'",
                        (float(timestamp), utc_now(), guid.lower()))

    def transition(self, guid: str, allowed_states: tuple[str, ...], new_state: str,
                   *, before_expiry: bool = False, recover_after_expiry: float | None = None) -> bool:
        """Atomic cross-process lease ownership; the watchdog has its OWN lock.

        A process-local RLock cannot serialize the agent with the independent
        watchdog, so all claims and state transitions are committed in SQLite.
        """
        if not allowed_states:
            return False
        placeholders = ",".join("?" for _ in allowed_states)
        sql = ("UPDATE holds SET state=?,updated_utc=? WHERE guid=? AND state IN ("
               + placeholders + ")")
        args: list[Any] = [new_state, utc_now(), guid.lower(), *allowed_states]
        if before_expiry:
            sql += " AND expires_epoch > ?"
            args.append(time.time())
        if recover_after_expiry is not None:
            sql += " AND expires_epoch <= ?"
            args.append(time.time() - recover_after_expiry)
        with self._conn() as con:
            cur = con.execute(sql, args)
            return cur.rowcount == 1

    def get(self, guid: str) -> Optional[Dict[str, Any]]:
        with self._conn() as con:
            row = con.execute("SELECT event_json,state,expires_epoch,suspended_epoch FROM holds WHERE guid=?", (guid.lower(),)).fetchone()
        if row is None:
            return None
        return {"event": json.loads(row[0]), "state": row[1], "expires_epoch": row[2], "suspended_epoch": row[3]}

    def active(self):
        with self._conn() as con:
            rows = con.execute("SELECT guid FROM holds WHERE state IN ('PREPARED','SUSPENDED','RELEASING','KILLING','RELEASE_FAILED')").fetchall()
        return [guid for (guid,) in rows]


def append_audit(path: Path, **fields):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"utc": utc_now(), **fields}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return entry


class FastHoldManager:
    def __init__(self, data_dir: Path, *, enabled: bool = False, lease_sec: float = DEFAULT_LEASE_SEC,
                 max_age_sec: float = 4.0, process_factory=None):
        self.enabled = bool(enabled)
        self.lease_sec = min(MAX_LEASE_SEC, max(1.5, float(lease_sec)))
        self.max_age_sec = max(0.2, min(10.0, float(max_age_sec)))
        self.data_dir = Path(data_dir)
        self.store = LeaseStore(self.data_dir / "fast_hold.sqlite3")
        self.audit = self.data_dir / "fast_hold_audit.jsonl"
        if process_factory is None:
            import psutil
            process_factory = psutil.Process
        self.process_factory = process_factory
        self.lock = threading.RLock()

    def consider(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return {"result": "DISABLED"}
        reason = fast_rule(event, max_age_sec=self.max_age_sec)
        if reason != "FAST_HIGH_RISK_COMMAND":
            return {"result": reason}
        return self._suspend_verified(event, "FAST_HIGH_RISK_COMMAND")

    def consider_correlated(self, creation: Dict[str, Any], related) -> Dict[str, Any]:
        """EID11+13-triggered hold; never uses a model-selected PID.

        The caller MUST persist the real Sysmon EID11/EID13 before calling.
        This path is separately opt-in via `correlated_response_enabled`.
        """
        if not self.enabled:
            return {"result": "DISABLED"}
        from agent.guarded_containment import eligible_evidence
        allowed, reason, matching = eligible_evidence(creation, related)
        if not allowed:
            return {"result": reason}
        # Require the two independent evidence types on a non-FastRule creation
        # for this second path; existing high-risk EID1 still uses initial hold.
        if reason != "CORRELATED_STEALTH_PERSISTENCE":
            return {"result": "NOT_EVIDENCE_TRIGGERED"}
        # Do not contain from delayed/replayed EID11/13. The event may be
        # generated long after EID1, but its DELIVERY must still be fresh.
        recent = [parse_event_time(item) for item in matching]
        recent = [dt for dt in recent if dt is not None]
        if not recent or not (0 <= (datetime.now(timezone.utc) - max(recent)).total_seconds() <= self.max_age_sec):
            return {"result": "SKIP_STALE_CORROBORATION"}
        return self._suspend_verified(creation, "CORRELATED_STEALTH_PERSISTENCE")

    def _suspend_verified(self, event: Dict[str, Any], rule_name: str) -> Dict[str, Any]:
        guid = str(event["process_guid"]).lower()
        proc, identity = process_identity(event, self.process_factory)
        if proc is None:
            append_audit(self.audit, kind="FAST_RULE", guid=guid, record_id=event.get("record_id"),
                         pid=event.get("pid"), result=identity)
            return {"result": identity}
        with self.lock:
            expiry = time.time() + self.lease_sec
            if not self.store.prepare(event, expiry):
                return {"result": "ALREADY_HELD"}
            # PREPARED is durable *before* suspension: watchdog can recover a crash.
            try:
                proc.suspend()
                held_at = time.time()
                # The watchdog could have claimed an expired PREPARED lease
                # while psutil.suspend() was in progress. If so, undo this
                # suspension immediately; never resurrect a released lease.
                if not self.store.transition(guid, ("PREPARED",), "SUSPENDED", before_expiry=True):
                    proc.resume()
                    append_audit(self.audit, kind="FAST_HOLD", guid=guid,
                                 record_id=event.get("record_id"), pid=event.get("pid"),
                                 result="LEASE_LOST_DURING_SUSPEND")
                    return {"result": "LEASE_LOST_DURING_SUSPEND"}
                # Preserve precise suspension time for benchmark reports.
                self.store.set_suspended_epoch(guid, held_at)
                dt = parse_event_time(event)
                latency = max(0.0, (held_at - dt.timestamp()) * 1000) if dt else None
                append_audit(self.audit, kind="FAST_HOLD", guid=guid, record_id=event.get("record_id"),
                             pid=event.get("pid"), result="SUSPENDED", rule=rule_name,
                             time_to_block_ms=round(latency, 3) if latency is not None else None,
                             suspended_epoch=held_at, expires_epoch=expiry)
                return {"result": "SUSPENDED", "guid": guid, "time_to_block_ms": latency}
            except Exception as exc:
                # Failed suspend may be partial: resume exact PID when possible.
                try:
                    proc.resume()
                except Exception:
                    pass
                self.store.transition(guid, ("PREPARED", "SUSPENDED"), "RELEASED")
                append_audit(self.audit, kind="FAST_HOLD", guid=guid, record_id=event.get("record_id"),
                             pid=event.get("pid"), result="SUSPEND_FAILED:" + type(exc).__name__)
                return {"result": "SUSPEND_FAILED:" + type(exc).__name__}

    def resolve(self, guid: str, *, kill_requested: bool = False,
                termination: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
                reason: str = "SLM_DECISION") -> Dict[str, Any]:
        """Claim a lease atomically, then kill OR resume a verified process.

        Never kill a merely PREPARED process. The agent and standalone watchdog
        are separate processes; the SQLite state transition prevents both from
        concurrently performing a conflicting action against the same lease.
        """
        guid = str(guid).lower()
        with self.lock:
            lease = self.store.get(guid)
            if lease is None or lease["state"] not in (
                    "PREPARED", "SUSPENDED", "RELEASING", "KILLING", "RELEASE_FAILED"):
                return {"executed_action": "NONE", "response_reason": "NO_ACTIVE_HOLD"}
            event = lease["event"]
            kill_result = None
            kill_attempted = False

            # Require a persisted, confirmed SUSPENDED state and an unexpired
            # deadline; the database checks expiry atomically with the claim.
            if (kill_requested and lease["state"] == "SUSPENDED"
                    and termination is not None
                    and self.store.transition(guid, ("SUSPENDED",), "KILLING",
                                              before_expiry=True)):
                kill_attempted = True
                try:
                    kill_result = termination(event)
                except Exception as exc:
                    kill_result = {"executed_action": "NONE",
                                   "response_reason": "KILL_EXCEPTION:" + type(exc).__name__}
                if (kill_result.get("executed_action") == "KILL_PROCESS"
                        and kill_result.get("response_reason") == "POST_VERIFY_OK"):
                    transitioned = self.store.transition(guid, ("KILLING",), "KILLED")
                    append_audit(self.audit, kind="RESOLVE", guid=guid,
                                 pid=event.get("pid"),
                                 result="KILLED" if transitioned else "KILL_CONFIRMED_AFTER_LEASE_RACE",
                                 reason=reason, kill_verified=True)
                    if not transitioned:
                        return {"executed_action": "KILL_PROCESS",
                                "response_reason": "POST_VERIFY_OK_WITH_STATE_RACE"}
                    return kill_result
                # A failed/unverified kill must not leave an indefinite Hold.
                # We own state KILLING: only our worker can move it to RELEASING.
                if not self.store.transition(guid, ("KILLING",), "RELEASING"):
                    return {"executed_action": "NONE", "response_reason": "HOLD_CLAIM_LOST"}
            else:
                # Another process might already own the same hold. In-flight
                # KILLING/RELEASING may only be recovered by the watchdog after
                # its expiry PLUS a grace interval, never in the normal path.
                claimable = ("PREPARED", "SUSPENDED", "RELEASE_FAILED")
                owned = self.store.transition(guid, claimable, "RELEASING")
                if not owned and reason == "WATCHDOG_TIMEOUT":
                    owned = self.store.transition(
                        guid, ("KILLING", "RELEASING"), "RELEASING",
                        recover_after_expiry=CLAIM_RECOVERY_GRACE_SEC)
                if not owned:
                    return {"executed_action": "NONE", "response_reason": "RESOLUTION_IN_PROGRESS"}

            proc, identity = process_identity(event, self.process_factory)
            try:
                if proc is not None:
                    proc.resume()
                    status = "RELEASED"
                elif identity == "PROCESS_FINISHED_BEFORE_BLOCK":
                    status = "ALREADY_EXITED"
                else:
                    status = "RELEASE_UNVERIFIED:" + identity
                self.store.transition(guid, ("RELEASING",),
                                      "RELEASED" if status in ("RELEASED", "ALREADY_EXITED")
                                      else "RELEASE_FAILED")
            except Exception as exc:
                status = "RELEASE_FAILED:" + type(exc).__name__
                self.store.transition(guid, ("RELEASING",), "RELEASE_FAILED")
            append_audit(self.audit, kind="RESOLVE", guid=guid,
                         pid=event.get("pid"), result=status, reason=reason,
                         kill_attempted=kill_attempted,
                         kill_verified=False,
                         kill_failure=(kill_result or {}).get("response_reason"))
            if kill_attempted:
                # "kill attempted" is NOT equivalent to verified termination.
                return {"executed_action": "RESUME_PROCESS" if status == "RELEASED" else "NONE",
                        "response_reason": "KILL_UNVERIFIED_THEN_" + status}
            return {"executed_action": "RESUME_PROCESS" if status == "RELEASED" else "NONE",
                    "response_reason": reason + ":" + status}

    def release_expired(self, *, now_epoch: Optional[float] = None) -> int:
        count = 0
        for guid in self.store.active():
            lease = self.store.get(guid)
            if lease and (now_epoch if now_epoch is not None else time.time()) >= lease["expires_epoch"]:
                outcome = self.resolve(guid, reason="WATCHDOG_TIMEOUT")
                if outcome["response_reason"] != "RESOLUTION_IN_PROGRESS":
                    append_audit(self.audit, kind="WATCHDOG", guid=guid, result=outcome["response_reason"])
                    count += 1
        return count


def main():
    import argparse
    parser = argparse.ArgumentParser(description="DACN Fast Hold independent safety watchdog")
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parents[1] / "data")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--release-all", action="store_true")
    args = parser.parse_args()
    manager = FastHoldManager(args.data_dir)
    if args.release_all:
        # Emergency release all leases; no kill or further suspension.
        for guid in manager.store.active():
            print(guid, manager.resolve(guid, reason="EMERGENCY_RELEASE"))
    elif args.watch:
        while True:
            try:
                manager.release_expired()
            except Exception as exc:
                # A transient SQLite/process error must not stop safety recovery.
                print(f"Watchdog retry after: {type(exc).__name__}", flush=True)
            time.sleep(0.25)
    else:
        print("Use --watch or --release-all")


if __name__ == "__main__":
    main()
