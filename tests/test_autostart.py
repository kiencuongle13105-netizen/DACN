import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.autostart import QueueDB, SingleInstance, audit_verdict, load_config
from Sensor.event_listener import parse_sysmon_event
from agent.bo_nao_ai import BoNaoAIAgent

XML_SAMPLE = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>1</EventID><EventRecordID>17852</EventRecordID>
<TimeCreated SystemTime="2026-11-07T15:58:34Z"/></System><EventData>
<Data Name="ProcessId">1234</Data><Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -e aQBmACAAJgAmAA== &amp; echo test</Data>
<Data Name="ProcessGuid">{123}</Data></EventData></Event>'''


class TestSysmonParsing(unittest.TestCase):
    def test_xml_decodes_special_characters(self):
        event = parse_sysmon_event(XML_SAMPLE)
        self.assertEqual(event["record_id"], "17852")
        self.assertEqual(event["pid"], 1234)
        self.assertIn("& echo test", event["command_line"])
        self.assertEqual(event["process_guid"], "{123}")

    def test_reject_missing_recordid(self):
        with self.assertRaises(ValueError):
            parse_sysmon_event(XML_SAMPLE.replace("<EventRecordID>17852</EventRecordID>", ""))


class TestDurableQueue(unittest.TestCase):
    def test_restart_preserves_pending_events_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as d:
            db = QueueDB(Path(d) / "queue.sqlite3")
            event = {"record_id": "17852", "event_id": 1, "command_line": "safe"}
            db.put(event)
            db.put(event)
            self.assertEqual(db.count_pending(), 1)
            db = QueueDB(Path(d) / "queue.sqlite3")
            self.assertEqual(db.next_pending(), event)
            db.failed(17852)
            self.assertEqual(db.count_pending(), 1)
            db.done(17852)
            self.assertEqual(db.count_pending(), 0)

    def test_file_lock_blocks_second_agent(self):
        with tempfile.TemporaryDirectory() as d:
            lock = Path(d) / "lock"
            with SingleInstance(lock):
                with self.assertRaises(RuntimeError):
                    with SingleInstance(lock):
                        pass

    def test_verdict_is_only_logged_not_executed(self):
        with tempfile.TemporaryDirectory() as d:
            audit = Path(d) / "audit.jsonl"
            audit_verdict(audit, {"record_id": "17852", "image": "powershell.exe"}, {
                "is_threat": True, "action": "KILL_PROCESS", "severity": "HIGH",
                "reasoning": "untrusted verdict",
            })
            log = json.loads(audit.read_text(encoding="utf-8").strip())
            self.assertEqual(log["ai_action"], "KILL_PROCESS")
            self.assertEqual(log["executed_action"], "NONE")
            self.assertEqual(log["response_mode"], "SIMULATION_ONLY")


class TestConfig(unittest.TestCase):
    def test_rejects_unrecognized_enforcement_mode(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "config.json"
            f.write_text(json.dumps({"ai_endpoint": "http://192.168.62.1:1236/v1",
                                     "model": "qwen2.5-coder-3b-instruct-awq",
                                     "response_mode": "KILL_EVERYTHING"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(f)

    def test_missing_ai_url_fails(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "config.json"
            f.write_text('{"model":"x"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(f)


class FakeResponse:
    def __enter__(self): return self
    def __exit__(self, *_): return None
    def read(self):
        return json.dumps({"choices": [{"message": {"content": json.dumps({
            "is_threat": False, "severity": "LOW", "action": "LOG_ONLY",
            "mitre_technique": "T1059.001", "reasoning": "single event",
        })}}]}).encode()


class TestAI(unittest.TestCase):
    def test_valid_structured_verdict(self):
        mock_opener = unittest.mock.Mock()
        mock_opener.open.return_value = FakeResponse()
        with patch("urllib.request.build_opener", return_value=mock_opener):
            result = BoNaoAIAgent().phan_tich_su_kien({"event_id": 1, "cleaned_command": "Hello"})
        self.assertFalse(result["is_threat"])
        self.assertEqual(result["action"], "LOG_ONLY")

    def test_bad_ai_response_fails_closed(self):
        mock_opener = unittest.mock.Mock()
        mock_opener.open.side_effect = TimeoutError("offline")
        with patch("urllib.request.build_opener", return_value=mock_opener):
            result = BoNaoAIAgent().phan_tich_su_kien({"event_id": 1, "cleaned_command": "Hello"})
        self.assertEqual(result["severity"], "ERROR")
        self.assertEqual(result["action"], "LOG_ONLY")


if __name__ == "__main__": unittest.main()

class TestCursorDurability(unittest.TestCase):
    def test_cursor_is_saved_after_yield_consumer_ack(self):
        from Sensor.event_listener import EventSensorAgent
        with tempfile.TemporaryDirectory() as d:
            sensor = EventSensorAgent(state_path=Path(d) / "cursor.json")
            sensor._initialized = True
            sensor.last_record_id = 17850
            sensor._iter_event_xml = lambda *args, **kwargs: iter([XML_SAMPLE])
            gen = sensor._scan()
            event = next(gen)
            self.assertEqual(event["record_id"], "17852")
            self.assertEqual(sensor.last_record_id, 17850)
            with self.assertRaises(StopIteration):
                next(gen)
            self.assertEqual(sensor.last_record_id, 17852)
            second_instance = EventSensorAgent(state_path=Path(d) / "cursor.json")
            self.assertEqual(second_instance.last_record_id, 17852)
