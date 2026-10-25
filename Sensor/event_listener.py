import time
import logging
import re
import win32evtlog
from typing import Generator, Dict, Any, List
# Cấu hình Evidentiary Logging cho Tầng Sensor
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
class EventSensorAgent:
    SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self, polling_interval: float = 0.5):
        self.polling_interval = polling_interval
        self.processed_record_ids: set = set()
        self.max_cache_size = 5000
    def _trich_xuat_truong(self, xml_str: str, field_name: str) -> str:
        match = re.search(fr'<Data Name=["\']?{field_name}["\']?>(.*?)</Data>', xml_str, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else ""
    def doc_su_kien_sysmon_moi_nhat(self) -> List[Dict[str, Any]]:
        danh_sach_su_kien = []
        xpath_query = "*[System[(EventID=1)]]"
        try:
            query_handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                xpath_query
            )
            events = win32evtlog.EvtNext(query_handle, 15)
            for event in events:
                xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                # Trích xuất EventRecordID làm khóa nhận dạng duy nhất
                rec_match = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml_content)
                if not rec_match:
                    continue
                record_id = rec_match.group(1)
                if record_id in self.processed_record_ids:
                    continue
                self.processed_record_ids.add(record_id)
                # Trích xuất dữ liệu tiến trình
                image = self._trich_xuat_truong(xml_content, "Image")
                command_line = self._trich_xuat_truong(xml_content, "CommandLine")
                pid_str = self._trich_xuat_truong(xml_content, "ProcessId")
                user = self._trich_xuat_truong(xml_content, "User")
                parent_image = self._trich_xuat_truong(xml_content, "ParentImage")
                pid = int(pid_str) if pid_str.isdigit() else 0
                # Bắt các Shell nghi vấn
                image_lower = image.lower()
                if any(shell in image_lower for shell in ["powershell.exe", "cmd.exe", "pwsh.exe", "wscript.exe", "cscript.exe"]):
                    danh_sach_su_kien.append({
                        "source": "Sysmon_EID1",
                        "event_id": 1,
                        "record_id": record_id,
                        "pid": pid,
                        "image": image,
                        "command_line": command_line,
                        "user": user,
                        "parent_image": parent_image,
                        "timestamp": time.time()
                    })
        except Exception as e:
            logging.error(f"[SENSOR ERROR] Lỗi đọc Sysmon Log: {str(e)}")

        return danh_sach_su_kien

    def quat_lang_nghe_lien_tuc(self) -> Generator[Dict[str, Any], None, None]:
        logging.info("[*] [SENSOR] Đã kết nối thành công dịch vụ Sysmon64 (Running).")
        logging.info(f"[*] [SENSOR] Kênh lắng nghe : {self.SYSMON_CHANNEL}")
        logging.info(f"[*] [SENSOR] Chu kỳ quét    : {self.polling_interval}s")

        # Nạp cache các record lịch sử ban đầu để tránh phát lại log cũ
        try:
            query_handle = win32evtlog.EvtQuery(
                self.SYSMON_CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                "*[System[(EventID=1)]]"
            )
            init_events = win32evtlog.EvtNext(query_handle, 50)
            for ev in init_events:
                xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                rec = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml)
                if rec:
                    self.processed_record_ids.add(rec.group(1))
        except Exception:
            pass

        logging.info("[*] [SENSOR] Đang chờ sự kiện tiến trình mới...")

        while True:
            events = self.doc_su_kien_sysmon_moi_nhat()
            for event in events:
                yield event

            if len(self.processed_record_ids) > self.max_cache_size:
                self.processed_record_ids.clear()

            time.sleep(self.polling_interval)
if __name__ == "__main__":
    print("=" * 70)
    print(" [TEST] KÍCH HOẠT KIỂM THỬ THỜI GIAN THỰC TẦNG SENSOR (SYSMON 64)")
    print(" Mở 1 cửa sổ PowerShell mới và gõ lệnh bất kỳ để thử nghiệm bắt Log!")
    print("=" * 70)

    sensor = EventSensorAgent(polling_interval=0.5)
    try:
        for event_data in sensor.quat_lang_nghe_lien_tuc():
            print(f"\n[+] BẮT ĐƯỢC SỰ KIỆN SYSMON ID 1 (PROCESS CREATION):")
            print(f" - Record ID     : {event_data['record_id']}")
            print(f" - Process PID   : {event_data['pid']}")
            print(f" - Tiến trình    : {event_data['image']}")
            print(f" - Command Line  : {event_data['command_line']}")
            print(f" - User Context  : {event_data['user']}")
            print("-" * 70)
    except KeyboardInterrupt:
        print("\n[*] Đã dừng Tầng Sensor Agent.")