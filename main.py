import time
from Sensor.event_listener import EventSensorAgent
from utils.bo_giai_ma import BoGiaiMaPowerShell
from agent.bo_nao_ai import BoNaoAIAgent
from actuator.xuly_tien_trinh import TrietTieuTienTrinh

class HeThongPhanUngMoiDeDoa:
   
    def __init__(self, ai_endpoint: str = "http://192.168.62.1:1235/v1"):
        print("[*] Đang khởi tạo hệ thống EDR Agent (REA Engine)...")
        self.sensor = EventSensorAgent(polling_interval=0.5)
        self.ai_agent = BoNaoAIAgent(base_url=ai_endpoint)
        print(f"    -> AI Endpoint kết nối: {ai_endpoint}")
    def run(self):
        print("\n" + "=" * 70)
        print(" KÍCH HOẠT HỆ THỐNG REA AGENT GIÁM SÁT THỜI GIAN THỰC")
        print(" Đang theo dõi liên tục các sự kiện tiến trình từ Sysmon64...")
        print("=" * 70 + "\n")
        try:
            # Lắng nghe dòng sự kiện liên tục từ Tầng Sensor
            for event in self.sensor.quat_lang_nghe_lien_tuc():
                self.xu_ly_su_kien(event)
        except KeyboardInterrupt:
            print("\n[*] Đã dừng hệ thống REA Agent.")
    def xu_ly_su_kien(self, raw_event: dict):
        pid = raw_event.get("pid")
        record_id = raw_event.get("record_id")
        print("\n" + "=" * 70)
        print(f"[1] TẦNG SENSOR: Bắt sự kiện Sysmon ID 1 (Record ID: {record_id} | PID: {pid})")
        print(f"    - Tiến trình  : {raw_event.get('image')}")
        print(f"    - Lệnh gốc    : {raw_event.get('command_line')}")
        # TẦNG 2: TIỀN XỬ LÝ & GIẢI MÃ (PREPROCESSOR)
        processed_event = BoGiaiMaPowerShell.tien_xu_ly_su_kien(raw_event)
        print(f"\n[2] TẦNG TIỀN XỬ LÝ (DEOBFUSCATOR):")
        print(f"    - Phát hiện Base64 : {processed_event['is_obfuscated']}")
        print(f"    - Chuỗi lệnh sạch  : {processed_event['cleaned_command']}")
        # TẦNG 3: PHÁN QUYẾT BỞI AI CORE (QWEN 2.5 SLM)
        print(f"\n[3] TẦNG AI CORE (Gửi dữ liệu sang Qwen 2.5 Coder 3B)...")
        start_time = time.time()
        verdict = self.ai_agent.phan_tich_su_kien(processed_event)
        elapsed_time = time.time() - start_time
        print(f"    -> Thời gian suy luận : {elapsed_time:.2f} giây")
        print(f"    -> Phán quyết AI     : Mối đe dọa={verdict.get('is_threat')} | Action={verdict.get('action')}")
        print(f"    -> Mã MITRE ATT&CK   : {verdict.get('mitre_technique')}")
        print(f"    -> Lý do             : {verdict.get('reasoning')}")
        # TẦNG 4: THỰC THI CHUYÊN BỆT (ACTUATOR)
        print(f"\n[4] TẦNG THỰC THI (ACTUATOR):")
        TrietTieuTienTrinh.thuc_hien_hanh_dong(pid=pid, ai_verdict=verdict)
        print("=" * 70)
if __name__ == "__main__":
    agent = HeThongPhanUngMoiDeDoa(ai_endpoint="http://192.168.62.1:1235/v1")
    agent.run()