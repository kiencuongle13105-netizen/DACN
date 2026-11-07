import os
import sys
import logging
import ctypes
from datetime import datetime
from typing import Dict, Any
import psutil
# Cấu hình Evidentiary Logging 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
class TrietTieuTienTrinh:
    @staticmethod
    def kiem_tra_quyen_admin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    @classmethod
    def thuc_hien_hanh_dong(cls, pid: int, ai_verdict: Dict[str, Any]) -> bool:
        action = ai_verdict.get("action", "LOG_ONLY")
        severity = ai_verdict.get("severity", "INFO")
        reasoning = ai_verdict.get("reasoning", "N/A")
        mitre_technique = ai_verdict.get("mitre_technique", "N/A")
        # Phản ứng theo cấp độ phán quyết (NIST SP 800-61 Rev. 2)
        if action == "KILL_PROCESS":
            return cls.diet_tien_trinh(
                pid=pid, 
                severity=severity, 
                reasoning=reasoning, 
                mitre_technique=mitre_technique
            )
        elif action == "LOG_ONLY":
            logging.warning(
                f"[D3-PA] [LOG_ONLY] PID {pid} có dấu hiệu nghi vấn. "
                f"Kỹ thuật: {mitre_technique} | Lý do: {reasoning}"
            )
            return True
        else:
            logging.info(f"[D3-PA] [IGNORE] PID {pid} an toàn. Bỏ qua.")
            return True
    @classmethod
    def diet_tien_trinh(cls, pid: int, severity: str, reasoning: str, mitre_technique: str = "N/A") -> bool:
        if not cls.kiem_tra_quyen_admin():
            print("[!] CẢNH BÁO: Agent chưa được khởi chạy dưới quyền Administrator!")

        try:
            # Tra cứu thông tin tiến trình trong bảng tiến trình Kernel (Process Table)
            process = psutil.Process(pid)
            process_name = process.name()
            cmd_line = " ".join(process.cmdline()) if process.cmdline() else "N/A"
            # Thực thi ngắt tiến trình độc hại ngay lập tức (TerminateProcess)
            process.kill()
            # Xuất nhật ký phản ứng khẩn cấp (Evidentiary Logging - MITRE D3-PA)
            print("\n" + "=" * 70)
            print("[!] KÍCH HOẠT PHẢN ỨNG THỜI GIAN THỰC (REAL-TIME CONTAINMENT)")
            print("=" * 70)
            print(f" [+] Kỹ thuật áp dụng : MITRE D3-KPT (Kernel Process Termination)")
            print(f" [+] PID mục tiêu     : {pid}")
            print(f" [+] Tên tiến trình   : {process_name}")
            print(f" [+] Chuỗi lệnh (CMD) : {cmd_line}")
            print(f" [+] Mức độ nguy hại  : {severity}")
            print(f" [+] Kỹ thuật MITRE   : {mitre_technique}")
            print(f" [+] Phán quyết AI    : {reasoning}")
            print(f" [+] Thời điểm diệt   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 70 + "\n")
            logging.info(f"[D3-KPT SUCCESS] Đã triệt tiêu thành công PID {pid} ({process_name}).")
            return True
        except psutil.NoSuchProcess:
            print(f"[*] [D3-KPT] Tiến trình PID {pid} không còn tồn tại hoặc đã tự kết thúc.")
            logging.info(f"[D3-KPT] PID {pid} đã thoát trước khi triệt tiêu.")
            return False
        except psutil.AccessDenied:
            print(f"[!] [D3-KPT ERROR] Bị từ chối truy cập (AccessDenied) khi diệt PID {pid}.")
            print("    -> Vui lòng chạy lại ứng dụng bằng 'Run as Administrator'.")
            logging.error(f"[D3-KPT ERROR] Lỗi AccessDenied đối với PID {pid}.")
            return False
        except Exception as e:
            print(f"[!] [D3-KPT ERROR] Lỗi ngoại lệ khi triệt tiêu PID {pid}: {str(e)}")
            logging.error(f"[D3-KPT ERROR] Ngoại lệ: {str(e)}")
            return False