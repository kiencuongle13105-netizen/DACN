import json
import re
import urllib.request
import urllib.error
from typing import Dict, Any

class BoNaoAIAgent:
    def __init__(self, base_url: str = "http://192.168.62.1:1235/v1"):
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/chat/completions"
    def _tao_system_prompt(self) -> str:
        return (
            "Bạn là Chuyên gia EDR/SOC Agent phân tích lệnh Windows.\n\n"
            "QUY TẮC PHÁN QUYẾT BẮT BUỘC:\n"
            "1. ĐỘC HẠI (is_threat: true, action: 'KILL_PROCESS', severity: 'CRITICAL'):\n"
            "   - NẾU LỆNH CHỨA BẤT KỲ TỪ KHÓA NÀY -> BẮT BUỘC PHẢN ỨNG MẠNH: Mimikatz, Invoke-Mimikatz, SharpHound, BloodHound, DumpCreds, Net.WebClient, DownloadString, DownloadFile, IEX, Invoke-Expression, -enc, -EncodedCommand, mshta.\n\n"
            "2. AN TOÀN (is_threat: false, action: 'IGNORE', severity: 'INFO'):\n"
            "   - Lệnh tra cứu/quản trị thông thường KHÔNG chứa từ khóa độc hại trên: Get-Service, Get-Process, Select-Object, Where-Object, Format-Table, ipconfig, ping.\n\n"
            "YÊU CẦU OUTPUT: Trả về duy nhất 1 chuỗi JSON hợp lệ với đúng 5 trường (is_threat, severity, action, mitre_technique, reasoning). Không dùng markdown."
        )
    def phan_tich_su_kien(self, processed_event: Dict[str, Any]) -> Dict[str, Any]:
        eid = processed_event.get("event_id", "N/A")
        image = processed_event.get("image", "N/A")
        pid = processed_event.get("pid", "N/A")
        cleaned_cmd = processed_event.get("cleaned_command", "N/A")
        is_obfuscated = processed_event.get("is_obfuscated", False)

        user_content = (
            f"Event ID: {eid} | Process: {image} (PID: {pid})\n"
            f"Command: {cleaned_cmd}\n"
            f"Obfuscated Base64: {is_obfuscated}\n"
            f"JSON Output:"
        )

        payload = {
            "model": "qwen2.5-coder-3b-instruct-awq",
            "messages": [
                {"role": "system", "content": self._tao_system_prompt()},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.0,
            "max_tokens": 120,
          
        }

        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.api_url, 
                data=data, 
                headers={'Content-Type': 'application/json'},
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=15) as response:
                res_body = response.read().decode('utf-8')
                result = json.loads(res_body)
                
                content = result['choices'][0]['message']['content'].strip()
                
                # Xóa sạch các cờ Markdown ```json nếu có
                clean_content = re.sub(r'```(?:json)?', '', content).strip()
                
                # Trích xuất khối JSON đầu tiên
                match = re.search(r'\{[\s\S]*?\}', clean_content)
                if match:
                    parsed = json.loads(match.group(0))
                    # Đảm bảo luôn trả về đủ tất cả các trường dữ liệu
                    return {
                        "is_threat": parsed.get("is_threat", False),
                        "severity": parsed.get("severity", "INFO"),
                        "action": parsed.get("action", "IGNORE"),
                        "mitre_technique": parsed.get("mitre_technique", "T1059.001" if parsed.get("is_threat") else "N/A"),
                        "reasoning": parsed.get("reasoning", "Thực thi lệnh PowerShell" if parsed.get("is_threat") else "Lệnh hệ thống hợp lệ")
                    }

                raise ValueError("Không thể bóc tách JSON")

        except Exception as e:
            return {
                "is_threat": False,
                "severity": "ERROR",
                "action": "LOG_ONLY",
                "mitre_technique": "N/A",
                "reasoning": f"Lỗi xử lý phản hồi từ AI: {str(e)}"
            }