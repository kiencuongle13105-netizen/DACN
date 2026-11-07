import base64
import re
from typing import Dict, Any, Tuple

class BoGiaiMaPowerShell:
    # Regex bắt chuỗi mã hóa Base64 đứng sau các cờ mã hóa PowerShell
    B64_PATTERN = r'(?:-e|-enc|-encodedcommand|-ec|-encoded)\s+([A-Za-z0-9+/=]+)'
    @classmethod
    def giai_ma_base64_utf16(cls, command_line: str) -> Tuple[bool, str]:
        if not command_line:
            return False, ""
        match = re.search(cls.B64_PATTERN, command_line, re.IGNORECASE)
        if match:
            b64_str = match.group(1)
            try:
                # Tự động bổ sung Padding '=' nếu chuỗi Base64 bị thiếu
                missing_padding = len(b64_str) % 4
                if missing_padding:
                    b64_str += '=' * (4 - missing_padding)
                # Giải mã Byte Base64 -> Chuyển đổi Unicode UTF-16LE sang chuỗi rõ
                decoded_bytes = base64.b64decode(b64_str)
                decoded_text = decoded_bytes.decode('utf-16le', errors='ignore')
                return True, decoded_text.strip()
            except Exception:
                return False, command_line
        return False, command_line
    @classmethod
    def chuan_hoa_van_ban(cls, text: str) -> str:
        if not text:
            return ""
        cleaned = re.sub(r'\s+', ' ', text)
        return cleaned.strip()
    @classmethod
    def tien_xu_ly_su_kien(cls, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        processed_event = raw_event.copy()
        eid = raw_event.get("event_id")
        # Xử lý log Tiến trình khởi chạy (Sysmon Event ID 1)
        if eid == 1:
            cmd_line = raw_event.get("command_line", "")
            is_decoded, decoded_cmd = cls.giai_ma_base64_utf16(cmd_line)
            processed_event["is_obfuscated"] = is_decoded
            processed_event["cleaned_command"] = cls.chuan_hoa_van_ban(decoded_cmd if is_decoded else cmd_line)
        # Xử lý log Thực thi Script Block (PowerShell Event ID 4104)
        elif eid == 4104:
            script_text = raw_event.get("script_block_text", "")
            is_decoded, decoded_script = cls.giai_ma_base64_utf16(script_text)
            processed_event["is_obfuscated"] = is_decoded
            processed_event["cleaned_command"] = cls.chuan_hoa_van_ban(decoded_script if is_decoded else script_text)
        return processed_event