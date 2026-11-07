# DACN-main — Windows VM AutoStart + Guarded Live Response

Đây là bản cập nhật trực tiếp từ `DACN-main.zip` (mã gốc) của người dùng, **không dùng repo Phase 1–8 khác**.

## Chức năng

- `DACN-Git-Agent` tự chạy lúc Windows VM khởi động; không chạy `py main.py`.
- Sysmon EID **1, 8, 11, 13** được thu thập qua Windows Event Log và lưu hàng đợi SQLite. Nếu máy chính/LM Studio tắt, Agent tự thử kết nối lại.
- Qwen2.5-Coder-3B-AWQ qua LM Studio `http://192.168.62.1:1236/v1` trả JSON có cấu trúc.
- **GUARDED_AUTO**: có thể kết thúc tiến trình Windows **thật** bằng `psutil.Process.kill()` khi *đồng thời*:
  1. Tiến trình là `powershell.exe` hoặc `pwsh.exe` tương tác (không thuộc tài khoản hệ thống/dịch vụ).
  2. Sysmon EID1 và ít nhất một EID8/11/13 bổ trợ đủ điều kiện, **cùng ProcessGuid**, trong 90 giây.
  3. Lệnh có dấu hiệu rủi ro cao (ví dụ tải và thực thi mã trong bộ nhớ), không chỉ Base64/`-EncodedCommand`.
  4. Qwen trả **is_threat=true, severity HIGH/CRITICAL, action KILL_PROCESS**.
  5. PID, đường dẫn thực thi, user và thời điểm tạo tiến trình kiểm tra trực tiếp trên Windows khớp Sysmon; sự kiện tối đa 120 giây.
- Lưu toàn bộ quyết định, trường hợp từ chối và xác minh hậu xử lý vào `decision_audit.jsonl`.
- Phản ứng thật là **opt-in** bằng công tắc khi cài đặt. Chế độ mặc định vẫn `SIMULATION_ONLY`.

### Cài đặt trên **Windows 10 VMware, PowerShell Administrator**

Tải và giải nén ZIP vào `Downloads` để có thư mục `DACN-main`, sau đó:

```powershell
cd "$env:USERPROFILE\Downloads\DACN-main"
Set-ExecutionPolicy -Scope Process RemoteSigned -Force
& '.\scripts\install_autostart.ps1' -AiEndpoint 'http://192.168.62.1:1236/v1' -ReplaceExistingDACN -EnableGuardedAuto
& '.\scripts\status_autostart.ps1'
```

Nếu không có ba task DACN cũ, bỏ `-ReplaceExistingDACN`. Script sẽ sao lưu danh sách trạng thái task cũ và vô hiệu hóa chúng để không trùng Sensor.

Phần mềm được cài vào `C:\ProgramData\DACN-Git\app`. LM Studio trên **máy chính** vẫn do bạn bật thủ công, cần load `qwen2.5-coder-3b-instruct-awq` và bật server cổng `1236` cho phép VM kết nối qua host-only. `GUARDED_AUTO` **không dùng** API Server cũ `8765`.

### Kiểm tra chế độ và phản ứng

```powershell
& '.\scripts\status_autostart.ps1'
Get-Content 'C:\ProgramData\DACN-Git\app\data\heartbeat.json'
Get-Content 'C:\ProgramData\DACN-Git\app\data\decision_audit.jsonl' -Tail 10
Get-Content 'C:\ProgramData\DACN-Git\app\logs\dacn_agent.log' -Tail 20
```

Cần thấy `response_mode: GUARDED_AUTO` trong heartbeat. **Running** chỉ cho biết Agent còn chạy; không chứng minh đã kết thúc được tiến trình. Log `executed_action: KILL_PROCESS` và `response_reason: POST_VERIFY_OK` mới thể hiện một trường hợp thành công sau khi xác minh. `AI_DID_NOT_APPROVE`, `INSUFFICIENT_INDEPENDENT_EVIDENCE`, `PID_REUSED_OR_TIME_MISMATCH`, `STALE_EVENT` là kết quả từ chối đúng theo chính sách.

### Tắt phản ứng thật ngay nhưng giữ giám sát

```powershell
& '.\scripts\set_response_mode.ps1' -Mode SIMULATION_ONLY
```

Bật lại sau khi đánh giá:

```powershell
& '.\scripts\set_response_mode.ps1' -Mode GUARDED_AUTO
```

Nếu cần **dừng toàn bộ Agent ngay lập tức**:

```powershell
Stop-ScheduledTask -TaskName DACN-Git-Agent
```

### Giới hạn / cảnh báo

- Chỉ kích hoạt trong **VM đã chụp Snapshot** và nơi bạn quản trị được. Không triển khai chế độ kill trực tiếp lên máy Windows cá nhân hoặc máy chủ production nếu chưa thẩm định.
- Đây là chặn tiến trình **có điều kiện**, không phải tự động xử lý toàn bộ malware. Một tiến trình đã thoát trước khi AI trả lời, có sự kiện cũ, không phải PowerShell hoặc không có Sysmon bổ trợ sẽ **không bị kill**.
- Test `Write-Output` qua `-EncodedCommand` là hành vi hợp lệ, **không nên bị kill**. Atomic Red Team test không tự động đồng nghĩa malware.
- EID8/11/13 phải được Sysmon bật thu thập theo cấu hình hiện tại; nếu không có sự kiện liên quan, policy sẽ từ chối kill.
- Logic Windows PS Task Scheduler/Sysmon và kill thật cần được kiểm chứng trên VM của bạn. Bài test đóng gói chỉ có thể mô phỏng tiến trình bằng mocks ở môi trường xây dựng ZIP.
- Log SQLite chứa command lines nhạy cảm; không commit log, DB, `.env` hoặc khóa API lên GitHub.

### Kiểm thử Python

```powershell
py -3.12 -m unittest discover -s tests -v
```

Gỡ và khôi phục các task DACN cũ:

```powershell
& '.\scripts\uninstall_autostart.ps1' -RestorePreviousTasks
```
