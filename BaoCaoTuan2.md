I. BÁO CÁO TIẾN ĐỘ THỰC NGHIỆM TRONG TUẦN 2
1. Các Kết Quả Đã Đạt Được
 Hoàn thiện Kiến trúc Hệ thống:
  1.Bắt trực tiếp Sysmon Event ID 1 (Process Creation) thời gian thực thông qua Win32 EvtQuery API.
  2.Giải mã Base64 UTF-16LE, làm sạch ký tự HTML/XML và chuẩn hóa dòng lệnh.
  3.Tích hợp thành công mô hình Qwen 2.5 Coder 3B Instruct qua LM Studio Local API (http://192.168.62.1:1235/v1).
  4 Triệt tiêu tiến trình khẩn cấp theo chuẩn  (psutil.kill()) và ghi nhật ký sự cố.
2. Hạn Chế
 Độ trễ suy luận SLM
 Thời gian suy luận của Qwen 2.5 3B dao động từ $1.3\text{s} - 2.3\text{s}$.
 Với các tiến trình thực thi cực ngắn, tiến trình có thể thực thi xong trước khi nhận lệnh diệt.
Sự phụ thuộc đơn nguồn :
 Phụ thuộc hoàn toàn vào dịch vụ Sysmon. Nếu attacker tắt Sysmon (net stop sysmon64), Agent sẽ bị mù dữ liệu đầu vào.
Giới hạn giải mã tĩnh (Static Deobfuscation Limits):**
 Bộ Deobfuscator dựa trên Regex mới xử lý được mã hóa Base64 đơn tầng.
II. HƯỚNG DẪN CÀI ĐẶT VÀ VẬN HÀNH 
1. Yêu Cầu Môi Trường
 Máy thật:
   Cài đặt LM Studio và đã nạp Model Qwen 2.5 Coder 3B Instruct (AWQ).
  Card mạng VMware/VirtualBox Host-Only
 Máy ảo Windows 10:
   Python 3.10+ (Đã cài thư viện: psutil, pywin32).
   Dịch vụ Sysmon64 đang chạy (Microsoft-Windows-Sysmon/Operational).
   Môi trường Atomic Red Team (Invoke-AtomicRedTeam).
2. Quy Trình Khởi Động Hệ Thống.
 Bước 1: Khởi chạy AI Server trên Máy thật
  Mở LM Studio Chuyển sang tab  Local Server.
  Chọn Model Qwen 2.5 Coder 3B.
  Đặt Port: 1235 và bật công tắc Start Server
 Bước 2: Chuẩn bị Môi trường trên Máy ảo
  Mở PowerShell Administrator trên máy ảo và chạy lệnh mở quyền thực thi:
  powershell
  Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
 Bước 3: Khởi chạy 
  Mở cửa sổ PowerShell Admin tại thư mục dự án:
  python main.py
  Dấu hiệu thành công: Màn hình xuất hiện log:  
  [INFO] - [*] [SENSOR] Đã kết nối thành công dịch vụ Sysmon64 (Running).
  [INFO] - [*] [SENSOR] Đang chờ sự kiện tiến trình mới...
Bước 4: Thực thi Diễn tập Tấn công (Cửa sổ 2 - Attacker Simulator)
Mở cửa sổ PowerShell Admin thứ hai, nạp module Atomic Red Team và test các kịch bản:
 Nạp Module Atomic Red Team
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
 Kịch bản 1: Test Mimikatz (T1059.001) -> Bị diệt (Exit Code 15)
  Invoke-AtomicTest T1059.001 -TestNumbers 1