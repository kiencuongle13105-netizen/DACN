1. Mục tiêu trong tuần
Tập trung hoàn thiện cơ chế phản ứng hai giai đoạn theo góp ý của giảng viên: Fast Rule phát hiện và tạm dừng tiến trình nghi ngờ trước, SLM phân tích rồi quyết định cho chạy tiếp  hoặc kết thúc . Đồng thời xây dựng kiểm thử Atomic Red Team kết hợp script quản trị lành tính và chuẩn hóa bằng chứng, số liệu đánh giá.
2. Công việc đã thực hiện
2.1. Hoàn thiện cơ chế phòng thủ hai giai đoạn
- Duy trì luồng thu thập Sysmon → Fast Rule → Suspend → SLM → Resume/Terminate theo chính sách an toàn.
- Tiếp tục sử dụng chế độ GUARDED_AUTO, đối chiếu danh tính tiến trình (PID, đường dẫn, thời gian tạo, ProcessGuid), và watchdog để giảm rủi ro tiến trình bị treo lâu.
- Kiểm tra khả năng kết nối Windows 10 VM với LM Studio trên Windows 11 Host tại 192.168.62.1:1236; ghi nhận kết nối TCP thành công và agent hoạt động qua Scheduled Task.
- Có bằng chứng phản ứng thực tế Suspend và Resume. Chưa chứng minh được nhánh SLM tự quyết định Terminate trong đợt kiểm thử Atomic mới nhất.
2.2. Tích hợp Atomic Red Team và kịch bản lành tính
- Cài đặt và kiểm tra module invoke-atomicredteam; khảo sát các bài thuộc kỹ thuật T1059.001 – PowerShell.
- Kiểm tra điều kiện chạy và nội dung những bài T1059.001-10, -11, -12, -15 và -17. Bài -12 thiếu điều kiện PSRemoting; bài -10 có trường hợp Microsoft Defender can thiệp, vì vậy không đưa cả hai bài này vào nhóm mặc định của một số đợt thử.
- Xây dựng và chạy bộ 100 lượt kiểm thử, gồm 50 lượt Atomic Red Team và 50 lượt chương trình/script quản trị lành tính.
- Bổ sung quy trình Review → phê duyệt nội dung bằng SHA256 → Run, dọn dẹp sau thử nghiệm, ghi nhận và phân loại sự can thiệp của Defender.
2.3. Cải tiến thu thập và đối chiếu bằng chứng
- Nâng cấp bộ báo cáo để liên kết launcher và tiến trình con của Atomic bằng ProcessGuid/`ParentProcessGuid`, thay vì chỉ theo dõi PowerShell khởi chạy.
- Xuất sự kiện Sysmon, audit phản ứng và phán quyết SLM, bằng chứng từng ca và báo cáo CSV/JSON/Markdown.
- Phân biệt Fast Hold gây gián đoạn nhầm với SLM phân loại nhầm, tránh cộng gộp hai loại sai số.
- Tách trường hợp Defender có hoạt động gần thời điểm thử khỏi đánh giá chính thức khi chưa đủ bằng chứng quy trách nhiệm.
- Kiểm tra, sửa bộ cài trên Windows 10: giải quyết vấn đề khóa SQLite (WinError 32) trong kiểm thử và lỗi PowerShell xử lý đầu ra unittest thành NativeCommandError.
2.4. Khắc phục thiếu Sysmon Event ID 5
- Phát hiện cấu hình C:\Sysmon\sysmonconfig.dacn-atomic.xml chỉ thu thập ProcessTerminate cho một số đường dẫn, không bao gồm PowerShell hệ thống.
- Sao lưu và cập nhật nhóm quy tắc ProcessTerminate để bao gồm powershell.exe và pwsh.exe, giữ nguyên các quy tắc khác.
- Kiểm tra thực tế cùng một tiến trình PID 6956:
  - EID 1: 17:40:58 ngày 15/11/2026.
  - EID 5: 17:41:02 ngày 15/11/2026.
- Kết quả xác nhận Sysmon đã ghi nhận cả thời điểm tạo lẫn thời điểm kết thúc tiến trình PowerShell.
4. Khó khăn, vướng mắc đang gặp
- Chưa chứng minh SLM tự Terminate trong kiểm thử mới: chưa đủ minh chứng yêu cầu phản ứng hoàn toàn tự động. Tình trạng/hướng xử lý: Thiết kế ca thử an toàn trên tiến trình mẫu cô lập, thu phán quyết SLM thật, ProcessGuid, lệnh Terminate và hậu kiểm tiến trình đã dừng.
- Thiếu nhãn dương tính được xác minh: không tính được TP/FN, Recall trên mẫu hành vi độc hại. Tình trạng/hướng xử lý: Gán nhãn theo bằng chứng thực thi hành vi; không mặc định mọi bài Atomic là malware.
- Nhiều bài Atomic chỉ xác nhận launcher chạy xong: không đủ chứng minh payload/technique thực thi thành công. Tình trạng/hướng xử lý: Thêm marker/hậu điều kiện theo từng Atomic, ghép cây tiến trình và Sysmon.
- Defender can thiệp hoặc trùng thời gian: khó quy trách nhiệm phát hiện/chặn cho DACN. Tình trạng/hướng xử lý: Giữ Defender bật; ghi nhận sự kiện 1116/1117, đối chiếu thời gian, đường dẫn và tiến trình; tách/loại ca chưa rõ.
- Fast Hold trên chương trình lành tính: có gián đoạn tạm thời dù SLM sau đó cho Resume. Tình trạng/hướng xử lý: Tinh chỉnh điều kiện luật nhanh và kiểm thử script quản trị thực tế; tách chỉ số Fast Hold FPR khỏi SLM FPR.
- SLM có độ trễ suy luận: tiến trình ngắn có thể kết thúc trước khi quyết định. Tình trạng/hướng xử lý: Ưu tiên luật nhanh trước suy luận, đo P50/P95, bổ sung mốc hoàn thành hành vi để đánh giá hiệu quả chặn.
- EID 5 từng bị lọc bỏ với PowerShell: không đo được thời gian kết thúc tiến trình. Tình trạng/hướng xử lý: Đã sửa và xác minh EID 1/EID 5 trên PID 6956; cần duy trì cấu hình ổn định khi triển khai.
