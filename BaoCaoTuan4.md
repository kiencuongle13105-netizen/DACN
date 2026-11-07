1. Những công việc đã thực hiện trong tuần
Trong tuần 4, nhóm tập trung nâng cấp chương trình DACN từ cách vận hành thủ công bằng main.py thành Agent có thể hoạt động tự động trên Windows 10 VMware.
- Tự động khởi động: Tích hợp Agent với Windows Task Scheduler. Sau khi cài đặt, chương trình có thể tự chạy nền cùng Windows, không cần mở VS Code hoặc thực thi main.py thủ công.
- Thu thập và quản lý sự kiện: Cải tiến bộ thu thập Sysmon, bổ sung hàng đợi SQLite để lưu sự kiện và cơ chế ghi nhật ký, theo dõi trạng thái Agent. Khi dịch vụ AI chưa sẵn sàng, Agent vẫn có thể tiếp tục thu thập và lưu sự kiện.
- Kết nối AI: Thiết lập kết nối giữa Windows VMware và mô hình Qwen 2.5 Coder 3B Instruct (AWQ) chạy trên LM Studio ở máy chính. Đã khắc phục vấn đề cấu hình mạng và cổng API khiến máy ảo không truy cập được mô hình.
- Tích hợp xử lý tự động: Bổ sung chế độ GUARDED_AUTO cho phép hệ thống xem xét kết thúc tiến trình đáng ngờ sau khi có đề xuất từ AI và vượt qua các bước kiểm tra bằng chứng, danh tính tiến trình.
- Chạy thử và rà soát hoạt động: Sử dụng các tình huống PowerShell và công cụ Atomic Red Team để quan sát khả năng ghi nhận sự kiện, phân tích và đưa ra quyết định của Agent.
2. Kết quả đạt được
- Agent đã chạy tự động thành công: Tác vụ DACN-Git-Agent hiển thị trạng thái Running; chương trình ghi nhận trạng thái hoạt động và không báo lỗi tại thời điểm kiểm tra.
- Kết nối giữa VMware và AI đã hoạt động: Máy ảo truy cập được API của LM Studio trên máy chính và nhận diện đúng mô hình Qwen đang sử dụng.
- Hệ thống đã tự thu thập và xử lý sự kiện mới: Agent ghi nhận các hoạt động PowerShell thông qua Sysmon, đưa sự kiện vào quy trình xử lý và lưu kết quả phân tích.
- Đã nhận được quyết định từ luồng AI: Một số trường hợp thử nghiệm được phân loại là hành vi thông thường, với kết quả LOG_ONLY; hệ thống không tự ý kết thúc tiến trình khi chưa có đủ căn cứ.
- Đã tích hợp cơ chế phản ứng có kiểm soát: Chế độ GUARDED_AUTO được cấu hình và khởi chạy. Phần này đã có trong chương trình, tuy nhiên kết quả trên máy ảo hiện mới xác nhận được việc kích hoạt chế độ, chưa xác nhận một lần kết thúc tiến trình thật thành công.
Nhìn chung, kết quả nổi bật của tuần 4 là DACN đã chuyển được từ chương trình cần chạy thủ công sang hệ thống Agent tự khởi động, thu thập sự kiện và phối hợp phân tích với AI.
3. Các vấn đề đang gặp và những phần chưa hoàn thành
- Chưa huấn luyện AI riêng: Nhóm hiện sử dụng Qwen 2.5 Coder 3B Instruct (AWQ) đã được huấn luyện trước, thông qua LM Studio để suy luận. Chưa xây dựng hoàn chỉnh dữ liệu huấn luyện và chưa thực hiện training hoặc fine-tuning mô hình cho bài toán phát hiện fileless malware.
- Chưa xác minh thành công tự động diệt tiến trình thật: Mặc dù đã tích hợp và bật GUARDED_AUTO, những lần thử hiện tại chưa tạo ra bản ghi xác nhận DACN tự kết thúc tiến trình mục tiêu. Phần lớn kết quả là LOG_ONLY, NO_HIGH_RISK_COMMAND hoặc STALE_EVENT vì chưa đủ điều kiện phản ứng.
- Dữ liệu kiểm thử chưa đáp ứng đầy đủ điều kiện tương quan: Một số sự kiện phát sinh từ PowerShell đã mở trước đó nên không phù hợp giới hạn thời gian xử lý. Cần tiếp tục kiểm tra cách liên kết các sự kiện của cùng một tiến trình.
- Còn nhiễu trong dữ liệu Sysmon: Một số tệp kiểm tra do PowerShell tự tạo có thể bị tính như bằng chứng bổ sung. Nhật ký Agent cũng có trường hợp ghi nhãn EID1 cố định cho sự kiện thuộc loại khác; cần hiệu chỉnh để tránh gây hiểu nhầm khi đánh giá.
- Phụ thuộc vào dịch vụ AI trên máy chính: Agent trong VMware đã tự khởi động, nhưng LM Studio hiện vẫn phải được bật thủ công. Khi mô hình chưa chạy, việc suy luận AI chưa thể thực hiện ngay.
Tóm tắt tiến độ: Tuần 4 đã hoàn thành phần tự động khởi động Agent, thu thập Sysmon và kết nối suy luận với Qwen. Hai nội dung quan trọng chưa hoàn thành là huấn luyện/tinh chỉnh AI riêng và xác minh thực nghiệm khả năng tự động kết thúc tiến trình thật.