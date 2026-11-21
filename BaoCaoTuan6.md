# BÁO CÁO TIẾN ĐỘ TUẦN 6

1. Những công việc đã thực hiện trong tuần
Trong tuần 6, nhóm tập trung hoàn thiện và kiểm thử cơ chế phát hiện, tạm dừng và xử lý các tiến trình nghi ngờ trên Windows. Mục tiêu chính là đảm bảo các thành phần của hệ thống hoạt động đúng trước khi tiến hành huấn luyện và tối ưu mô hình AI chuyên biệt.
1.1. Hoàn thiện cơ chế phát hiện và tạm dừng tiến trình
Nhóm tiếp tục phát triển cơ chế phát hiện hai giai đoạn gồm FAST_RULE và SLM. Khi Sysmon ghi nhận tiến trình có hành vi đáng ngờ, FAST_RULE sẽ phân tích nhanh các dấu hiệu trong command line và thực hiện Suspend tiến trình trước khi chuyển dữ liệu cho AI.
Cơ chế này giúp hạn chế việc tiến trình tiếp tục thực thi trong thời gian mô hình AI phân tích và đưa ra quyết định.
Qua kiểm thử thực tế, hệ thống đã Suspend thành công các tiến trình PowerShell trong bài Atomic Red Team T1059.001 #19.
1.2. Nâng cấp khả năng thu thập và phân tích bằng chứng
Nhóm bổ sung cơ chế thu thập PowerShell Script Block Logging (Event ID 4104), kết hợp với dữ liệu Sysmon nhằm cung cấp thêm thông tin cho mô hình SLM.
Các thông tin gửi đến AI bao gồm PID, ProcessGuid, command line, mã FAST_RULE, trạng thái tiến trình và các bằng chứng liên quan.
Trong quá trình nâng cấp, nhóm đã sửa lỗi xử lý Windows Event Log khiến việc thu thập EID 4104 bị gián đoạn. Sau khi khắc phục, hệ thống đã liên kết thành công 2 sự kiện EID 4104 với tiến trình đang được phân tích.
1.3. Hoàn thiện cơ chế xử lý tiến trình
Nhóm kiểm tra các chức năng Suspend, Resume và Kill thông qua bộ điều khiển TwoStageController.
Hệ thống được thiết kế để chỉ tiêu diệt tiến trình khi nhận được phán quyết hợp lệ và xác minh được danh tính tiến trình. Nếu AI không xác định đủ bằng chứng nguy hiểm, hệ thống sẽ Resume để tránh ảnh hưởng đến hoạt động hợp pháp.
Nhóm xây dựng bộ Verification11 nhằm kiểm thử độc lập ba nhánh xử lý:

- Suspend → Resume đối với tiến trình được xác định là an toàn.
- Từ chối Kill khi phán quyết không đáp ứng điều kiện bảo vệ.
- Suspend → Kill → xác minh tiến trình thực sự kết thúc.

Kết quả: cả 3/3 nhánh kiểm thử đều PASS. Trong đó, nhánh Kill đã thực hiện kết thúc một tiến trình Windows thật và xác minh thành công trạng thái `TERMINATED_VERIFIED`.
Bộ kiểm thử này sử dụng phán quyết giả lập để kiểm tra cơ chế xử lý, chưa phải kết quả Kill do mô hình AI thật phê duyệt.

1.4. Tích hợp và kiểm thử với Atomic Red Team

Nhóm xây dựng bộ Verification10 Atomic-Only, sử dụng hoàn toàn các bài kiểm thử nguyên bản của Atomic Red Team, không thay đổi nội dung kịch bản. Các kỹ thuật được sử dụng gồm T1059.001, T1057 và T1082. Nhóm phân chia kịch bản mô phỏng tấn công và các thao tác quản trị hợp pháp để đánh giá khả năng phát hiện cũng như hạn chế báo nhầm. Kết quả đã thực hiện 9 lượt kiểm thử trên 5 kịch bản Atomic. Trong đó, 6 lượt đối chứng lành tính được ghi nhận là âm tính đúng (TN), chưa ghi nhận trường hợp dương tính giả (FP) trong tập đối chứng này. Thời gian đến khi Hold trung vị đo được là 1.082,56 ms trên 2 mẫu quan sát hợp lệ. Đối với các tiến trình chạy quá nhanh, nhóm tiếp tục ghi nhận và nghiên cứu chỉ số Completed Before Hold.
 2. Khó khăn và các vấn đề gặp phải
2.1. Mô hình SLM chưa được huấn luyện chuyên biệt cho Fileless Malware 
Hiện tại, hệ thống đang sử dụng mô hình Qwen 2.5 Coder 3B thông qua LM Studio trên máy Host để phân tích các hành vi nghi ngờ. Tuy nhiên, đây là mô hình ngôn ngữ tổng quát, chưa được fine-tune chuyên biệt trên dữ liệu fileless malware của đề tài. Do đó, khả năng phân biệt giữa hoạt động quản trị hợp pháp và các hành vi tấn công còn hạn chế. Trong bài kiểm thử Atomic Red Team T1059.001 #19, hệ thống đã phát hiện và Suspend thành công tiến trình thực thi PowerUp. Mô hình AI cũng nhận được bằng chứng từ Sysmon và PowerShell EID 4104. Tuy nhiên, mô hình vẫn đưa ra quyết định `LOG_ONLY` thay vì `KILL_PROCESS`, với nhận định rằng hành vi tải và thực thi PowerShell từ xa có dấu hiệu đáng ngờ nhưng chưa đủ căn cứ để khẳng định mục đích độc hại. Điều này cho thấy mô hình có khả năng nhận diện những dấu hiệu rủi ro, nhưng chưa đưa ra được quyết định xử lý dứt khoát trên các kịch bản mô phỏng tấn công. Đồng thời, PowerUp cũng có thể được sử dụng trong kiểm thử bảo mật hợp pháp, nên không thể mặc định quyết định Resume của AI là sai.
2.2. Thời gian phân tích của AI còn tương đối lớn
Trong các lần kiểm thử, mô hình SLM cần khoảng 2–4 giây để đưa ra phán quyết. Đây là khoảng thời gian tương đối lớn đối với các tiến trình độc hại có thời gian thực thi ngắn.
Mặc dù FAST_RULE đã được thiết kế để Suspend trước khi gọi AI, hệ thống vẫn gặp khó khăn nếu sự kiện Sysmon đến sau khi tiến trình đã kết thúc. Điển hình, trong bài Atomic T1059.001 #10, một số tiến trình chỉ tồn tại khoảng 240–426 ms, trong khi thời gian từ lúc tạo sự kiện đến khi hệ thống nhận được có thể vượt quá 1 giây. Vì vậy, việc phát hiện và tạm dừng không phải lúc nào cũng kịp thời. Đây là hạn chế của cơ chế thu thập sự kiện sau khi tiến trình đã bắt đầu thực thi.
2.3. Chưa có kết quả Kill được phê duyệt bởi SLM thật
Mặc dù nhóm đã chứng minh cơ chế Suspend, Resume và Kill hoạt động đúng thông qua Verification11, hệ thống chưa ghi nhận được một trường hợp hoàn chỉnh mà mô hình SLM thật phê duyệt `KILL_PROCESS` và agent xác minh Kill thành công trên cùng ProcessGuid. Nguyên nhân hiện tại không phải do bộ điều khiển không thể Kill, mà chủ yếu do mô hình AI chưa đưa ra phán quyết Kill hợp lệ trong những bài kiểm thử mà tiến trình được Suspend thành công.Do đó, nhóm chưa thể kết luận hệ thống đã phát hiện và tiêu diệt fileless malware hoàn toàn tự động với độ chính xác đạt yêu cầu.
2.4. Phương hướng khắc phục**
Trong giai đoạn tiếp theo, nhóm dự kiến tập trung xây dựng và fine-tune một mô hình SLM chuyên biệt cho bài toán phát hiện fileless malware trên nền tảng Qwen 2.5 3B. Nhóm sẽ chuẩn hóa dữ liệu huấn luyện, kiểm tra nhãn của các hành vi độc hại và lành tính, đồng thời đánh giá mô hình bằng các chỉ số Precision, Recall, F1-score, False Positive Rate và thời gian suy luận. Sau khi hoàn thiện mô hình, nhóm sẽ tích hợp lại vào hệ thống hiện tại và thực hiện kiểm thử để so sánh hiệu quả trước và sau huấn luyện.
Kết luận tuần 6: Nhóm đã hoàn thiện và kiểm chứng các chức năng cốt lõi của hệ thống phòng vệ ở mức cơ chế. Khó khăn lớn nhất hiện nay nằm ở chất lượng phán quyết của mô hình SLM và độ trễ phát hiện đối với các tiến trình tồn tại trong thời gian ngắn. Vì vậy, nhóm quyết định giữ ổn định kiến trúc hiện tại và chuyển trọng tâm sang huấn luyện, tối ưu mô hình AI chuyên biệt cho fileless malware trong giai đoạn tiếp theo.