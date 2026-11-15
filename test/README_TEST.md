# Ket qua kiem thu DACN

Dot ket qua nguon: atomic_e2e_20261115_174723
Thoi diem dong goi: 2026-11-15 18:59:15

- summary_final.json: TP, FP, TN, FN, mau du dieu kien va bi loai, thoi gian Hold, EID1/EID5.
- case_results.csv va case_evidence.csv: ket qua / bang chung theo tung luot (neu co).
- BAO_CAO_NGHIEM_THU_CUOI.md: tong hop cho bao cao do an (neu co).
- execution_summary.csv: thong tin thuc thi Atomic/benign (neu co).

LUU Y KHOA HOC:
- TP=0, FN=0 khi khong co mau duong tinh hop le KHONG chung minh recall=100%.
- EID5 chung minh tien trinh ket thuc, khong tu dong chung minh payload Atomic hoan tat.
- Suspend nham Fast Rule khac voi SLM phan loai sai.
- Defender can thiep can duoc ghi rieng, khong tinh la DACN da ngan chan.
- Khong co KILL_PROCESS duoc chung minh trong dot thi khong tuyen bo terminate malware thanh cong.

Da loai log/raw audit/ban ghi Sysmon va Defender tho, run_*.txt, database, khoa va tai khoan.
Ket qua neu muon truy vet day du can luu ZIP EVIDENCE rieng.