# SOC lab — tài liệu thực hành và blog

Tạo ngày 2026-09-28 theo yêu cầu của người dùng.

Thư mục: C:\Users\KH4NG\Documents\HTB\Lab\mitm-soc-lab

## Dùng thư mục này thế nào

- journal.md: nhật ký ngắn sau mỗi buổi hoặc mốc kiểm tra.
- blog/phase-1-draft.md: bản nháp bài viết phase 1, hoàn thiện sau nghiệm thu.
- evidence/: ảnh, đầu ra lệnh, log và PCAP được chọn để minh họa bài viết.
- configs/: bản cấu hình mẫu hoặc bản sao trước/sau thay đổi cần giữ.

Hồ sơ thiết kế và file tiến độ gốc vẫn ở C:\Users\KH4NG\Documents\ChatGPT\SOC\mitm-soc-lab. Tiếp tục cập nhật duy nhất [phase-1/progress.md](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/progress.md) cho checklist và bước tiếp theo; không tạo bản progress thứ hai ở đây.

Ảnh Kali đã có được lưu tại [bằng chứng phase 1](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-kali-network-before.png), không cần nhân đôi.

## Quyết định hiện tại

- Không dùng snapshot Kali theo yêu cầu người dùng để tiết kiệm dung lượng.
- Bài làm HTB nằm trên Windows tại C:\Users\KH4NG\Documents\HTB.
- Người dùng xác nhận Ubuntu Server đã cài xong; tiếp theo kiểm tra guest và chuẩn bị máy này làm soc-router.
- Giữ Client và Kali trên LAB-LAN 10.10.10.0/24; Router nối sang LAB-SERVER 10.10.20.0/24; Web server riêng. Splunk đến phase 4.
- Chưa kiểm thử mạng lab; không ghi ping/HTTP thành công trước khi có kết quả.
- Không lưu mật khẩu, private key hoặc file VPN có thông tin bí mật vào nội dung blog.

VM và ISO giữ ở vị trí hiện có, không chép vào thư mục viết bài. Chưa có thao tác commit, push hoặc đăng blog.

Hướng dẫn thực hành tiếp theo: [đặt IP card phía Server của Router bằng tay](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/02-router-server-interface.md), có giải thích, kiểm tra và khôi phục. Xem progress gốc để biết bước nào đã thực hiện.
