# Dựng mạng cho mini SOC lab phát hiện ARP poisoning

Trạng thái: bản nháp; phase 1 chưa nghiệm thu. Chưa đăng bài.

## 1. Mục tiêu và phạm vi

Xây dựng mạng VMware có Client, Kali, Router riêng và Web server riêng để chuẩn bị cho các bước thu thập dữ liệu và điều tra sau này. Phase 1 chưa chạy MITM và chưa cài Splunk.

## 2. Mô hình đã chọn

Client 10.10.10.10 và Kali 10.10.10.20 nằm trên LAB-LAN.
Router nối LAB-LAN bằng 10.10.10.1 và LAB-SERVER bằng 10.10.20.1.
Web 10.10.20.10 nằm trên LAB-SERVER; Splunk 10.10.20.20 được bổ sung ở phase 4.

Hai LAN được định tuyến qua Router, không NAT giữa hai LAN. Các địa chỉ trên là thiết kế, chưa được nghiệm thu.

## 3. Chuẩn bị thực tế

Đã kiểm kê VM và ISO trước khi tạo mới. Kali đang dùng NAT; MAC trong guest khớp cấu hình VMware. Ảnh kiểm tra guest xác nhận Ubuntu Server 24.04.5, hostname lab, ens33 có MAC khớp VMware, IP NAT 192.168.35.130/24 và gateway 192.168.35.2. Disk đã cài là 30G; giữ nguyên cho Router thay dự kiến 20 GB. Root filesystem còn 20G; thời gian UTC, NTP hoạt động và đồng hồ được báo đã đồng bộ. [Ảnh bằng chứng](../../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-ubuntu-server-before.png). Quyết định không dùng snapshot Kali để tiết kiệm dung lượng; ghi cấu hình trước/sau mỗi thay đổi.

## 4. Các bước triển khai

Đã đổi hostname Ubuntu thành soc-router và kiểm tra ánh xạ cục bộ 127.0.1.1. tcpdump 4.99.4/curl 8.5.0 đã có và chạy được; lệnh APT không cài thêm gói. [Đầu ra qua SSH](../../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-router-hostname-tools.txt).

Ghi nhận khi chuẩn bị: cp -n phát cảnh báo về tính tương thích; chuyển hướng dẫn tương lai sang --update=none. Bản sao cần kiểm tra đầy đủ trước khi sửa Netplan. Người dùng đang SSH nên bước đổi mạng sẽ dùng console VMware để không phụ thuộc kết nối NAT.

Bổ sung sau khi thực hiện: chuẩn bị soc-router, cài Client/Web, tạo LAN Segment, cấu hình IP/route/forwarding/firewall. Dùng nhật ký làm nguồn, không viết như đã hoàn tất.

Card thứ hai ens37 đã xuất hiện trong guest với MAC 00:0c:29:8b:86:82. Ở mốc kiểm tra này, ens37 còn DOWN/chưa có IPv4 và chưa nằm trong Netplan; ens33 vẫn dùng NAT. Các mục sao lưu hostname/hosts/netplan đã thấy đầy đủ, UFW inactive. [Ảnh kiểm tra](../../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-router-two-interfaces.png). Chưa xác minh LAN Segment qua ảnh Settings hoặc cấu hình IP lab.

## 5. Kiểm chứng

Chưa có kết quả. Sẽ bổ sung:
- Client truy cập Web qua Router.
- Capture ở hai card Router xác nhận đường đi.
- Access log Web thấy nguồn 10.10.10.10.
- Sau reboot, IP/route/forwarding/HTTP vẫn đúng.

## 6. Lỗi đã gặp và bài học

Điền lỗi thực tế, bước tìm nguyên nhân, cách sửa và bằng chứng kiểm tra lại. Không cần tạo lỗi giả để làm bài viết dài hơn.

## 7. Kết quả và giới hạn

Chỉ hoàn thiện phần này khi có kiểm thử thực tế. Thành công của phase 1 là dựng mạng và xác minh đường đi; chưa phải kết quả phát hiện MITM.

Nguồn nội bộ: [nhật ký](../journal.md) và [tiến độ gốc](../../../../ChatGPT/SOC/mitm-soc-lab/phase-1/progress.md).