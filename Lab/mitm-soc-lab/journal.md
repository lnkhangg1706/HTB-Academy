# Nhật ký SOC lab

Ghi ngắn sau mỗi mốc: đã làm gì, vì sao, kết quả thật và bằng chứng. Chỉ cần vài dòng; lỗi và cách sửa cũng là nội dung có ích cho bài viết.

## 2026-09-28 — Kiểm kê và chuẩn bị Router

**Mục tiêu:** tận dụng Kali hiện có và Ubuntu Server đã cài để bắt đầu phase 1.

**Đã xác minh:**
- Kali Rolling 2026.3; eth0; MAC 00:0c:29:93:b3:e8 khớp VMware.
- Mạng Kali hiện tại là NAT: 192.168.35.129/24, gateway 192.168.35.2, profile Wired connection 1.
- Ảnh không cho thấy interface VPN hoặc PID OpenVPN.
- File VMX Ubuntu Server: 2 vCPU, 4 GiB RAM, một card NAT, MAC 00:0c:29:8b:86:78.
- Người dùng xác nhận Ubuntu Server đã cài xong; phiên bản OS, interface và disk trong guest chưa có kết quả lệnh.
- Bài làm HTB lưu trên Windows. Người dùng chọn không dùng snapshot Kali.

**Quyết định:** dự kiến dùng Ubuntu Server hiện có làm soc-router. Giữ Web server riêng; chưa đổi tên, phần cứng hoặc mạng VM.

**Bằng chứng:** [ảnh Kali](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-kali-network-before.png) và [progress gốc](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/progress.md).

**Bước tiếp theo:** chạy lệnh đọc trạng thái trong console Ubuntu Server; đối chiếu phiên bản, MAC, mạng NAT, disk và giờ trước khi cấu hình.

## 2026-09-28 — Đã kiểm tra guest Ubuntu Server

**Thời điểm trên ảnh:** 10:04:10 UTC. Đây là đầu ra người dùng chạy, không phải kiểm thử do trợ lý thực hiện trực tiếp.

**Kết quả:** Ubuntu 24.04.5 LTS; hostname lab; ens33 UP, MAC 00:0c:29:8b:86:78 khớp VMware; IP NAT 192.168.35.130/24; default gateway 192.168.35.2 qua DHCP. Disk sda hiển thị 30G, root LVM 28G; đã dùng 6.4G, còn 20G (25%). Timezone Etc/UTC, NTP active và system clock synchronized=yes.

**Quyết định:** giữ disk 30G đã cài cho Router; không thu nhỏ về dự kiến 20 GB. Tổng trần disk ba Ubuntu VM phase 1 cập nhật thành 85 GB, chưa tính Kali. Giữ mô hình hai LAN, Router và Web riêng.

**Bằng chứng:** [ảnh console Ubuntu](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-ubuntu-server-before.png).

**Bước tiếp theo đã hướng dẫn, chưa xác nhận thực hiện:** lưu bản cấu hình nhỏ trong /root/phase1-before; đổi hostname thành soc-router và cập nhật /etc/hosts; cài tcpdump/curl khi còn NAT; gửi kết quả hostname/getent/phiên bản công cụ để kiểm tra. Chưa đổi IP, thêm card hoặc bật forwarding.

## 2026-09-28 — Hostname/công cụ đã kiểm tra qua SSH

Người dùng xác nhận đang kết nối SSH và gửi đầu ra: hostname soc-router, getent trả 127.0.1.1 soc-router, tcpdump 4.99.4 và curl 8.5.0 chạy được. APT báo hai gói đã có sẵn; không cài mới/nâng cấp/xóa gói trong lượt này.

Lệnh cp -an phát cảnh báo về tính tương thích của -n, không phải thông báo lỗi sao chép. Phần ls bản sao được gửi chỉ có “hostname  host”, nên chưa đánh dấu bản sao đầy đủ. Hướng dẫn lần sau dùng --update=none; không ghi đè bản cũ bằng trạng thái sau đổi hostname.

Bằng chứng: [đầu ra người dùng](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-router-hostname-tools.txt).

Bước kế tiếp đã hướng dẫn, chưa thực hiện được xác nhận: poweroff, đổi tên VMware thành soc-router, RAM 2 GB / 1 vCPU, thêm card LAB-SERVER; tạm giữ card đầu NAT để SSH tiếp. Sau khởi động, đọc interface/MAC, Netplan/UFW và kiểm tra bản sao. Khi thực sự chuyển NAT sang LAB-LAN, dùng console VMware vì đường SSH NAT sẽ không còn được bảo đảm. Trạng thái cuối vẫn hai card LAB-LAN/LAB-SERVER, không thêm card quản trị.

## 2026-09-28 — Hai interface Router đã xuất hiện

Nguồn: [ảnh console người dùng](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-router-two-interfaces.png). Chỉ đọc ảnh và cập nhật tài liệu; không có thao tác kiểm kê/triển khai tự động trên host hoặc VM.

Đã thấy tên VMware và hostname soc-router. ens33 UP, MAC 00:0c:29:8b:86:78, IP NAT 192.168.35.130/24, gateway 192.168.35.2. Card mới ens37 có MAC 00:0c:29:8b:86:82, DOWN và chưa có IPv4. Netplan gộp chỉ có ens33/dhcp4=true; ens37 chưa được khai báo.

Danh sách sao lưu hiện đầy đủ hostname, hosts và netplan/50-cloud-init.yaml; chưa so sánh nội dung byte. UFW inactive; không tự tắt firewall. Chưa biết các ruleset khác hoặc trạng thái forwarding.

Chưa có ảnh Settings để xác nhận 1 vCPU/2 GB và ánh xạ LAB-SERVER. Bước kế tiếp là người dùng đối chiếu Settings, đọc file Netplan nguồn/cloud-init/nftables/forwarding; sau đó mới hướng dẫn đặt IP tĩnh. Card đầu vẫn giữ NAT lúc đọc cấu hình, việc đổi mạng sẽ làm từ console VMware.

## 2026-09-28 — Đối chiếu phần cứng và MAC trong VMware

[Ảnh Settings do người dùng gửi](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-router-vmware-settings.png) cho thấy Router có RAM 2 GB, 1 vCPU, disk 30 GB. Card đầu NAT; card thứ hai ở chế độ LAN Segment, Connected/Connect at power on được chọn. MAC 00:0C:29:8B:86:82 trong Advanced khớp ens37 trong Linux.

Tên LAN Segment đang bị cửa sổ Advanced che, chưa xác nhận LAB-SERVER. Chờ người dùng kiểm tra tên segment và gửi đầu ra Netplan nguồn/cloud-init/firewall/forwarding. Chưa đổi IP hoặc khai báo ens37 trong YAML. Trợ lý chỉ ghi tài liệu từ ảnh, không thao tác VMware.

## 2026-09-28 — Đã đọc nguồn Netplan và trạng thái forwarding

[Ảnh người dùng gửi](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-router-netplan-firewall-before.png) cho thấy /etc/netplan chỉ có 50-cloud-init.yaml với ens33/dhcp4=true; /run/netplan không tồn tại, /lib/netplan chỉ có PLACEHOLDER. grep phát hiện mục network trong 90-installer-network.cfg; chưa đọc toàn bộ file đó. nft list ruleset không in rule; net.ipv4.ip_forward=0.

Đã soạn [hướng dẫn thủ công đặt IP card phía Server](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/02-router-server-interface.md), gồm lưu cấu hình, YAML, giải thích, kiểm tra và khôi phục. Mục tiêu kế tiếp là ens37=10.10.20.1/24, tạm giữ ens33 NAT/DHCP và forwarding=0. Người dùng phải kiểm tra card 2 thực sự chọn LAB-SERVER trước khi áp dụng. Chưa có kết quả đã sửa YAML hoặc đã chấp nhận netplan try.

Trợ lý chỉ cập nhật tài liệu từ bằng chứng; mọi thao tác cấu hình sẽ do người dùng thực hiện.

## 2026-09-28 — Bản sao Netplan đã đối chiếu

[Ảnh người dùng](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-28-router-backup-compared.png) cho thấy 90-installer-network.cfg do Subiquity ghi, chỉ khai báo ens33 DHCP với network version 2. Lệnh cp --update=none sao lưu file này không báo lỗi; chưa so sánh bản sao cloud-init.

Lần cmp đầu gõ nhầm 50cloud-init.yaml, thiếu dấu gạch nối sau 50, nên không tìm thấy file. Người dùng đã sửa thành 50-cloud-init.yaml và chạy lại; cmp không in gì, xác nhận Netplan hiện tại giống bản sao. Không cần tạo lại bản sao Netplan vì lỗi gõ đã được xử lý.

Tiếp theo: người dùng kiểm tra LAB-SERVER, tự thêm file tắt riêng cloud-init network, sửa YAML để ens37=10.10.20.1/24 và chạy netplan generate. Chưa có bằng chứng đã sửa cấu hình hoặc áp dụng IP; ens33 vẫn giữ NAT theo kế hoạch. Trợ lý chỉ cập nhật tài liệu từ ảnh.

## 2026-09-29 — YAML đúng và netplan generate không báo lỗi

[Ảnh do người dùng gửi](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-router-netplan-generated.png) xác nhận nội dung file cloud-init riêng là network/config=disabled. Netplan dùng version 2, renderer networkd; ens33 vẫn dhcp4=true, ens37 dhcp4=false với địa chỉ 10.10.20.1/24. Lệnh chmod 600 và netplan generate không báo lỗi.

Đã hoàn thành ghi cấu hình và tạo backend; chưa có bằng chứng IP/route đang hoạt động hoặc đã chạy netplan try. Chưa kiểm thử đường đi giữa Client và Web. Tên segment LAB-SERVER vẫn cần kiểm tra trong Settings; giữ nguyên mô hình hai LAN và không dùng snapshot Kali.

Bước kế tiếp do người dùng tự làm: mở sẵn SSH, kiểm tra card 2 LAB-SERVER/card đầu NAT, chạy netplan try --timeout 180 từ console VMware. Trong lúc chờ, kiểm tra ip -br addr, ip -4 route và ip route get 10.10.20.10 qua SSH; nếu đúng thì quay lại console nhấn Enter trong thời hạn. Sau đó gửi kết quả. Trợ lý chỉ lưu bằng chứng/tài liệu.

## 2026-09-29 — SSH thiếu tên tài khoản Ubuntu

[Ảnh lỗi SSH](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-ssh-wrong-username.png): lệnh ssh 192.168.35.130 dùng username kh4ng và nhận Permission denied. Tài khoản trong Ubuntu đã biết là khang. Hướng dẫn người dùng Ctrl+C, chạy ssh khang@192.168.35.130 tại PowerShell, nhập mật khẩu của khang trên Ubuntu. Chưa có kết quả sau sửa username; chưa kết luận mật khẩu khang sai. Chờ mở được SSH rồi tiếp tục netplan try. Trợ lý chỉ ghi tài liệu, không thử đăng nhập hoặc đổi cấu hình SSH.

## 2026-09-29 — SSH thành công bằng khang

Người dùng chạy ssh khang@192.168.35.130 và vào được prompt khang@soc-router. Banner ghi Ubuntu 24.04.5 LTS, kernel 6.8.0-142-generic, ens33=192.168.35.130; thông tin hệ thống lúc 12:21:35 UTC. Vấn đề chọn username kh4ng trước đó đã được xử lý; không cần suy ra trùng IP từ lỗi xác thực. Chưa kiểm tra trùng IP toàn mạng.

Bằng chứng: [trích đoạn terminal](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-router-ssh-success.txt). Giữ phiên SSH đã mở để kiểm tra trong lúc người dùng chạy netplan try tại console VMware. Chưa có bằng chứng áp dụng IP ens37 hoặc kết quả route. Trợ lý chỉ cập nhật tài liệu.

## 2026-09-29 — ens37 có IP và route đúng

[Đầu ra người dùng](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-router-ens37-runtime.txt) xác minh ens37 UP/10.10.20.1/24 và route trực tiếp 10.10.20.0/24; ens33 vẫn UP/192.168.35.130/24, default qua 192.168.35.2. Route get tới 10.10.20.10 chọn ens37/source 10.10.20.1. Tra cứu tới chính địa chỉ Router 10.10.20.1 trả local/dev lo là đúng, không phải lỗi.

Đã đạt kiểm tra IP/route ở thời điểm gửi, chưa chứng minh kết nối tới máy Web. Còn chờ người dùng xác nhận đã nhấn Enter chấp nhận netplan try và tên segment LAB-SERVER. Đã nhắc nhấn Enter ngay nếu console còn chờ; nếu đã hết hạn thì kiểm tra trạng thái thực tế trước khi tiếp tục. Chưa kiểm tra sau reboot hoặc nghiệm thu mạng toàn lab. Trợ lý chỉ ghi bằng chứng/tài liệu.

## 2026-09-29 — Try đã chấp nhận, kiểm tra job cũ

[Ảnh console](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-netplan-accepted-stopped-job.png) xác nhận lượt cuối báo Configuration accepted. Trước đó có [1]+ Stopped cho một lượt try, thông báo restoring/netplan-try.ready ở lần gọi tiếp theo và một lượt hết hạn/Reverting. Ảnh chưa chứng minh job cũ đã kết thúc; không tự kết luận YAML sai từ lỗi restoring vì generate trước đó đã thành công.

Bước kế tiếp chỉ đọc, do người dùng tự làm: jobs -l trong chính shell console VMware đã chạy try; ip -br addr, ip -4 route và sudo netplan get trong SSH. Mục đích là xem job cũ còn hay không và xác minh cấu hình sau lần chấp nhận cuối. Chưa hướng dẫn xóa marker hoặc chạy thêm try/apply. Chưa kiểm tra sau reboot, kết nối Web hay tên LAB-SERVER. Trợ lý chỉ cập nhật tài liệu và lưu ảnh.

## 2026-09-29 — Job 1/PID 1000 còn Stopped, mạng và YAML đúng

[Ảnh jobs](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-netplan-job1-stopped.png) xác minh job số 1, PID hiển thị 1000, còn Stopped với lệnh sudo netplan try --timeout 180. [Đầu ra SSH](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-netplan-job1-current-network.txt) xác minh ens33 NAT/DHCP .130/default .2 và ens37 UP/10.10.20.1/24/route trực tiếp; Netplan gộp đúng version 2, networkd, ens33 DHCP và ens37 tĩnh.

Đã soạn hướng dẫn mục 6B: người dùng chạy fg %1 trong đúng console để tiếp tục lượt cũ; để nó hết hạn/hoàn tác hoặc Ctrl+C một lần nếu còn hỏi xác nhận, chờ prompt. Sau đó kiểm tra jobs và YAML; chỉ khi job đã kết thúc, YAML đúng và generate không lỗi mới apply rồi kiểm tra IP/route. Mọi thao tác do người dùng thực hiện, chưa có kết quả xử lý. Không đoán PID con hoặc xóa marker. Chưa xác nhận tên LAB-SERVER/kiểm thử sau reboot/mạng toàn lab.

## 2026-09-29 — Apply và kiểm tra mạng đã đạt

[Ảnh mới](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-netplan-applied-jobs-empty.png): jobs -l không in gì trong shell hiện tại; netplan get đúng; generate/apply không lỗi. Sau apply, ens33 UP/NAT .130/default .2, ens37 UP/10.10.20.1/24 và route trực tiếp đúng. Đã ghi nhận bước áp dụng thành công, không yêu cầu lặp lại.

Ảnh có banner đăng nhập mới, không có đoạn fg hoặc bằng chứng reboot; jobs trống chỉ phản ánh shell hiện tại. Bước ngắn còn lại: người dùng chạy pgrep -af '[n]etplan.*try' trên soc-router và xác nhận card 2 là LAB-SERVER. Khi rõ hai điểm này, chuyển sang dựng soc-web riêng theo mô hình đã chốt. Trợ lý chỉ lưu bằng chứng/tài liệu, chưa thực hiện kiểm tra guest hoặc tạo VM.

## 2026-09-29 — Hoàn tất IP ens37/LAB-SERVER, chuyển sang tạo Web

Người dùng xác nhận pgrep không có kết quả, sau đó trả lời riêng rằng Network Adapter 2 của Router đã chọn LAB-SERVER. Kết hợp bằng chứng apply/IP/route trước đó, hoàn tất bước card phía Server: ens37 10.10.20.1/24 trên LAB-SERVER; không còn tiến trình try được tìm thấy. ens33 vẫn NAT .130/default .2, chưa chuyển LAB-LAN hoặc bật forwarding. Chưa kiểm tra sau reboot; không coi toàn phase 1 đã hoàn thành.

Đã soạn [hướng dẫn tạo soc-web bằng tay](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/03-create-soc-web.md): 1 vCPU/2 GB/25 GB, NAT tạm, dùng lại ISO Server 24.04.5 trên E. Người dùng kiểm tra dung lượng C, tạo VM mới tại Virtual Machines/soc-web và gửi Settings trước khi cài OS. Chưa có bằng chứng đã tạo Web. Trợ lý chỉ soạn tài liệu, không thao tác VMware hoặc tự động hóa cài đặt.

## 2026-09-29 — Settings Web đúng, C còn 110 GB; chuẩn bị cài Ubuntu

[Ảnh Settings người dùng gửi](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/evidence/2026-09-29-soc-web-settings.png) cho thấy RAM 2048 MB/2 GB, Processors 1, disk SCSI 25 GB và một card NAT. Các thông số khớp thiết kế Web. ISO chỉ thấy tiền tố E:\ubuntu-24.04.5...; tên VM/đường dẫn VM và tên ISO đầy đủ không hiện trong ảnh, nên người dùng cần đối chiếu đúng soc-web và live-server-amd64.iso trước khi cài.

Người dùng báo ổ C trống **110 GB**. Đây là số liệu người dùng cung cấp, không phải phép đo mới của trợ lý. Đủ mốc 25 GB disk Web và 25 GB dự phòng cho bước này; chưa phải bảo đảm dung lượng cho toàn bộ lab.

Đã soạn [hướng dẫn cài Ubuntu Server cho soc-web](../../../ChatGPT/SOC/mitm-soc-lab/phase-1/04-install-soc-web.md): giữ DHCP NAT trong lúc cài, dùng disk mới 25 GB, hostname soc-web, username khang, cài OpenSSH, reboot và đọc OS/IP/route/disk/giờ. Chưa có bằng chứng cài OS hoặc lưu Settings bằng OK. Nginx và IP LAB-SERVER sẽ làm ở mốc sau. Trợ lý chỉ lưu ảnh và tài liệu, không thao tác VMware/host/guest.

## Mẫu cho mốc tiếp theo

- Ngày/giờ và VM:
- Mục tiêu / lý do:
- Thao tác hoặc lệnh:
- Kết quả thực tế:
- Đường dẫn ảnh/log/cấu hình:
- Lỗi và cách xử lý (nếu có):
- Bước kế tiếp:

Khi bắt đầu các lần kiểm thử lưu lượng, thêm run_id và thời gian UTC để liên kết log với PCAP.








