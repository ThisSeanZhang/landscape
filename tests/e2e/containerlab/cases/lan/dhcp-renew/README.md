# LAN 客户端续租 DHCPv4

本场景已在临时实验中验证，仓库内的自动化入口待补。它复用单 WAN 接线，针对已有租约的续租行为。[单 WAN 拓扑](../../../single-wan/README.md) · [Issue #25](https://github.com/ThisSeanZhang/landscape/issues/25)

1. 从无地址的 LAN 节点启动常驻 `udhcpc`。首次获租后保持客户端进程和 MAC，记录地址和 Landscape API 中的租约到期时间。首次获租用例使用的 `-q` 参数会让客户端在获租后退出。[BusyBox 参数](https://busybox.net/BusyBox.html)
2. 向同一进程发送 `SIGUSR1` 触发续租，在 LAN 链路观察 DHCPREQUEST 和 DHCPACK。
3. 按同一 MAC 再查租约，检查地址保持一致、到期时间后移，并从客户端访问 WAN 验证连通性。[HTTP/NAT 检查](../../../single-wan/check-forward.sh)

2026-11-18 使用 Robot Framework 7.5.1 驱动实验。抓包观察到 DHCPREQUEST → DHCPACK，服务端延长了原地址的租约，随后 HTTP/NAT 检查通过。
