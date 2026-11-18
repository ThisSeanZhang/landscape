# LAN 客户端续租 DHCPv4

从仓库根目录运行 `just e2e-lan-dhcp-renew`。用例使用单 WAN 拓扑，验证已有租约的续租行为。[单 WAN 拓扑](../../../topologies/lan/single-wan/README.md) · [Issue #25](https://github.com/ThisSeanZhang/landscape/issues/25)

1. 从无地址的 LAN 节点启动常驻 `udhcpc`。首次获租后保持客户端进程和 MAC，记录地址和 Landscape API 中的租约到期时间。首次获租用例使用的 `-q` 参数会让客户端在获租后退出。[BusyBox 参数](https://busybox.net/BusyBox.html)
2. 向同一进程发送 `SIGUSR1` 触发续租，在 LAN 链路观察 DHCPREQUEST 和 DHCPACK。
3. 按同一 MAC 再查租约，检查地址保持一致、到期时间后移，并从客户端访问 WAN 验证连通性。[HTTP/NAT 检查](../../../lib/check-forward.sh)

2026-11-18 运行通过。客户端续租后保留 `192.0.2.140`，服务端记录的到期时间比首次获租时晚 988 毫秒，随后 WAN 收到来自路由器 NAT 地址的 HTTP 请求。
