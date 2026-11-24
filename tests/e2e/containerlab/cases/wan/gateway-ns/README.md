# Ethernet WAN 网关 NS

从仓库根目录运行 `just e2e-wan-gateway-ns`。用例使用单 WAN 拓扑，由 WAN 对端的 scapy DHCPv6-PD 应答器分配 `2001:db8:1000::/56`，并在 WAN 侧抓取 NS/NA 和从 LAN 发出的 UDP 探针。委派前缀的 LAN 侧使用 `2001:db8:1000:1::/64`；PD 应答器以 WAN 链路的链路本地地址作为源（该地址同时是 NS 探测的网关和路由器主动探测的源地址）。[单 WAN 拓扑](../../../topologies/lan/single-wan/README.md)

与 [gateway-arp](../gateway-arp/README.md) 对应，验证 IPv6 一侧：

1. 通过 WAN Link API 打开 PD。观察路由器发出的 NS 和网关应答，核对 TC egress root 的 `confirmed_gateway_mac6`。路由器的静态邻居表给网关植入了另一个 MAC，从 LAN 发往网段外的 UDP 探针必须使用主动探测确认的 MAC，而不是邻居回退。
2. 从对端移除网关地址，观察连续两次没有应答的 NS，核对转发仍使用最后确认的 MAC。
3. 通过 API 关闭 PD，核对新 root 中的 MAC 归零；恢复对端地址并再次启用后，确认探测和转发恢复。
