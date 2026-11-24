# Ethernet WAN 网关 ARP

从仓库根目录运行 `just e2e-wan-gateway-arp`。用例使用单 WAN 拓扑，在 WAN 对端抓取 ARP 和从 LAN 发出的 UDP 探针。LAN 地址为 `192.0.2.10`，WAN 网关为 `198.51.100.1`，同网段主机为具有独立 MAC 的 macvlan 接口 `198.51.100.77`。[单 WAN 拓扑](../../../topologies/lan/single-wan/README.md)

1. 观察路由器发出的 ARP 请求和网关应答。从 LAN 分别发往 `203.0.113.9` 和 `198.51.100.77`，核对 WAN 侧以太网头的目的 MAC，以及 NAT 后的源 IP。路由器的静态邻居表里，同网段主机使用其真实 MAC，网关使用另一个测试 MAC。这使抓包能够区分主动探测结果和邻居回退。
2. 保持网关 IP，修改对端 MAC。等待主动刷新，核对同一个 TC egress root 的 `confirmed_gateway_mac` 和新转发帧的目的 MAC。
3. 从对端移除网关 IP，观察连续两次没有应答的请求，核对转发仍使用最后确认的 MAC。
4. 通过 WAN Link API 关闭 IPv4，再以原地址启用。网关静默期间两次检查 root 中的 MAC 均为零。恢复对端 IP 后，再次确认探测和转发恢复。
