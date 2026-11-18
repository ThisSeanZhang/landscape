# LAN 客户端首次获取 DHCPv4 租约

客户端从没有 IPv4 地址和默认路由的状态启动，运行 `udhcpc` 向 Landscape 申请租约。[单 WAN 拓扑](../../../single-wan/README.md) · [客户端探针](../../../single-wan/cases/dhcp-acquire.py)

从仓库根目录运行。

```bash
./tests/e2e/containerlab/single-wan/run.sh dhcp
```

1. 在客户端核对地址属于配置的 DHCP 池，并检查实际安装的前缀、默认网关和 DNS 服务器。
2. 用客户端 MAC 从 Landscape 的 LAN 设备 API 找到对应租约，核对 IP、接口、有效期和租期。
3. 使用刚获得的地址访问 WAN，核对响应内容和 WAN 日志中的 NAT 源地址。[HTTP/NAT 检查](../../../single-wan/check-forward.sh)

2026-11-18 实跑通过。该次获租地址为 `192.0.2.116/24`，网关和 DNS 均为 `192.0.2.1`，租期 600 秒，随后成功访问 WAN。分配的具体地址可随运行变化。
