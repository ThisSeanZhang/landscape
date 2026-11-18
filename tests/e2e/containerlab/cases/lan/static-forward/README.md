# 单 WAN 静态 IPv4 转发

验证使用固定地址的 LAN 客户端能通过 Landscape 的 TC 转发和 IPv4 NAT 访问 WAN。[单 WAN 拓扑](../../../topologies/lan/single-wan/README.md) · [客户端脚本](run.sh)

从仓库根目录运行。

```bash
./tests/e2e/containerlab/cases/lan/static-forward/run.sh
```

客户端在 `eth1` 配置 `192.0.2.10/24` 和默认网关 `192.0.2.1`，然后向 `198.51.100.1:8080` 请求本轮运行的唯一标识。客户端必须读回相同标识，WAN 服务日志必须记录同一请求、状态 200 和转换后的源地址 `198.51.100.2`。[HTTP/NAT 检查](../../../lib/check-forward.sh)

2026-11-18 实跑通过。客户端读回了本轮标识，WAN 日志确认请求来自 `198.51.100.2`。
