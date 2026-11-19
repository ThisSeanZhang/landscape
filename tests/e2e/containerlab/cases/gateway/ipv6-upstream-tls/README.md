# Gateway 校验链路本地 IPv6 上游的证书

从仓库根目录运行 `just e2e-gateway-ipv6-tls`。

用例复用 [WAN 到 LAN 拓扑](../../../topologies/gateway/wan-to-lan/README.md)。LAN 后端的同一 TLS 服务监听 `fe80::10` 和 `fe80::11`。本轮生成的测试 CA 签发一张只含 `IP:fe80::10` 的证书，路由器容器在 Gateway 启动时信任该 CA。

1. WAN 通过 HTTP 访问 `match.lab.test/origin.txt`。Gateway 向 `[fe80::10%lan0]:8443` 建立 TLS 连接，客户端收到后端的本轮标记。
2. WAN 访问 `mismatch.lab.test/origin.txt`，由 Gateway 连接 `[fe80::11%lan0]:8443`。同一张证书缺少这个 IP，客户端应收到 HTTP 502 和 `upstream_tls_failed`。
