# Gateway 按 SNI 透传 TLS

WAN 客户端以两个域名连接同一个 Gateway 地址 `198.51.100.2:443`。Gateway 持有一张对两个域名都有效的证书。`passthrough.lab.test` 另有一条 SNI 规则，指向 LAN 的 TLS 后端 `192.0.2.10:8443`。后端在容器内生成自己的证书和私钥，WAN 探针只接收两端的公钥证书。[WAN 到 LAN 拓扑](../../../topologies/gateway/wan-to-lan/README.md) · [SNI 规则](rules.toml)

从仓库根目录运行。

```bash
./tests/e2e/containerlab/cases/gateway/sni-passthrough/run.sh
```

| WAN 发出的 SNI | 验收条件 |
| --- | --- |
| `gateway.lab.test` | TLS 握手成功，主机名验证通过，叶证书的 SHA-256 指纹等于 Gateway 证书指纹 |
| `passthrough.lab.test` | 主机名验证通过，叶证书指纹等于 LAN 后端证书指纹。同一连接访问 `/origin.txt` 返回 HTTP 200 和本轮后端标记 |

2026-11-18 实跑通过。两个域名分别返回了预期的 Gateway 和 LAN 后端证书，指纹不同，透传连接读回了本轮后端标记。
