# Gateway 使用生成的证书代理 HTTPS 请求

本用例从 WAN 访问 `https://app.lab.test/api/orders?id=7`，在同一条 TLS 连接上检查证书和响应，并从 LAN 后端核对实际收到的请求。[WAN 到 LAN 拓扑](../../../topologies/gateway/wan-to-lan/README.md) · [路径规则](rules.toml)

从仓库根目录执行以下命令。

```bash
./tests/e2e/containerlab/cases/gateway/https-path-rewrite/run.sh
```

初始化配置将 WAN 下一跳设为访问节点 198.51.100.1，通过 Landscape 的 LAN DHCP 服务配置 192.0.2.1/24 并登记直连网段。后端使用地址池之外的静态地址 192.0.2.10。入口等待 Gateway HTTPS 监听就绪，并从路由器确认后端可访问。

1. 入口构建默认的 `landscape-webserver`，启动 Gateway 并加载 `/api` 去前缀规则。LAN 后端为 `/orders` 提供本次运行专属的响应内容。
2. 通过 Landscape 证书管理 API 为 `app.lab.test` 生成自签证书，指定 `for_gateway=true`。WAN 客户端仅接收公钥证书，并在连接 198.51.100.2:443 时使用 `app.lab.test` 作为 SNI 和主机名。
3. 客户端验证信任链、主机名和实际叶证书的 SHA-256 指纹，随后检查 HTTP 200 及响应内容。后端访问日志必须记录 `GET /orders?id=7` 和状态 200，才能确认 Gateway 去除了前缀并保留了查询参数。

实验只使用这次生成的证书，域名在探针中映射到 Gateway 的 WAN 地址。失败时入口在清理前输出 Gateway 状态、节点日志、地址、路由和 TC 过滤器。[WAN 客户端探针](../../../lib/probe-https.py)

2026-11-18 实跑通过。WAN 验证了 Gateway 的证书并收到本轮响应，LAN 后端的访问日志记录了 `GET /orders?id=7 HTTP/1.1` 和状态 200。
