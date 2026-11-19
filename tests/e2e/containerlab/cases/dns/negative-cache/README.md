# CNAME 负缓存到期

从仓库根目录运行 `just e2e-dns-negative-cache`。用例使用单 WAN 拓扑，在路由器的默认 flow 启用自研上游池，并将负缓存上限设为 5 秒。[单 WAN 拓扑](../../../topologies/lan/single-wan/README.md) · [DNS 配置](dns.toml)

LAN 客户端向路由器查询 A 记录。WAN 上游返回 TTL 为 40 秒的 CNAME，目标首次返回无 SOA 的 NODATA，随后即可返回 A 记录。立即重查时，客户端应只收到剩余 TTL 至多 5 秒的 CNAME。5 秒后再次查询时，应同时收到 CNAME 和新的 A 记录。WAN 日志应只出现两组别名和目标查询。[客户端和上游](probe.py)
