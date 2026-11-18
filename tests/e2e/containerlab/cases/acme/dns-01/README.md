# ACME DNS-01 签发

在仓库根目录运行。入口为本用例启用 Cargo 的 `e2e-acme` feature，并构建包含 Pebble 和 Python dnslib 的实验镜像。账户、提供商配置和私钥保存在本轮实验节点中。[单 WAN 拓扑](../../../single-wan/README.md) · [运行脚本](run.sh)

```bash
./tests/e2e/containerlab/cases/acme/dns-01/run.sh
```

WAN 节点运行 Pebble、权威 DNS 和模拟 Cloudflare 的管理 API。Landscape 通过现有的证书账户和 DNS 提供商 API 创建配置。测试构建接受以下两个提供商值。[Pebble 项目说明](https://github.com/letsencrypt/pebble)

| 配置 | 实验中的值 |
| --- | --- |
| ACME 账户的 `provider_config` | `{"e2e":{"directory_url":"https://198.51.100.1:14000/dir"}}` |
| DNS profile 的 `provider_config` | `{"e2e":{"api_url":"http://198.51.100.1:8055/client/v4","api_token":"<本轮令牌>"}}` |

1. 路由器信任本轮生成的 HTTPS 服务端 CA，通过 Pebble 目录注册账户。DNS 提供商验证 Bearer 令牌和托管区域，复用 Cloudflare 适配器的 TXT 创建和按记录 ID 删除逻辑。
2. Landscape 为 `app.lab.test` 和 `*.app.lab.test` 提交同一笔订单。两个授权共用 `_acme-challenge.app.lab.test`。实验 DNS 预置一个其他 TXT 值，Pebble 实际查询 DNS 时应同时看到三个不同值。
3. 等待 Landscape 将订单置为 `valid`。从 Pebble 管理端取得本轮签发根证书，校验证书链、基础域名及匹配通配符的子域名。最后直接查询权威 DNS，确认只剩预置 TXT。[验收脚本](issue.py)

2026-11-18 实跑通过。两个主机名的证书链验证均成功，两条挑战记录完成清理，预置 TXT 得以保留。
