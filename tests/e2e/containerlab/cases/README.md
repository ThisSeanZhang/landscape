# Containerlab E2E 用例索引

按功能查找用例。每个用例的说明包含所用拓扑、执行步骤和通过条件。运行前可先查看[环境要求](../README.md#运行环境)。

## 可直接运行

| 用例目录 | 测什么 |
| --- | --- |
| [lan/static-forward](lan/static-forward/README.md) | 使用静态 IPv4 的 LAN 客户端经 TC 和 NAT 访问 WAN |
| [lan/dhcp-acquire](lan/dhcp-acquire/README.md) | LAN 客户端首次获租，应用网关和 DNS 配置，随后访问 WAN |
| [acme/dns-01](acme/dns-01/README.md) | 通过实验 DNS 提供商向本地 Pebble 申请普通域名和通配符证书，并核对 TXT 清理 |
| [gateway/https-path-rewrite](gateway/https-path-rewrite/README.md) | Gateway 使用生成的证书终止 TLS，向后端转发去前缀且保留查询参数的请求 |
| [gateway/sni-passthrough](gateway/sni-passthrough/README.md) | 按 SNI 选择 TLS 透传或本地终止，在 WAN 核对证书指纹 |
| [gateway/live-upstream-update](gateway/live-upstream-update/README.md) | 通过 API 更新上游，确认同一域名的新连接切换到新后端 |

## 探索与待实现用例

| 用例目录 | 测什么 | 当前状态 |
| --- | --- | --- |
| [lan/dhcp-renew](lan/dhcp-renew/README.md) | 同一客户端续租后地址保持一致、租约延长、WAN 仍可达 | 临时实验已验证，待加入运行脚本 |
| [pppoe/redial-udp](pppoe/redial-udp/README.md) | 接入端强制断开会话，重拨换址后已有 UDP 流恢复 | TC 路径的临时实验已验证，待加入运行脚本 |
| [pppoe/mode-switch-dns](pppoe/mode-switch-dns/README.md) | 从 pppd 切换到原生 PPPoE 后，默认 flow 的 DNS 查询恢复 | 用例设计，待实现 |
