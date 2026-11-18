# Gateway 在线修改上游

同一个 LAN 节点运行两个独立的 HTTP 服务。A 监听 `192.0.2.10:8081`，B 监听 `192.0.2.10:8082`，同一路径在两个服务上分别返回带 A 或 B 的本轮标记。WAN 客户端把 `switch.lab.test` 指向 Gateway 的 WAN 地址。[WAN 到 LAN 拓扑](../../../topologies/gateway/wan-to-lan/README.md) · [规则更新与断言](switch.py)

从仓库根目录运行。

```bash
./tests/e2e/containerlab/cases/gateway/live-upstream-update/run.sh
```

1. 通过 `POST /api/v1/gateway/rules` 创建指向 A 的域名规则。WAN 新建 HTTP 连接，检查返回的 A 标记，并在 A 的日志中核对本次请求。
2. 使用 API 返回的规则 ID 和版本更新同一条规则，将上游端口改为 8082。保存成功后立即从 WAN 新建连接，请求同一 URL，检查 B 标记和 B 的日志。
3. 在路由器中核对更新前后 80 端口的监听套接字 inode 集合，并从 API 确认仍只有一条规则、ID 相同且指向 B。

两次访问都使用新连接，观测范围是规则更新后新请求的路由选择。

2026-11-18 实跑通过。更新前的请求出现在 A 的日志里，保存后的第一个新连接命中了 B。规则 ID 和 80 端口的监听套接字保持一致。
