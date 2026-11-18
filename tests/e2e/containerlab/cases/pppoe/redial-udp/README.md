# PPPoE 强制重拨后已有 UDP 流恢复

从仓库根目录运行 `just e2e-pppoe-redial-udp`。宿主机需要提供 `/dev/ppp`。WAN 节点充当 PPPoE 接入端和 UDP 回显服务，Landscape 使用原生 PPPoE、IPCP 和 TC。[PPPoE 拓扑](../../../topologies/pppoe/single-wan/README.md)

1. WAN 接入端使用 Debian 的 `pppoe` 4.0 和 `ppp` 2.5.2，在 `eth1` 启动 `pppoe-server -F -I eth1 -L 198.51.100.1 -R 198.51.100.2 -N 4 -O /tmp/ac-options`，通过实验专用的 PAP 配置认证客户端。
2. LAN 客户端从同一 UDP socket 向 `198.51.100.1` 持续发送带序号的报文。WAN 服务回传序号和观察到的源 IP。
3. 在接入端结束当前会话的 pppd 子进程，保持接入服务和以太网链路运行。抓包核对旧会话的 PADT 和新会话的 PADS，并在原 socket 上检查回包序号和新的 WAN 源地址。

用例要求同一 LAN socket 的请求在重拨前后分别以 `198.51.100.2` 和 `198.51.100.3` 到达 WAN，且两次 PPPoE 会话的 ID 不同。此次验证覆盖 TC 路径，[Issue #214](https://github.com/ThisSeanZhang/landscape/issues/214) 报告的 XDP NAT 路径仍需单独验证。

2026-11-18 运行通过。抓包观察到会话 `0x1` 终止、新会话 `0x2` 建立。LAN 端同一 socket（`192.0.2.10:33306`）在两次会话中均收到对应序号的回包。

仓库另有两条 Rust 协议测试，分别验证 PADT 和链路丢失触发的重拨。在具备 root、veth 和 eBPF 条件的 Linux 主机上，从仓库根目录运行。[协议测试源码](../../../../../../landscape/tests/pppoe_e2e/scenarios.rs)

```bash
cargo test --locked --profile fast -p landscape --test pppoe_e2e -- redial --ignored --test-threads=1
```
