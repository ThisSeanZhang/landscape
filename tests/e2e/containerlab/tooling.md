# Containerlab E2E 工具选型

同一个 Containerlab 拓扑可以供 Shell、pytest、Robot Framework 或 Rust 用例使用。先确定要从哪一端观察结果，再选能产生这个结果的客户端或服务端。已有的拓扑、配置和验收逻辑可以复用。

## 按场景选择工具

| 要验证的场景 | 建议组合 | 决定是否通过的观测 |
| --- | --- | --- |
| 静态地址、TC 转发、IPv4 NAT | 沿用 Shell、`curl` 和 WAN HTTP 服务 | LAN 读回本轮请求标识，WAN 日志记录同一请求及转换后的源地址。[静态 IPv4 转发用例](cases/lan/static-forward/README.md) |
| Gateway TLS 终止、SNI 透传 | Shell 启动节点，Python 标准库在 WAN 发起 TLS 和 HTTP 请求，OpenSSL 提供实验 TLS 后端 | 在同一条连接上检查实际叶证书的指纹和响应内容。[SNI 透传用例](cases/gateway/sni-passthrough/README.md) |
| 单个 LAN 客户端获租、续租 | 运行真实 `udhcpc`。租约和 API 数据可用 pytest 比较，跨节点操作步骤也适合写成 Robot 关键字 | 续租时保持同一进程和租约。检查 REQUEST/ACK、地址不变、服务端到期时间后移和 LAN 到 WAN 的连通性。[DHCP 续租流程](https://www.rfc-editor.org/rfc/rfc2131#section-4.4.5) · [项目中的续租验证](cases/lan/dhcp-renew/README.md) |
| 地址池竞争、多客户端批量续租 | 在 LAN 节点用 Kea `perfdhcp` 指定模拟客户端数量、请求速率和续租速率 | 观察成功分配数、超时和租约唯一性。另用 Linux 客户端验证操作系统实际安装的路由和 DNS。[perfdhcp 手册](https://github.com/isc-projects/kea/blob/master/doc/sphinx/man/perfdhcp.8.rst) |
| PPPoE 协商、PADT 响应时限、断链重连 | 沿用 Rust 网络命名空间测试和脚本化接入端。链路延迟或丢包可用 Containerlab 的 netem 加在对端接口 | 指定旧会话收到哪种事件，观察下一次建连和 keepalive。可分别覆盖收到 PADT、链路断开和链路仍 UP 但对端无响应。[仓库协议测试](../../../landscape/tests/pppoe_e2e/scenarios.rs) · [Containerlab 链路故障注入](https://containerlab.dev/cmd/tools/netem/set/) |
| PPPoE 强制重拨、换址后已有 UDP 流恢复 | WAN 节点运行 RP-PPPoE 的 `pppoe-server` 和 UDP 回显服务。LAN 节点用常驻 Python 或 Rust 进程持有 socket。需要按用户或会话管理接入端时，也可评估 Accel-PPP | 指定地址池，验证确实获得地址 B。用同一个 socket 向同一 WAN 地址及端口发送带序号的报文，让对端回传它看到的源 IP 和序号。[RP-PPPoE 服务端](https://manpages.debian.org/trixie/pppoe/pppoe-server.8.en.html) · [Accel-PPP](https://github.com/accel-ppp/accel-ppp) · [重拨与 UDP 换址验证](cases/pppoe/redial-udp/README.md) |
| 拨号模式切换后默认 flow 的 DNS 恢复 | LAN 使用 `dig`，WAN 侧可用 dnsdist 提供受控 DoH 上游，连接实验 DNS 后端 | 先发查询建立上游连接，再从外部 pppd 切至内置 PPPoE。切换后查询另一个未缓存名称，验证答案及上游的新连接源地址。[dnsdist 的 DoH 配置](https://github.com/PowerDNS/pdns/blob/master/pdns/dnsdistdist/docs/guides/dns-over-https.rst) · [拨号切换的 DNS 用例设计](cases/pppoe/mode-switch-dns/README.md) |

## 用什么表达用例

| 候选 | 适用时机 | 接入现有项目的成本 |
| --- | --- | --- |
| pytest / pytest-clab | 要保存前后两次租约、地址、会话等数据，或把一条用例参数化到多个拨号模式 | pytest fixture 可以按用例隔离拓扑。项目中用 pytest 9.2.0 和 pytest-clab 0.1.3 加载过单 WAN 拓扑，验证了无管理 IPv4 的三节点接线和会话结束后的清理。插件默认在整个测试会话结束时清理。需隔离租约或 NAT 状态时，为每条用例分配独立的实验名。若用例要求退出时立即销毁拓扑，可在自己的 fixture 中调用 Containerlab CLI。两种接法都应等待 Landscape API 和 TC 程序就绪。[pytest fixture](https://docs.pytest.org/en/stable/how-to/fixtures.html) · [pytest-clab 0.1.3](https://pypi.org/project/pytest-clab/0.1.3/) |
| Robot Framework | 要让做网络验收的人也能直接读写“获租、触发续租、确认到期时间、访问 WAN”等步骤 | 可通过 `Process` 调用现有命令，用关键字封装轮询和数据提取。适合跨多个用例重复的步骤。Containerlab 自己也用它做集成测试。[Robot Framework](https://robotframework.org/robotframework/latest/RobotFrameworkUserGuide.html) · [Containerlab 的测试方式](https://containerlab.dev/manual/dev/test/) |
| Cucumber-rs | 希望用 `.feature` 文件评审场景，同时用项目已有的 Rust/Tokio 代码实现步骤 | 每个场景的 `World` 可保存会话和探针句柄，需要维护自然语言步骤到 Rust 函数的映射。单个协议时序测试直接写 Rust 的成本更低。[Cucumber-rs](https://docs.rs/cucumber/latest/cucumber/) |
| OVH Venom | 想在已有拓扑上用 YAML 列出一组命令、HTTP 调用和预期结果 | 可用 `exec` 调用 `docker exec`。对于跨步骤复用 UDP socket 的用例，仍需让 LAN 探针进程持有它。[Venom 用例与执行器](https://github.com/ovh/venom) |
| netlab validate | 将来有一组多路由器拓扑，要逐节点验证邻接、路由和收敛 | netlab 的 `validate` 支持命令、断言、配置变化及等待条件。标准工作流从 netlab 拓扑生成 Containerlab 实验，采用它意味着需要维护 netlab 的拓扑模型。[验证语法](https://netlab.tools/topology/validate/) · [Containerlab provider](https://netlab.tools/labs/clab/) |

当测试对象扩展到多款网关或实机时，还有两个可复用的来源。

- **Boardfarm 3** 已经定义了 CPE、LAN、WAN 角色和 DHCP 操作，适合需要在不同设备上复用流程的场景，接入时要适配设备清单及控制方式。其 `dhcp_renew_ipv4` 会先调用 `release_dhcp`，再重新申请地址。测已有租约的续租时，应让处于 BOUND 状态的客户端发出 DHCPREQUEST。[Boardfarm 入门](https://github.com/lgirdk/boardfarm/blob/master/docs/getting_started.md) · [DHCP 用例源码](https://github.com/lgirdk/boardfarm/blob/master/boardfarm3/use_cases/dhcp.py)
- **CDRouter** 是带许可的网关测试套件，适合要运行现成互操作用例的团队，需为被测网关接入 LAN/WAN 测试接口。公开目录也可作为设计用例的参考，例如 `cdrouter_dhcp_server_1` 检查续租后的 IP，`cdrouter_pppoe_client_330` 检查客户端空闲超时后主动发送 PADT。后者的发起方与运营商强制下线不同。[用例目录](https://support.qacafe.com/cdrouter/test-summary/cdrouter-test-summary/) · [测试环境和许可](https://support.qacafe.com/cdrouter/quick-start-guide/preparation-and-installation-of-cdrouter-demo/)
