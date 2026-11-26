# Containerlab 网络 E2E

用 Containerlab 连接 LAN、Landscape 路由器和 WAN 节点，运行仓库构建的 `landscape-webserver`。每次运行使用独立的网络、配置、SQLite 和 BPF 文件系统，入口脚本负责部署与清理。

## 运行环境

在支持特权网络容器的 Linux 主机或 VM 上，从仓库根目录执行用例命令。需要 Linux 6.12+、BTF/BPF、项目的原生 Rust 构建工具、Bash、GNU strip、Python 3.11+、本机 Docker Engine（含 BuildKit）和 Containerlab。PPPoE 用例还需要宿主机提供 `/dev/ppp`。当前使用 Containerlab 0.83.0。首次构建需下载 Debian 镜像和依赖。[项目构建说明](../../../BUILD.zh.md)

## 按改动范围选择用例

日常开发运行覆盖本次改动的用例。按实际受影响的行为选择范围，运行 `just --list` 可查看任务。

- 改动只涉及一个行为时，运行对应的单个用例。例如调整 DHCP 续租探针后，运行 `just e2e-lan-dhcp-renew`。
- 改动影响多个行为时，运行相关用例或模块。例如修改 Gateway 规则匹配，运行 `just e2e-gateway`；修改共享拓扑时，运行复用该拓扑的用例，包括其他模块中的用例。
- 修改所有用例共用的启动或清理逻辑（`lib/lab.sh`），或难以判断影响范围时，运行 `just e2e` 做全量回归。纯文字改动核对链接和命令即可。

- **运行用例**　按功能查找 case，进入对应说明查看拓扑、运行命令和验收条件。[用例索引](cases/README.md)
- **编写用例**　按要观察的网络行为选择执行器、客户端和服务端。[工具选型](tooling.md)
