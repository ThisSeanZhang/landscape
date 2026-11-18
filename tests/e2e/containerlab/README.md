# Containerlab 网络 E2E

用 Containerlab 连接 LAN、Landscape 路由器和 WAN 节点，运行仓库构建的 `landscape-webserver`。每次运行使用独立的网络、配置、SQLite 和 BPF 文件系统，入口脚本负责部署与清理。

## 运行环境

在支持特权网络容器的 Linux 主机或 VM 上，从仓库根目录执行用例命令。需要 Linux 6.12+、BTF/BPF、项目的原生 Rust 构建工具、Bash、GNU strip、Python 3.11+、本机 Docker Engine（含 BuildKit）和 Containerlab。当前使用 Containerlab 0.83.0。首次构建需下载 Debian 镜像和依赖。[项目构建说明](../../../BUILD.zh.md)

## 从哪里开始

- **运行用例**　按功能查找 case，进入对应说明查看拓扑、运行命令和验收条件。[用例索引](cases/README.md)
- **编写用例**　按要观察的网络行为选择执行器、客户端和服务端。[工具选型](tooling.md)
