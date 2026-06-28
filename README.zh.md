# Landscape - eBPF Linux 路由器，DNS 驱动分流

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-green.svg)](https://www.gnu.org/licenses/gpl-3.0)  
Landscape 的目标是让你在自己熟悉的 Linux 发行版上轻松运行路由功能

将 Linux 变成域名感知的路由器 — DNS 信号 + eBPF 内核数据面

> 基于 Rust / eBPF / AF_PACKET 开发。

[简体中文](./README.zh.md) | [English](./README.md)

文档: <https://landscape.whileaway.dev/>

## 截图
![Landscape Web UI](main.zh.png)

---

## 架构

Landscape 将流量导向分为两层：

**DNS 平面（用户态）。** 每个设备拥有独立的 DNS 服务器（Hickory）— 独立缓存、上游（UDP/DoH/DoT/DoQ）和规则。解析结果写入内核中对应流的 eBPF map。

**数据平面（内核态）。** XDP 与 TC 钩子读取 eBPF map，在线速下导向数据包。命中规则的流量被重定向，其余直连通过 — 无用户态切换，零开销。

DNS 解析 → eBPF 流 map → TC/XDP 内核导向 → 接口路由

DNS 平面决策。内核强制执行。

## 核心特性
* DNS 驱动内核级 eBPF 分流 — 解析 IP 直接注入内核 map
* 细粒度 NAT — 默认严格 NAT4，按域名/IP 放通 NAT1（[详情](https://landscape.whileaway.dev/features/nat.html)）
* 每流独立 DNS 隔离 — 独立缓存与上游配置，无跨流泄漏
* 域名匹配流量导入 Docker 容器 — 可运行任意 TProxy 兼容程序
* 地理数据库管理 — 支持 DAT/TXT 格式
* 完整 REST API — UI 所有功能均可脚本化

---

## 为什么编写 Landscape

**标准 Linux，不被锁定。** Debian、Arch、openSUSE。不仅是你的"路由"，而是"你的"路由。

**升级无忧。** 单目录管理。替换二进制即升级，配置自动迁移，降级同样支持。

**NAT，按需开放。** BT/PT 放开 NAT1，其余默认 NAT4 — 域名/IP 级控制，不搞一刀切。

**故障不扩散。** 每设备独立 DNS 和分流策略。容器挂了？只有经过它的流量受影响。

## 快速开始

### 前提条件

- Linux 内核 ≥ 6.9，启用 BTF/BPF，需要 `root` 权限；不支持非 Linux 内核（FreeBSD、macOS）
- Docker（可选，用于容器导流）

### 1. 创建配置目录

```bash
mkdir -p /root/.landscape-router
```

### 2. 下载发布资源

- 从 [Releases](https://github.com/ThisSeanZhang/landscape/releases)（后端二进制和前端静态资源分开发布）
  - 下载 `static.zip`
  - 下载对应架构的 `landscape-webserver` 二进制文件
- 解压到 `/root/.landscape-router/static` (可额外指定, 此为默认路径)

### 3. 启动 Landscape

使用 `root` 运行：

```bash
./landscape-webserver
```

默认参数：配置目录 `/root/.landscape-router`，HTTPS 端口 `6443`，用户/密码 `root` / `root`。

Landscape 可以在没有预置配置文件的情况下直接启动。如果你想通过 `landscape_init.toml` 进行初始化，请查看文档站中的配置说明。

更多参数可通过 `./landscape-webserver --help` 查看。

### 4. 打开管理界面

- `http://landscape.local:6300` 会自动跳转到 HTTPS
- `https://landscape.local:6443` 打开 Web UI
- `https://landscape.local:6443/api/docs` 打开 REST API 文档

## systemd 服务

确认服务运行正常后，可以把它配置成 `systemd` 服务：

```ini
[Unit]
Description=Landscape Router

[Service]
ExecStart=/root/landscape-webserver
Restart=always
User=root
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

请把 `ExecStart` 改成你实际的二进制路径。

## License

- `landscape-ebpf`: [GNU General Public License v2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
- 其他部分: [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

如果你有建议或遇到问题，请在这里提交 issue: <https://github.com/ThisSeanZhang/landscape/issues>

## 开发

构建指南: [BUILD.md](./BUILD.md) | [BUILD.zh.md](./BUILD.zh.md)

## Star History

<a href="https://www.star-history.com/#ThisSeanZhang/landscape&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=ThisSeanZhang/landscape&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=ThisSeanZhang/landscape&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=ThisSeanZhang/landscape&type=Date" />
 </picture>
</a>
