# Landscape - Linux 路由器配置工具

Landscape 是一个基于 Web UI 的工具，可以轻松将您喜爱的 Linux 发行版配置为路由器。

> 基于 Rust / eBPF / AF_PACKET 开发。

[中文文档](./README.zh.md) | [English](./README.md)

## 截图
![](docs/images/1.png)

---
## 功能
> ✅ 已经实现并且已经测试  
> ⚠ 可行但是未测试  
> ❌ 未实现  

- <u>IP 配置</u>
    - *静态 IP 配置*
        - ✅ 指定 IP 
        - ✅ 配置网关指定默认路由
    - *DHCP Client*
        - ✅ 指定主机名称
        - ❌ 自定义 Option
    - *PPPoE ( PPPD 版 )*
        - ✅ 默认路由指定
        - ⚠ 多网卡拨号
        - ✅ 网卡名称指定
    - *PPPoE ( eBPF 版 )*
        - ✅ 协议主体实现
        - ❌ 网卡 GRO/GSO 导致的数据包大小超 MTU (未解决)
    - *DHCP Server*
        - ✅ 提供简单 IP 地址分配和续期服务
        - ✅ 自定义分配 IP 的 网关 网段 访问 配置
- <u>标记模块</u>
    - ✅ 将被标记流量按照标记配置( 直连/丢弃/禁止打洞/重定向到 Docker 容器或者网卡 )进行转发 
    - ❌ 流量统计
    - ❌ 流量跟踪标记
    - ✅ 内网 IP 行为控制, 按照标记的规则控制内网 IP
    - ✅ 外网 IP 行为控制, 按照标记的规则控制外网 IP, 并支持使用 `geoip.dat` 协助配置
    - ❌ GeoIP 文件自动更新
- <u>DNS</u>
    - ✅ 支持指定网址使用特定上游 DNS
    - ✅ DNS 劫持 ( 返回 A 解析 )
    - ❌ DNS 劫持返回多条记录 ( 除了 A 解析之外的)
    - ✅ 对指定 DNS 解析结果进行 IP 标记, 配置标记模块进行处理
    - ✅ GeoSite 文件支持
    - ❌ 自动定时更新 GeoSite 文件
    - ❌ 支持将 Docker 容器镜像名加入解析缓存
- <u>NAT (eBPF) 实现</u>
    - ✅ 基础 NAT 
    - ⚠ 静态映射 / 开放指定端口 ( UI 界面未完善 )
    - ✅ NAT 打洞禁止, 依据标记模块的标记对指定 IP 开启的端口禁止其他 IP 进行连接
- <u> Docker </u>
    - ✅ 支持简单运行和管理 Docker 容器
    - ⚠ 镜像拉取
    - ✅ 将流量导入运行 TProxy 的 Docker 容器
- <u> WIFI </u>
    - ❌ 创建 WIFI 热点
    - ❌ 接入 WIFI 热点
- <u> 杂项 </u>
    - ✅ 登录界面
    - ❌ 添加英文版前端页面
    - ❌ 规范化日志记录 
    - ❌ 网卡 XPS/RSP 优化, 将网卡压力负载到不同的核心, 提升整体吞吐

---

## 启动方式和限制

### 系统要求
- 支持的 Linux 内核版本：`6.1` 及以上。
- 安装 `iptables (pppd 版本 pppoe mss 钳制)`, `docker`

### 常规启动步骤
1. 创建配置文件夹：
   ```shell
   mkdir -p ~/.landscape-router
   ```
2. 创建初始文件 `landscape_init.toml` 可参考 [快速启动中配置](https://landscape.whileaway.dev/quick.html)

3. 启动服务：
   从 [Release](https://github.com/ThisSeanZhang/landscape/releases) 中下载需要的版本，运行以下命令启动服务（默认端口：`6300`）：
   ```shell
   ./landscape-webserver
   ```

### Docker Compose 启动体验
见文档 [快速启动](https://landscape.whileaway.dev/quick.html)


### Armbian 集成
见文档 [Armbian 集成](https://landscape.whileaway.dev/compilation/armbian.html)

---

## 编译
见文档 [编译](https://landscape.whileaway.dev/compilation/)

## LICENSE

- `landscape-ebpf`: [GNU General Public License v2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
- 其他部分: [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

---

如果您有任何建议或问题，可以在 [issues](./issues/new) 页面提交您的反馈。
