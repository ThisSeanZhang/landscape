# 配置文件介绍

程序的配置来源主要有以下:
* `landscape_init.toml`: 全量配置文件, 除了包含各种规则配置还包含完整的 `landscape.toml`, 仅在初始化时进行读取一次, 
    读取后将会创建一个 `landscape_init.lock` 文件, 可在 UI 界面中导出当前的配置的 `init` 文件. 方便使用当前配置进行重新部署.
* `landscape.toml`: 每次启动进行读取, 只包含监听地址. 登录用户名和密码, 日志等配置.

启动时可以不进行任何文件的配置即可启动.   
如果第一次启动时想要达到开机即使用, 可以配置 `landscape_init.toml`.

`landscape.toml` 中配置的优先级低于命令行传入的参数.

::: warning
当删除了 `landscape_init.lock` 文件后, 启动将会清空所有的已有配置, 然后使用 `landscape_init.toml` 中的内容刷新整个配置包含 `landscape.toml` 中的配置.
所以谨慎删除此文件.
:::

## landscape.toml 配置示例
```toml
[auth]
# 登录用户名
admin_user = "root"
# 登录密码
admin_pass = "root"

[web]
# Web 根目录路径
web_root = "~/.landscape-router/static"
# HTTP 监听端口
port = 6300
# HTTPS 监听端口
https_port = 6443
# 监听地址 仅监听 IPV4 时使用 0.0.0.0
address = "::"

[log]
# 日志文件路径
log_path = "~/.landscape-router/logs"
# 是否启用调试模式
debug = false
# 是否在终端输出日志
log_output_in_terminal = false
# 最大日志文件数量
max_log_files = 10

[store]
# 数据库路径
database_path = "=sqlite://~/.landscape-router/landscape_db.sqlite?mode=rwc"

```
## landscape_init.toml 配置示例
### 网卡定义
```toml
[[ifaces]]
name = "ens3" # 网卡名称
create_dev_type = "no_need_to_create" # 物理网卡不需要创建
zone_type = "wan" # 所属区域
enable_in_boot = true # 启动时将此网卡也启动
wifi_mode = "undefined" # 是不是 WIFI 网卡

# xps_rps 配置, 用于 CPU 软负载, CPU 单核心较弱时需要配置
[ifaces.xps_rps]
xps = "4"
rps = "4"
```

### 网卡 IP 配置方式
```toml
[[ipconfigs]]
iface_name = "ens3" # 应用在哪张网卡上
enable = true # 是否启用

[ipconfigs.ip_model] # 具体的 IP 配置方式
t = "static" # 静态 IP 配置
default_router_ip = "10.1.1.10" # 路由 IP
default_router = true # 是否将 default_router_ip 设置为默认路由
ipv4 = "10.1.1.237" # 当前网卡将要设置的静态 IP
ipv4_mask = 24
```

### DHCP 服务配置
```toml
[[dhcpv4_services]]
iface_name = "test"
enable = false

[dhcpv4_services.config]
ip_range_start = "192.168.5.2"
ip_range_end = "192.168.5.255"
server_ip_addr = "192.168.5.1"
network_mask = 24

# 绑定 IP 的 MAC 地址
mac_binding_records = [
    { mac = "00:11:22:33:44:55", ip = "192.168.5.100" },
    { mac = "00:11:22:33:44:55", ip = "192.168.5.200" },
]
```

