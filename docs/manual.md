# 手工部署

## 文件准备
::: warning
1. 部署之前需要先确认当前的系统是否满足, [注意事项](./attention.md) 中的要求  
2. 不进行任何配置是可以直接启动的, 唯一的副作用是会将 `/etc/resolv.conf` 修改为 `127.0.0.1`, 如停止后发现无法访问网络, 可以检查这个文件
3. 以下的可选是在没有使用到时可选
:::

::: warning
记得先使用 ```ss -lutp``` 检查当前主机是否有 DNS 服务已经占用了 `53` 端口, 如果已被占用则无法启动.
:::


1. Landscape Router 文件主体, 可从 [此处](https://github.com/ThisSeanZhang/landscape/releases/) 下载
2. 静态页面文件, 可从 [此处](https://github.com/ThisSeanZhang/landscape/releases/) 下载, 并且解压到 `/root/.landscape-router/static` 文件夹中
3. (可选) 安装 PPP，用于 pppoe 拨号
4. (可选) 安装 Docker.
5. (*假如有桌面环境, 并有浏览器时可选*) 准备初始化配置文件  
  (注意, 此配置文件只在第一次运行被读取):   
    放置在 -> `/root/.landscape-router/landscape_init.toml`
6. (可选) geosite / geoip 文件

## 关闭本机自动配置 IP 服务 / DNS 服务
1. Debian:
修改文件: `/etc/network/interfaces`  
将 LAN 网卡全设置为 manual 后, 将 WAN 的网卡额外在配置文件中设置一个静态 IP, 方便即使路由程序出现故障时, 使用另外一台机器设置静态 IP 后也能进行访问.

```
auto <第一张网卡名> <- 比如设置为 WAN
iface <第一张网卡名> inet static
    address 192.168.22.1
    netmask 255.255.255.0

auto <第二张网卡名> <- 以下都是 LAN
iface <第二张网卡名> inet manual

auto <第三张网卡名>
iface <第三张网卡名> inet manual
```
效果: 
```
auto ens3
iface ens3 inet static
    address 192.168.22.1
    netmask 255.255.255.0

auto ens4
iface ens4 inet manual

auto ens5
iface ens5 inet manual
```

这样即使路由出现故障后, 使用另外一台主机设置为 192.168.22.0/24 网段的任意地址 (比如: 192.168.22.2/24) , 直连这个网口, 就能连上路由器.


> 其他系统待添加... 欢迎 PR 分享部署过程

## 关闭本机 DNS 服务 (如果不存在此服务可忽略)
```shell
systemctl stop systemd-resolved
systemctl disable systemd-resolved
systemctl mask systemd-resolved
```

## 手动启动验证
在配置 systemd 服务之前, 可以先手动直接运行 `/root/landscape-webserver`, 确认是否能够执行.
运行成功时会输出如下内容, 展示当前的配置, 可以验证下 Auth 以及对应的 Web 路径是否正确:
```text
██╗      █████╗ ███╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
██║     ██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
██║     ███████║██╔██╗ ██║██║  ██║███████╗██║     ███████║██████╔╝█████╗  
██║     ██╔══██║██║╚██╗██║██║  ██║╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝  
███████╗██║  ██║██║ ╚████║██████╔╝███████║╚██████╗██║  ██║██║     ███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝
                                                                          
██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗                        
██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗                       
██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝                       
██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗                       
██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║                       
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝                       

Landscape Home Path: /root/.landscape-router

[Auth]
Admin User: admin
Admin Pass: root

[Log]
Log Path: /root/.landscape-router/logs
Debug: true
Log Output In Terminal: true
Max Log Files: 7

[Web]
Web Root Path: /root/.landscape-router/static
Listen HTTP on: http://[::]:6300
Listen HTTPS on: https://[::]:6443

[Store]
Database Connect: sqlite://./db.sqlite?mode=rwc
```


## 创建 systemd 服务文件
创建 `/etc/systemd/system/landscape-router.service`
文件内容: 
```text
[Unit]
Description=Landscape Router

[Service]
ExecStart=/root/landscape-webserver <- 记得修改此处
Restart=always
User=root
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```


```shell
# 启动服务
systemctl start landscape-router.service
# 开机启动服务 ( 确认没有问题之后执行 )
systemctl enable landscape-router.service
# 停止服务
systemctl stop landscape-router.service
```
## 升级 landscape-router

1. 下载新版 `landscape-webserver` 与 `static` 并解压
2. 停止 landscape-router.service
3. 换入新版 `landscape-webserver` 与 `static`  
4. 重启系统（仅重启 landscape-router.service 会导致分流功能不可用）

## 使用升级脚本
- 仅限于可执行文件landscape-webserver和.landscape-router配置目录都在/root/目录下时可使用
- 从仓库中下载update.sh到root目录下，并执行update.sh脚本，执行完重启系统即可
- 脚本会自动从仓库的最新Release下载，新下载的文件会放在downloads目录下，当前可执行文件会放在backup目录下
- 旧的web静态文件会重命名为static_bak