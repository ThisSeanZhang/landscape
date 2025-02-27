---
outline: deep
---

# 快速体验
可以使用 Docker Compose 快速进行启动体验, (不建议使用这样的方式进行部署)

## 初始化配置文件准备 ( 命名为: **landscape_init.toml** )
```toml
# 定义第一张网卡
[[ifaces]]
# 网卡名称
name = "eth0"
# 网卡所属区域
zone_type = "wan"

# 第二张网卡
[[ifaces]]
name = "br_lan"
# 因为是虚拟设备, 所以是需要设定创建的类型
create_dev_type = "bridge"
zone_type = "lan"

[[ifaces]]
name = "pc1"
# 指定网卡附属的网卡, 在网络拓扑中表现为连接到某张网卡
controller_name = "br_lan"

[[ifaces]]
name = "pc2"
controller_name = "br_lan"

# 配置网卡获取 IP 的行为
[[ipconfigs]]
iface_name = "eth0"
# 启用
enable = true

# 静态 IP 配置
[ipconfigs.ip_model]
t = "static"
ipv4 = "172.123.0.2"
ipv4_mask = 16

# 对 eth0 启用 NAT 配置
[[nats]]
iface_name = "eth0"
enable = true

# 对 eth0 启用 Mark 服务
[[marks]]
iface_name = "eth0"
enable = true

# 配置 br_lan 网卡启用 DHCP Server
[[ipconfigs]]
iface_name = "br_lan"
enable = true

[ipconfigs.ip_model]
t = "dhcpserver"
server_ip_addr = "192.168.5.1"
network_mask = 24
ip_range_start = "192.168.5.100"


# DNS 规则
[[dns_rules]]
# 名称 用于区分
name = "default rule"
# 优先级 并且是唯一值, 相同的会被覆盖
index = 1000
# 是否启用
enable = true
# 是否为控制转发
redirection = false
# 当 source 为空时将会配置所有的域名
# 因此, 默认规则的 index 要比其他所有的规则大才行
source = []

[[dns_rules]]
name = "example"
index = 200
enable = true
redirection = false
source = [
    # 匹配的方式是使用 geosite 的 key ( geosite 文件要存在)
    { t = "geokey", key = "geo_key_value" },
    # 匹配的方式是使用自定义的配置 match_type 见文档 DNS 配置部分
    { t = "config", match_type = "plain", value = "google.com" },
]

```

## Compose 文件
```yaml{11}
services:
  landscap:
    image: thisseanzhang/landscape:quick
    container_name: land_rt
    privileged: true
    pull_policy: missing
    environment:
      LANDSCAPE_EBPF_MAP_SPACE: docker
    volumes:
      # 需要配置初始化文件 landscape_init.toml
      - ./landscape_init.toml:/root/.landscape-router/landscape_init.toml
      # 需要将 eBPF 映射入容器
      - /sys/fs/bpf/docker/:/sys/fs/bpf/
    networks:
      out:
        ipv4_address: 172.123.0.2

  firefox:
    container_name: land_ff
    image: jlesage/firefox
    environment:
      LANG: zh_CN.UTF-8
      FF_OPEN_URL: "http://land_rt:6300"
      ENABLE_CJK_FONT: 1
    dns:
      - 1.1.1.1
    ports:
      - "5800:5800"
    networks:
      out:
        ipv4_address: 172.123.0.3

networks:
  out:
    driver: bridge
    ipam:
      config:
        - subnet: 172.123.0.0/16
          gateway: 172.123.0.1
```