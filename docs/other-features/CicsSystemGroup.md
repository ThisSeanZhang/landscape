# 系统基本信息

## 创建网桥
1、创建网桥  
2、为网桥绑定网卡  
![alt text](../images/other-features/CicsSystemGroup/13.png)  


## 设置成 Wan/Lan 网卡
![](../images/other-features/CicsSystemGroup/1.png)  
![](../images/other-features/CicsSystemGroup/2.png)  
## 开启/关闭 网卡
![](../images/other-features/CicsSystemGroup/3.png)  
## 默认路由
默认路由为 flow 0 出口
## 设置 PPPOE 网卡为默认路由（添加 PPPOE 账号）
1、在wan网卡上添加PPPOE账号  
2、在PPPOE账号里设为默认路由  
![](../images/other-features/CicsSystemGroup/4.png)  
![](../images/other-features/CicsSystemGroup/5.png)  
![alt text](../images/other-features/CicsSystemGroup/6.png)  
![alt text](../images/other-features/CicsSystemGroup/7.png)  
## 设置 Wan 网卡为默认路由
为网卡配置ip后，可开启默认路由  
![alt text](../images/other-features/CicsSystemGroup/8.png)  
![alt text](../images/other-features/CicsSystemGroup/9.png)  

## Wan 网卡配置
全部按默认值启用即可
1-1 TCP MSS 钳制  
1-2 防火墙服务配置  
1-3 网卡NAT配置  
2-1 IPV6-PD 客户端配置  
2-2 Wan 路由转发服务  
![alt text](../images/other-features/CicsSystemGroup/10.png)  
## Lan 网卡配置
按需配置  
1-1 DHCPv4 服务配置  （包含 Mac IP 地址绑定）  
1-2 ICMPV6-RA 服务配置  
1-3 Lan 路由 转发 （应当启用）  
![alt text](../images/other-features/CicsSystemGroup/11.png)  


## 无线网卡 

## 启用 Wan 和 Lan 网卡的路由转发功
![alt text](../images/other-features/CicsSystemGroup/12.png)  
