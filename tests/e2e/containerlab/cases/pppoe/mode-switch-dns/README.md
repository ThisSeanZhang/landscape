# PPPoE 拨号模式切换后的 DNS 恢复

本用例处于设计阶段。拟复用单 WAN 的三节点接线，在 WAN 节点提供 PPPoE 接入和可观察连接来源的 DoH 上游，验证拨号模式切换后默认 flow 的 DNS 查询能恢复。[单 WAN 接线](../../../topologies/lan/single-wan/README.md) · [Issue #243](https://github.com/ThisSeanZhang/landscape/issues/243)

1. 通过外部 pppd 获得 WAN 地址 A，让默认 flow 使用实验 DoH 上游，从 LAN 发起查询以建立长连接。
2. 保持 Landscape 进程运行，切换至原生 PPPoE，让接入端分配不同的 WAN 地址 B。
3. 从 LAN 查询一个未缓存的名称。验收时需同时观察到客户端收到预期答案，DoH 上游收到来自地址 B 的新连接。
