---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Landscape Router"
  text: "将 Linux 配置成路由"
  tagline: 不想用命令行配置路由? 试试用这个 UI 进行配置吧
  actions:
    - theme: brand
      text: 阅读文档
      link: /introduction
    - theme: alt
      text: 使用 Docker Compose 一键启动体验
      link: /quick

features:
  - title: Linux 为基础
    details: "自由选择你想要的发行版 <br> (注: 内核 6.1.x 以上, musl 暂时不支持)"
  - title: DNS
    details: 控制任意域名流量的行为, 无论是劫持还是重定向转发至 Docker 容器中, 详见文档
  - title: eBPF
    details: 所有数据包的修改和重定向都在 eBPF 中进行
---

