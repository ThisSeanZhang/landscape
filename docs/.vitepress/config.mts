import { defineConfig } from "vitepress";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Landscape Router",
  description: "Configuring Linux as a Router",
  lastUpdated: true,
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    lastUpdatedText: '最后更新时间',
    nav: [
      { text: "主页", link: "/" },
      { text: "文档", link: "/introduction" },
    ],

    sidebar: [
      {
        text: "介绍",
        items: [
          { text: "简介", link: "/introduction" },
          { text: "部分界面截图", link: "/screenshot" },
        ],
      },
      {
        text: "部署指南",
        items: [
          { text: "注意 Linux 版本 / 内核要求", link: "/attention" },
          { text: "手工部署", link: "/manual" },
          { text: "康康其他人怎么做 (链接)", link: "/community-guides" },
        ],
      },
      {
        text: "配置介绍",
        items: [
          { text: ".landscape-router 目录介绍", link: "/config/home_path.md" },
          { text: "配置文件介绍", link: "/config/index.md" },
        ],
      },
      {
        text: "特性",
        items: [
          { text: "分流控制", link: "/flow" },
          { text: "eBPF 路由", link: "/feature/route.md" },
        ],
      },
      {
        text: "编译",
        items: [
          { text: "编译", link: "/compilation/index.md" },
          { text: "与 Armbian 集成", link: "/compilation/armbian.md" },
          { text: "交叉编译", link: "/compilation/cross.md" },
        ],
      },
      {
        text: "FAQ",
        items: [
          { text: "DNS 服务相关", link: "/faq/dns.md" },
          // { text: "在已有网络基础上运行", link: "/faq/coexist.md" },
          { text: "与 iptable 的关系是-没关系", link: "/faq/iptables.md" },
        ],
      },
      // {
      //   text: "拓扑",
      //   items: [
      //     { text: "网卡区域", link: "/iface/zone.md" },
      //     { text: "服务配置", link: "/iface/service.md" },
      //   ],
      // },
      // {
      //   text: "网卡服务",
      //   items: [
      //     { text: "静态 IP 配置 (WAN / LAN)", link: "/todo" },
      //     { text: "PPPD (WAN)", link: "/todo" },
      //     { text: "DHCP Client (WAN)", link: "/todo" },
      //     { text: "DHCP Server (LAN)", link: "/todo" },
      //   ],
      // },
      // {
      //   text: "系统服务",
      //   items: [
      //     { text: "DNS", link: "/todo" },
      //     { text: "IP 行为配置", link: "/todo" },
      //     { text: "Docker", link: "/todo" },
      //   ],
      // },
    ],

    search: {
      provider: 'local',
      options: {
        locales: {
          root: {
            translations: {
              button: {
                buttonText: '搜索文档',
                buttonAriaLabel: '搜索文档'
              },
              modal: {
                noResultsText: '无法找到相关结果',
                resetButtonTitle: '清除查询条件',
                footer: {
                  selectText: '选择',
                  navigateText: '切换',
                  closeText: '关闭',
                }
              }
            }
          }
        }
      }
    },

    socialLinks: [
      { icon: "github", link: "https://github.com/ThisSeanZhang/landscape" },
    ],
    footer: {
      message: "",
      copyright: "Copyright © 2025-present Sean",
    },

    editLink: {
      pattern:
        "https://github.com/ThisSeanZhang/landscape/edit/docs/docs/:path",
      text: "在 GitHub 上编辑此页",
    },
  },
});
