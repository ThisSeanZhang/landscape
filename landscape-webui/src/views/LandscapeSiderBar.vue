<script setup lang="ts">
import type { MenuOption } from "naive-ui";
import type { Component } from "vue";
import { computed, h, ref, watch } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { NIcon } from "naive-ui";

import {
  Network4,
  Settings,
  CicsSystemGroup,
  ModelBuilder,
  ChartCombo,
  ServerDns,
  NetworkPublic,
  Dashboard,
  Terminal,
} from "@vicons/carbon";
import { ImportExportRound } from "@vicons/material";
import { Wall } from "@vicons/tabler";
import { Docker } from "@vicons/fa";
import { BookGlobe20Regular } from "@vicons/fluent";

import CopyRight from "@/components/CopyRight.vue";
import { usePtyStore } from "@/stores/pty";

const route = useRoute();
const router = useRouter();
const ptyStore = usePtyStore();

const menu_active_key = ref(
  route.name && typeof route.name === "string" ? route.name : "",
);

// const route_path = computed(() => route.name);
// watch(route_path, (path) => {
//   console.log(path);
// });
const collapsed = ref(true);

function click_menu(key: string) {
  // Special handler for WebShell
  if (key === "web-pty") {
    ptyStore.toggleOpen();
    // Reset selection to current route so WebShell doesn't look "selected" as a page
    menu_active_key.value =
      route.name && typeof route.name === "string" ? route.name : "";
    return;
  }

  router.push({
    path: `/${key}`,
  });
}

function renderIcon(icon: Component) {
  return () => h(NIcon, null, { default: () => h(icon) });
}

const menuOptions: MenuOption[] = [
  {
    label: "系统基本信息",
    key: "",
    icon: renderIcon(CicsSystemGroup),
  },
  {
    label: "服务状态",
    key: "status",
    icon: renderIcon(Dashboard),
    children: [
      {
        label: "DHCPv4 服务",
        key: "dhcp-v4",
        disabled: false,
      },
      {
        label: "IPv6-PD  服务",
        key: "ipv6-pd",
      },
      {
        label: "IPv6 RA 服务",
        key: "ipv6-ra",
        disabled: false,
      },
    ],
  },
  // {
  //   label: "网络拓扑",
  //   key: "topology",
  //   icon: renderIcon(Network4),
  // },
  {
    label: "静态 NAT 管理",
    key: "nat",
    icon: renderIcon(ImportExportRound),
    disabled: false,
  },
  {
    label: "防火墙",
    key: "firewall",
    icon: renderIcon(Wall),
  },
  {
    label: "DNS 相关",
    key: "dns",
    icon: renderIcon(ServerDns),
    children: [
      {
        label: "重定向规则管理",
        key: "dns-redirect",
      },
      {
        label: "上游 DNS 配置管理",
        key: "dns-upstream",
      },
    ],
  },
  // {
  //   label: "网络管理",
  //   key: "net",
  //   icon: renderIcon(NetworkPublic),
  //   children: [
  //
  //   ],
  // },
  {
    label: "分流设置",
    key: "flow",
    icon: renderIcon(ModelBuilder),
  },
  {
    label: "Docker",
    key: "docker",
    icon: renderIcon(Docker),
  },
  {
    label: "连接信息",
    key: "metric",
    icon: renderIcon(ChartCombo),
  },
  {
    label: "地理关系库管理",
    key: "geo",
    icon: renderIcon(BookGlobe20Regular),
    children: [
      {
        label: "域名",
        key: "geo-domain",
      },
      {
        label: "IP",
        key: "geo-ip",
      },
    ],
  },
  {
    label: "WebShell",
    key: "web-pty",
    icon: renderIcon(Terminal),
  },
  {
    label: "系统配置",
    key: "config",
    icon: renderIcon(Settings),
  },
];
</script>
<template>
  <n-layout-sider
    position="relative"
    :native-scrollbar="false"
    bordered
    collapse-mode="width"
    :collapsed-width="64"
    :width="240"
    :collapsed="collapsed"
    show-trigger="bar"
    @collapse="collapsed = true"
    @expand="collapsed = false"
  >
    <n-layout position="absolute">
      <n-layout-header
        v-if="!collapsed"
        style="height: 30px; display: flex"
        bordered
      >
        <n-flex justify="center" style="flex: 1" align="center">
          Landscape
        </n-flex>
      </n-layout-header>
      <n-layout
        :native-scrollbar="false"
        position="absolute"
        style="top: 30px; bottom: 64px"
      >
        <!-- {{ menu_active_key }} -->
        <n-menu
          v-model:value="menu_active_key"
          @update:value="click_menu"
          :collapsed="collapsed"
          :collapsed-width="64"
          :collapsed-icon-size="22"
          :options="menuOptions"
        />
      </n-layout>
      <n-layout-footer
        bordered
        position="absolute"
        content-style="dispaly: flex; height: 30px"
      >
        <n-flex
          style="flex: 1; height: 30px"
          :justify="collapsed ? 'center' : 'start'"
          align="center"
        >
          <CopyRight :icon="true"></CopyRight>
        </n-flex>
      </n-layout-footer>
    </n-layout>
  </n-layout-sider>
</template>
