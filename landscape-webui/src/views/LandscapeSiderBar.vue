<script setup lang="ts">
import type { MenuOption } from "naive-ui";
import type { Component } from "vue";
import { computed, h, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute, useRouter } from "vue-router";
import { NIcon } from "naive-ui";

import {
  Settings,
  CicsSystemGroup,
  ModelBuilder,
  ChartCombo,
  ServerDns,
  Devices,
  Dashboard,
  Certificate,
  Gateway,
} from "@vicons/carbon";
import { Wall } from "@vicons/tabler";
import { Docker } from "@vicons/fa";
import { BookGlobe20Regular } from "@vicons/fluent";

import CopyRight from "@/components/CopyRight.vue";

const route = useRoute();
const router = useRouter();
const { t } = useI18n();

const menu_active_key = ref<string>("");

const activeMenuByPath: Record<string, string> = {
  "/metrics/conn/history-src": "metrics/conn/history",
  "/metrics/conn/history-dst": "metrics/conn/history",
};

watch(
  () => route.path,
  (path) => {
    const menuPath = activeMenuByPath[path] ?? path;
    const key = menuPath.startsWith("/") ? menuPath.substring(1) : menuPath;
    menu_active_key.value = key;
  },
  { immediate: true },
);
const collapsed = ref(true);

function click_menu(key: string) {
  router.push({
    path: `/${key}`,
  });
}

function renderIcon(icon: Component) {
  return () => h(NIcon, null, { default: () => h(icon) });
}

const menuOptions = computed<MenuOption[]>(() => [
  {
    label: t("routes.dashboard"),
    key: "",
    icon: renderIcon(CicsSystemGroup),
  },
  {
    label: t("routes.flow"),
    key: "flow",
    icon: renderIcon(ModelBuilder),
  },
  {
    label: t("routes.mac-binding"),
    key: "mac-binding",
    icon: renderIcon(Devices),
  },
  {
    label: t("routes.network-status"),
    key: "network-status",
    icon: renderIcon(Dashboard),
    children: [
      {
        label: t("routes.dhcp-v4"),
        key: "network/dhcp-v4",
        disabled: false,
      },
      {
        label: t("routes.ipv6-pd"),
        key: "network/ipv6-pd",
      },
      {
        label: t("routes.ipv6-ra"),
        key: "network/ipv6-ra",
        disabled: false,
      },
    ],
  },
  {
    label: t("routes.firewall-nat"),
    key: "firewall-nat",
    icon: renderIcon(Wall),
    children: [
      {
        label: t("routes.firewall"),
        key: "firewall-nat/firewall",
      },
      {
        label: t("routes.nat-v4"),
        key: "firewall-nat/nat/v4",
      },
      {
        label: t("routes.nat-v6"),
        key: "firewall-nat/nat/v6",
      },
    ],
  },
  {
    label: t("routes.dns"),
    key: "dns",
    icon: renderIcon(ServerDns),
    children: [
      {
        label: t("routes.dns-upstream"),
        key: "dns/upstream",
      },
      {
        label: t("routes.dns-redirect"),
        key: "dns/redirect",
      },
    ],
  },
  {
    label: t("routes.geo"),
    key: "geo",
    icon: renderIcon(BookGlobe20Regular),
    children: [
      {
        label: t("routes.geo-domain"),
        key: "geo/domain",
      },
      {
        label: t("routes.geo-ip"),
        key: "geo/ip",
      },
    ],
  },
  {
    label: t("routes.domains"),
    key: "domains",
    icon: renderIcon(Certificate),
    children: [
      {
        label: t("routes.dns-provider-profiles"),
        key: "domains/dns-providers",
      },
      {
        label: t("routes.ddns"),
        key: "domains/ddns",
      },
      {
        label: t("routes.cert-accounts"),
        key: "domains/cert-accounts",
      },
      {
        label: t("routes.certs"),
        key: "domains/certs",
      },
    ],
  },
  {
    label: t("routes.gateway"),
    key: "gateway",
    icon: renderIcon(Gateway),
  },
  {
    label: t("routes.docker"),
    key: "docker",
    icon: renderIcon(Docker),
  },
  {
    label: t("routes.metric-group"),
    key: "metric-group",
    icon: renderIcon(ChartCombo),
    children: [
      {
        label: t("routes.dns-metric"),
        key: "metrics/dns",
      },
      {
        label: t("routes.connect-live"),
        key: "metrics/conn/live",
      },
      {
        label: t("routes.connect-iface"),
        key: "metrics/conn/iface",
      },
      {
        label: t("routes.connect-src"),
        key: "metrics/conn/src",
      },
      {
        label: t("routes.connect-dst"),
        key: "metrics/conn/dst",
      },
      {
        label: t("routes.connect-history"),
        key: "metrics/conn/history",
      },
    ],
  },
  {
    label: t("routes.config"),
    key: "config",
    icon: renderIcon(Settings),
  },
]);
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
