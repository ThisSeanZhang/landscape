<script setup lang="ts">
import type { MenuOption } from "naive-ui";
import type { Component } from "vue";
import { computed, h, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
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
  Devices,
  Dashboard,
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
const { t } = useI18n();

const menu_active_key = ref<string>("");

watch(
  () => route.path,
  (path) => {
    // Remove the leading slash to match menu keys
    const key = path.startsWith("/") ? path.substring(1) : path;
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
    label: t("routes.status"),
    key: "status",
    icon: renderIcon(Dashboard),
    children: [
      {
        label: t("routes.dhcp-v4"),
        key: "dhcp-v4",
        disabled: false,
      },
      {
        label: t("routes.ipv6-pd"),
        key: "ipv6-pd",
      },
      {
        label: t("routes.ipv6-ra"),
        key: "ipv6-ra",
        disabled: false,
      },
    ],
  },
  {
    label: t("routes.nat"),
    key: "nat",
    icon: renderIcon(ImportExportRound),
    disabled: false,
  },
  {
    label: t("routes.firewall"),
    key: "firewall",
    icon: renderIcon(Wall),
  },
  {
    label: t("routes.dns"),
    key: "dns",
    icon: renderIcon(ServerDns),
    children: [
      {
        label: t("routes.dns-redirect"),
        key: "dns-redirect",
      },
      {
        label: t("routes.dns-upstream"),
        key: "dns-upstream",
      },
    ],
  },
  {
    label: t("routes.flow"),
    key: "flow",
    icon: renderIcon(ModelBuilder),
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
        label: t("routes.connect-info"),
        key: "connect-info",
        children: [
          {
            label: t("routes.connect-live"),
            key: "metric/conn/live",
          },
          {
            label: t("routes.connect-src"),
            key: "metric/conn/src",
          },
          {
            label: t("routes.connect-dst"),
            key: "metric/conn/dst",
          },
          {
            label: t("routes.connect-history"),
            key: "metric/conn/history",
          },
        ],
      },
      {
        label: t("routes.dns-metric"),
        key: "metric/dns",
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
        key: "geo-domain",
      },
      {
        label: t("routes.geo-ip"),
        key: "geo-ip",
      },
    ],
  },
  {
    label: t("routes.mac-binding"),
    key: "mac-binding",
    icon: renderIcon(Devices),
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
