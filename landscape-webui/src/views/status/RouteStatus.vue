<script lang="ts" setup>
import {
  get_route_status,
  type LanRouteMode,
  type RouteOwner,
  type RouteStatusView,
} from "@/api/route/status";
import { link_label } from "@/lib/wan_link";
import { useWanLinkStore } from "@/stores/wan_link";
import { NTag, type DataTableColumns } from "naive-ui";
import { computed, h, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import type {
  Ipv4LanRouteEntry,
  Ipv6LanRouteEntry,
  WanRouteEntry,
} from "@landscape-router/types/api/schemas";

const { t } = useI18n();
const wanLinkStore = useWanLinkStore();

const loading = ref(false);
const status = ref<RouteStatusView>({
  ipv4_wan: [],
  ipv6_wan: [],
  ipv4_lan: [],
  ipv6_lan: [],
});

function owner_label(owner: RouteOwner): string {
  if ("Link" in owner) {
    return link_label(wanLinkStore.links, owner.Link) || owner.Link;
  }
  return `netns:${owner.Netns}`;
}

function mode_label(mode: LanRouteMode): string {
  if (mode === "Reachable") {
    return t("route_status.mode_reachable");
  }
  if (mode === "WanReachable") {
    return t("route_status.mode_wan_reachable");
  }
  return t("route_status.mode_next_hop", {
    ip: mode.NextHop.next_hop_ip,
  });
}

const wan_columns = computed<DataTableColumns<WanRouteEntry>>(() => [
  {
    title: t("route_status.owner"),
    key: "owner",
    minWidth: 160,
    render: (row) => owner_label(row.owner),
  },
  {
    title: t("route_status.iface"),
    key: "iface_name",
    render: (row) => row.info.iface_name,
  },
  {
    title: t("route_status.iface_ip"),
    key: "iface_ip",
    render: (row) => row.info.iface_ip,
  },
  {
    title: t("route_status.gateway_ip"),
    key: "gateway_ip",
    render: (row) => row.info.gateway_ip,
  },
  {
    title: t("route_status.weight"),
    key: "weight",
    width: 90,
    render: (row) => row.info.weight,
  },
  {
    title: t("route_status.default_route"),
    key: "default_route",
    width: 110,
    render: (row) =>
      row.info.default_route
        ? h(NTag, { size: "small", type: "success" }, () =>
            t("route_status.default_route"),
          )
        : "-",
  },
  {
    title: t("route_status.source"),
    key: "is_docker",
    width: 110,
    render: (row) =>
      row.info.is_docker
        ? h(NTag, { size: "small", type: "info" }, () =>
            t("route_status.docker"),
          )
        : "-",
  },
]);

const lan_v4_columns = computed<DataTableColumns<Ipv4LanRouteEntry>>(() => [
  {
    title: t("route_status.owner"),
    key: "owner",
    minWidth: 140,
  },
  {
    title: t("route_status.iface"),
    key: "iface_name",
    render: (row) => row.info.iface_name,
  },
  {
    title: t("route_status.subnet"),
    key: "subnet",
    render: (row) => `${row.info.iface_ip}/${row.info.prefix}`,
  },
  {
    title: t("route_status.mode"),
    key: "mode",
    render: (row) => mode_label(row.info.mode),
  },
]);

const lan_v6_columns = computed<DataTableColumns<Ipv6LanRouteEntry>>(() => [
  {
    title: t("route_status.iface"),
    key: "iface_name",
    render: (row) => row.key.iface_name,
  },
  {
    title: t("route_status.subnet"),
    key: "subnet",
    render: (row) => `${row.key.subnet}/${row.key.prefix_len}`,
  },
  {
    title: t("route_status.iface_ip"),
    key: "iface_ip",
    render: (row) => row.info.iface_ip,
  },
  {
    title: t("route_status.mode"),
    key: "mode",
    render: (row) => mode_label(row.info.mode),
  },
]);

async function refresh() {
  try {
    loading.value = true;
    await wanLinkStore.UPDATE_INFO();
    status.value = await get_route_status();
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);
</script>

<template>
  <n-flex vertical style="flex: 1">
    <n-flex>
      <n-button :loading="loading" @click="refresh">{{
        t("common.refresh")
      }}</n-button>
    </n-flex>
    <n-tabs type="line" display-directive="show">
      <n-tab-pane name="wan" :tab="t('route_status.tab_wan')">
        <n-flex vertical>
          <n-h3 prefix="bar" style="margin: 4px 0">
            {{ t("route_status.ipv4_wan") }}
          </n-h3>
          <n-data-table
            :columns="wan_columns"
            :data="status.ipv4_wan"
            :bordered="false"
            size="small"
          />
          <n-h3 prefix="bar" style="margin: 4px 0">
            {{ t("route_status.ipv6_wan") }}
          </n-h3>
          <n-data-table
            :columns="wan_columns"
            :data="status.ipv6_wan"
            :bordered="false"
            size="small"
          />
        </n-flex>
      </n-tab-pane>
      <n-tab-pane name="lan" :tab="t('route_status.tab_lan')">
        <n-flex vertical>
          <n-h3 prefix="bar" style="margin: 4px 0">
            {{ t("route_status.ipv4_lan") }}
          </n-h3>
          <n-data-table
            :columns="lan_v4_columns"
            :data="status.ipv4_lan"
            :bordered="false"
            size="small"
          />
          <n-h3 prefix="bar" style="margin: 4px 0">
            {{ t("route_status.ipv6_lan") }}
          </n-h3>
          <n-data-table
            :columns="lan_v6_columns"
            :data="status.ipv6_lan"
            :bordered="false"
            size="small"
          />
        </n-flex>
      </n-tab-pane>
    </n-tabs>
  </n-flex>
</template>
