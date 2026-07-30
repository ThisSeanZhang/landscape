<script setup lang="ts">
import { Handle, Position } from "@vue-flow/core";
import DHCPv4ServiceEditModal from "@/components/dhcp_v4/DHCPv4ServiceEditModal.vue";
import FirewallServiceEditModal from "@/components/firewall/FirewallServiceEditModal.vue";
import LanIPv6EditModal from "@/components/lan_ipv6/LanIPv6EditModal.vue";
import IpConfigModal from "@/components/ipconfig/IpConfigModal.vue";
import IPv6PDEditModal from "@/components/ipv6pd/IPv6PDEditModal.vue";
import MSSClampServiceEditModal from "@/components/mss_clamp/MSSClampServiceEditModal.vue";
import NATEditModal from "@/components/nat/NATEditModal.vue";
import PPPDServiceListDrawer from "@/components/pppd/PPPDServiceListDrawer.vue";
import RouteLanServiceEditModal from "@/components/route/lan/RouteLanServiceEditModal.vue";
import RouteWanServiceEditModal from "@/components/route/wan/RouteWanServiceEditModal.vue";
import WifiModeChange from "@/components/wifi/WifiModeChange.vue";
import WifiServiceEditModal from "@/components/wifi/WifiServiceEditModal.vue";
import { Link } from "@vicons/carbon";
import { useThemeVars } from "naive-ui";
import { changeColor } from "seemly";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

import { DevStateType, NetDev } from "@/lib/dev";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import { formatPackets, formatRate } from "@/lib/util";
import {
  ServiceExhibitSwitch,
  ServiceStatus,
  get_service_status_color,
  get_service_status_label,
} from "@/lib/services";
import { useDHCPv4ConfigStore } from "@/stores/status_dhcp_v4";
import { useFirewallConfigStore } from "@/stores/status_firewall";
import { useIpConfigStore } from "@/stores/status_ipconfig";
import { useIPv6PDStore } from "@/stores/status_ipv6pd";
import { useLanIPv6Store } from "@/stores/status_lan_ipv6";
import { useMSSClampConfigStore } from "@/stores/status_mss_clamp";
import { useNATConfigStore } from "@/stores/status_nats";
import { useRouteLanConfigStore } from "@/stores/status_route_lan";
import { useRouteWanConfigStore } from "@/stores/status_route_wan";
import { useWifiConfigStore } from "@/stores/status_wifi";
import { useIfaceNodeStore } from "@/stores/iface_node";
import type { IfaceRealtimeStat } from "@landscape-router/types/api/schemas";

const props = withDefaults(
  defineProps<{
    node: NetDev;
    metric?: IfaceRealtimeStat;
    selected?: boolean;
    dimmed?: boolean;
  }>(),
  {
    selected: false,
    dimmed: false,
  },
);

const { t } = useI18n();
const themeVars = useThemeVars();
const show_switch = computed(() => new ServiceExhibitSwitch(props.node));
const ifaceNodeStore = useIfaceNodeStore();
const show_mss_clamp_edit = ref(false);
const iface_dhcp_v4_service_edit_show = ref(false);
const iface_wifi_edit_show = ref(false);
const iface_firewall_edit_show = ref(false);
const iface_lan_ipv6_edit_show = ref(false);
const iface_ipv6pd_edit_show = ref(false);
const iface_nat_edit_show = ref(false);
const iface_service_edit_show = ref(false);
const show_pppd_drawer = ref(false);
const show_route_lan_drawer = ref(false);
const show_route_wan_drawer = ref(false);

const ipConfigStore = useIpConfigStore();
const dhcpv4ConfigStore = useDHCPv4ConfigStore();
const natConfigStore = useNATConfigStore();
const firewallConfigStore = useFirewallConfigStore();
const ipv6PDStore = useIPv6PDStore();
const lanIpv6Store = useLanIPv6Store();
const wifiConfigStore = useWifiConfigStore();
const routeLanConfigStore = useRouteLanConfigStore();
const routeWanConfigStore = useRouteWanConfigStore();
const mssClampConfigStore = useMSSClampConfigStore();

const ip_config_status = computed(
  () => ipConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const dhcp_v4_status = computed(
  () => dhcpv4ConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const nat_status = computed(
  () => natConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const firewall_status = computed(
  () => firewallConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const ipv6pd_status = computed(
  () => ipv6PDStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const lan_ipv6_status = computed(
  () => lanIpv6Store.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const wifi_status = computed(
  () => wifiConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const route_lan_status = computed(
  () => routeLanConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const route_wan_status = computed(
  () => routeWanConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);
const mss_clamp_status = computed(
  () => mssClampConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
);

const status_type = computed(() => {
  if (props.node.dev_status.t === DevStateType.Up) {
    return "success";
  }
  if (props.node.dev_status.t === DevStateType.Down) {
    return "error";
  }
  return "warning";
});

const zone_type = computed(() => {
  if (props.node.zone_type === IfaceZoneType.wan) {
    return "warning";
  }
  if (props.node.zone_type === IfaceZoneType.lan) {
    return "info";
  }
  return "default";
});

const role_tags = computed(() => {
  const tags: string[] = [];

  if (props.node.dev_kind === "bridge") {
    tags.push("bridge");
  }

  if (props.node.wifi_info) {
    tags.push(props.node.wifi_info.wifi_type.t);
  } else if (props.node.dev_type) {
    tags.push(props.node.dev_type);
  }

  return tags.slice(0, 2);
});

const is_wan_node = computed(() => props.node.zone_type === IfaceZoneType.wan);
const node_width = computed(() => (is_wan_node.value ? 235 : 235));
const title_max_width = computed(
  () => `${Math.max(node_width.value - 126, 140)}px`,
);
const has_metric = computed(
  () =>
    props.metric !== undefined &&
    ((props.metric.stats.ingress_bps || 0) > 0 ||
      (props.metric.stats.egress_bps || 0) > 0 ||
      (props.metric.stats.active_conns || 0) > 0),
);

function serviceStatusText(status?: ServiceStatus) {
  return get_service_status_label(status, t);
}

function serviceStatusColor(status?: ServiceStatus) {
  return get_service_status_color(status, themeVars.value);
}

function serviceStatusStyle(status?: ServiceStatus) {
  const color = serviceStatusColor(status);

  return {
    borderColor: changeColor(color, { alpha: status ? 0.45 : 0.22 }),
    backgroundColor: changeColor(color, { alpha: status ? 0.12 : 0.06 }),
    color,
  };
}

async function refreshGraph() {
  await ifaceNodeStore.UPDATE_INFO();
}

function openServiceEditor(service_key: string) {
  switch (service_key) {
    case "ip_config":
      iface_service_edit_show.value = true;
      break;
    case "dhcp_v4":
      iface_dhcp_v4_service_edit_show.value = true;
      break;
    case "nat":
      iface_nat_edit_show.value = true;
      break;
    case "firewall":
      iface_firewall_edit_show.value = true;
      break;
    case "wifi":
      iface_wifi_edit_show.value = true;
      break;
    case "ipv6pd":
      iface_ipv6pd_edit_show.value = true;
      break;
    case "lan_ipv6":
      iface_lan_ipv6_edit_show.value = true;
      break;
    case "route_lan":
      show_route_lan_drawer.value = true;
      break;
    case "route_wan":
      show_route_wan_drawer.value = true;
      break;
    case "mss_clamp":
      show_mss_clamp_edit.value = true;
      break;
    case "pppd":
      show_pppd_drawer.value = true;
      break;
  }
}

const service_items = computed(() => {
  const items: Array<{
    key: string;
    label: string;
    short_label: string;
    status?: ServiceStatus;
  }> = [];

  if (show_switch.value.mss_clamp) {
    items.push({
      key: "mss_clamp",
      label: t("topology.panel.open_mss_clamp"),
      short_label: "MSS",
      status: mss_clamp_status.value,
    });
  }
  if (show_switch.value.ip_config) {
    items.push({
      key: "ip_config",
      label: t("topology.panel.open_ip_config"),
      short_label: "IP",
      status: ip_config_status.value,
    });
  }
  if (show_switch.value.dhcp_v4) {
    items.push({
      key: "dhcp_v4",
      label: t("topology.panel.open_dhcp_v4"),
      short_label: "DHCPv4",
      status: dhcp_v4_status.value,
    });
  }
  if (show_switch.value.nat_config) {
    items.push({
      key: "nat",
      label: t("topology.panel.open_nat"),
      short_label: "NAT",
      status: nat_status.value,
    });
  }
  if (show_switch.value.firewall) {
    items.push({
      key: "firewall",
      label: t("topology.panel.open_firewall"),
      short_label: "FW",
      status: firewall_status.value,
    });
  }
  if (show_switch.value.wifi) {
    items.push({
      key: "wifi",
      label: t("topology.panel.open_wifi"),
      short_label: "WF",
      status: wifi_status.value,
    });
  }
  if (show_switch.value.ipv6pd) {
    items.push({
      key: "ipv6pd",
      label: t("topology.panel.open_ipv6pd"),
      short_label: "PD",
      status: ipv6pd_status.value,
    });
  }
  if (show_switch.value.lan_ipv6) {
    items.push({
      key: "lan_ipv6",
      label: t("topology.panel.open_lanv6"),
      short_label: "LANv6",
      status: lan_ipv6_status.value,
    });
  }
  if (show_switch.value.route_lan) {
    items.push({
      key: "route_lan",
      label: t("topology.panel.open_route_lan"),
      short_label: "LR",
      status: route_lan_status.value,
    });
  }
  if (show_switch.value.route_wan) {
    items.push({
      key: "route_wan",
      label: t("topology.panel.open_route_wan"),
      short_label: "WR",
      status: route_wan_status.value,
    });
  }

  return items;
});

const node_style = computed(() => ({
  "--topology-node-width": `${node_width.value}px`,
  "--topology-node-title-max": title_max_width.value,
  "--topology-node-border": themeVars.value.borderColor,
  "--topology-node-bg": changeColor(themeVars.value.cardColor, { alpha: 0.98 }),
  "--topology-node-bg-soft": changeColor(themeVars.value.tableColor, {
    alpha: 0.82,
  }),
  "--topology-node-shadow": "none",
  "--topology-node-selected-border": changeColor(themeVars.value.primaryColor, {
    alpha: 0.5,
  }),
  "--topology-node-selected-shadow": `0 18px 36px ${changeColor(themeVars.value.primaryColor, { alpha: 0.18 })}, 0 0 0 1px ${changeColor(themeVars.value.primaryColor, { alpha: 0.18 })}`,
  "--topology-node-text": themeVars.value.textColor1,
  "--topology-node-muted": themeVars.value.textColor3,
  "--topology-node-carrier-ring": changeColor(themeVars.value.textColor3, {
    alpha: 0.12,
  }),
  "--topology-node-service-bg": changeColor(themeVars.value.bodyColor, {
    alpha: 0.68,
  }),
  "--topology-node-service-border": themeVars.value.borderColor,
  "--topology-node-service-text": themeVars.value.textColor3,
  "--topology-node-egress": themeVars.value.infoColor,
  "--topology-node-ingress": themeVars.value.successColor,
  "--topology-node-handle-bg": changeColor(themeVars.value.primaryColor, {
    alpha: 0.9,
  }),
  "--topology-node-handle-ring": changeColor(themeVars.value.cardColor, {
    alpha: 0.98,
  }),
  "--topology-node-handle-shadow": `0 0 0 4px ${changeColor(themeVars.value.primaryColor, { alpha: 0.12 })}`,
}));
</script>

<template>
  <div
    class="topology-node"
    :class="{ 'is-selected': selected, 'is-dimmed': dimmed }"
    :data-testid="`topology-node-${node.index}`"
    :style="node_style"
  >
    <div class="topology-node__main">
      <div class="topology-node__card-shell">
        <Handle
          v-if="node.has_target_hook()"
          type="target"
          :position="Position.Left"
          class="topology-node__handle"
        />

        <div class="topology-node__card">
          <div class="topology-node__title-row">
            <div class="topology-node__title">
              <span
                class="topology-node__carrier"
                :style="{
                  backgroundColor: node.carrier
                    ? themeVars.successColor
                    : themeVars.borderColor,
                }"
              />
              <n-performant-ellipsis
                :tooltip="false"
                style="max-width: var(--topology-node-title-max)"
              >
                {{ node.name }}
              </n-performant-ellipsis>
            </div>
            <div class="topology-node__header-actions">
              <WifiModeChange
                v-if="show_switch.wifi || show_switch.station"
                :iface_name="node.name"
                :wifi_info="node.wifi_mode"
                :show_switch="show_switch"
                @refresh="refreshGraph"
              />
              <n-button
                v-if="show_switch.pppd"
                quaternary
                circle
                size="tiny"
                :focusable="false"
                data-testid="topology-node-open-pppd"
                @click.stop="show_pppd_drawer = true"
              >
                <template #icon>
                  <n-icon><Link /></n-icon>
                </template>
              </n-button>
              <n-tag size="small" :type="status_type" round>
                {{ node.dev_status.t }}
              </n-tag>
            </div>
          </div>

          <div class="topology-node__tags">
            <n-tag size="tiny" :type="zone_type" round>
              {{ node.zone_type }}
            </n-tag>
            <n-tag v-for="tag in role_tags" :key="tag" size="tiny" tertiary>
              {{ tag }}
            </n-tag>
          </div>

          <div v-if="has_metric && metric" class="topology-node__metric">
            <div class="topology-node__metric-row">
              <span
                class="topology-node__metric-label topology-node__metric-label--egress"
                >↑</span
              >
              <span>{{ formatRate(metric.stats.egress_bps || 0) }}</span>
              <span class="topology-node__metric-pps">{{
                formatPackets(metric.stats.egress_pps || 0)
              }}</span>
            </div>
            <div class="topology-node__metric-row">
              <span
                class="topology-node__metric-label topology-node__metric-label--ingress"
                >↓</span
              >
              <span>{{ formatRate(metric.stats.ingress_bps || 0) }}</span>
              <span class="topology-node__metric-pps">{{
                formatPackets(metric.stats.ingress_pps || 0)
              }}</span>
            </div>
          </div>
        </div>

        <Handle
          v-if="node.has_source_hook()"
          type="source"
          :position="Position.Right"
          class="topology-node__handle"
        />
      </div>

      <div v-if="service_items.length" class="topology-node__services">
        <n-tooltip
          v-for="item in service_items"
          :key="item.key"
          trigger="hover"
        >
          <template #trigger>
            <span
              class="topology-node__service-pill"
              role="button"
              tabindex="0"
              :data-testid="`topology-node-${node.index}-service-${item.key}`"
              :style="serviceStatusStyle(item.status)"
              @click.stop="openServiceEditor(item.key)"
              @keydown.enter.stop.prevent="openServiceEditor(item.key)"
              @keydown.space.stop.prevent="openServiceEditor(item.key)"
            >
              <span>{{ item.short_label }}</span>
            </span>
          </template>
          {{ item.label }} · {{ serviceStatusText(item.status) }}
        </n-tooltip>
      </div>
    </div>

    <PPPDServiceListDrawer
      v-model:show="show_pppd_drawer"
      :attach_iface_name="node.name"
      @refresh="refreshGraph"
    />
    <IpConfigModal
      v-model:show="iface_service_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <DHCPv4ServiceEditModal
      v-model:show="iface_dhcp_v4_service_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <NATEditModal
      v-model:show="iface_nat_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <IPv6PDEditModal
      v-model:show="iface_ipv6pd_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      :mac="node.mac ?? null"
      @refresh="refreshGraph"
    />
    <LanIPv6EditModal
      v-model:show="iface_lan_ipv6_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      :mac="node.mac"
      @refresh="refreshGraph"
    />
    <FirewallServiceEditModal
      v-model:show="iface_firewall_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <WifiServiceEditModal
      v-model:show="iface_wifi_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <MSSClampServiceEditModal
      v-model:show="show_mss_clamp_edit"
      :iface_name="node.name"
    />
    <RouteLanServiceEditModal
      v-model:show="show_route_lan_drawer"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <RouteWanServiceEditModal
      v-model:show="show_route_wan_drawer"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
  </div>
</template>

<style scoped>
.topology-node {
  position: relative;
  width: var(--topology-node-width);
  box-sizing: border-box;
  transition:
    opacity 0.18s ease,
    filter 0.18s ease;
}

.topology-node.is-dimmed {
  opacity: 0.34;
  filter: saturate(0.55);
}

.topology-node.is-dimmed .topology-node__card {
  box-shadow: none;
}

.topology-node.is-dimmed .topology-node__services {
  opacity: 0.7;
}

.topology-node__main {
  display: flex;
  width: var(--topology-node-width);
  flex-direction: column;
  gap: 8px;
  box-sizing: border-box;
}

.topology-node__card-shell {
  position: relative;
  width: var(--topology-node-width);
  box-sizing: border-box;
}

.topology-node__card {
  width: var(--topology-node-width);
  min-height: 78px;
  padding: 10px 12px;
  border-radius: 16px;
  border: 1px solid var(--topology-node-border);
  background: linear-gradient(
    180deg,
    var(--topology-node-bg),
    var(--topology-node-bg-soft)
  );
  box-shadow: var(--topology-node-shadow);
  transition:
    border-color 0.2s ease,
    box-shadow 0.2s ease,
    transform 0.2s ease;
  box-sizing: border-box;
}

.is-selected .topology-node__card {
  border-color: var(--topology-node-selected-border);
  box-shadow: var(--topology-node-selected-shadow);
  transform: translateY(-1px);
}

.topology-node__title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.topology-node__header-actions {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.topology-node__title {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: var(--topology-node-text);
}

.topology-node__carrier {
  width: 9px;
  height: 9px;
  flex: none;
  border-radius: 999px;
  box-shadow: 0 0 0 4px var(--topology-node-carrier-ring);
}

.topology-node__tags {
  display: flex;
  margin-top: 8px;
  flex-wrap: wrap;
  gap: 6px;
}

.topology-node__metric {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
  margin-top: 8px;
  color: var(--topology-node-text);
  font-variant-numeric: tabular-nums;
}

.topology-node__metric-row {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
  padding: 4px 6px;
  border-radius: 8px;
  background: var(--topology-node-service-bg);
  font-size: 11px;
  font-weight: 650;
  line-height: 1.1;
  white-space: nowrap;
}

.topology-node__metric-label {
  font-weight: 800;
}

.topology-node__metric-label--egress {
  color: var(--topology-node-egress);
}

.topology-node__metric-label--ingress {
  color: var(--topology-node-ingress);
}

.topology-node__metric-pps {
  overflow: hidden;
  color: var(--topology-node-muted);
  font-size: 10px;
  text-overflow: ellipsis;
}

.topology-node__services {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  width: var(--topology-node-width);
  box-sizing: border-box;
}

.topology-node__service-pill {
  display: inline-flex;
  align-items: center;
  padding: 3px 7px;
  border-radius: 999px;
  border: 1px solid var(--topology-node-service-border);
  background: var(--topology-node-service-bg);
  color: var(--topology-node-service-text);
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
  cursor: pointer;
  transition:
    background-color 0.18s ease,
    border-color 0.18s ease,
    transform 0.18s ease;
}

.topology-node__service-pill:hover {
  transform: translateY(-1px);
}

.topology-node__service-pill--muted {
  opacity: 0.78;
}

.topology-node__handle {
  width: 12px;
  height: 12px;
  opacity: 1;
  z-index: 2;
  cursor: crosshair;
  pointer-events: auto;
  background: var(--topology-node-handle-bg);
  border: 2px solid var(--topology-node-handle-ring);
  box-shadow: var(--topology-node-handle-shadow);
}
</style>
