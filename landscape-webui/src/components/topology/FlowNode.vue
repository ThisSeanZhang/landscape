<script setup lang="ts">
import { Handle, Position } from "@vue-flow/core";
import { useThemeVars } from "naive-ui";
import { changeColor } from "seemly";
import { computed } from "vue";
import { useI18n } from "vue-i18n";

import { DevStateType, NetDev } from "@/lib/dev";
import { ZoneType } from "@/lib/service_ipconfig";
import {
  ServiceExhibitSwitch,
  ServiceStatus,
  ServiceStatusType,
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

const props = withDefaults(
  defineProps<{
    node: NetDev;
    selected?: boolean;
  }>(),
  {
    selected: false,
  },
);

const { t } = useI18n();
const themeVars = useThemeVars();
const show_switch = computed(() => new ServiceExhibitSwitch(props.node));

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
  if (props.node.zone_type === ZoneType.Wan) {
    return "warning";
  }
  if (props.node.zone_type === ZoneType.Lan) {
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

const is_wan_node = computed(() => props.node.zone_type === ZoneType.Wan);
const node_width = computed(() => (is_wan_node.value ? 360 : 280));
const title_max_width = computed(
  () => `${Math.max(node_width.value - 126, 140)}px`,
);

const meta_text = computed(() => {
  if (props.node.controller_id !== undefined && props.node.controller_name) {
    return `${props.node.dev_kind || props.node.dev_type} <- ${props.node.controller_name}`;
  }

  return props.node.dev_kind || props.node.dev_type || props.node.name;
});

function serviceStatusText(status?: ServiceStatus) {
  if (!status) {
    return t("common.not_configured");
  }

  switch (status.t) {
    case ServiceStatusType.Staring:
      return t("common.starting");
    case ServiceStatusType.Running:
      return t("common.running");
    case ServiceStatusType.Stopping:
      return t("common.stopping");
    case ServiceStatusType.Stop:
      return t("common.stopped");
  }
}

function serviceStatusColor(status?: ServiceStatus) {
  if (!status) {
    return themeVars.value.textColor3;
  }

  return status.t === ServiceStatusType.Stop
    ? themeVars.value.errorColor
    : themeVars.value.successColor;
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
      label: t("misc.topology_panel.open_mss_clamp"),
      short_label: "MSS",
      status: mss_clamp_status.value,
    });
  }
  if (show_switch.value.ip_config) {
    items.push({
      key: "ip_config",
      label: t("misc.topology_panel.open_ip_config"),
      short_label: "IP",
      status: ip_config_status.value,
    });
  }
  if (show_switch.value.dhcp_v4) {
    items.push({
      key: "dhcp_v4",
      label: t("misc.topology_panel.open_dhcp_v4"),
      short_label: "D4",
      status: dhcp_v4_status.value,
    });
  }
  if (show_switch.value.nat_config) {
    items.push({
      key: "nat",
      label: t("misc.topology_panel.open_nat"),
      short_label: "NAT",
      status: nat_status.value,
    });
  }
  if (show_switch.value.firewall) {
    items.push({
      key: "firewall",
      label: t("misc.topology_panel.open_firewall"),
      short_label: "FW",
      status: firewall_status.value,
    });
  }
  if (show_switch.value.wifi) {
    items.push({
      key: "wifi",
      label: t("misc.topology_panel.open_wifi"),
      short_label: "WF",
      status: wifi_status.value,
    });
  }
  if (show_switch.value.ipv6pd) {
    items.push({
      key: "ipv6pd",
      label: t("misc.topology_panel.open_ipv6pd"),
      short_label: "PD",
      status: ipv6pd_status.value,
    });
  }
  if (show_switch.value.lan_ipv6) {
    items.push({
      key: "lan_ipv6",
      label: t("misc.topology_panel.open_icmpv6_ra"),
      short_label: "RA",
      status: lan_ipv6_status.value,
    });
  }
  if (show_switch.value.route_lan) {
    items.push({
      key: "route_lan",
      label: t("misc.topology_panel.open_route_lan"),
      short_label: "LR",
      status: route_lan_status.value,
    });
  }
  if (show_switch.value.route_wan) {
    items.push({
      key: "route_wan",
      label: t("misc.topology_panel.open_route_wan"),
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
    :class="{ 'is-selected': selected }"
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
            <n-tag size="small" :type="status_type" round>
              {{ node.dev_status.t }}
            </n-tag>
          </div>

          <div class="topology-node__tags">
            <n-tag size="tiny" :type="zone_type" round>
              {{ node.zone_type }}
            </n-tag>
            <n-tag v-for="tag in role_tags" :key="tag" size="tiny" tertiary>
              {{ tag }}
            </n-tag>
          </div>

          <div class="topology-node__meta">
            {{ meta_text }}
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
            <span class="topology-node__service-pill">
              <span
                class="topology-node__service-dot"
                :style="{ backgroundColor: serviceStatusColor(item.status) }"
              />
              <span>{{ item.short_label }}</span>
            </span>
          </template>
          {{ item.label }} · {{ serviceStatusText(item.status) }}
        </n-tooltip>
      </div>
    </div>
  </div>
</template>

<style scoped>
.topology-node {
  position: relative;
  width: var(--topology-node-width);
}

.topology-node__main {
  display: flex;
  width: var(--topology-node-width);
  flex-direction: column;
  gap: 8px;
}

.topology-node__card-shell {
  position: relative;
  width: var(--topology-node-width);
}

.topology-node__card {
  width: var(--topology-node-width);
  min-height: 98px;
  padding: 12px 14px;
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
  margin-top: 10px;
  flex-wrap: wrap;
  gap: 6px;
}

.topology-node__meta {
  margin-top: 10px;
  font-size: 12px;
  color: var(--topology-node-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.topology-node__services {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 0 4px;
}

.topology-node__service-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 7px;
  border-radius: 999px;
  border: 1px solid var(--topology-node-service-border);
  background: var(--topology-node-service-bg);
  color: var(--topology-node-service-text);
  font-size: 11px;
  line-height: 1;
}

.topology-node__service-pill--muted {
  opacity: 0.78;
}

.topology-node__service-dot {
  width: 6px;
  height: 6px;
  flex: none;
  border-radius: 999px;
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
