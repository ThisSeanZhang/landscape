<script setup lang="ts">
import { Handle, Position } from "@vue-flow/core";
import DHCPv4ServiceEditModal from "@/components/dhcp_v4/DHCPv4ServiceEditModal.vue";
import LanIPv6EditModal from "@/components/lan_ipv6/LanIPv6EditModal.vue";
import RouteLanServiceEditModal from "@/components/route/lan/RouteLanServiceEditModal.vue";
import RouteWanServiceEditModal from "@/components/route/wan/RouteWanServiceEditModal.vue";
import WanLinkEditModal from "@/components/wan_link/WanLinkEditModal.vue";
import WifiModeChange from "@/components/wifi/WifiModeChange.vue";
import WifiServiceEditModal from "@/components/wifi/WifiServiceEditModal.vue";
import { Add, Edit } from "@vicons/carbon";
import { useThemeVars } from "naive-ui";
import { changeColor } from "seemly";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

import { DevStateType, NetDev } from "@/lib/dev";
import {
  IfaceZoneType,
  type IfaceRealtimeStat,
  type LinkStatus,
  type WanLinkConfig,
} from "@landscape-router/types/api/schemas";
import { formatPackets, formatRate } from "@/lib/util";
import {
  ServiceExhibitSwitch,
  ServiceStatus,
  get_service_status_color,
  get_service_status_label,
} from "@/lib/services";
import {
  useWanLinkStore,
  wanLinkKind,
  wanLinkLabel,
  wanLinkNetIface,
  type WanLinkKind,
} from "@/stores/wan_link";
import { useWanLinkStatusStore } from "@/stores/status_wan_link";
import { useDHCPv4ConfigStore } from "@/stores/status_dhcp_v4";
import { useLanIPv6Store } from "@/stores/status_lan_ipv6";
import { useRouteLanConfigStore } from "@/stores/status_route_lan";
import { useRouteWanConfigStore } from "@/stores/status_route_wan";
import { useWifiConfigStore } from "@/stores/status_wifi";
import { useIfaceNodeStore } from "@/stores/iface_node";

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
const wanLinkStore = useWanLinkStore();
const wanLinkStatusStore = useWanLinkStatusStore();
const iface_dhcp_v4_service_edit_show = ref(false);
const iface_wifi_edit_show = ref(false);
const iface_lan_ipv6_edit_show = ref(false);
const show_route_lan_drawer = ref(false);
const show_route_wan_drawer = ref(false);

const show_link_modal = ref(false);
const editing_link = ref<WanLinkConfig | undefined>(undefined);
const create_link_kind = ref<WanLinkKind>("ethernet");

const dhcpv4ConfigStore = useDHCPv4ConfigStore();
const lanIpv6Store = useLanIPv6Store();
const wifiConfigStore = useWifiConfigStore();
const routeLanConfigStore = useRouteLanConfigStore();
const routeWanConfigStore = useRouteWanConfigStore();

const dhcp_v4_status = computed(
  () => dhcpv4ConfigStore.GET_STATUS_BY_IFACE_NAME(props.node.name).value,
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

const status_type = computed(() => {
  if (props.node.dev_status.t === DevStateType.Up) {
    return "success";
  }
  if (props.node.dev_status.t === DevStateType.Down) {
    return "error";
  }
  return "warning";
});

const status_text = computed(() => props.node.dev_status.t);

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

// ---- WAN links ----

const iface_links = computed(() =>
  is_wan_node.value ? wanLinkStore.byIface(props.node.name) : [],
);

function link_status(link_id: string | undefined): LinkStatus | undefined {
  if (!link_id) return undefined;
  return wanLinkStatusStore.status.get(link_id);
}

function link_state_color(state: LinkStatus["state"] | undefined) {
  if (!state) return themeVars.value.textColor3;
  switch (state) {
    case "running":
      return themeVars.value.successColor;
    case "starting":
    case "degraded":
      return themeVars.value.warningColor;
    case "failed":
      return themeVars.value.errorColor;
    default:
      return themeVars.value.textColor3;
  }
}

function link_state_label(state: LinkStatus["state"] | undefined) {
  if (!state) return t("common.not_configured");
  return t(`wan_link.state_${state}`);
}

function link_kind_label(link: WanLinkConfig) {
  switch (wanLinkKind(link)) {
    case "pppoe_native":
      return "PPPoE";
    case "pppd":
      return "pppd";
    default:
      return "eth";
  }
}

/** Live state of the ppp device a pppd link owns (folded into the link row). */
function link_net_dev(net_iface: string) {
  return ifaceNodeStore.net_devs.find((each) => each.name === net_iface);
}

function link_tooltip(link: WanLinkConfig) {
  const status = link_status(link.id);
  if (!status) {
    return `${wanLinkLabel(link)} · ${t("common.not_configured")}`;
  }
  const parts = [
    `session: ${get_service_status_label(status.session, t)}`,
    `PD: ${get_service_status_label(status.pd, t)}`,
    `NAT: ${get_service_status_label(status.nat, t)}`,
    `FW: ${get_service_status_label(status.firewall, t)}`,
    `MSS: ${get_service_status_label(status.mss, t)}`,
  ];
  return `${wanLinkLabel(link)} · ${link_state_label(status.state)}\n${parts.join(" · ")}`;
}

interface LinkServiceChip {
  key: "pd" | "nat" | "firewall" | "mss";
  short: string;
  status?: ServiceStatus;
  enabled: boolean;
}

/**
 * All four sub-service chips render on every link row (disabled ones greyed
 * out) so every row keeps the same two-line height and cards stay uniform.
 */
function link_service_chips(link: WanLinkConfig): LinkServiceChip[] {
  const status = link_status(link.id);
  return [
    {
      key: "pd",
      short: "PD",
      enabled: link.pd?.enable ?? false,
      status: status?.pd,
    },
    {
      key: "nat",
      short: "NAT",
      enabled: link.nat?.enable ?? false,
      status: status?.nat,
    },
    {
      key: "firewall",
      short: "FW",
      enabled: link.firewall?.enable ?? false,
      status: status?.firewall,
    },
    {
      key: "mss",
      short: "MSS",
      enabled: link.mss?.enable ?? false,
      status: status?.mss,
    },
  ];
}

function link_service_label(key: LinkServiceChip["key"]) {
  return t(`wan_link.tab_${key}`);
}

function link_chip_style(chip: LinkServiceChip) {
  if (!chip.enabled) {
    return {
      borderColor: changeColor(themeVars.value.textColor3, { alpha: 0.18 }),
      backgroundColor: "transparent",
      color: changeColor(themeVars.value.textColor3, { alpha: 0.55 }),
    };
  }
  return serviceStatusStyle(chip.status);
}

function link_chip_tooltip(chip: LinkServiceChip) {
  if (!chip.enabled) {
    return `${link_service_label(chip.key)} · ${t("common.disabled")}`;
  }
  return `${link_service_label(chip.key)} · ${serviceStatusText(chip.status)}`;
}

function open_link_edit(link: WanLinkConfig) {
  editing_link.value = link;
  show_link_modal.value = true;
}

function open_link_create() {
  editing_link.value = undefined;
  create_link_kind.value = "ethernet";
  show_link_modal.value = true;
}

async function refreshGraph() {
  await Promise.all([
    ifaceNodeStore.UPDATE_INFO(),
    wanLinkStatusStore.UPDATE_INFO(),
  ]);
}

function serviceStatusText(status?: ServiceStatus) {
  return get_service_status_label(status, t);
}

function serviceStatusStyle(status?: ServiceStatus) {
  const color = get_service_status_color(status, themeVars.value);

  return {
    borderColor: changeColor(color, { alpha: status ? 0.45 : 0.22 }),
    backgroundColor: changeColor(color, { alpha: status ? 0.12 : 0.06 }),
    color,
  };
}

function openServiceEditor(service_key: string) {
  switch (service_key) {
    case "dhcp_v4":
      iface_dhcp_v4_service_edit_show.value = true;
      break;
    case "wifi":
      iface_wifi_edit_show.value = true;
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
  }
}

const service_items = computed(() => {
  const items: Array<{
    key: string;
    label: string;
    short_label: string;
    status?: ServiceStatus;
  }> = [];

  if (show_switch.value.dhcp_v4) {
    items.push({
      key: "dhcp_v4",
      label: t("topology.panel.open_dhcp_v4"),
      short_label: "DHCPv4",
      status: dhcp_v4_status.value,
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
  "--topology-node-link-hover": changeColor(themeVars.value.primaryColor, {
    alpha: 0.08,
  }),
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
              <n-button
                v-if="is_wan_node"
                quaternary
                circle
                size="tiny"
                :focusable="false"
                :data-testid="`topology-node-${node.index}-wan-link-add`"
                :aria-label="t('wan_link.add_link')"
                @click.stop="open_link_create"
              >
                <template #icon>
                  <n-icon><Add /></n-icon>
                </template>
              </n-button>
              <WifiModeChange
                v-if="show_switch.wifi || show_switch.station"
                :iface_name="node.name"
                :wifi_info="node.wifi_mode"
                :show_switch="show_switch"
                @refresh="refreshGraph"
              />
              <n-tag size="small" :type="status_type" round>
                {{ status_text }}
              </n-tag>
              <n-tooltip
                v-if="show_switch.route_wan"
                trigger="hover"
                placement="bottom"
              >
                <template #trigger>
                  <span
                    class="topology-node__service-pill topology-node__service-pill--inline"
                    role="button"
                    tabindex="0"
                    :data-testid="`topology-node-${node.index}-service-route_wan`"
                    :style="serviceStatusStyle(route_wan_status)"
                    @click.stop="openServiceEditor('route_wan')"
                    @keydown.enter.stop.prevent="openServiceEditor('route_wan')"
                    @keydown.space.stop.prevent="openServiceEditor('route_wan')"
                  >
                    WR
                  </span>
                </template>
                {{
                  `${t("topology.panel.open_route_wan")} · ${serviceStatusText(route_wan_status)}`
                }}
              </n-tooltip>
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

          <div
            v-if="is_wan_node && iface_links.length > 0"
            class="topology-node__links"
          >
            <div
              v-for="link in iface_links"
              :key="link.id"
              class="topology-node__link-row"
              role="button"
              tabindex="0"
              :data-testid="`topology-node-${node.index}-wan-link-${link.id}`"
              @click.stop="open_link_edit(link)"
              @keydown.enter.stop.prevent="open_link_edit(link)"
            >
              <div class="topology-node__link-top">
                <n-tooltip trigger="hover" placement="top">
                  <template #trigger>
                    <span class="topology-node__link-main">
                      <span
                        class="topology-node__link-dot"
                        :style="{
                          backgroundColor: link_state_color(
                            link_status(link.id)?.state,
                          ),
                        }"
                      />
                      <n-performant-ellipsis
                        :tooltip="false"
                        style="max-width: 96px"
                      >
                        {{ wanLinkLabel(link) }}
                      </n-performant-ellipsis>
                      <n-tag size="tiny" round :bordered="false">
                        {{ link_kind_label(link) }}
                      </n-tag>
                    </span>
                  </template>
                  <span style="white-space: pre-line">{{
                    link_tooltip(link)
                  }}</span>
                </n-tooltip>

                <span
                  v-if="wanLinkKind(link) === 'pppd'"
                  class="topology-node__link-netdev"
                >
                  <span
                    class="topology-node__link-dot topology-node__link-dot--sm"
                    :style="{
                      backgroundColor:
                        link_net_dev(wanLinkNetIface(link))?.dev_status.t ===
                        DevStateType.Up
                          ? themeVars.successColor
                          : themeVars.borderColor,
                    }"
                  />
                  <n-performant-ellipsis
                    :tooltip="false"
                    style="max-width: 72px"
                  >
                    {{ wanLinkNetIface(link) }}
                  </n-performant-ellipsis>
                </span>

                <span class="topology-node__link-actions">
                  <n-button
                    quaternary
                    circle
                    size="tiny"
                    :focusable="false"
                    :data-testid="`topology-node-${node.index}-wan-link-edit`"
                    @click.stop="open_link_edit(link)"
                  >
                    <template #icon>
                      <n-icon><Edit /></n-icon>
                    </template>
                  </n-button>
                </span>
              </div>

              <div class="topology-node__link-chips">
                <n-tooltip
                  v-for="chip in link_service_chips(link)"
                  :key="chip.key"
                  trigger="hover"
                  placement="top"
                >
                  <template #trigger>
                    <span
                      class="topology-node__link-chip"
                      :class="{
                        'topology-node__link-chip--off': !chip.enabled,
                      }"
                      :data-testid="`topology-node-${node.index}-wan-link-${link.id}-chip-${chip.key}`"
                      :style="link_chip_style(chip)"
                    >
                      {{ chip.short }}
                    </span>
                  </template>
                  {{ link_chip_tooltip(chip) }}
                </n-tooltip>
              </div>
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
          {{ `${item.label} · ${serviceStatusText(item.status)}` }}
        </n-tooltip>
      </div>
    </div>

    <WanLinkEditModal
      v-model:show="show_link_modal"
      :attach_iface_name="node.name"
      :attach_mac="node.mac ?? null"
      :origin="editing_link"
      :initial_kind="create_link_kind"
      @refresh="refreshGraph"
    />
    <DHCPv4ServiceEditModal
      v-model:show="iface_dhcp_v4_service_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <LanIPv6EditModal
      v-model:show="iface_lan_ipv6_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      :mac="node.mac"
      @refresh="refreshGraph"
    />
    <WifiServiceEditModal
      v-model:show="iface_wifi_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
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

.topology-node__links {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-top: 8px;
  padding: 6px;
  border-radius: 10px;
  border: 1px dashed var(--topology-node-service-border);
  background: var(--topology-node-service-bg);
}

.topology-node__link-row {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
  padding: 2px 4px;
  border-radius: 8px;
  cursor: pointer;
  transition: background-color 0.18s ease;
}

.topology-node__link-row:hover {
  background: var(--topology-node-link-hover);
}

.topology-node__link-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  min-width: 0;
}

.topology-node__link-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  padding-left: 14px;
}

.topology-node__link-chip {
  display: inline-flex;
  align-items: center;
  padding: 1px 6px;
  border-radius: 999px;
  border: 1px solid;
  font-size: 10px;
  font-weight: 700;
  line-height: 1.4;
}

.topology-node__link-main {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  font-size: 12px;
  font-weight: 600;
  color: var(--topology-node-text);
}

.topology-node__link-dot {
  width: 8px;
  height: 8px;
  flex: none;
  border-radius: 999px;
}

.topology-node__link-dot--sm {
  width: 6px;
  height: 6px;
}

.topology-node__link-netdev {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
  font-size: 11px;
  color: var(--topology-node-muted);
}

.topology-node__link-actions {
  display: inline-flex;
  align-items: center;
  opacity: 0;
  transition: opacity 0.18s ease;
}

.topology-node__link-row:hover .topology-node__link-actions,
.topology-node__link-row:focus-visible .topology-node__link-actions {
  opacity: 1;
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

.topology-node__service-pill--inline {
  padding: 2px 6px;
  font-size: 10px;
  flex: none;
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
