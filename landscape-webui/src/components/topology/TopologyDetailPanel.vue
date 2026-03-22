<script setup lang="ts">
import DHCPv4ServiceEditModal from "@/components/dhcp_v4/DHCPv4ServiceEditModal.vue";
import FirewallServiceEditModal from "@/components/firewall/FirewallServiceEditModal.vue";
import IfaceChangeZone from "@/components/iface/IfaceChangeZone.vue";
import IfaceCpuSoftBalance from "@/components/iface/IfaceCpuSoftBalance.vue";
import IfaceDisableGuardModal from "@/components/iface/IfaceDisableGuardModal.vue";
import ICMPRaEditModal from "@/components/icmp_ra/ICMPRaEditModal.vue";
import IpConfigModal from "@/components/ipconfig/IpConfigModal.vue";
import IPv6PDEditModal from "@/components/ipv6pd/IPv6PDEditModal.vue";
import MSSClampServiceEditModal from "@/components/mss_clamp/MSSClampServiceEditModal.vue";
import NATEditModal from "@/components/nat/NATEditModal.vue";
import PPPDServiceListDrawer from "@/components/pppd/PPPDServiceListDrawer.vue";
import RouteLanServiceEditModal from "@/components/route/lan/RouteLanServiceEditModal.vue";
import RouteWanServiceEditModal from "@/components/route/wan/RouteWanServiceEditModal.vue";
import WifiServiceEditModal from "@/components/wifi/WifiServiceEditModal.vue";
import {
  add_controller,
  change_iface_status,
  change_wifi_mode,
  delete_bridge,
} from "@/api/network";
import { stop_and_del_iface_wifi } from "@/api/service_wifi";
import { DevStateType, NetDev, WifiMode, WLANTypeTag } from "@/lib/dev";
import { ZoneType } from "@/lib/service_ipconfig";
import {
  ServiceExhibitSwitch,
  ServiceStatus,
  ServiceStatusType,
} from "@/lib/services";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useIfaceNodeStore } from "@/stores/iface_node";
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
import { useMessage, useThemeVars } from "naive-ui";
import { changeColor } from "seemly";
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";

const props = defineProps<{
  node: NetDev;
}>();

const emit = defineEmits(["close"]);

const { t } = useI18n();
const message = useMessage();
const frontEndStore = useFrontEndStore();
const ifaceNodeStore = useIfaceNodeStore();
const themeVars = useThemeVars();

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

const show_mss_clamp_edit = ref(false);
const iface_dhcp_v4_service_edit_show = ref(false);
const iface_wifi_edit_show = ref(false);
const iface_firewall_edit_show = ref(false);
const iface_lan_ipv6_edit_show = ref(false);
const iface_ipv6pd_edit_show = ref(false);
const iface_nat_edit_show = ref(false);
const iface_service_edit_show = ref(false);
const show_zone_change = ref(false);
const show_pppd_drawer = ref(false);
const show_route_lan_drawer = ref(false);
const show_route_wan_drawer = ref(false);
const show_cpu_balance_btn = ref(false);
const delete_loading = ref(false);
const selected_bridge_ifindex = ref<number | null>(null);
const disable_guard_modal = ref<InstanceType<
  typeof IfaceDisableGuardModal
> | null>(null);

watch(
  () => props.node.index,
  () => {
    selected_bridge_ifindex.value = null;
  },
  { immediate: true },
);

const show_switch = computed(() => new ServiceExhibitSwitch(props.node));

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

const has_controller = computed(() => props.node.controller_id !== undefined);
const controller_dev = computed(() => {
  if (!has_controller.value) {
    return undefined;
  }

  return ifaceNodeStore.FIND_DEV_BY_IFINDEX(props.node.controller_id!);
});
const child_devices = computed(() =>
  ifaceNodeStore.visible_net_devs.filter(
    (dev) => dev.controller_id === props.node.index,
  ),
);
const available_bridge_options = computed(() =>
  ifaceNodeStore.bridges
    .filter((bridge) => bridge.ifindex !== props.node.index)
    .map((bridge) => ({ label: bridge.label, value: bridge.ifindex })),
);
const can_manage_controller = computed(() => {
  if (props.node.dev_kind === "bridge") {
    return false;
  }
  if (props.node.zone_type === ZoneType.Wan) {
    return false;
  }
  return true;
});
const controller_hint = computed(() => {
  if (!can_manage_controller.value) {
    return t("misc.topology_panel.connect_unavailable");
  }
  if (has_controller.value) {
    return "";
  }
  if (
    props.node.wifi_info &&
    props.node.wifi_info.wifi_type.t !== WLANTypeTag.Ap
  ) {
    return t("misc.topology_panel.wifi_client_hint");
  }
  if (available_bridge_options.value.length === 0) {
    return t("misc.topology_panel.no_bridges");
  }
  return t("misc.topology_panel.connect_hint");
});
const service_sections = computed(() => {
  const sections: Array<{
    key: string;
    short_label: string;
    label: string;
    status?: ServiceStatus;
  }> = [];

  if (show_switch.value.mss_clamp) {
    sections.push({
      key: "mss_clamp",
      short_label: "MSS",
      label: t("misc.topology_panel.open_mss_clamp"),
      status: mss_clamp_status.value,
    });
  }
  if (show_switch.value.ip_config) {
    sections.push({
      key: "ip_config",
      short_label: "IP",
      label: t("misc.topology_panel.open_ip_config"),
      status: ip_config_status.value,
    });
  }
  if (show_switch.value.dhcp_v4) {
    sections.push({
      key: "dhcp_v4",
      short_label: "D4",
      label: t("misc.topology_panel.open_dhcp_v4"),
      status: dhcp_v4_status.value,
    });
  }
  if (show_switch.value.nat_config) {
    sections.push({
      key: "nat",
      short_label: "NAT",
      label: t("misc.topology_panel.open_nat"),
      status: nat_status.value,
    });
  }
  if (show_switch.value.firewall) {
    sections.push({
      key: "firewall",
      short_label: "FW",
      label: t("misc.topology_panel.open_firewall"),
      status: firewall_status.value,
    });
  }
  if (show_switch.value.wifi) {
    sections.push({
      key: "wifi",
      short_label: "WF",
      label: t("misc.topology_panel.open_wifi"),
      status: wifi_status.value,
    });
  }
  if (show_switch.value.ipv6pd) {
    sections.push({
      key: "ipv6pd",
      short_label: "PD",
      label: t("misc.topology_panel.open_ipv6pd"),
      status: ipv6pd_status.value,
    });
  }
  if (show_switch.value.lan_ipv6) {
    sections.push({
      key: "lan_ipv6",
      short_label: "RA",
      label: t("misc.topology_panel.open_icmpv6_ra"),
      status: lan_ipv6_status.value,
    });
  }
  if (show_switch.value.route_lan) {
    sections.push({
      key: "route_lan",
      short_label: "LR",
      label: t("misc.topology_panel.open_route_lan"),
      status: route_lan_status.value,
    });
  }
  if (show_switch.value.route_wan) {
    sections.push({
      key: "route_wan",
      short_label: "WR",
      label: t("misc.topology_panel.open_route_wan"),
      status: route_wan_status.value,
    });
  }
  if (show_switch.value.pppd) {
    sections.push({
      key: "pppd",
      short_label: "PPP",
      label: t("misc.topology_panel.configure_pppd"),
    });
  }

  return sections;
});
const wifi_mode_target_label = computed(() =>
  show_switch.value.wifi
    ? t("misc.topology_panel.switch_to_client")
    : t("misc.topology_panel.switch_to_ap"),
);
const panelStyle = computed(() => ({
  "--topology-panel-border": themeVars.value.borderColor,
  "--topology-panel-bg": changeColor(themeVars.value.cardColor, {
    alpha: 0.98,
  }),
  "--topology-panel-bg-soft": changeColor(themeVars.value.bodyColor, {
    alpha: 0.94,
  }),
  "--topology-panel-header-bg": changeColor(themeVars.value.bodyColor, {
    alpha: 0.92,
  }),
  "--topology-panel-shadow": `0 14px 30px ${changeColor(
    themeVars.value.textColor1,
    {
      alpha: 0.12,
    },
  )}`,
  "--topology-panel-card-border": themeVars.value.borderColor,
  "--topology-panel-card-shadow": "none",
  "--topology-panel-rail-bg": changeColor(themeVars.value.bodyColor, {
    alpha: 0.9,
  }),
  "--topology-panel-rail-hover": changeColor(themeVars.value.primaryColor, {
    alpha: 0.08,
  }),
  "--topology-panel-muted": themeVars.value.textColor3,
  "--topology-panel-text": themeVars.value.textColor1,
}));

function closePanel() {
  emit("close");
}

function maskValue(value?: string | null) {
  const masked = frontEndStore.MASK_INFO(value ?? "N/A");
  return masked || "N/A";
}

function displayValue(value?: string | number | null) {
  if (value === undefined || value === null || value === "") {
    return "N/A";
  }
  return `${value}`;
}

function boolLabel(value: boolean) {
  return value ? t("misc.topology_panel.yes") : t("misc.topology_panel.no");
}

function statusTagType(state: string) {
  if (state === DevStateType.Up) {
    return "success";
  }
  if (state === DevStateType.Down) {
    return "error";
  }
  return "warning";
}

function zoneTagType(zone: ZoneType) {
  if (zone === ZoneType.Wan) {
    return "warning";
  }
  if (zone === ZoneType.Lan) {
    return "info";
  }
  return "default";
}

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

async function refreshGraph() {
  await ifaceNodeStore.UPDATE_INFO();
}

async function changeDeviceStatus() {
  if (props.node.dev_status.t === DevStateType.Up) {
    if (disable_guard_modal.value) {
      await disable_guard_modal.value.check_and_execute(async () => {
        await change_iface_status(props.node.name, false);
        await refreshGraph();
      });
    } else {
      await change_iface_status(props.node.name, false);
      await refreshGraph();
    }
  } else {
    await change_iface_status(props.node.name, true);
    await refreshGraph();
  }
}

async function removeController() {
  await add_controller({
    link_name: props.node.name,
    link_ifindex: props.node.index,
    master_name: null,
    master_ifindex: null,
  });
  await refreshGraph();
}

async function attachController() {
  if (selected_bridge_ifindex.value === null) {
    return;
  }

  if (
    props.node.wifi_info &&
    props.node.wifi_info.wifi_type.t !== WLANTypeTag.Ap
  ) {
    message.warning(t("misc.topology.wifi_client_mode_warning"));
    return;
  }

  const bridge = ifaceNodeStore.bridges.find(
    (item) => item.ifindex === selected_bridge_ifindex.value,
  );
  if (!bridge) {
    return;
  }

  await add_controller({
    link_name: props.node.name,
    link_ifindex: props.node.index,
    master_name: bridge.label,
    master_ifindex: bridge.ifindex,
  });
  selected_bridge_ifindex.value = null;
  await refreshGraph();
}

async function switchWifiMode() {
  const next_mode = show_switch.value.wifi ? WifiMode.Client : WifiMode.AP;
  await stop_and_del_iface_wifi(props.node.name);
  await change_wifi_mode(props.node.name, next_mode);
  await refreshGraph();
}

async function handleDeleteBridge() {
  try {
    delete_loading.value = true;
    await delete_bridge(props.node.name);
    await refreshGraph();
    message.info(t("misc.topology_node.delete_success"));
    closePanel();
  } catch (_error) {
    message.error(t("misc.topology_node.delete_failed"));
  } finally {
    delete_loading.value = false;
  }
}
</script>

<template>
  <div class="topology-detail-shell" :style="panelStyle">
    <div v-if="service_sections.length" class="topology-detail__rail-shell">
      <div class="topology-detail__rail">
        <n-tooltip
          v-for="section in service_sections"
          :key="section.key"
          trigger="hover"
        >
          <template #trigger>
            <button
              type="button"
              class="topology-detail__rail-button"
              @click="openServiceEditor(section.key)"
            >
              <span class="topology-detail__rail-label">
                {{ section.short_label }}
              </span>
              <span
                class="topology-detail__rail-dot"
                :style="{ backgroundColor: serviceStatusColor(section.status) }"
              />
            </button>
          </template>
          {{ section.label }} · {{ serviceStatusText(section.status) }}
        </n-tooltip>
      </div>
    </div>

    <div class="topology-detail">
      <div class="topology-detail__header">
        <div class="topology-detail__header-main">
          <div class="topology-detail__eyebrow">
            {{ t("misc.topology_panel.summary") }}
          </div>
          <div class="topology-detail__title-row">
            <h3 class="topology-detail__title">{{ node.name }}</h3>
            <n-button quaternary circle size="small" @click="closePanel">
              ×
            </n-button>
          </div>
          <n-flex size="small" wrap>
            <n-tag size="small" :type="statusTagType(node.dev_status.t)" round>
              {{ node.dev_status.t }}
            </n-tag>
            <n-tag size="small" :type="zoneTagType(node.zone_type)" round>
              {{ node.zone_type }}
            </n-tag>
            <n-tag size="small" tertiary>
              {{ node.dev_kind || node.dev_type }}
            </n-tag>
            <n-tag v-if="node.wifi_info" size="small" tertiary>
              {{ node.wifi_info.wifi_type.t }}
            </n-tag>
          </n-flex>
        </div>
      </div>

      <n-scrollbar class="topology-detail__content">
        <div class="topology-detail__content-inner">
          <n-flex vertical size="large">
            <n-card size="small" embedded>
              <template #header>
                {{ t("misc.topology_panel.basic_info") }}
              </template>
              <n-descriptions label-placement="left" :column="1" size="small">
                <n-descriptions-item
                  :label="t('misc.topology_node.iface_name')"
                >
                  {{ node.name }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('misc.topology_panel.ifindex')">
                  {{ node.index }}
                </n-descriptions-item>
                <n-descriptions-item
                  :label="t('misc.topology_node.device_type')"
                >
                  {{ displayValue(node.dev_type) }}/{{
                    displayValue(node.dev_kind)
                  }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('misc.topology_node.status')">
                  {{ node.dev_status.t }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('misc.topology_panel.carrier')">
                  {{ boolLabel(node.carrier) }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('misc.topology_panel.boot')">
                  {{ boolLabel(node.enable_in_boot) }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('misc.topology_panel.zone')">
                  {{ node.zone_type }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('misc.topology_node.mac_addr')">
                  {{ maskValue(node.mac) }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('misc.topology_node.perm_mac')">
                  {{ maskValue(node.perm_mac) }}
                </n-descriptions-item>
                <n-descriptions-item
                  :label="t('misc.topology_panel.wifi_type')"
                >
                  {{
                    node.wifi_info
                      ? node.wifi_info.wifi_type.t
                      : displayValue(undefined)
                  }}
                </n-descriptions-item>
                <n-descriptions-item
                  :label="t('misc.topology_panel.peer_link')"
                >
                  {{ displayValue(node.peer_link_id) }}
                </n-descriptions-item>
              </n-descriptions>
            </n-card>

            <n-card size="small" embedded>
              <template #header>
                {{ t("misc.topology_panel.relationship") }}
              </template>
              <n-flex vertical size="small">
                <n-descriptions label-placement="left" :column="1" size="small">
                  <n-descriptions-item :label="t('misc.topology_panel.parent')">
                    <n-flex align="center" justify="space-between" wrap>
                      <span>
                        {{
                          controller_dev?.name ??
                          (has_controller ? node.controller_name : undefined) ??
                          t("misc.topology_panel.no_parent")
                        }}
                      </span>
                      <n-button
                        v-if="has_controller"
                        tertiary
                        size="tiny"
                        @click="removeController"
                      >
                        {{ t("misc.topology_node.disconnect") }}
                      </n-button>
                    </n-flex>
                  </n-descriptions-item>
                  <n-descriptions-item
                    :label="t('misc.topology_panel.children')"
                  >
                    <n-flex v-if="child_devices.length" wrap size="small">
                      <n-tag
                        v-for="child in child_devices"
                        :key="child.index"
                        size="small"
                        tertiary
                      >
                        {{ child.name }}
                      </n-tag>
                    </n-flex>
                    <span v-else>{{
                      t("misc.topology_panel.no_children")
                    }}</span>
                  </n-descriptions-item>
                </n-descriptions>

                <div
                  v-if="can_manage_controller"
                  class="topology-detail__controller-box"
                >
                  <n-text depth="3">
                    {{ controller_hint }}
                  </n-text>
                  <n-input-group
                    v-if="
                      !has_controller &&
                      available_bridge_options.length > 0 &&
                      (!node.wifi_info ||
                        node.wifi_info.wifi_type.t === WLANTypeTag.Ap)
                    "
                  >
                    <n-select
                      v-model:value="selected_bridge_ifindex"
                      :options="available_bridge_options"
                      :placeholder="t('misc.topology_panel.select_bridge')"
                      clearable
                    />
                    <n-button
                      type="primary"
                      ghost
                      :disabled="selected_bridge_ifindex === null"
                      @click="attachController"
                    >
                      {{ t("misc.topology_panel.attach_bridge") }}
                    </n-button>
                  </n-input-group>
                </div>
              </n-flex>
            </n-card>

            <n-card size="small" embedded>
              <template #header>
                {{ t("misc.topology_panel.actions") }}
              </template>
              <n-flex wrap size="small">
                <n-popconfirm
                  v-if="show_switch.enable_in_boot"
                  @positive-click="changeDeviceStatus"
                >
                  <template #trigger>
                    <n-button tertiary size="small">
                      {{
                        node.dev_status.t === DevStateType.Up
                          ? t("misc.topology_node.action_disable")
                          : t("misc.topology_node.action_enable")
                      }}
                    </n-button>
                  </template>
                  {{
                    t("misc.topology_node.confirm_toggle_iface", {
                      action:
                        node.dev_status.t === DevStateType.Up
                          ? t("misc.topology_node.action_disable")
                          : t("misc.topology_node.action_enable"),
                    })
                  }}
                </n-popconfirm>

                <n-button
                  v-if="show_switch.zone_type"
                  tertiary
                  size="small"
                  @click="show_zone_change = true"
                >
                  {{ t("misc.topology_panel.change_zone") }}
                </n-button>

                <n-button
                  tertiary
                  size="small"
                  @click="show_cpu_balance_btn = true"
                >
                  {{ t("misc.topology_panel.edit_cpu_balance") }}
                </n-button>

                <n-popconfirm
                  v-if="show_switch.wifi || show_switch.station"
                  @positive-click="switchWifiMode"
                >
                  <template #trigger>
                    <n-button tertiary size="small">
                      {{ wifi_mode_target_label }}
                    </n-button>
                  </template>
                  {{ t("misc.topology_panel.confirm_switch_wifi_mode") }}
                </n-popconfirm>

                <n-popconfirm
                  v-if="
                    node.dev_kind === 'bridge' &&
                    node.name !== 'docker0' &&
                    node.dev_status.t === DevStateType.Down
                  "
                  :show-icon="false"
                  :positive-button-props="{ type: 'error', ghost: true }"
                  :positive-text="t('misc.topology_node.delete_btn')"
                  @positive-click="handleDeleteBridge"
                >
                  <template #trigger>
                    <n-button
                      tertiary
                      size="small"
                      type="error"
                      :loading="delete_loading"
                    >
                      {{ t("misc.topology_panel.delete_bridge") }}
                    </n-button>
                  </template>
                  {{ t("misc.topology_node.delete_bridge") }}
                </n-popconfirm>
              </n-flex>
            </n-card>
          </n-flex>
        </div>
      </n-scrollbar>
    </div>

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
    <IfaceChangeZone
      v-model:show="show_zone_change"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <PPPDServiceListDrawer
      v-model:show="show_pppd_drawer"
      :attach_iface_name="node.name"
      @refresh="refreshGraph"
    />
    <IPv6PDEditModal
      v-model:show="iface_ipv6pd_edit_show"
      :zone="node.zone_type"
      :iface_name="node.name"
      :mac="node.mac ?? null"
      @refresh="refreshGraph"
    />
    <ICMPRaEditModal
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
    <IfaceCpuSoftBalance
      v-model:show="show_cpu_balance_btn"
      :iface_name="node.name"
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
    <IfaceDisableGuardModal
      ref="disable_guard_modal"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
  </div>
</template>

<style scoped>
.topology-detail-shell {
  display: flex;
  width: 100%;
  height: 100%;
  align-items: flex-start;
  gap: 14px;
}

.topology-detail {
  display: flex;
  height: 100%;
  min-width: 0;
  flex: 1;
  min-height: 0;
  flex-direction: column;
  overflow: hidden;
  border: 1px solid var(--topology-panel-border);
  border-radius: 22px;
  background: linear-gradient(
    180deg,
    var(--topology-panel-bg),
    var(--topology-panel-bg-soft)
  );
  box-shadow: var(--topology-panel-shadow);
  color: var(--topology-panel-text);
  backdrop-filter: blur(16px);
}

.topology-detail__header {
  flex: none;
  padding: 18px 18px 14px;
  border-bottom: 1px solid var(--topology-panel-border);
  background: var(--topology-panel-header-bg);
}

.topology-detail__header-main {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.topology-detail__eyebrow {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--topology-panel-muted);
}

.topology-detail__title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.topology-detail__title {
  margin: 0;
  font-size: 20px;
  line-height: 1.1;
}

.topology-detail__rail-shell {
  display: flex;
  height: 100%;
  flex: none;
  align-items: flex-start;
  padding-top: 76px;
}

.topology-detail__rail {
  display: flex;
  width: 54px;
  flex: none;
  flex-direction: column;
  align-items: center;
  gap: 10px;
}

.topology-detail__rail-button {
  display: inline-flex;
  width: 46px;
  height: 46px;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 4px;
  border: 1px solid var(--topology-panel-card-border);
  border-radius: 14px;
  background: var(--topology-panel-bg);
  color: var(--topology-panel-text);
  cursor: pointer;
  transition:
    background-color 0.18s ease,
    border-color 0.18s ease,
    transform 0.18s ease;
}

.topology-detail__rail-button:hover {
  background: var(--topology-panel-rail-hover);
  transform: translateY(-1px);
}

.topology-detail__rail-label {
  font-size: 11px;
  line-height: 1;
  font-weight: 600;
}

.topology-detail__rail-dot {
  width: 6px;
  height: 6px;
  border-radius: 999px;
}

.topology-detail__content {
  min-width: 0;
  flex: 1;
}

.topology-detail__content-inner {
  padding: 16px;
}

.topology-detail :deep(.n-card) {
  border: 1px solid var(--topology-panel-card-border);
  box-shadow: var(--topology-panel-card-shadow);
}

.topology-detail__controller-box {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-top: 4px;
}

@media (max-width: 960px) {
  .topology-detail-shell {
    flex-direction: column;
    gap: 10px;
  }

  .topology-detail {
    border-radius: 20px 20px 0 0;
  }

  .topology-detail__rail-shell {
    width: 100%;
    height: auto;
    padding-top: 0;
  }

  .topology-detail__rail {
    width: 100%;
    flex-direction: row;
    justify-content: flex-start;
    overflow-x: auto;
    padding: 0 2px;
  }
}
</style>
