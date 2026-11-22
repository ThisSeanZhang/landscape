<script setup lang="ts">
import { computed, ref, watch, type Component } from "vue";
import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";
import { ChevronRight } from "@vicons/carbon";
import { changeColor } from "seemly";
import type { ServiceStatus } from "@landscape-router/types/api/schemas";
import type { NetDev } from "@/lib/network/dev";
import {
  ServiceExhibitSwitch,
  get_service_status_color,
  get_service_status_label,
} from "@/lib/network/services";
import { useWanLinkStore } from "@/stores/wan_link";
import DHCPv4ServiceEditModal from "@/components/dhcp_v4/DHCPv4ServiceEditModal.vue";
import FirewallServiceEditModal from "@/components/firewall/FirewallServiceEditModal.vue";
import HealthCheckEditModal from "@/components/health_check/HealthCheckEditModal.vue";
import LanIPv6EditModal from "@/components/lan_ipv6/LanIPv6EditModal.vue";
import IpConfigModal from "@/components/ipconfig/IpConfigModal.vue";
import IPv6PDEditModal from "@/components/ipv6pd/IPv6PDEditModal.vue";
import MSSClampServiceEditModal from "@/components/mss_clamp/MSSClampServiceEditModal.vue";
import NATEditModal from "@/components/nat/NATEditModal.vue";
import RouteLanServiceEditModal from "@/components/route/lan/RouteLanServiceEditModal.vue";
import RouteWanServiceEditModal from "@/components/route/wan/RouteWanServiceEditModal.vue";
import WifiServiceEditModal from "@/components/wifi/WifiServiceEditModal.vue";
import { useDHCPv4ConfigStore } from "@/stores/status_dhcp_v4";
import { useLanIPv6Store } from "@/stores/status_lan_ipv6";
import { useRouteLanConfigStore } from "@/stores/status_route_lan";
import { useRouteWanConfigStore } from "@/stores/status_route_wan";
import { useWifiConfigStore } from "@/stores/status_wifi";

const { node, list = false } = defineProps<{ node: NetDev; list?: boolean }>();
const emit = defineEmits<{ refresh: [] }>();
const { t } = useI18n();
const theme = useThemeVars();
const wan = useWanLinkStore();
const dhcp = useDHCPv4ConfigStore();
const lanV6 = useLanIPv6Store();
const wifi = useWifiConfigStore();
const lanRoute = useRouteLanConfigStore();
const wanRoute = useRouteWanConfigStore();
const editing = ref<string>();
// The detail drawer also works when dashboard polling is paused.
watch(
  [() => list, () => node.zone_type, () => node.wifi_info?.wifi_type.t],
  () => {
    if (!list) return;
    const show = new ServiceExhibitSwitch(node);
    const requests = [];
    if (show.ip_config || show.nat_config) requests.push(wan.UPDATE_INFO());
    if (show.dhcp_v4) requests.push(dhcp.UPDATE_INFO());
    if (show.lan_ipv6) requests.push(lanV6.UPDATE_INFO());
    if (show.route_lan) requests.push(lanRoute.UPDATE_INFO());
    if (show.route_wan) requests.push(wanRoute.UPDATE_INFO());
    if (show.wifi) requests.push(wifi.UPDATE_INFO());
    void Promise.allSettled(requests);
  },
  { immediate: true },
);

function sectionStatus(
  enabled?: boolean,
  status?: ServiceStatus,
): ServiceStatus | undefined {
  if (enabled === false) return { t: "disabled" };
  return status;
}

const services = computed(() => {
  const show = new ServiceExhibitSwitch(node);
  const name = { iface_name: node.name };
  const iface = { ...name, zone: node.zone_type };
  const link = wan.RESOLVE_NODE_LINK(node.name).value;
  const status = link && wan.status.get(link.id);
  const health = link?.health_check.enable
    ? (wan.health.get(link.id) ?? "unknown")
    : undefined;
  const items: {
    key: string;
    short: string;
    label: string;
    status?: ServiceStatus;
    editor: Component;
    props: {
      iface_name: string;
      zone?: NetDev["zone_type"];
      mac?: string | null;
    };
    verdict?: string;
  }[] = [];
  if (show.mss_clamp)
    items.push({
      key: "mss_clamp",
      short: "MSS",
      label: t("topology.panel.open_mss_clamp"),
      status: sectionStatus(link?.mss.enable, status?.mss),
      editor: MSSClampServiceEditModal,
      props: name,
    });
  if (show.health_check)
    items.push({
      key: "health_check",
      short: "HC",
      label: t("topology.panel.open_health_check"),
      status: sectionStatus(link?.health_check.enable, status?.health_check),
      verdict: health && t("route_status.health_" + health),
      editor: HealthCheckEditModal,
      props: name,
    });
  if (show.ip_config)
    items.push({
      key: "ip_config",
      short: "IP",
      label: t("topology.panel.open_ip_config"),
      status: sectionStatus(
        link && link.v4.enable && link.v4.model.t !== "nothing",
        status?.session,
      ),
      editor: IpConfigModal,
      props: iface,
    });
  if (show.dhcp_v4)
    items.push({
      key: "dhcp_v4",
      short: "DHCPv4",
      label: t("topology.panel.open_dhcp_v4"),
      status: dhcp.GET_STATUS_BY_IFACE_NAME(node.name).value,
      editor: DHCPv4ServiceEditModal,
      props: iface,
    });
  if (show.nat_config)
    items.push({
      key: "nat",
      short: "NAT",
      label: t("topology.panel.open_nat"),
      status: sectionStatus(link?.nat.enable, status?.nat4),
      editor: NATEditModal,
      props: iface,
    });
  if (show.firewall)
    items.push({
      key: "firewall",
      short: "FW",
      label: t("topology.panel.open_firewall"),
      status: sectionStatus(link?.firewall.enable, status?.firewall),
      editor: FirewallServiceEditModal,
      props: iface,
    });
  const withMac = { ...iface, mac: node.mac };
  if (show.wifi)
    items.push({
      key: "wifi",
      short: "WF",
      label: t("topology.panel.open_wifi"),
      status: wifi.GET_STATUS_BY_IFACE_NAME(node.name).value,
      editor: WifiServiceEditModal,
      props: iface,
    });
  if (show.ipv6pd)
    items.push({
      key: "ipv6pd",
      short: "PD",
      label: t("topology.panel.open_ipv6pd"),
      status: sectionStatus(link?.pd.enable, status?.pd),
      editor: IPv6PDEditModal,
      props: { ...withMac, mac: node.mac ?? null },
    });
  if (show.lan_ipv6)
    items.push({
      key: "lan_ipv6",
      short: "LANv6",
      label: t("topology.panel.open_lanv6"),
      status: lanV6.GET_STATUS_BY_IFACE_NAME(node.name).value,
      editor: LanIPv6EditModal,
      props: withMac,
    });
  if (show.route_lan)
    items.push({
      key: "route_lan",
      short: "LR",
      label: t("topology.panel.open_route_lan"),
      status: lanRoute.GET_STATUS_BY_IFACE_NAME(node.name).value,
      editor: RouteLanServiceEditModal,
      props: name,
    });
  if (show.route_wan)
    items.push({
      key: "route_wan",
      short: "WR",
      label: t("topology.panel.open_route_wan"),
      status: wanRoute.GET_STATUS_BY_IFACE_NAME(node.name).value,
      editor: RouteWanServiceEditModal,
      props: iface,
    });
  return items;
});
function pillStyle(status?: ServiceStatus) {
  const color = get_service_status_color(status, theme.value);
  return {
    borderColor: changeColor(color, { alpha: status ? 0.45 : 0.22 }),
    backgroundColor: changeColor(color, { alpha: status ? 0.12 : 0.06 }),
    color,
  };
}
</script>
<template>
  <section
    v-if="list && services.length"
    class="service-list"
    :aria-label="t('topology.panel.services')"
  >
    <h4>{{ t("topology.panel.services") }}</h4>
    <button
      v-for="item in services"
      :key="item.key"
      type="button"
      class="service-row"
      :disabled="node.virtual"
      @click="editing = item.key"
    >
      <span>{{ item.label }}</span>
      <span
        class="service-state"
        :style="{ color: get_service_status_color(item.status, theme) }"
        >{{ get_service_status_label(item.status, t)
        }}<template v-if="item.verdict"> · {{ item.verdict }}</template></span
      >
      <n-icon :component="ChevronRight" aria-hidden="true" />
    </button>
  </section>
  <div v-else-if="!list && services.length" class="service-pills">
    <n-tooltip v-for="item in services" :key="item.key" trigger="hover">
      <template #trigger>
        <button
          type="button"
          class="service-pill"
          :disabled="node.virtual"
          :aria-label="item.label"
          :data-testid="`topology-node-${node.index}-service-${item.key}`"
          :style="pillStyle(item.status)"
          @click.stop="editing = item.key"
          @keydown.enter.stop
          @keydown.space.stop
        >
          {{ item.short }}
        </button>
      </template>
      {{ item.label }} ·
      {{
        node.virtual
          ? t("pppoe.service_locked_hint")
          : get_service_status_label(item.status, t)
      }}<template v-if="!node.virtual && item.verdict">
        · {{ item.verdict }}</template
      >
    </n-tooltip>
  </div>
  <component
    v-for="item in services"
    :key="item.key"
    :is="item.editor"
    v-bind="item.props"
    :show="editing === item.key"
    @update:show="
      (show: boolean) => {
        if (!show && editing === item.key) editing = undefined;
      }
    "
    @refresh="emit('refresh')"
  />
</template>
<style scoped>
.service-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.service-pill {
  font-family: inherit;
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
  padding: 3px 7px;
  border: 1px solid;
  border-radius: 999px;
  cursor: pointer;
}
.service-pill:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.service-list {
  padding: 0 12px;
  border: 1px solid v-bind("theme.dividerColor");
  border-radius: 10px;
}
.service-list h4 {
  margin: 0;
  padding: 10px 0 5px;
  color: v-bind("theme.textColor2");
  font-size: 13px;
}
.service-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto;
  align-items: center;
  gap: 8px;
  width: 100%;
  min-height: 44px;
  padding: 6px 0;
  text-align: start;
  font: inherit;
  color: inherit;
  background: transparent;
  border: 0;
  cursor: pointer;
}
.service-row + .service-row {
  border-top: 1px solid v-bind("theme.dividerColor");
}
.service-state {
  font-size: 12px;
}
.service-row .n-icon {
  color: v-bind("theme.textColor3");
}
</style>
