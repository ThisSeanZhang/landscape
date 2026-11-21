<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";
import {
  ChevronRight,
  Network3,
  NetworkPublic,
  Router,
  Wifi,
} from "@vicons/carbon";
import { get_visible_devices, useIfaceNodeStore } from "@/stores/iface_node";
import type { NetDev } from "@/lib/network/dev";
import TopologyDetailPanel from "./TopologyDetailPanel.vue";
import PPPDCreateConfigModal from "@/components/pppd/CreatePPPDConfigModal.vue";

const { t } = useI18n();
const theme = useThemeVars();
const interfaces = useIfaceNodeStore();
const devices = computed(() => get_visible_devices(interfaces.net_devs, false));
const selectedIndex = ref<number>();
const selected = computed(() =>
  devices.value.find((dev) => dev.index === selectedIndex.value),
);
const virtualLink = computed(() =>
  selected.value?.virtual ? selected.value.wan_link : undefined,
);

function close() {
  selectedIndex.value = undefined;
}
watch(selected, (dev) => {
  if (!dev) close();
});
function refresh() {
  // The store exposes the failure to the list and to the global poller.
  return interfaces.UPDATE_INFO().catch(() => {});
}
onMounted(refresh);

function role(dev: NetDev) {
  if (dev.controller_id !== undefined) {
    const bridge =
      dev.controller_name ||
      interfaces.FIND_DEV_BY_IFINDEX(dev.controller_id)?.name;
    if (bridge) return t("topology.bridge_member", { name: bridge });
  }
  const zone =
    dev.zone_type === "undefined"
      ? t("interface.zone_undefined")
      : dev.zone_type.toUpperCase();
  return dev.dev_kind === "bridge" ? zone + " · " + t("topology.bridge") : zone;
}
function status(dev: NetDev) {
  if (dev.virtual)
    return t(
      dev.wan_link?.v4.enable
        ? "pppoe.status_not_dialed"
        : "pppoe.status_disabled",
    );
  return t("topology.link_state." + dev.dev_status.t);
}
</script>

<template>
  <section class="interface-list" :aria-label="t('topology.interfaces')">
    <div
      v-if="interfaces.loadState === 'failed'"
      class="list-notice"
      role="status"
    >
      {{ t("topology.load_failed") }}
      <n-button size="small" secondary @click="refresh">{{
        t("common.retry")
      }}</n-button>
    </div>
    <div v-else-if="!devices.length" class="list-notice" role="status">
      {{
        t(
          interfaces.loadState === "ready"
            ? "topology.empty_interfaces"
            : "common.sample_pending",
        )
      }}
    </div>
    <button
      v-for="dev in devices"
      :key="dev.index"
      type="button"
      class="interface-row"
      @click="selectedIndex = dev.index"
    >
      <span class="device-icon" :class="dev.zone_type">
        <n-icon
          :component="
            dev.wifi_info
              ? Wifi
              : dev.dev_kind === 'bridge'
                ? Network3
                : dev.zone_type === 'wan'
                  ? NetworkPublic
                  : Router
          "
        />
      </span>
      <span class="identity"
        ><strong>{{ dev.name }}</strong
        ><small>{{ role(dev) }}</small></span
      >
      <span
        class="link-state"
        :class="{
          up: !dev.virtual && dev.dev_status.t === 'up',
          down: !dev.virtual && dev.dev_status.t === 'down',
        }"
        >{{ status(dev) }}</span
      >
      <n-icon class="open-icon" :component="ChevronRight" />
    </button>
  </section>
  <n-drawer
    placement="bottom"
    height="80%"
    :show="!!selected && !selected.virtual"
    @update:show="!$event && close()"
  >
    <n-drawer-content body-content-style="padding: 0">
      <TopologyDetailPanel
        v-if="selected && !selected.virtual"
        :node="selected"
        @close="close"
      />
    </n-drawer-content>
  </n-drawer>
  <PPPDCreateConfigModal
    v-if="virtualLink"
    :show="true"
    :attach_iface_name="virtualLink.attach_iface_name"
    :origin_value="virtualLink"
    @update:show="!$event && close()"
    @refresh="refresh"
  />
</template>

<style scoped>
.interface-list {
  border: 1px solid v-bind("theme.dividerColor");
  border-radius: 12px;
  background: v-bind("theme.cardColor");
  overflow: hidden;
}
.interface-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto auto;
  align-items: center;
  width: 100%;
  gap: 12px;
  padding: 13px 14px;
  border: 0;
  background: transparent;
  color: v-bind("theme.textColor1");
  text-align: start;
  font: inherit;
  cursor: pointer;
}
.interface-row + .interface-row {
  border-top: 1px solid v-bind("theme.dividerColor");
}
.interface-row:focus-visible {
  outline: 2px solid v-bind("theme.primaryColor");
  outline-offset: -3px;
}
.interface-row:hover {
  background: v-bind("theme.hoverColor");
}
.device-icon {
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: 9px;
  background: v-bind("theme.actionColor");
  font-size: 20px;
}
.device-icon.wan {
  color: v-bind("theme.warningColor");
}
.device-icon.lan {
  color: v-bind("theme.infoColor");
}
.identity {
  display: grid;
  gap: 2px;
  overflow-wrap: anywhere;
}
.identity strong {
  font: 600 15px/1.35 var(--font-mono);
}
.identity small,
.open-icon {
  color: v-bind("theme.textColor3");
}
.link-state {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: v-bind("theme.textColor2");
  font-size: 12px;
}
.link-state::before {
  content: "";
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}
.link-state.up::before {
  background: v-bind("theme.successColor");
}
.link-state.down::before {
  background: v-bind("theme.errorColor");
}
.list-notice {
  padding: 14px;
  color: v-bind("theme.textColor2");
}
</style>
