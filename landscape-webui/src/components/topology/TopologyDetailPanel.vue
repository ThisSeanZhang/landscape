<script setup lang="ts">
import IfaceChangeZone from "@/components/iface/IfaceChangeZone.vue";
import IfaceCpuSoftBalance from "@/components/iface/IfaceCpuSoftBalance.vue";
import IfaceDisableGuardModal from "@/components/iface/IfaceDisableGuardModal.vue";
import {
  add_controller,
  change_iface_boot_status,
  change_iface_status,
  delete_bridge,
} from "@/api/network";
import { DevStateType, NetDev, WifiMode, WLANTypeTag } from "@/lib/dev";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import {
  canManageBridgeAttachment,
  getBridgeAttachIssue,
} from "@/lib/topology";
import { ServiceExhibitSwitch } from "@/lib/services";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useIfaceNodeStore } from "@/stores/iface_node";
import { useDialog, useMessage, useThemeVars } from "naive-ui";
import { changeColor } from "seemly";
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";

const props = defineProps<{
  node: NetDev;
}>();

const emit = defineEmits(["close"]);

const { t } = useI18n();
const dialog = useDialog();
const message = useMessage();
const frontEndStore = useFrontEndStore();
const ifaceNodeStore = useIfaceNodeStore();
const themeVars = useThemeVars();
const show_zone_change = ref(false);
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
const can_manage_controller = computed(() =>
  canManageBridgeAttachment(props.node),
);
const can_attach_bridge = computed(
  () =>
    can_manage_controller.value &&
    props.node.zone_type === IfaceZoneType.undefined,
);
const can_manage_device_state = computed(() => props.node.dev_type !== "ppp");
const controller_hint = computed(() => {
  if (!can_attach_bridge.value) {
    return t("topology.panel.connect_unavailable");
  }
  if (has_controller.value) {
    return "";
  }
  if (
    props.node.wifi_info &&
    props.node.wifi_info.wifi_type.t !== WLANTypeTag.Ap
  ) {
    return t("topology.panel.wifi_client_hint");
  }
  if (available_bridge_options.value.length === 0) {
    return t("topology.panel.no_bridges");
  }
  return t("topology.panel.connect_hint");
});
const action_sections = computed(() => {
  const sections: Array<{
    key: string;
    short_label: string;
    label: string;
  }> = [];

  if (can_manage_device_state.value) {
    sections.push({
      key: "toggle_device",
      short_label: props.node.dev_status.t === DevStateType.Up ? "OFF" : "ON",
      label:
        props.node.dev_status.t === DevStateType.Up
          ? t("topology.node.action_disable")
          : t("topology.node.action_enable"),
    });

    sections.push({
      key: "boot",
      short_label: "BOOT",
      label: props.node.enable_in_boot
        ? t("topology.panel.disable_boot")
        : t("topology.panel.enable_boot"),
    });
  }

  if (show_switch.value.zone_type) {
    sections.push({
      key: "change_zone",
      short_label: "ZONE",
      label: t("topology.panel.change_zone"),
    });
  }
  sections.push({
    key: "cpu_balance",
    short_label: "CPU",
    label: t("topology.panel.edit_cpu_balance"),
  });

  if (props.node.dev_kind === "bridge" && props.node.name !== "docker0") {
    sections.push({
      key: "delete_bridge",
      short_label: "DEL",
      label: t("topology.panel.delete_bridge"),
    });
  }

  return sections;
});
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
  "--topology-panel-rail-active-bg": changeColor(themeVars.value.successColor, {
    alpha: 0.14,
  }),
  "--topology-panel-rail-active-border": changeColor(
    themeVars.value.successColor,
    {
      alpha: 0.42,
    },
  ),
  "--topology-panel-rail-active-text": themeVars.value.successColor,
  "--topology-panel-rail-wan-bg": changeColor(themeVars.value.warningColor, {
    alpha: 0.14,
  }),
  "--topology-panel-rail-wan-border": changeColor(
    themeVars.value.warningColor,
    {
      alpha: 0.42,
    },
  ),
  "--topology-panel-rail-wan-text": themeVars.value.warningColor,
  "--topology-panel-rail-lan-bg": changeColor(themeVars.value.infoColor, {
    alpha: 0.14,
  }),
  "--topology-panel-rail-lan-border": changeColor(themeVars.value.infoColor, {
    alpha: 0.42,
  }),
  "--topology-panel-rail-lan-text": themeVars.value.infoColor,
  "--topology-panel-muted": themeVars.value.textColor3,
  "--topology-panel-text": themeVars.value.textColor1,
}));

function isActiveAction(action_key: string) {
  switch (action_key) {
    case "toggle_device":
      return props.node.dev_status.t === DevStateType.Up;
    case "boot":
      return props.node.enable_in_boot;
    default:
      return false;
  }
}

function zoneActionClass(action_key: string) {
  if (action_key !== "change_zone") {
    return undefined;
  }

  if (props.node.zone_type === IfaceZoneType.wan) {
    return "is-wan";
  }

  if (props.node.zone_type === IfaceZoneType.lan) {
    return "is-lan";
  }

  return undefined;
}

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
  return value ? t("topology.panel.yes") : t("topology.panel.no");
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

function zoneTagType(zone: IfaceZoneType) {
  if (zone === IfaceZoneType.wan) {
    return "warning";
  }
  if (zone === IfaceZoneType.lan) {
    return "info";
  }
  return "default";
}

function bridgeAttachWarning(
  controller: NetDev | undefined,
  child: NetDev | undefined,
) {
  const issue = getBridgeAttachIssue(controller, child);

  switch (issue) {
    case "device_not_found":
      return t("topology.device_not_found");
    case "bridge_connection_rule":
      return t("topology.bridge_connection_rule");
    case "device_has_parent":
      return t("topology.device_has_parent");
    case "connect_unavailable":
      return t("topology.panel.connect_unavailable");
    case "wifi_client_mode_warning":
      return t("topology.wifi_client_mode_warning");
  }
}

async function refreshGraph() {
  await ifaceNodeStore.UPDATE_INFO();
}

function openQuickAction(action_key: string) {
  switch (action_key) {
    case "toggle_device":
      dialog.warning({
        title: t("topology.panel.actions"),
        content: t("topology.node.confirm_toggle_iface", {
          action:
            props.node.dev_status.t === DevStateType.Up
              ? t("topology.node.action_disable")
              : t("topology.node.action_enable"),
        }),
        positiveText: t("topology.panel.yes"),
        negativeText: t("topology.panel.close"),
        onPositiveClick: () => changeDeviceStatus(),
      });
      break;
    case "change_zone":
      show_zone_change.value = true;
      break;
    case "boot":
      dialog.warning({
        title: t("topology.panel.actions"),
        content: props.node.enable_in_boot
          ? t("topology.panel.confirm_disable_boot")
          : t("topology.panel.confirm_enable_boot"),
        positiveText: t("topology.panel.yes"),
        negativeText: t("topology.panel.close"),
        onPositiveClick: async () => {
          await change_iface_boot_status(
            props.node.name,
            !props.node.enable_in_boot,
          );
          await refreshGraph();
        },
      });
      break;
    case "cpu_balance":
      show_cpu_balance_btn.value = true;
      break;
    case "delete_bridge":
      dialog.error({
        title: t("topology.panel.delete_bridge"),
        content: t("topology.node.delete_bridge"),
        positiveText: t("topology.node.delete_btn"),
        negativeText: t("topology.panel.close"),
        onPositiveClick: () => handleDeleteBridge(),
      });
      break;
  }
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

  const bridge = ifaceNodeStore.bridges.find(
    (item) => item.ifindex === selected_bridge_ifindex.value,
  );
  const bridge_dev = bridge
    ? ifaceNodeStore.FIND_DEV_BY_IFINDEX(bridge.ifindex)
    : undefined;
  const warning = bridgeAttachWarning(bridge_dev, props.node);

  if (warning) {
    message.warning(warning);
    return;
  }

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

async function handleDeleteBridge() {
  try {
    delete_loading.value = true;
    await delete_bridge(props.node.name);
    await refreshGraph();
    message.info(t("topology.node.delete_success"));
    closePanel();
  } catch (_error) {
    message.error(t("topology.node.delete_failed"));
  } finally {
    delete_loading.value = false;
  }
}
</script>

<template>
  <div
    class="topology-detail-shell nopan nowheel"
    :data-testid="`topology-detail-${node.index}`"
    :style="panelStyle"
  >
    <div v-if="action_sections.length" class="topology-detail__rail-shell">
      <div class="topology-detail__rail">
        <n-tooltip
          v-for="section in action_sections"
          :key="section.key"
          trigger="hover"
        >
          <template #trigger>
            <button
              type="button"
              class="topology-detail__rail-button"
              :class="[
                { 'is-active': isActiveAction(section.key) },
                zoneActionClass(section.key),
              ]"
              :data-testid="`topology-detail-${node.index}-action-${section.key}`"
              @click="openQuickAction(section.key)"
            >
              <span class="topology-detail__rail-label">
                {{ section.short_label }}
              </span>
            </button>
          </template>
          {{ section.label }}
        </n-tooltip>
      </div>
    </div>

    <div class="topology-detail">
      <div class="topology-detail__header">
        <div class="topology-detail__header-main">
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

      <n-scrollbar class="topology-detail__content nowheel">
        <div class="topology-detail__content-inner">
          <n-flex vertical size="large">
            <n-card size="small" embedded class="topology-detail__card--plain">
              <template #header>
                {{ t("topology.panel.basic_info") }}
              </template>
              <n-descriptions label-placement="left" :column="1" size="small">
                <n-descriptions-item :label="t('topology.node.iface_name')">
                  {{ node.name }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.panel.ifindex')">
                  {{ node.index }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.node.device_type')">
                  {{ displayValue(node.dev_type) }}/{{
                    displayValue(node.dev_kind)
                  }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.node.status')">
                  {{ node.dev_status.t }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.panel.carrier')">
                  {{ boolLabel(node.carrier) }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.panel.boot')">
                  {{ boolLabel(node.enable_in_boot) }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.panel.zone')">
                  {{ node.zone_type }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.node.mac_addr')">
                  {{ maskValue(node.mac) }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.node.perm_mac')">
                  {{ maskValue(node.perm_mac) }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.panel.wifi_type')">
                  {{
                    node.wifi_info
                      ? node.wifi_info.wifi_type.t
                      : displayValue(undefined)
                  }}
                </n-descriptions-item>
                <n-descriptions-item :label="t('topology.panel.peer_link')">
                  {{ displayValue(node.peer_link_id) }}
                </n-descriptions-item>
              </n-descriptions>
            </n-card>

            <n-card size="small" embedded class="topology-detail__card--plain">
              <template #header>
                {{ t("topology.panel.relationship") }}
              </template>
              <n-flex vertical size="small">
                <n-descriptions label-placement="left" :column="1" size="small">
                  <n-descriptions-item :label="t('topology.panel.parent')">
                    <n-flex align="center" justify="space-between" wrap>
                      <span>
                        {{
                          controller_dev?.name ??
                          (has_controller ? node.controller_name : undefined) ??
                          t("topology.panel.no_parent")
                        }}
                      </span>
                      <n-button
                        data-testid="topology-detach-controller"
                        v-if="has_controller"
                        tertiary
                        size="tiny"
                        @click="removeController"
                      >
                        {{ t("topology.node.disconnect") }}
                      </n-button>
                    </n-flex>
                  </n-descriptions-item>
                  <n-descriptions-item :label="t('topology.panel.children')">
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
                    <span v-else>{{ t("topology.panel.no_children") }}</span>
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
                      can_attach_bridge &&
                      !has_controller &&
                      available_bridge_options.length > 0 &&
                      (!node.wifi_info ||
                        node.wifi_info.wifi_type.t === WLANTypeTag.Ap)
                    "
                  >
                    <n-select
                      v-model:value="selected_bridge_ifindex"
                      :options="available_bridge_options"
                      :placeholder="t('topology.panel.select_bridge')"
                      clearable
                    />
                    <n-button
                      data-testid="topology-attach-controller"
                      type="primary"
                      ghost
                      :disabled="selected_bridge_ifindex === null"
                      @click="attachController"
                    >
                      {{ t("topology.panel.attach_bridge") }}
                    </n-button>
                  </n-input-group>
                </div>
              </n-flex>
            </n-card>
          </n-flex>
        </div>
      </n-scrollbar>
    </div>
    <IfaceChangeZone
      v-model:show="show_zone_change"
      :zone="node.zone_type"
      :iface_name="node.name"
      @refresh="refreshGraph"
    />
    <IfaceCpuSoftBalance
      v-model:show="show_cpu_balance_btn"
      :iface_name="node.name"
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

.topology-detail__rail-button.is-active {
  border-color: var(--topology-panel-rail-active-border);
  background: var(--topology-panel-rail-active-bg);
  color: var(--topology-panel-rail-active-text);
}

.topology-detail__rail-button.is-active:hover {
  border-color: var(--topology-panel-rail-active-border);
  background: var(--topology-panel-rail-active-bg);
}

.topology-detail__rail-button.is-wan {
  border-color: var(--topology-panel-rail-wan-border);
  background: var(--topology-panel-rail-wan-bg);
  color: var(--topology-panel-rail-wan-text);
}

.topology-detail__rail-button.is-wan:hover {
  border-color: var(--topology-panel-rail-wan-border);
  background: var(--topology-panel-rail-wan-bg);
}

.topology-detail__rail-button.is-lan {
  border-color: var(--topology-panel-rail-lan-border);
  background: var(--topology-panel-rail-lan-bg);
  color: var(--topology-panel-rail-lan-text);
}

.topology-detail__rail-button.is-lan:hover {
  border-color: var(--topology-panel-rail-lan-border);
  background: var(--topology-panel-rail-lan-bg);
}

.topology-detail__rail-label {
  font-size: 11px;
  line-height: 1;
  font-weight: 600;
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

.topology-detail :deep(.topology-detail__card--plain.n-card) {
  border-color: transparent;
  box-shadow: none;
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
