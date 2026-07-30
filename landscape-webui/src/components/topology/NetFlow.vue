<script setup lang="ts">
import { type Connection, VueFlow, useVueFlow } from "@vue-flow/core";
import { MiniMap } from "@vue-flow/minimap";
import { useElementSize } from "@vueuse/core";
import { useMessage, useThemeVars } from "naive-ui";
import { changeColor } from "seemly";
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";

import { add_controller } from "@/api/network";
import FlowHeaderExtra from "@/components/topology/FlowHeaderExtra.vue";
import FlowNode from "@/components/topology/FlowNode.vue";
import TopologyDetailPanel from "@/components/topology/TopologyDetailPanel.vue";
import { NetDev, WLANTypeTag } from "@/lib/dev";
import { getBridgeAttachIssue } from "@/lib/topology";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import { useIfaceNodeStore } from "@/stores/iface_node";
import { useMetricStore } from "@/stores/status_metric";

interface Props {
  fit_padding?: number;
}

const props = withDefaults(defineProps<Props>(), {
  fit_padding: 0.3,
});

const { t } = useI18n();
const {
  fitView,
  getViewport,
  onNodeClick,
  onPaneClick,
  setCenter,
  setViewport,
} = useVueFlow();
const message = useMessage();
const ifaceNodeStore = useIfaceNodeStore();
const metricStore = useMetricStore();
const themeVars = useThemeVars();
const containerRef = ref<HTMLElement | null>(null);
const { width } = useElementSize(containerRef);
const selectedIfaceId = ref<number | null>(null);
const connectionLoading = ref(false);

const MOBILE_BREAKPOINT = 960;
const DESKTOP_MIN_READABLE_ZOOM = 0.78;
const MINIMAP_WIDTH = 180;
const MINIMAP_HEIGHT = 112;
const TOP_ALIGN_PADDING = 56;

const isDrawerMode = computed(
  () => width.value > 0 && width.value < MOBILE_BREAKPOINT,
);
const selectedIface = computed(() =>
  ifaceNodeStore.visible_net_devs.find(
    (dev) => dev.index === selectedIfaceId.value,
  ),
);
const highlightedIfaces = computed(() => {
  if (!selectedIface.value) {
    return undefined;
  }

  const highlighted = new Set<number>([selectedIface.value.index]);

  if (selectedIface.value.controller_id !== undefined) {
    highlighted.add(selectedIface.value.controller_id);
  }

  for (const dev of ifaceNodeStore.visible_net_devs) {
    if (dev.controller_id === selectedIface.value.index) {
      highlighted.add(dev.index);
    }
  }

  return highlighted;
});
const flowNodes = computed(() => {
  const highlighted = highlightedIfaces.value;

  return ifaceNodeStore.nodes.map((node) => ({
    ...node,
    class: highlighted && !highlighted.has(Number(node.id)) ? "is-dimmed" : "",
  }));
});
const ifaceStatsByIfindex = computed(
  () => new Map(metricStore.iface_stats.map((item) => [item.ifindex, item])),
);
const flowEdges = computed(() => {
  const highlighted = highlightedIfaces.value;

  return ifaceNodeStore.edges.map((edge) => ({
    ...edge,
    class:
      highlighted &&
      (!highlighted.has(Number(edge.source)) ||
        !highlighted.has(Number(edge.target)))
        ? "normal-edge is-dimmed"
        : "normal-edge",
  }));
});
const detailOpen = computed(() => selectedIface.value !== undefined);
const miniMapMaskColor = computed(() =>
  changeColor(themeVars.value.primaryColor, { alpha: 0.08 }),
);
const miniMapMaskStrokeColor = computed(() =>
  changeColor(themeVars.value.primaryColor, { alpha: 0.4 }),
);
const flowStyle = computed(() => ({
  "--topology-flow-accent": changeColor(themeVars.value.primaryColor, {
    alpha: 0.16,
  }),
  "--topology-flow-accent-soft": changeColor(themeVars.value.infoColor, {
    alpha: 0.08,
  }),
  "--topology-flow-bg": changeColor(themeVars.value.bodyColor, { alpha: 0.98 }),
  "--topology-flow-bg-soft": changeColor(themeVars.value.cardColor, {
    alpha: 0.98,
  }),
  "--topology-flow-edge": changeColor(themeVars.value.textColor3, {
    alpha: 0.78,
  }),
  "--topology-flow-minimap-bg": changeColor(themeVars.value.cardColor, {
    alpha: 0.96,
  }),
  "--topology-flow-minimap-border": changeColor(themeVars.value.borderColor, {
    alpha: 0.96,
  }),
  "--topology-flow-minimap-shadow": `0 10px 24px ${changeColor(
    themeVars.value.textColor1,
    {
      alpha: 0.1,
    },
  )}`,
}));

function closePanel() {
  selectedIfaceId.value = null;
}

async function fitTopology(mode: "overview" | "readable" = "readable") {
  const fit_params: {
    duration?: number;
    minZoom?: number;
    padding: number;
  } = {
    duration: 180,
    padding: props.fit_padding,
  };

  if (mode === "readable" && !isDrawerMode.value) {
    fit_params.minZoom = DESKTOP_MIN_READABLE_ZOOM;
  }

  await fitView(fit_params);

  if (isDrawerMode.value || ifaceNodeStore.nodes.length === 0) {
    return;
  }

  const viewport = getViewport();
  const top_y = Math.min(
    ...ifaceNodeStore.nodes.map(
      (node) => node.position?.y ?? TOP_ALIGN_PADDING,
    ),
  );
  const aligned_y = TOP_ALIGN_PADDING - top_y * viewport.zoom;

  if (Math.abs(viewport.y - aligned_y) > 1) {
    await setViewport(
      {
        x: viewport.x,
        y: aligned_y,
        zoom: viewport.zoom,
      },
      { duration: 160 },
    );
  }
}

function scheduleFitTopology(mode: "overview" | "readable" = "readable") {
  void nextTick(() => {
    requestAnimationFrame(() => {
      void fitTopology(mode);
    });
  });
}

function handleFitOverview() {
  scheduleFitTopology("overview");
}

function handleMiniMapClick(params: { position: { x: number; y: number } }) {
  const viewport = getViewport();

  void setCenter(params.position.x, params.position.y, {
    duration: 180,
    zoom: viewport.zoom,
  });
}

function miniMapNodeColor(node: any) {
  const dev = node?.data;

  if (dev?.dev_kind === "bridge") {
    return changeColor(themeVars.value.textColor3, { alpha: 0.78 });
  }

  if (dev?.zone_type === IfaceZoneType.wan) {
    return changeColor(themeVars.value.warningColor, { alpha: 0.88 });
  }

  if (dev?.zone_type === IfaceZoneType.lan) {
    return changeColor(themeVars.value.infoColor, { alpha: 0.88 });
  }

  return changeColor(themeVars.value.successColor, { alpha: 0.84 });
}

function miniMapNodeStrokeColor() {
  return changeColor(themeVars.value.bodyColor, { alpha: 0.96 });
}

function findDeviceByNodeId(nodeId?: string | null) {
  if (!nodeId) {
    return undefined;
  }

  const ifindex = Number(nodeId);
  if (Number.isNaN(ifindex)) {
    return undefined;
  }

  return ifaceNodeStore.FIND_DEV_BY_IFINDEX(ifindex);
}

function getConnectionWarning(
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

async function handleConnect(connection: Connection) {
  if (connectionLoading.value) {
    return;
  }

  const controller = findDeviceByNodeId(connection.source);
  const child = findDeviceByNodeId(connection.target);
  const warning = getConnectionWarning(controller, child);

  if (warning) {
    message.warning(warning);
    return;
  }

  connectionLoading.value = true;

  try {
    await add_controller({
      link_name: child!.name,
      link_ifindex: child!.index,
      master_name: controller!.name,
      master_ifindex: controller!.index,
    });
    await ifaceNodeStore.UPDATE_INFO();
    selectedIfaceId.value = child!.index;
  } finally {
    connectionLoading.value = false;
  }
}

ifaceNodeStore.SETTING_CALL_BACK(() => {
  scheduleFitTopology("readable");
});

watch(
  width,
  (currentWidth) => {
    if (currentWidth <= 0) {
      return;
    }

    ifaceNodeStore.SET_LAYOUT_CONTEXT(Math.round(currentWidth), 0);
  },
  { immediate: true },
);

watch(selectedIface, (value) => {
  if (!value && selectedIfaceId.value !== null) {
    selectedIfaceId.value = null;
  }
});

onMounted(() => {
  ifaceNodeStore.UPDATE_INFO();
  metricStore.SET_ENABLE("iface", true);
  metricStore.UPDATE_INFO();
});

onUnmounted(() => {
  metricStore.SET_ENABLE("iface", false);
});

onNodeClick(({ node }) => {
  selectedIfaceId.value = Number(node.id);
});

onPaneClick(() => {
  closePanel();
});
</script>

<template>
  <div ref="containerRef" class="topology-shell" data-testid="topology-page">
    <VueFlow
      class="topology-flow"
      :style="flowStyle"
      :nodes="flowNodes"
      :edges="flowEdges"
      :nodes-draggable="false"
      :nodes-connectable="true"
      :elements-selectable="false"
      :connect-on-click="false"
      :zoom-on-scroll="false"
      :fit-view-on-init="false"
      :pane-click-distance="4"
      @connect="handleConnect"
    >
      <template #node-netflow="nodeProps">
        <FlowNode
          :node="nodeProps.data"
          :metric="ifaceStatsByIfindex.get(Number(nodeProps.id))"
          :selected="selectedIfaceId === Number(nodeProps.id)"
          :dimmed="
            Boolean(
              highlightedIfaces && !highlightedIfaces.has(Number(nodeProps.id)),
            )
          "
        />
      </template>

      <FlowHeaderExtra @fit-view="handleFitOverview" />

      <MiniMap
        v-if="!isDrawerMode"
        class="topology-minimap"
        position="bottom-left"
        :aria-label="t('topology.minimap')"
        :height="MINIMAP_HEIGHT"
        :mask-border-radius="10"
        :mask-color="miniMapMaskColor"
        :mask-stroke-color="miniMapMaskStrokeColor"
        :mask-stroke-width="1.25"
        :node-border-radius="6"
        :node-color="miniMapNodeColor"
        :node-stroke-color="miniMapNodeStrokeColor"
        :node-stroke-width="1"
        :pannable="true"
        :width="MINIMAP_WIDTH"
        :zoomable="false"
        @click="handleMiniMapClick"
      />

      <transition name="topology-panel">
        <aside
          v-if="selectedIface && !isDrawerMode"
          class="topology-side-panel nopan nowheel"
          data-testid="topology-side-panel"
        >
          <TopologyDetailPanel :node="selectedIface" @close="closePanel" />
        </aside>
      </transition>

      <n-drawer
        v-if="isDrawerMode"
        :show="detailOpen"
        placement="bottom"
        height="78%"
        :trap-focus="false"
        :block-scroll="false"
        @update:show="(show: boolean) => !show && closePanel()"
      >
        <n-drawer-content :closable="false" body-content-style="padding: 0;">
          <div class="topology-drawer-panel nopan nowheel">
            <TopologyDetailPanel
              v-if="selectedIface"
              :node="selectedIface"
              @close="closePanel"
            />
          </div>
        </n-drawer-content>
      </n-drawer>
    </VueFlow>
  </div>
</template>

<style>
@import "@vue-flow/core/dist/style.css";
@import "@vue-flow/core/dist/theme-default.css";
@import "@vue-flow/minimap/dist/style.css";
</style>

<style scoped>
.topology-shell {
  position: relative;
  width: 100%;
  min-height: 550px;
  height: 100%;
}

.topology-flow {
  width: 100%;
  height: 100%;
  min-height: 550px;
  border-radius: 20px;
  background:
    radial-gradient(
      circle at top left,
      var(--topology-flow-accent),
      transparent 24%
    ),
    radial-gradient(
      circle at top right,
      var(--topology-flow-accent-soft),
      transparent 22%
    ),
    linear-gradient(
      180deg,
      var(--topology-flow-bg),
      var(--topology-flow-bg-soft)
    );
}

.topology-flow :deep(.vue-flow__node-netflow) {
  background: transparent;
  border: none;
  box-shadow: none;
  padding: 0;
  transition: opacity 0.18s ease;
}

.topology-flow :deep(.vue-flow__edge-path) {
  stroke-width: 2;
  stroke: var(--topology-flow-edge);
  transition: opacity 0.18s ease;
}

.topology-flow :deep(.vue-flow__edge.is-dimmed .vue-flow__edge-path) {
  opacity: 0.18;
}

.topology-flow :deep(.vue-flow__edge.animated path) {
  stroke-dasharray: 6 6;
}

.topology-flow :deep(.topology-minimap) {
  background: var(--topology-flow-minimap-bg);
  border: 1px solid var(--topology-flow-minimap-border);
  border-radius: 16px;
  box-shadow: var(--topology-flow-minimap-shadow);
  overflow: hidden;
}

.topology-flow :deep(.vue-flow__panel.bottom.left) {
  margin: 16px;
}

.topology-side-panel {
  position: absolute;
  z-index: 6;
  top: 16px;
  right: 16px;
  bottom: 16px;
  width: 468px;
  overflow: visible;
}

.topology-drawer-panel {
  height: 100%;
}

.topology-panel-enter-active,
.topology-panel-leave-active {
  transition:
    transform 0.22s ease,
    opacity 0.22s ease;
}

.topology-panel-enter-from,
.topology-panel-leave-to {
  opacity: 0;
  transform: translateX(14px);
}
</style>
