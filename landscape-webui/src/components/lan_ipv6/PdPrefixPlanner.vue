<script setup lang="ts">
import type {
  IPv6ServiceMode,
  LanIPv6ServiceConfigV2,
  LanPrefixGroupConfig,
} from "@landscape-router/types/api/schemas";
import type { LDIAPrefix } from "@/api/service_ipv6pd";
import {
  buildPrefixPlannerViewFromGroups,
  inspectPlannerCandidateFromGroups,
  plannerSelectionIsConflict,
  plannerUnitLabels,
  poolIndexFromPlannerUnitStart,
  type PlannerUnit,
} from "@/lib/ipv6_planner";
import type { SourceKind } from "@/lib/lan_ipv6_v2_helpers";
import { useThemeVars } from "naive-ui";
import {
  computed,
  nextTick,
  onBeforeUnmount,
  ref,
  watch,
  watchEffect,
} from "vue";
import { scaleColor } from "seemly";
import { useI18n } from "vue-i18n";

const { t } = useI18n({ useScope: "global" });
const themeVars = useThemeVars();

const props = defineProps<{
  currentIfaceName: string;
  currentGroups: LanPrefixGroupConfig[];
  currentMode?: IPv6ServiceMode;
  editGroup?: LanPrefixGroupConfig;
  otherConfigsV2: LanIPv6ServiceConfigV2[];
  selectedKind: SourceKind;
  prefixInfos: Map<string, LDIAPrefix | null>;
  expectedPdLens: Map<string, number>;
  draftPdPoolLen?: number;
}>();

const emit = defineEmits<{
  (e: "selectPoolIndex", value: number): void;
  (
    e: "interactPoolIndex",
    value: {
      poolIndex: number;
      unitStart: number;
      unitSpan: number;
      canSave: boolean;
      saveError?: string;
      occupants: {
        scope: "current" | "other";
        serviceKind: "ra" | "na" | "pd";
        ifaceName: string;
        groupId: string;
        effectiveIndex: number;
        effectiveEndIndex: number;
        poolLen: number;
        conflictsWithSelection: boolean;
      }[];
    },
  ): void;
}>();

const planner = computed(() =>
  buildPrefixPlannerViewFromGroups({
    currentIfaceName: props.currentIfaceName,
    currentGroups: props.currentGroups,
    currentMode: props.currentMode,
    otherConfigsV2: props.otherConfigsV2,
    editGroup: props.editGroup,
    selectedKind: props.selectedKind,
    prefixInfos: props.prefixInfos,
    expectedPdLens: props.expectedPdLens,
    draftPdPoolLen: props.draftPdPoolLen,
  }),
);

const canvasRef = ref<HTMLCanvasElement>();
const hoveredUnitIndex = ref<number>();
const clickError = ref<string>();

const columns = computed(() => {
  const total = planner.value.totalUnits;
  if (total <= 0) return 1;
  if (total <= 256) return Math.min(16, Math.ceil(Math.sqrt(total)));
  return Math.min(64, Math.ceil(Math.sqrt(total)));
});

const cellSize = computed(() => {
  const total = planner.value.totalUnits;
  if (total > 2048) return 10;
  if (total > 512) return 12;
  return 18;
});

const rows = computed(() => {
  if (planner.value.totalUnits <= 0) return 1;
  return Math.ceil(planner.value.totalUnits / columns.value);
});

const canvasWidth = computed(() => columns.value * cellSize.value);
const canvasHeight = computed(() => rows.value * cellSize.value);

const reasonText = computed(() => {
  switch (planner.value.stateReason) {
    case "no_parent_iface":
      return t("lan_ipv6.planner_reason_no_parent_iface");
    case "missing_pd_config":
      return t("lan_ipv6.planner_reason_missing_pd_config");
    case "no_static_prefix":
      return t("lan_ipv6.planner_reason_no_static_prefix");
    case "target_shorter_than_parent":
      return t("lan_ipv6.planner_reason_target_shorter_than_parent", {
        target: planner.value.targetPrefixLen,
        parent: planner.value.parentPrefixLen,
      });
    case "selection_out_of_range":
      return t("lan_ipv6.planner_reason_selection_out_of_range");
    case "target_more_specific_than_64":
      return t("lan_ipv6.planner_reason_more_specific_than_64");
    case "too_many_units":
      return t("lan_ipv6.planner_reason_too_many_units", {
        count: planner.value.totalUnits,
      });
    default:
      return "";
  }
});

const hoveredRange = computed(() => {
  if (
    hoveredUnitIndex.value === undefined ||
    planner.value.targetPrefixLen === undefined ||
    planner.value.targetPrefixLen > 64
  ) {
    return undefined;
  }
  const unitSpan = 1 << (64 - planner.value.targetPrefixLen);
  const unitStart = Math.floor(hoveredUnitIndex.value / unitSpan) * unitSpan;
  return { unitStart, unitSpan };
});

const displayError = computed(() => clickError.value);
const selectedRangeConflicts = computed(() =>
  plannerSelectionIsConflict(planner.value.selectedStatus),
);
const wanPrefixWarning = computed(() =>
  planner.value.wanCompatible === false
    ? t("lan_ipv6.planner_warning_wan_prefix_mismatch")
    : undefined,
);

function occupantRangeLabel(occupant: {
  effectiveIndex: number;
  effectiveEndIndex: number;
  poolLen: number;
}) {
  const range =
    occupant.effectiveIndex === occupant.effectiveEndIndex
      ? `${occupant.effectiveIndex}`
      : `${occupant.effectiveIndex}-${occupant.effectiveEndIndex}`;
  return `${range} /${occupant.poolLen}`;
}

function themeValue(name: string, fallback: string) {
  const element = canvasRef.value;
  if (!element) {
    return fallback;
  }
  const value = getComputedStyle(element).getPropertyValue(name).trim();
  return value || fallback;
}

function plannerPalette() {
  return {
    border: themeVars.value.borderColor,
    text: themeVars.value.textColor1,
    mutedText: themeVars.value.textColor3,
    hover: themeVars.value.hoverColor,
    success: themeVars.value.successColor,
    error: themeVars.value.errorColor,
    info: themeVars.value.infoColor,
    warning: themeVars.value.warningColor,
    primary: themeVars.value.primaryColor,
    pd: "#8b5cf6",
    defaultFill: themeVars.value.cardColor,
    embedded: themeVars.value.actionColor,
    blocked: themeValue("--n-action-color", themeVars.value.actionColor),
  };
}

function serviceColorForKind(kind: SourceKind, palette = plannerPalette()) {
  switch (kind) {
    case "ra":
      return palette.info;
    case "na":
      return palette.success;
    case "pd":
      return palette.pd;
  }
}

function groupColor(color: string, groupId: string | undefined) {
  const currentGroupId = props.editGroup?.group_id;
  if (!groupId || !currentGroupId) {
    return color;
  }

  return scaleColor(color, {
    lightness: groupId === currentGroupId ? 0.72 : 0.45,
  });
}

const legendItems = computed(() => {
  const palette = plannerPalette();
  return [
    { label: "RA", color: palette.info, kind: "solid" },
    { label: "IA_NA", color: palette.success, kind: "solid" },
    { label: "PD", color: palette.pd, kind: "solid" },
    {
      label: t("lan_ipv6.planner_legend_other_lan"),
      color: palette.embedded,
      kind: "solid",
    },
    {
      label: t("lan_ipv6.planner_legend_wan"),
      color: palette.warning,
      kind: "solid",
    },
    {
      label: t("lan_ipv6.planner_legend_blocked"),
      color: palette.blocked,
      kind: "striped",
    },
    {
      label: t("lan_ipv6.planner_conflict"),
      color: palette.error,
      kind: "solid",
    },
  ];
});

function colorForUnit(unit: PlannerUnit) {
  const palette = plannerPalette();
  switch (unit.kind) {
    case "wan":
      return palette.warning;
    case "blocked":
      return palette.blocked;
    case "ra":
      return groupColor(
        serviceColorForKind("ra", palette),
        unit.currentGroupId,
      );
    case "na":
      return groupColor(
        serviceColorForKind("na", palette),
        unit.currentGroupId,
      );
    case "pd":
      return groupColor(
        serviceColorForKind("pd", palette),
        unit.currentGroupId,
      );
    case "other_lan":
      return palette.embedded;
    case "conflict":
      return palette.error;
    default:
      return palette.defaultFill;
  }
}

function selectedFillColor(unit: PlannerUnit) {
  const palette = plannerPalette();

  if (selectedRangeConflicts.value) {
    return palette.error;
  }
  if (unit.kind === "wan") {
    return palette.warning;
  }
  if (unit.kind === "blocked") {
    return palette.blocked;
  }
  if (unit.kind === "conflict") {
    return palette.error;
  }
  if (unit.kind === "other_lan") {
    return palette.embedded;
  }

  return groupColor(
    serviceColorForKind(props.selectedKind, palette),
    props.editGroup?.group_id,
  );
}

function drawUnits() {
  const canvas = canvasRef.value;
  if (!canvas || planner.value.renderMode !== "full") {
    return;
  }
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }
  const dpr = window.devicePixelRatio || 1;
  const palette = plannerPalette();
  const width = canvasWidth.value;
  const height = canvasHeight.value;
  canvas.width = Math.max(1, Math.floor(width * dpr));
  canvas.height = Math.max(1, Math.floor(height * dpr));
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  ctx.font = `${Math.max(8, cellSize.value - 6)}px sans-serif`;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";

  planner.value.units.forEach((unit) => {
    const x = (unit.index % columns.value) * cellSize.value;
    const y = Math.floor(unit.index / columns.value) * cellSize.value;
    ctx.fillStyle = unit.selected
      ? selectedFillColor(unit)
      : colorForUnit(unit);
    ctx.fillRect(x, y, cellSize.value, cellSize.value);
    ctx.strokeStyle = palette.border;
    ctx.strokeRect(x + 0.5, y + 0.5, cellSize.value - 1, cellSize.value - 1);

    if (
      (unit.kind === "conflict" || unit.kind === "blocked") &&
      !(unit.selected && selectedRangeConflicts.value)
    ) {
      ctx.save();
      ctx.beginPath();
      ctx.rect(x + 1, y + 1, cellSize.value - 2, cellSize.value - 2);
      ctx.clip();
      ctx.strokeStyle =
        unit.kind === "blocked" ? palette.mutedText : palette.error;
      for (
        let offset = -cellSize.value;
        offset < cellSize.value * 2;
        offset += 6
      ) {
        ctx.beginPath();
        ctx.moveTo(x + offset, y);
        ctx.lineTo(x + offset + cellSize.value, y + cellSize.value);
        ctx.stroke();
      }
      ctx.restore();
    }

    if (cellSize.value >= 12) {
      const labels = plannerUnitLabels(unit, props.selectedKind);
      if (labels) {
        ctx.fillStyle =
          unit.selected || unit.currentGroupId ? "#fff" : palette.text;
        ctx.fillText(labels, x + cellSize.value / 2, y + cellSize.value / 2);
      } else if (unit.kind === "blocked" && cellSize.value >= 14) {
        ctx.fillStyle = palette.mutedText;
        ctx.fillText("/", x + cellSize.value / 2, y + cellSize.value / 2);
      }
    }

    if (unit.selected) {
      ctx.strokeStyle = selectedRangeConflicts.value
        ? palette.error
        : palette.success;
      ctx.lineWidth = 2;
      ctx.strokeRect(x + 1, y + 1, cellSize.value - 2, cellSize.value - 2);
      ctx.lineWidth = 1;
    }
  });

  if (hoveredRange.value) {
    ctx.save();
    ctx.strokeStyle = palette.text;
    ctx.setLineDash([4, 3]);
    ctx.fillStyle = palette.hover;
    for (
      let index = hoveredRange.value.unitStart;
      index < hoveredRange.value.unitStart + hoveredRange.value.unitSpan;
      index++
    ) {
      if (index < 0 || index >= planner.value.units.length) {
        continue;
      }
      const x = (index % columns.value) * cellSize.value;
      const y = Math.floor(index / columns.value) * cellSize.value;
      ctx.fillRect(x + 1, y + 1, cellSize.value - 2, cellSize.value - 2);
      ctx.strokeRect(x + 1, y + 1, cellSize.value - 2, cellSize.value - 2);
    }
    ctx.restore();
  }
}

function unitIndexFromEvent(event: MouseEvent) {
  const canvas = canvasRef.value;
  if (!canvas) {
    return undefined;
  }
  const rect = canvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  const column = Math.floor(x / cellSize.value);
  const row = Math.floor(y / cellSize.value);
  const index = row * columns.value + column;
  if (
    column < 0 ||
    row < 0 ||
    index < 0 ||
    index >= planner.value.units.length
  ) {
    return undefined;
  }
  return index;
}

function onCanvasMouseMove(event: MouseEvent) {
  hoveredUnitIndex.value = unitIndexFromEvent(event);
}

function onCanvasLeave() {
  hoveredUnitIndex.value = undefined;
}

function scheduleRedraw() {
  void nextTick().then(() => {
    drawUnits();
  });
}

function onCanvasClick(event: MouseEvent) {
  const unitIndex = unitIndexFromEvent(event);
  if (unitIndex === undefined || planner.value.targetPrefixLen === undefined) {
    return;
  }
  if (
    planner.value.targetPrefixLen <= 0 ||
    planner.value.targetPrefixLen > 64
  ) {
    return;
  }
  const unitSpan = 1 << (64 - planner.value.targetPrefixLen);
  const unitStart = Math.floor(unitIndex / unitSpan) * unitSpan;
  const nextPoolIndex = poolIndexFromPlannerUnitStart(
    planner.value.targetPrefixLen,
    unitStart,
  );
  const candidate = inspectPlannerCandidateFromGroups(
    {
      currentIfaceName: props.currentIfaceName,
      currentGroups: props.currentGroups,
      currentMode: props.currentMode,
      otherConfigsV2: props.otherConfigsV2,
      editGroup: props.editGroup,
      selectedKind: props.selectedKind,
      prefixInfos: props.prefixInfos,
      expectedPdLens: props.expectedPdLens,
      draftPdPoolLen: props.draftPdPoolLen,
    },
    nextPoolIndex,
  );
  emit("interactPoolIndex", {
    poolIndex: nextPoolIndex,
    unitStart,
    unitSpan,
    canSave: candidate.canSave,
    saveError: candidate.saveError,
    occupants: candidate.selectedOccupants.map((occupant) => ({
      scope: occupant.scope,
      serviceKind: occupant.serviceKind,
      ifaceName: occupant.ifaceName,
      groupId: occupant.groupId,
      effectiveIndex: occupant.effectiveIndex,
      effectiveEndIndex: occupant.effectiveEndIndex,
      poolLen: occupant.poolLen,
      conflictsWithSelection: occupant.conflictsWithSelection,
    })),
  });
  if (!candidate.canSave) {
    clickError.value = candidate.saveError;
    return;
  }
  clickError.value = undefined;
  emit("selectPoolIndex", nextPoolIndex);
  scheduleRedraw();
}

watchEffect(() => {
  if (planner.value.canSave) {
    clickError.value = undefined;
  }
});

watch(
  () => [
    planner.value.units,
    planner.value.renderMode,
    planner.value.selectedUnitStart,
    planner.value.selectedUnitSpan,
    hoveredRange.value?.unitStart,
    hoveredRange.value?.unitSpan,
    canvasWidth.value,
    canvasHeight.value,
  ],
  () => {
    scheduleRedraw();
  },
  { deep: true, immediate: true },
);

onBeforeUnmount(() => {
  hoveredUnitIndex.value = undefined;
});
</script>

<template>
  <n-card size="small" :bordered="false" class="planner-card">
    <n-flex vertical :size="10">
      <n-flex
        v-if="props.editGroup?.parent.t === 'pd'"
        align="center"
        :size="8"
      >
        <n-text depth="3" style="font-size: 12px">
          {{ t("lan_ipv6.planner_snapshot_prefix_len") }}
        </n-text>
        <n-text strong>/{{ planner.parentPrefixLen ?? "-" }}</n-text>
        <n-text
          v-if="planner.actualPrefixLen !== undefined"
          depth="3"
          style="font-size: 12px"
        >
          {{ t("lan_ipv6.planner_actual_prefix") }} /{{
            planner.actualPrefixLen
          }}
        </n-text>
      </n-flex>

      <n-alert v-if="wanPrefixWarning" type="warning" :bordered="false">
        {{ wanPrefixWarning }}
      </n-alert>

      <div v-if="planner.renderMode === 'full'" class="planner-canvas-wrap">
        <canvas
          ref="canvasRef"
          class="planner-canvas"
          @mousemove="onCanvasMouseMove"
          @mouseleave="onCanvasLeave"
          @click="onCanvasClick"
        />
      </div>
      <n-alert v-else type="warning" :bordered="false">
        {{ reasonText || t("lan_ipv6.planner_summary_only") }}
      </n-alert>

      <n-alert v-if="displayError" type="error" :bordered="false">
        {{ t(displayError) }}
      </n-alert>

      <n-flex
        v-if="planner.selectedOccupants.length > 0"
        class="planner-occupants"
        :size="6"
        wrap
      >
        <n-tag
          v-for="occupant in planner.selectedOccupants"
          :key="`${occupant.scope}:${occupant.ifaceName}:${occupant.groupId}:${occupant.serviceKind}:${occupant.effectiveIndex}`"
          size="small"
          :type="occupant.conflictsWithSelection ? 'error' : 'default'"
          :bordered="false"
        >
          {{ occupant.ifaceName }} · {{ occupant.serviceKind.toUpperCase() }} ·
          {{ occupantRangeLabel(occupant) }}
        </n-tag>
      </n-flex>

      <div class="planner-legend">
        <span
          v-for="item in legendItems"
          :key="item.label"
          class="planner-legend-item"
        >
          <i
            class="swatch"
            :class="{ 'swatch-striped': item.kind === 'striped' }"
            :style="{
              '--swatch-color': item.color,
              backgroundColor: item.color,
            }"
          />{{ item.label }}
        </span>
      </div>
    </n-flex>
  </n-card>
</template>

<style scoped>
.planner-card {
  margin-top: 8px;
}

.planner-canvas-wrap {
  overflow: auto;
  border: 1px solid var(--n-border-color);
  border-radius: 12px;
  background: var(--n-color);
  padding: 12px;
}

.planner-canvas {
  display: block;
  cursor: crosshair;
}

.planner-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 12px;
}

.planner-occupants {
  align-items: center;
}

.planner-legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.swatch {
  width: 12px;
  height: 12px;
  border-radius: 3px;
  border: 1px solid var(--n-border-color);
  display: inline-block;
}

.swatch-striped {
  background-image: repeating-linear-gradient(
    135deg,
    color-mix(in srgb, var(--swatch-color) 62%, var(--n-text-color)) 0 2px,
    color-mix(in srgb, var(--swatch-color) 18%, transparent) 2px 4px
  );
}
</style>
