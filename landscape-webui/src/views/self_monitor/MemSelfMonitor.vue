<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";
import { Renew } from "@vicons/carbon";
import { HelpCircleOutline } from "@vicons/ionicons5";
import {
  get_memory_modules,
  get_memory_modules_history,
  get_memory_history,
} from "@/api/self_monitor";
import type {
  MemorySnapshot,
  MemorySeriesResponse,
  MemHistoryResponse,
} from "@landscape-router/types/api/schemas";
import { formatSize } from "@/lib/util";
import { useCapabilityStore } from "@/stores/capability";
import { usePreferenceStore } from "@/stores/preference";
import MemLineChart from "@/components/self_monitor/mem/MemLineChart.vue";
import MemSubsystemTable from "@/components/self_monitor/mem/MemSubsystemTable.vue";

const { t } = useI18n();
const themeVars = useThemeVars();
const capabilityStore = useCapabilityStore();
const prefStore = usePreferenceStore();

const SNAPSHOT_POLL_MS = 3000;
const LIVE_CHART_POLL_MS = 5000;
const DEFAULT_TOP_N = 3;

const hasPersistent = computed(() => capabilityStore.HAS("metric_persistent"));

const activeTab = ref("live");

const snapshot = ref<MemorySnapshot | null>(null);
const liveResp = ref<MemorySeriesResponse | null>(null);
const liveLoading = ref(false);

const liveWindow = ref(300);
const liveWindowOptions = computed(() => [
  { label: t("self_monitor.mem.last_5m"), value: 300 },
  { label: t("self_monitor.mem.last_15m"), value: 900 },
  { label: t("self_monitor.mem.last_30m"), value: 1800 },
  { label: t("self_monitor.mem.last_1h"), value: 3600 },
]);

const fetchSnapshot = async () => {
  try {
    snapshot.value = await get_memory_modules();
  } catch (e) {
    console.error(e);
  }
};

const fetchLiveSeries = async () => {
  liveLoading.value = true;
  try {
    liveResp.value = await get_memory_modules_history({
      limit: liveWindow.value,
    });
  } catch (e) {
    console.error(e);
  } finally {
    liveLoading.value = false;
  }
};

const refreshLive = async () => {
  await Promise.all([fetchSnapshot(), fetchLiveSeries()]);
};

const meta = computed(() => snapshot.value?.meta);

const trackingDisabled = computed(
  () => snapshot.value !== null && snapshot.value.enabled === false,
);

const untracked = computed(() => {
  const value = meta.value?.untracked_bytes;
  if (value === null || value === undefined) return "--";
  const sign = value > 0 ? "+" : "";
  return `${sign}${formatSize(value)}`;
});

const compositionRows = computed(() => {
  const comp = snapshot.value?.meta?.composition;
  if (!comp) return [];
  const rows: Array<{ label: string; value: string }> = [
    {
      label: t("self_monitor.mem.comp_heap"),
      value: formatSize(comp.heap_rss_bytes),
    },
    {
      label: t("self_monitor.mem.comp_thread_stacks"),
      value: formatSize(comp.thread_stacks_rss_bytes),
    },
    {
      label: t("self_monitor.mem.comp_file_backed"),
      value: formatSize(comp.file_backed_rss_bytes),
    },
    {
      label: t("self_monitor.mem.comp_other_anon"),
      value: formatSize(comp.other_anon_rss_bytes),
    },
  ];
  if (comp.malloc_in_use_bytes != null) {
    rows.push({
      label: t("self_monitor.mem.comp_malloc_in_use"),
      value: formatSize(comp.malloc_in_use_bytes),
    });
  }
  if (comp.malloc_free_held_bytes != null) {
    rows.push({
      label: t("self_monitor.mem.comp_malloc_free_held"),
      value: formatSize(comp.malloc_free_held_bytes),
    });
  }
  if (comp.header_overhead_bytes != null) {
    rows.push({
      label: t("self_monitor.mem.comp_header_overhead"),
      value: formatSize(comp.header_overhead_bytes),
    });
  }
  if (comp.c_heap_estimated_bytes != null) {
    rows.push({
      label: t("self_monitor.mem.comp_c_heap"),
      value: formatSize(comp.c_heap_estimated_bytes),
    });
  }
  return rows;
});

const liveChartSeries = computed(() => {
  const resp = liveResp.value;
  if (!resp || resp.timestamps.length === 0) return [];
  const result = resp.series
    .map((s) => ({
      name: s.subsystem,
      data: resp.timestamps.map(
        (ts, i) => [ts, s.points[i]?.[2] ?? 0] as [number, number],
      ),
    }))
    .filter((s) => s.data.some(([, v]) => v > 0));
  if (resp.meta && resp.meta.length > 0) {
    const rss: [number, number][] = [];
    resp.timestamps.forEach((ts, i) => {
      const rssBytes = resp.meta![i]?.process_rss_bytes;
      if (typeof rssBytes === "number") {
        rss.push([ts, rssBytes]);
      }
    });
    if (rss.length > 0) {
      result.push({ name: t("self_monitor.mem.process_rss"), data: rss });
    }
  }
  return result;
});

const liveHidden = computed<string[]>(() => {
  const resp = liveResp.value;
  if (!resp) return [];
  const latest = new Map<string, number>();
  for (const s of resp.series) {
    const last = s.points.length > 0 ? s.points[s.points.length - 1][2] : 0;
    latest.set(s.subsystem, last);
  }
  const ranked = [...latest.entries()]
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1]);
  const top = new Set(ranked.slice(0, DEFAULT_TOP_N).map(([name]) => name));
  return [...latest.keys()].filter((name) => !top.has(name));
});

const historyResp = ref<MemHistoryResponse | null>(null);
const historyLoading = ref(false);
const historyLoaded = ref(false);
const historyError = ref(false);

const timeRange = ref<number | string | null>(86400);
const useCustomTimeRange = ref(false);
const customTimeRange = ref<[number, number] | null>(null);

const metricMode = ref("live_avg");
const metricModeOptions = computed(() => [
  { label: t("self_monitor.mem.mode_live_avg"), value: "live_avg" },
  { label: t("self_monitor.mem.mode_live_max"), value: "live_max" },
  { label: t("self_monitor.mem.mode_alloc"), value: "alloc" },
  { label: t("self_monitor.mem.mode_free"), value: "free" },
]);

const METRIC_MODE_INDEX: Record<string, number> = {
  live_avg: 0,
  live_max: 1,
  alloc: 2,
  free: 3,
};

const timeRangeOptions = computed(() => [
  { label: t("self_monitor.mem.last_1h"), value: 3600 },
  { label: t("self_monitor.mem.last_6h"), value: 21600 },
  { label: t("self_monitor.mem.last_24h"), value: 86400 },
  { label: t("self_monitor.mem.last_3d"), value: 259200 },
  { label: t("self_monitor.mem.custom_range"), value: "custom" },
]);

const selectedSubsystems = ref<string[]>([]);

const PROCESS_SUBSYSTEM = "(process)";

const subsystemLabel = (name: string) =>
  name === PROCESS_SUBSYSTEM ? t("self_monitor.mem.process_rss") : name;

const subsystemOptions = computed(() =>
  (historyResp.value?.series ?? []).map((s) => ({
    label: subsystemLabel(s.subsystem),
    value: s.subsystem,
  })),
);

const fetchHistory = async () => {
  if (!hasPersistent.value) return;
  historyLoading.value = true;
  historyError.value = false;
  try {
    let start_time = 0;
    let end_time = 0;
    if (useCustomTimeRange.value && customTimeRange.value) {
      start_time = customTimeRange.value[0];
      end_time = customTimeRange.value[1];
    } else if (typeof timeRange.value === "number") {
      start_time = Date.now() - timeRange.value * 1000;
    }
    historyResp.value = await get_memory_history({
      start_time,
      end_time,
      limit: 0,
    });
    historyLoaded.value = true;
  } catch (e) {
    console.error(e);
    historyError.value = true;
  } finally {
    historyLoading.value = false;
  }
};

const historyChartSeries = computed(() => {
  const resp = historyResp.value;
  if (!resp || resp.timestamps.length === 0) return [];
  const idx = METRIC_MODE_INDEX[metricMode.value] ?? 0;
  const filter = selectedSubsystems.value;
  return resp.series
    .filter((s) => filter.length === 0 || filter.includes(s.subsystem))
    .map((s) => ({
      name: subsystemLabel(s.subsystem),
      data: resp.timestamps.map(
        (ts, i) => [ts, s.points[i]?.[idx] ?? 0] as [number, number],
      ),
    }));
});

const historyHidden = computed<string[]>(() => {
  const ranked = historyChartSeries.value
    .map((s) => ({
      name: s.name,
      peak: s.data.reduce((max, [, v]) => (v > max ? v : max), 0),
    }))
    .sort((a, b) => b.peak - a.peak);
  const top = new Set(ranked.slice(0, DEFAULT_TOP_N).map((s) => s.name));
  return ranked.filter((s) => !top.has(s.name)).map((s) => s.name);
});

watch(timeRange, (newVal) => {
  if (newVal === "custom") {
    useCustomTimeRange.value = true;
  } else {
    useCustomTimeRange.value = false;
    customTimeRange.value = null;
    fetchHistory();
  }
});

watch(customTimeRange, () => {
  if (useCustomTimeRange.value && customTimeRange.value) {
    fetchHistory();
  }
});

watch(activeTab, (tab) => {
  if (tab === "history" && hasPersistent.value && !historyLoaded.value) {
    fetchHistory();
  }
});

let snapshotTimer: ReturnType<typeof setInterval> | null = null;
let liveTimer: ReturnType<typeof setInterval> | null = null;

const startTimers = () => {
  if (!snapshotTimer) {
    snapshotTimer = setInterval(fetchSnapshot, SNAPSHOT_POLL_MS);
  }
  if (!liveTimer) {
    liveTimer = setInterval(fetchLiveSeries, LIVE_CHART_POLL_MS);
  }
};

const stopTimers = () => {
  if (snapshotTimer) {
    clearInterval(snapshotTimer);
    snapshotTimer = null;
  }
  if (liveTimer) {
    clearInterval(liveTimer);
    liveTimer = null;
  }
};

const handleVisibilityChange = () => {
  if (document.hidden) {
    stopTimers();
  } else {
    startTimers();
    refreshLive();
  }
};

onMounted(() => {
  capabilityStore.LOAD();
  refreshLive();
  startTimers();
  document.addEventListener("visibilitychange", handleVisibilityChange);
});

onUnmounted(() => {
  stopTimers();
  document.removeEventListener("visibilitychange", handleVisibilityChange);
});
</script>

<template>
  <n-flex vertical style="flex: 1; overflow: hidden; min-height: 0">
    <n-empty
      v-if="trackingDisabled"
      :description="t('self_monitor.mem.need_mem_track')"
      style="flex: 1; justify-content: center"
    />
    <n-card
      v-else
      size="small"
      :bordered="false"
      style="margin-bottom: 12px; background-color: #f9f9f910; flex-shrink: 0"
    >
      <n-flex align="center" justify="space-between">
        <n-flex align="center" size="small">
          <span style="font-weight: 600">{{
            t("self_monitor.mem.title")
          }}</span>
          <n-tooltip trigger="hover">
            <template #trigger>
              <n-tag size="small" :bordered="false" type="success">
                {{ t("self_monitor.mem.enabled") }}
              </n-tag>
            </template>
            {{ t("self_monitor.mem.enabled_tip") }}
          </n-tooltip>
        </n-flex>
      </n-flex>
      <n-flex align="center" :wrap="true" size="large" style="margin-top: 8px">
        <n-flex align="center" size="small">
          <span style="color: #888; font-size: 13px">
            {{ t("self_monitor.mem.process_rss") }}:
          </span>
          <span style="font-weight: bold">
            {{
              meta?.process_rss_bytes != null
                ? formatSize(meta.process_rss_bytes)
                : "--"
            }}
          </span>
        </n-flex>
        <n-divider vertical />
        <n-flex align="center" size="small">
          <span style="color: #888; font-size: 13px">
            {{ t("self_monitor.mem.process_vsz") }}:
          </span>
          <span style="font-weight: bold">
            {{
              meta?.process_virtual_bytes != null
                ? formatSize(meta.process_virtual_bytes)
                : "--"
            }}
          </span>
        </n-flex>
        <n-divider vertical />
        <n-flex align="center" size="small">
          <span style="color: #888; font-size: 13px">
            {{ t("self_monitor.mem.total_live") }}:
          </span>
          <span :style="{ fontWeight: 'bold', color: themeVars.successColor }">
            {{ formatSize(meta?.total_live_bytes ?? 0) }}
          </span>
        </n-flex>
        <n-divider vertical />
        <n-tooltip trigger="hover">
          <template #trigger>
            <n-flex align="center" size="small" style="cursor: help">
              <span style="color: #888; font-size: 13px">
                {{ t("self_monitor.mem.untracked") }}:
              </span>
              <span
                :style="{
                  fontWeight: 'bold',
                  color:
                    (meta?.untracked_bytes ?? 0) > 0
                      ? themeVars.warningColor
                      : themeVars.textColor1,
                }"
              >
                {{ untracked }}
              </span>
              <n-icon size="14" style="color: #888">
                <HelpCircleOutline />
              </n-icon>
            </n-flex>
          </template>
          <n-flex vertical size="small">
            <span>{{ t("self_monitor.mem.untracked_tip") }}</span>
            <template v-if="compositionRows.length > 0">
              <n-divider style="margin: 4px 0" />
              <div style="font-weight: 600; margin-bottom: 2px">
                {{ t("self_monitor.mem.composition") }}
              </div>
              <n-flex
                v-for="row in compositionRows"
                :key="row.label"
                justify="space-between"
                size="large"
                style="gap: 24px"
              >
                <span>{{ row.label }}</span>
                <span style="font-weight: 600">{{ row.value }}</span>
              </n-flex>
            </template>
          </n-flex>
        </n-tooltip>
      </n-flex>
    </n-card>

    <n-tabs
      v-if="!trackingDisabled"
      v-model:value="activeTab"
      type="line"
      size="small"
      display-directive="show:lazy"
      style="flex: 1; min-height: 0; display: flex; flex-direction: column"
      pane-wrapper-style="flex: 1; min-height: 0"
      :pane-style="{
        height: '100%',
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
      }"
    >
      <n-tab-pane name="live" :tab="t('self_monitor.mem.live')">
        <n-flex vertical :size="12" style="flex: 1; min-height: 0">
          <n-flex align="center" size="small">
            <n-select
              v-model:value="liveWindow"
              :options="liveWindowOptions"
              size="small"
              style="width: 140px"
              @update:value="fetchLiveSeries"
            />
            <n-button size="small" :loading="liveLoading" @click="refreshLive">
              <template #icon>
                <n-icon><Renew /></n-icon>
              </template>
              {{ t("self_monitor.mem.refresh") }}
            </n-button>
            <n-tooltip trigger="hover">
              <template #trigger>
                <n-icon size="15" style="color: #888; cursor: help">
                  <HelpCircleOutline />
                </n-icon>
              </template>
              {{ t("self_monitor.mem.legend_hint") }}
            </n-tooltip>
          </n-flex>

          <n-card
            size="small"
            :bordered="false"
            style="background-color: #f9f9f910"
            content-style="padding: 8px"
          >
            <MemLineChart
              v-if="liveChartSeries.length > 0"
              :series="liveChartSeries"
              :x-axis-title="t('self_monitor.mem.time_window')"
              :y-axis-title="t('self_monitor.mem.live_bytes')"
              :value-formatter="formatSize"
              :hidden-by-default="liveHidden"
              :dashed-names="[t('self_monitor.mem.process_rss')]"
            />
            <n-empty
              v-else
              :description="t('self_monitor.mem.no_data')"
              style="height: 320px; justify-content: center"
            />
          </n-card>

          <n-card
            size="small"
            :bordered="false"
            style="
              flex: 1;
              min-height: 0;
              display: flex;
              flex-direction: column;
              background-color: #f9f9f910;
            "
            content-style="
              flex: 1;
              min-height: 0;
              display: flex;
              flex-direction: column;
              padding: 12px;
            "
          >
            <MemSubsystemTable :modules="snapshot?.modules ?? []" />
          </n-card>
        </n-flex>
      </n-tab-pane>

      <n-tab-pane name="history" :tab="t('self_monitor.mem.history')">
        <n-empty
          v-if="!hasPersistent"
          :description="t('self_monitor.mem.need_persistent')"
          style="height: 360px; justify-content: center"
        />
        <n-flex v-else vertical :size="12" style="flex: 1; min-height: 0">
          <n-flex align="center" :wrap="true" size="small">
            <n-select
              v-model:value="timeRange"
              :options="timeRangeOptions"
              size="small"
              style="width: 140px"
            />
            <n-date-picker
              v-if="useCustomTimeRange"
              v-model:value="customTimeRange"
              type="datetimerange"
              size="small"
              clearable
              style="width: 300px"
              format="yyyy-MM-dd HH:mm"
              :is-date-disabled="(ts: number) => ts > Date.now()"
              :time-picker-props="{ timeZone: prefStore.timezone }"
            />
            <n-select
              v-model:value="metricMode"
              :options="metricModeOptions"
              size="small"
              style="width: 160px"
            />
            <n-select
              v-model:value="selectedSubsystems"
              multiple
              clearable
              filterable
              max-tag-count="responsive"
              :options="subsystemOptions"
              :placeholder="t('self_monitor.mem.all_subsystems')"
              size="small"
              style="width: 260px"
            />
            <n-button
              size="small"
              type="primary"
              :loading="historyLoading"
              @click="fetchHistory"
            >
              {{ t("self_monitor.mem.query") }}
            </n-button>
            <n-tooltip trigger="hover">
              <template #trigger>
                <n-icon size="15" style="color: #888; cursor: help">
                  <HelpCircleOutline />
                </n-icon>
              </template>
              <div>{{ t("self_monitor.mem.legend_hint") }}</div>
              <div>{{ t("self_monitor.mem.zero_fill_tip") }}</div>
            </n-tooltip>
          </n-flex>

          <n-card
            size="small"
            :bordered="false"
            style="
              flex: 1;
              min-height: 0;
              display: flex;
              flex-direction: column;
              background-color: #f9f9f910;
            "
            content-style="
              flex: 1;
              min-height: 0;
              display: flex;
              flex-direction: column;
              padding: 8px;
            "
          >
            <MemLineChart
              v-if="historyChartSeries.length > 0"
              :series="historyChartSeries"
              :x-axis-title="t('self_monitor.mem.time_range')"
              :y-axis-title="
                metricMode === 'alloc' || metricMode === 'free'
                  ? t('self_monitor.mem.bytes_per_min')
                  : t('self_monitor.mem.live_bytes')
              "
              :value-formatter="formatSize"
              :hidden-by-default="historyHidden"
              height="100%"
            />
            <n-empty
              v-else-if="historyError"
              :description="t('self_monitor.mem.query_failed')"
              style="flex: 1; justify-content: center"
            />
            <n-empty
              v-else-if="historyLoaded"
              :description="t('self_monitor.mem.no_data')"
              style="flex: 1; justify-content: center"
            />
            <n-flex
              v-else
              align="center"
              justify="center"
              style="flex: 1; min-height: 240px"
            >
              <n-spin size="small" />
            </n-flex>
          </n-card>
        </n-flex>
      </n-tab-pane>
    </n-tabs>
  </n-flex>
</template>
