<script setup lang="ts">
import { ref, computed, onMounted, watch } from "vue";
import { useRoute } from "vue-router";
import { useI18n } from "vue-i18n";
import { useMetricStore } from "@/stores/status_metric";
import { useHistoryIpStats } from "@/composables/useHistoryIpStats";
import { formatSize } from "@/lib/util";
import { useThemeVars } from "naive-ui";
import HistoryIpStatsList from "@/components/metric/connect/history/HistoryIpStatsList.vue";
import ConnectViewSwitcher from "@/components/metric/connect/ConnectViewSwitcher.vue";
import FlowSelect from "@/components/flow/FlowSelect.vue";
import type {
  ConnectSortKey,
  SortOrder,
} from "@landscape-router/types/api/schemas";
import { usePreferenceStore } from "@/stores/preference";

const { direction } = defineProps<{ direction: "src" | "dst" }>();

const metricStore = useMetricStore();
const themeVars = useThemeVars();
const prefStore = usePreferenceStore();
const route = useRoute();
const { t } = useI18n();

const { stats, loading, query } = useHistoryIpStats(direction);

const timeRange = ref<number | "custom" | null>(300); // default 5 minutes
const queryLimit = ref<number | null>(100);
const initialFlow = route.query.flow_id;
const flowId = ref<number | null>(
  typeof initialFlow === "string" && /^\d+$/.test(initialFlow)
    ? Number(initialFlow)
    : null,
);
const ipSearch = ref(typeof route.query.ip === "string" ? route.query.ip : "");
const useCustomTimeRange = computed(() => timeRange.value === "custom");
const customTimeRange = ref<[number, number] | null>(null);

// Sort state
const sortKey = ref<ConnectSortKey>("egress");
const sortOrder = ref<SortOrder>("desc");

const globalStats = computed(() => metricStore.global_history_stats);

const timeRangeOptions = computed(() => [
  { label: t("metric.connect.filter.last_5m"), value: 300 },
  { label: t("metric.connect.filter.last_15m"), value: 900 },
  { label: t("metric.connect.filter.last_1h"), value: 3600 },
  { label: t("metric.connect.filter.last_6h"), value: 21600 },
  { label: t("metric.connect.filter.last_24h"), value: 86400 },
  { label: t("metric.connect.filter.last_3d"), value: 259200 },
  { label: t("metric.connect.filter.custom_range"), value: "custom" },
  { label: t("metric.connect.filter.all_status"), value: null },
]);

const limitOptions = computed(() => [
  { label: t("metric.connect.filter.limit_100"), value: 100 },
  { label: t("metric.connect.filter.limit_500"), value: 500 },
  { label: t("metric.connect.filter.limit_1000"), value: 1000 },
  { label: t("metric.connect.filter.unlimited"), value: null },
]);

function fetchStats() {
  const range = timeRange.value;
  const custom = range === "custom" ? customTimeRange.value : null;
  return query({
    start_time:
      typeof range === "number" ? Date.now() - range * 1000 : custom?.[0],
    end_time: custom?.[1],
    limit: queryLimit.value ?? undefined,
    flowId: flowId.value,
    ip: ipSearch.value,
    sort_key: sortKey.value,
    sort_order: sortOrder.value,
  });
}

const handleSortChange = ({
  key,
  order,
}: {
  key: ConnectSortKey;
  order: SortOrder;
}) => {
  sortKey.value = key;
  sortOrder.value = order;
  fetchStats();
};

watch(
  timeRange,
  (range) => {
    if (range !== "custom") customTimeRange.value = null;
  },
  { flush: "sync" },
);

watch(
  [timeRange, queryLimit, flowId, customTimeRange],
  ([range], [previousRange]) => {
    if (range === "custom" && previousRange !== "custom") return;
    return fetchStats();
  },
);

// Debounced query
watch(ipSearch, (_, __, onCleanup) => {
  const timer = setTimeout(fetchStats, 600);
  onCleanup(() => clearTimeout(timer));
});

onMounted(() => {
  fetchStats();
  if (!metricStore.global_history_stats) {
    metricStore.UPDATE_GLOBAL_HISTORY_STATS();
  }
});
</script>

<template>
  <n-flex vertical style="flex: 1; overflow: hidden">
    <!-- History global summary -->
    <n-card
      size="small"
      :bordered="false"
      style="margin-bottom: 12px; background-color: #f9f9f910"
    >
      <n-flex align="center" justify="space-between">
        <ConnectViewSwitcher />

        <n-flex align="center" size="large" v-if="globalStats">
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ $t("metric.connect.stats.total_history_conns") }}:</span
            >
            <span style="font-weight: bold">{{
              globalStats.total_connect_count
            }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ $t("metric.connect.stats.total_history_egress") }}:</span
            >
            <span :style="{ fontWeight: 'bold', color: themeVars.infoColor }">{{
              formatSize(globalStats.total_egress_bytes)
            }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ $t("metric.connect.stats.total_history_ingress") }}:</span
            >
            <span
              :style="{ fontWeight: 'bold', color: themeVars.successColor }"
              >{{ formatSize(globalStats.total_ingress_bytes) }}</span
            >
          </n-flex>
        </n-flex>
      </n-flex>
    </n-card>

    <!-- Filter toolbar -->
    <n-flex
      align="center"
      :wrap="true"
      style="margin-bottom: 12px"
      size="small"
    >
      <n-input
        v-model:value="ipSearch"
        :placeholder="$t(`metric.connect.filter.search_${direction}`)"
        clearable
        style="width: 180px"
        :disabled="loading"
      />
      <FlowSelect v-model="flowId" :disabled="loading" width="130px" />
      <n-divider vertical />
      <n-select
        v-model:value="timeRange"
        :options="timeRangeOptions"
        :disabled="loading"
        style="width: 150px"
      />
      <n-date-picker
        v-if="useCustomTimeRange"
        v-model:value="customTimeRange"
        type="datetimerange"
        :disabled="loading"
        clearable
        style="width: 360px"
        format="yyyy-MM-dd HH:mm"
        :is-date-disabled="(ts: number) => ts > Date.now()"
        :time-picker-props="{ timeZone: prefStore.timezone }"
      />
      <n-select
        v-model:value="queryLimit"
        :options="limitOptions"
        :disabled="loading"
        style="width: 150px"
      />
      <n-button @click="fetchStats" type="primary" :loading="loading">{{
        $t("metric.connect.stats.query")
      }}</n-button>
    </n-flex>

    <n-spin :show="loading">
      <HistoryIpStatsList
        :stats="stats"
        :title="$t(`metric.connect.stats.history_${direction}`)"
        :show-geo-lookup="direction === 'dst'"
        :ip-label="$t(`metric.connect.col.${direction}_ip`)"
        :sort-key="sortKey"
        :sort-order="sortOrder"
        @update:sort="handleSortChange"
        @search:ip="(ip) => (ipSearch = ip)"
      />
    </n-spin>
  </n-flex>
</template>
