<script setup lang="ts">
import { ref, computed, onMounted, watch } from "vue";
import { useRoute } from "vue-router";
import { useI18n } from "vue-i18n";
import { useMetricStore } from "@/stores/status_metric";
import { get_history_dst_ip_stats } from "@/api/metric";
import { formatSize } from "@/lib/util";
import { useThemeVars } from "naive-ui";
import HistoryIpStatsList from "@/components/metric/connect/history/HistoryIpStatsList.vue";
import ConnectViewSwitcher from "@/components/metric/connect/ConnectViewSwitcher.vue";
import FlowSelect from "@/components/flow/FlowSelect.vue";
import type {
  GetHistoryDstIpStatsParams as ConnectHistoryQueryParams,
  IpHistoryStat,
  ConnectSortKey,
  SortOrder,
} from "@landscape-router/types/api/schemas";
import { usePreferenceStore } from "@/stores/preference";

const metricStore = useMetricStore();
const themeVars = useThemeVars();
const prefStore = usePreferenceStore();
const route = useRoute();
const { t } = useI18n();

const stats = ref<IpHistoryStat[]>([]);
const loading = ref(false);

const timeRange = ref<number | string | null>(300); // default 5 minutes
const queryLimit = ref<number | null>(100);
const flowId = ref<number | null>(null);
const ipSearch = ref<string>("");
const useCustomTimeRange = ref(false);
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

const fetchStats = async () => {
  loading.value = true;
  try {
    let startTime: number | undefined;
    let endTime: number | undefined;

    if (useCustomTimeRange.value && customTimeRange.value) {
      startTime = customTimeRange.value[0];
      endTime = customTimeRange.value[1];
    } else if (timeRange.value !== null && timeRange.value !== "custom") {
      startTime = Date.now() - (timeRange.value as number) * 1000;
    }

    const params: ConnectHistoryQueryParams = {
      start_time: startTime,
      end_time: endTime,
      limit: queryLimit.value || undefined,
      flow_id: flowId.value || undefined,
      dst_ip: ipSearch.value || undefined,
      sort_key: sortKey.value,
      sort_order: sortOrder.value,
    };
    stats.value = await get_history_dst_ip_stats(params);
  } finally {
    loading.value = false;
  }
};

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

watch(timeRange, (newVal) => {
  if (newVal === "custom") {
    useCustomTimeRange.value = true;
  } else {
    useCustomTimeRange.value = false;
    customTimeRange.value = null;
    fetchStats();
  }
});

watch([queryLimit, flowId, customTimeRange], () => {
  fetchStats();
});

// Debounced query
let debounceTimer: ReturnType<typeof setTimeout> | null = null;
watch(ipSearch, () => {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    fetchStats();
  }, 600);
});

onMounted(() => {
  if (route.query.ip) ipSearch.value = route.query.ip as string;
  if (route.query.flow_id)
    flowId.value = parseInt(route.query.flow_id as string);

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
        :placeholder="$t('metric.connect.filter.search_dst')"
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
        :title="$t('metric.connect.stats.history_dst')"
        :ip-label="$t('metric.connect.col.dst_ip')"
        :sort-key="sortKey"
        :sort-order="sortOrder"
        show-geo-lookup
        @update:sort="handleSortChange"
        @search:ip="(ip) => (ipSearch = ip)"
      />
    </n-spin>
  </n-flex>
</template>
