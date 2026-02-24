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

const timeRange = ref<number | string | null>(300); // 默认 5 分钟
const queryLimit = ref<number | null>(100);
const flowId = ref<number | null>(null);
const ipSearch = ref<string>("");
const useCustomTimeRange = ref(false);
const customTimeRange = ref<[number, number] | null>(null);

// 排序状态
const sortKey = ref<ConnectSortKey>("egress");
const sortOrder = ref<SortOrder>("desc");

const globalStats = computed(() => metricStore.global_history_stats);

const timeRangeOptions = computed(() => [
  { label: "近 5 分钟", value: 300 },
  { label: "近 15 分钟", value: 900 },
  { label: "近 1 小时", value: 3600 },
  { label: "近 6 小时", value: 21600 },
  { label: "近 24 小时", value: 86400 },
  { label: "近 3 天", value: 259200 },
  { label: "自定义时间段", value: "custom" },
  { label: t("metric.connect.filter.all_status"), value: null },
]);

const limitOptions = computed(() => [
  { label: "限制 100 条", value: 100 },
  { label: "限制 500 条", value: 500 },
  { label: "限制 1000 条", value: 1000 },
  { label: "不限制数量", value: null },
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

// 防抖查询
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
    <!-- 历史全局汇总 -->
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

    <!-- 过滤器工具栏 -->
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
        @update:sort="handleSortChange"
        @search:ip="(ip) => (ipSearch = ip)"
      />
    </n-spin>
  </n-flex>
</template>
