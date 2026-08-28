<script setup lang="ts">
import { ref, computed, reactive, onMounted, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute } from "vue-router";
import { ConnectFilter } from "@/lib/metric.rs";
import { get_connect_history } from "@/api/metric";
import { formatSize, formatCount } from "@/lib/util";
import { useThemeVars } from "naive-ui";
import { useMetricStore } from "@/stores/status_metric";
import { useFrontEndStore } from "@/stores/front_end_config";
import HistoryItemInfo from "@/components/metric/connect/history/HistoryItemInfo.vue";
import ConnectChartDrawer from "@/components/metric/connect/ConnectChartDrawer.vue";
import FlowSelect from "@/components/flow/FlowSelect.vue";
import type {
  ConnectKey,
  ConnectGlobalStats,
} from "@landscape-router/types/api/schemas";
import { usePreferenceStore } from "@/stores/preference";
import { Renew } from "@vicons/carbon";
import ConnectViewSwitcher from "@/components/metric/connect/ConnectViewSwitcher.vue";

const prefStore = usePreferenceStore();
const metricStore = useMetricStore();
const route = useRoute();
const { t } = useI18n();

const themeVars = useThemeVars();
const frontEndStore = useFrontEndStore();

// 1. Declare all base reactive states.
const historicalData = ref<any[]>([]);
const timeRange = ref<number | string | null>(300); // default 5 minutes (300s)
const historyFilter = reactive(new ConnectFilter());
// 与后端 sqlite 查询偏移上限保持一致,防止翻页超过 offset clamp 后重复展示同一页。
const MAX_PAGE_OFFSET = 10_000;

const pagination = reactive({
  page: 1,
  pageSize: 50, // Default 50
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [50, 100, 200],
  "onUpdate:page": (page: number) => {
    pagination.page = page;
    fetchHistory();
  },
  onUpdatePageSize: (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    fetchHistory();
  },
});
const sortKey = computed(() => frontEndStore.history_conn_sort_key);
const sortOrder = computed(() => frontEndStore.history_conn_sort_order);

// Global history stats
const globalStats = computed(() => metricStore.global_history_stats);
const refreshingGlobalStats = ref(false);

const refreshGlobalStats = async (forceRefresh = true) => {
  if (refreshingGlobalStats.value) return;
  refreshingGlobalStats.value = true;
  try {
    await metricStore.UPDATE_GLOBAL_HISTORY_STATS(forceRefresh);
  } catch (e) {
    console.error(e);
  } finally {
    refreshingGlobalStats.value = false;
  }
};

// Chart drawer state
const showChart = ref(false);
const showChartKey = ref<ConnectKey | null>(null);
const showChartTitle = ref("");
const showChartCreateTimeMs = ref<number | undefined>();
const showChartLastReportTime = ref<number | undefined>();
const loading = ref(false);

// Custom time range.
const useCustomTimeRange = ref(false);
const customTimeRange = ref<[number, number] | null>(null);

const showChartDrawer = (history: any) => {
  showChartKey.value = history.key;
  showChartTitle.value = `${frontEndStore.MASK_INFO(history.src_ip)}:${frontEndStore.MASK_PORT(history.src_port)} => ${frontEndStore.MASK_INFO(history.dst_ip)}:${frontEndStore.MASK_PORT(history.dst_port)}`;
  showChartCreateTimeMs.value = history.create_time_ms;
  showChartLastReportTime.value = history.last_report_time;
  showChart.value = true;
};

// 2. Option constants
const protocolOptions = computed(() => [
  { label: t("metric.connect.all_types"), value: null },
  { label: "TCP", value: 6 },
  { label: "UDP", value: 17 },
  { label: "ICMP", value: 1 },
  { label: "ICMPv6", value: 58 },
]);

// Direction options.
const gressOptions = computed(() => [
  { label: t("metric.connect.all_types"), value: null },
  { label: t("metric.connect.filter.gress_egress"), value: 1 },
  { label: t("metric.connect.filter.gress_ingress"), value: 0 },
]);

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

// 3. Data fetching actions
const fetchHistory = async () => {
  loading.value = true;
  try {
    let startTime: number | undefined;
    let endTime: number | undefined;

    if (useCustomTimeRange.value && customTimeRange.value) {
      // Use custom time range.
      startTime = customTimeRange.value[0];
      endTime = customTimeRange.value[1];
    } else if (timeRange.value !== null && timeRange.value !== "custom") {
      // Use relative time range.
      startTime = Date.now() - (timeRange.value as number) * 1000;
    }

    const response = await get_connect_history({
      start_time: startTime,
      end_time: endTime,
      limit: pagination.pageSize,
      offset: (pagination.page - 1) * pagination.pageSize,
      src_ip: historyFilter.src_ip || undefined,
      dst_ip: historyFilter.dst_ip || undefined,
      port_start: historyFilter.port_start || undefined,
      port_end: historyFilter.port_end || undefined,
      l3_proto: historyFilter.l3_proto || undefined,
      l4_proto: historyFilter.l4_proto || undefined,
      flow_id: historyFilter.flow_id || undefined,
      gress: historyFilter.gress ?? undefined,
      ifindex: historyFilter.ifindex ?? undefined,
      sort_key: sortKey.value,
      sort_order: sortOrder.value,
    });
    historicalData.value = response.items;
    pagination.itemCount = Math.min(response.total, MAX_PAGE_OFFSET);
    // 过滤条件收紧导致 total 缩小后,若当前页已越界则回到最后一页并重新请求:
    // 程序赋值不会触发 onUpdate:page,否则列表停留在越界页(空白/陈旧数据)。
    const maxPage = Math.max(
      1,
      Math.ceil(pagination.itemCount / pagination.pageSize),
    );
    if (pagination.page > maxPage) {
      pagination.page = maxPage;
      await fetchHistory();
      return;
    }
  } finally {
    loading.value = false;
  }
};

const resetHistoryFilter = () => {
  Object.assign(historyFilter, new ConnectFilter());
  pagination.page = 1;
  fetchHistory();
};

const toggleSort = (
  key: "time" | "port" | "ingress" | "egress" | "duration",
) => {
  if (frontEndStore.history_conn_sort_key === key) {
    frontEndStore.history_conn_sort_order =
      frontEndStore.history_conn_sort_order === "asc" ? "desc" : "asc";
  } else {
    frontEndStore.history_conn_sort_key = key;
    frontEndStore.history_conn_sort_order = "desc";
  }
};

const handleSearchTuple = (history: any) => {
  historyFilter.src_ip = history.src_ip;
  historyFilter.dst_ip = history.dst_ip;
  historyFilter.port_start = history.src_port;
  historyFilter.port_end = history.dst_port;
  historyFilter.ifindex = history.ifindex;
};

function queryString(value: unknown) {
  const raw = Array.isArray(value) ? value[0] : value;
  return typeof raw === "string" && raw.length > 0 ? raw : undefined;
}

function queryNumber(value: unknown) {
  const raw = queryString(value);
  if (raw === undefined) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

// 4. Computed values
const filteredHistory = computed(() => {
  return historicalData.value || [];
});

const historyTotalStats = computed(() => {
  const stats = {
    totalIngressBytes: 0,
    totalEgressBytes: 0,
    totalIngressPkts: 0,
    totalEgressPkts: 0,
    count: 0,
  };
  if (filteredHistory.value) {
    filteredHistory.value.forEach((item) => {
      stats.totalIngressBytes += item.total_ingress_bytes || 0;
      stats.totalEgressBytes += item.total_egress_bytes || 0;
      stats.totalIngressPkts += item.total_ingress_pkts || 0;
      stats.totalEgressPkts += item.total_egress_pkts || 0;
      stats.count++;
    });
  }
  return stats;
});

// 5. Watchers & lifecycle
// Watch time range selection and toggle custom mode.
watch(timeRange, (newVal) => {
  if (newVal === "custom") {
    useCustomTimeRange.value = true;
  } else {
    useCustomTimeRange.value = false;
    customTimeRange.value = null;
    pagination.page = 1;
    fetchHistory();
  }
});

// Watch custom range changes.
watch(customTimeRange, () => {
  if (useCustomTimeRange.value && customTimeRange.value) {
    pagination.page = 1;
    fetchHistory();
  }
});

// Auto-query on sort changes.
watch([sortKey, sortOrder], () => {
  pagination.page = 1;
  fetchHistory();
});

// Debounced query: trigger 800ms after typing stops.
let debounceTimer: ReturnType<typeof setTimeout> | null = null;
watch(
  historyFilter,
  () => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      pagination.page = 1;
      fetchHistory();
    }, 800); // 800ms delay
  },
  { deep: true },
);

onMounted(() => {
  // Initialize filters from route query params.
  const srcIp = queryString(route.query.src_ip);
  const dstIp = queryString(route.query.dst_ip);
  const portStart = queryNumber(route.query.port_start);
  const portEnd = queryNumber(route.query.port_end);
  const flowId = queryNumber(route.query.flow_id);
  const ifindex = queryNumber(route.query.ifindex);

  if (srcIp) historyFilter.src_ip = srcIp;
  if (dstIp) historyFilter.dst_ip = dstIp;
  if (portStart !== null) historyFilter.port_start = portStart;
  if (portEnd !== null) historyFilter.port_end = portEnd;
  if (flowId !== null) historyFilter.flow_id = flowId;
  if (ifindex !== null) historyFilter.ifindex = ifindex;

  refreshGlobalStats(false);
  fetchHistory();
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
              >{{ t("metric.connect.stats.total_history_conns") }}:</span
            >
            <span style="font-weight: bold">{{
              globalStats.total_connect_count
            }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ t("metric.connect.stats.total_history_egress") }}:</span
            >
            <span :style="{ fontWeight: 'bold', color: themeVars.infoColor }">{{
              formatSize(globalStats.total_egress_bytes)
            }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ t("metric.connect.stats.total_history_ingress") }}:</span
            >
            <span
              :style="{ fontWeight: 'bold', color: themeVars.successColor }"
              >{{ formatSize(globalStats.total_ingress_bytes) }}</span
            >
          </n-flex>

          <n-tooltip trigger="hover">
            <template #trigger>
              <n-button
                quaternary
                circle
                size="tiny"
                @click="refreshGlobalStats"
                :loading="refreshingGlobalStats"
              >
                <template #icon>
                  <n-icon><Renew /></n-icon>
                </template>
              </n-button>
            </template>
            {{ t("metric.connect.stats.last_summary_time") }}:
            <n-time
              v-if="globalStats.last_calculate_time > 0"
              :time="globalStats.last_calculate_time"
              format="yyyy-MM-dd HH:mm:ss"
            />
            <span v-else>--</span>
          </n-tooltip>
        </n-flex>
        <div v-else style="height: 34px"></div>
      </n-flex>
    </n-card>

    <!-- Toolbar for history mode -->
    <n-flex
      align="center"
      :wrap="true"
      style="margin-bottom: 12px"
      size="small"
    >
      <n-input
        v-model:value="historyFilter.src_ip"
        :placeholder="$t('metric.connect.filter.src_ip')"
        clearable
        :disabled="loading"
        style="width: 150px"
      />
      <n-input
        v-model:value="historyFilter.dst_ip"
        :placeholder="$t('metric.connect.filter.dst_ip')"
        clearable
        :disabled="loading"
        style="width: 150px"
      />
      <n-input-group style="width: 220px">
        <n-input-number
          v-model:value="historyFilter.port_start"
          :placeholder="$t('metric.connect.filter.port_start')"
          :show-button="false"
          :disabled="loading"
          clearable
        />
        <n-input-group-label>=></n-input-group-label>
        <n-input-number
          v-model:value="historyFilter.port_end"
          :placeholder="$t('metric.connect.filter.port_end')"
          :show-button="false"
          :disabled="loading"
          clearable
        />
      </n-input-group>
      <n-select
        v-model:value="historyFilter.l4_proto"
        :placeholder="$t('metric.connect.filter.proto')"
        :options="protocolOptions"
        :disabled="loading"
        clearable
        style="width: 110px"
      />
      <n-select
        v-model:value="historyFilter.gress"
        :placeholder="$t('metric.connect.filter.gress')"
        :options="gressOptions"
        :disabled="loading"
        clearable
        style="width: 110px"
      />
      <FlowSelect
        v-model="historyFilter.flow_id"
        :disabled="loading"
        width="120px"
      />

      <n-divider vertical />

      <n-select
        v-model:value="timeRange"
        :options="timeRangeOptions"
        :disabled="loading"
        style="width: 150px"
      />

      <!-- Custom range picker -->
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

      <n-button-group>
        <n-button @click="fetchHistory" type="primary" :loading="loading">{{
          $t("metric.connect.stats.query")
        }}</n-button>
        <n-button @click="resetHistoryFilter" :disabled="loading">{{
          $t("metric.connect.stats.reset")
        }}</n-button>
      </n-button-group>

      <n-divider vertical />

      <n-button-group>
        <n-button
          :type="sortKey === 'time' ? 'primary' : 'default'"
          :disabled="loading"
          @click="toggleSort('time')"
        >
          {{ $t("metric.connect.filter.time") }}
          {{ sortKey === "time" ? (sortOrder === "asc" ? "↑" : "↓") : "" }}
        </n-button>
        <n-button
          :type="sortKey === 'port' ? 'primary' : 'default'"
          :disabled="loading"
          @click="toggleSort('port')"
        >
          {{ $t("metric.connect.filter.port") }}
          {{ sortKey === "port" ? (sortOrder === "asc" ? "↑" : "↓") : "" }}
        </n-button>
        <n-button
          :type="sortKey === 'egress' ? 'primary' : 'default'"
          :disabled="loading"
          @click="toggleSort('egress')"
        >
          {{ $t("metric.connect.col.total_egress") }}
          {{ sortKey === "egress" ? (sortOrder === "asc" ? "↑" : "↓") : "" }}
        </n-button>
        <n-button
          :type="sortKey === 'ingress' ? 'primary' : 'default'"
          :disabled="loading"
          @click="toggleSort('ingress')"
        >
          {{ $t("metric.connect.col.total_ingress") }}
          {{ sortKey === "ingress" ? (sortOrder === "asc" ? "↑" : "↓") : "" }}
        </n-button>
        <n-button
          :type="sortKey === 'duration' ? 'primary' : 'default'"
          :disabled="loading"
          @click="toggleSort('duration')"
        >
          {{ $t("metric.connect.filter.duration") }}
          {{ sortKey === "duration" ? (sortOrder === "asc" ? "↑" : "↓") : "" }}
        </n-button>
      </n-button-group>
    </n-flex>

    <n-grid x-gap="12" :cols="5" style="margin-bottom: 12px">
      <n-gi>
        <n-card
          size="small"
          :bordered="false"
          style="background-color: #f9f9f910; height: 100%"
        >
          <n-statistic
            :label="$t('metric.connect.stats.filter_total')"
            :value="historyTotalStats.count"
          />
        </n-card>
      </n-gi>
      <n-gi>
        <n-card
          size="small"
          :bordered="false"
          style="background-color: #f9f9f910; height: 100%"
        >
          <n-statistic :label="$t('metric.connect.stats.total_egress')">
            <span :style="{ color: themeVars.infoColor, fontWeight: 'bold' }">
              {{ formatSize(historyTotalStats.totalEgressBytes) }}
            </span>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card
          size="small"
          :bordered="false"
          style="background-color: #f9f9f910; height: 100%"
        >
          <n-statistic :label="$t('metric.connect.stats.total_ingress')">
            <span
              :style="{ color: themeVars.successColor, fontWeight: 'bold' }"
            >
              {{ formatSize(historyTotalStats.totalIngressBytes) }}
            </span>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card
          size="small"
          :bordered="false"
          style="background-color: #f9f9f910; height: 100%"
        >
          <n-statistic :label="$t('metric.connect.stats.filter_ingress_pkts')">
            <span style="color: #888">
              {{ formatCount(historyTotalStats.totalIngressPkts) }} pkt
            </span>
          </n-statistic>
        </n-card>
      </n-gi>
      <n-gi>
        <n-card
          size="small"
          :bordered="false"
          style="background-color: #f9f9f910"
        >
          <n-statistic :label="$t('metric.connect.stats.filter_egress_pkts')">
            <span style="color: #888">
              {{ formatCount(historyTotalStats.totalEgressPkts) }} pkt
            </span>
          </n-statistic>
        </n-card>
      </n-gi>
    </n-grid>

    <n-virtual-list style="flex: 1" :item-size="40" :items="filteredHistory">
      <template #default="{ item, index }">
        <HistoryItemInfo
          :history="item"
          :index="index"
          @show:chart="showChartDrawer"
          @search:tuple="handleSearchTuple"
          @search:src="(ip) => (historyFilter.src_ip = ip)"
          @search:dst="(ip) => (historyFilter.dst_ip = ip)"
        />
      </template>
    </n-virtual-list>
    <n-pagination
      v-if="pagination.itemCount > pagination.pageSize"
      v-bind="pagination"
      :disabled="loading"
      style="align-self: flex-end; margin-top: 12px"
    />
    <ConnectChartDrawer
      v-model:show="showChart"
      :conn="showChartKey"
      :title="showChartTitle"
      :create-time-ms="showChartCreateTimeMs"
      :last-report-time="showChartLastReportTime"
      type="history"
    />
  </n-flex>
</template>
