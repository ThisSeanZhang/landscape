<script setup lang="ts">
import { ref, computed, reactive, onMounted, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute } from "vue-router";
import { ConnectFilter } from "@/lib/metric.rs";
import { get_connect_history, get_connect_global_stats } from "@/api/metric";
import { formatSize, formatCount } from "@/lib/util";
import { useThemeVars } from "naive-ui";
import { useMetricStore } from "@/stores/status_metric";
import { useFrontEndStore } from "@/stores/front_end_config";
import HistoryItemInfo from "@/components/metric/connect/history/HistoryItemInfo.vue";
import ConnectChartDrawer from "@/components/metric/connect/ConnectChartDrawer.vue";
import FlowSelect from "@/components/flow/FlowSelect.vue";
import {
  ConnectKey,
  ConnectGlobalStats,
} from "landscape-types/common/metric/connect";
import { usePreferenceStore } from "@/stores/preference";
import { Renew } from "@vicons/carbon";
import ConnectViewSwitcher from "@/components/metric/connect/ConnectViewSwitcher.vue";

const prefStore = usePreferenceStore();
const metricStore = useMetricStore();
const route = useRoute();
const { t } = useI18n();

const themeVars = useThemeVars();
const frontEndStore = useFrontEndStore();

// 1. 声明所有基础响应式状态 (State)
const historicalData = ref<any[]>([]);
const timeRange = ref<number | string | null>(300); // 默认 5 分钟 (300秒)
const queryLimit = ref<number | null>(100); // 默认限制 100 条
const historyFilter = reactive(new ConnectFilter());
const sortKey = computed(() => frontEndStore.history_conn_sort_key);
const sortOrder = computed(() => frontEndStore.history_conn_sort_order);

// 全局历史统计
const globalStats = computed(() => metricStore.global_history_stats);
const refreshingGlobalStats = ref(false);

const refreshGlobalStats = async () => {
  if (refreshingGlobalStats.value) return;
  refreshingGlobalStats.value = true;
  try {
    await metricStore.UPDATE_GLOBAL_HISTORY_STATS();
  } catch (e) {
    console.error(e);
  } finally {
    refreshingGlobalStats.value = false;
  }
};

// 图表展示状态
const showChart = ref(false);
const showChartKey = ref<ConnectKey | null>(null);
const showChartTitle = ref("");
const loading = ref(false);

// 自定义时间段
const useCustomTimeRange = ref(false);
const customTimeRange = ref<[number, number] | null>(null);

const showChartDrawer = (history: any) => {
  showChartKey.value = history.key;
  showChartTitle.value = `${frontEndStore.MASK_INFO(history.src_ip)}:${frontEndStore.MASK_PORT(history.src_port)} => ${frontEndStore.MASK_INFO(history.dst_ip)}:${frontEndStore.MASK_PORT(history.dst_port)}`;
  showChart.value = true;
};

// 2. 声明常量选项 (Options)
const protocolOptions = computed(() => [
  { label: t("metric.connect.all_types"), value: null },
  { label: "TCP", value: 6 },
  { label: "UDP", value: 17 },
  { label: "ICMP", value: 1 },
  { label: "ICMPv6", value: 58 },
]);

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
  { label: "限制 5000 条", value: 5000 },
  { label: "不限制数量", value: null },
]);

// 3. 声明数据获取逻辑 (Actions)
const fetchHistory = async () => {
  loading.value = true;
  try {
    let startTime: number | undefined;
    let endTime: number | undefined;

    if (useCustomTimeRange.value && customTimeRange.value) {
      // 使用自定义时间段
      startTime = customTimeRange.value[0];
      endTime = customTimeRange.value[1];
    } else if (timeRange.value !== null && timeRange.value !== "custom") {
      // 使用相对时间范围
      startTime = Date.now() - (timeRange.value as number) * 1000;
    }

    historicalData.value = await get_connect_history({
      start_time: startTime,
      end_time: endTime,
      limit: queryLimit.value || undefined,
      src_ip: historyFilter.src_ip || undefined,
      dst_ip: historyFilter.dst_ip || undefined,
      port_start: historyFilter.port_start || undefined,
      port_end: historyFilter.port_end || undefined,
      l3_proto: historyFilter.l3_proto || undefined,
      l4_proto: historyFilter.l4_proto || undefined,
      flow_id: historyFilter.flow_id || undefined,
      sort_key: sortKey.value,
      sort_order: sortOrder.value,
    });
  } finally {
    loading.value = false;
  }
};

const resetHistoryFilter = () => {
  Object.assign(historyFilter, new ConnectFilter());
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
};

// 4. 计算属性 (Computed)
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

// 5. 监听器与生命周期 (Watchers & Lifecycle)
// 监听时间范围选择，切换自定义模式
watch(timeRange, (newVal) => {
  if (newVal === "custom") {
    useCustomTimeRange.value = true;
  } else {
    useCustomTimeRange.value = false;
    customTimeRange.value = null;
    fetchHistory();
  }
});

// 监听自定义时间段变化
watch(customTimeRange, () => {
  if (useCustomTimeRange.value && customTimeRange.value) {
    fetchHistory();
  }
});

// 只在查询限制、排序变化时自动查询
watch([queryLimit, sortKey, sortOrder], () => {
  fetchHistory();
});

// 防抖查询：用户停止输入 800ms 后自动查询
let debounceTimer: ReturnType<typeof setTimeout> | null = null;
watch(
  historyFilter,
  () => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      fetchHistory();
    }, 800); // 800ms 延迟
  },
  { deep: true },
);

onMounted(() => {
  // 从路由参数初始化过滤器
  if (route.query.src_ip) historyFilter.src_ip = route.query.src_ip as string;
  if (route.query.dst_ip) historyFilter.dst_ip = route.query.dst_ip as string;
  if (route.query.port_start)
    historyFilter.port_start = parseInt(route.query.port_start as string);
  if (route.query.port_end)
    historyFilter.port_end = parseInt(route.query.port_end as string);
  if (route.query.flow_id)
    historyFilter.flow_id = parseInt(route.query.flow_id as string);

  refreshGlobalStats();
  fetchHistory();
});
</script>

<template>
  <n-flex vertical style="flex: 1; overflow: hidden">
    <!-- 历史全局统计面板 -->
    <n-card
      size="small"
      :bordered="false"
      style="margin-bottom: 12px; background-color: #f9f9f910"
    >
      <n-flex align="center" justify="space-between">
        <ConnectViewSwitcher />

        <n-flex align="center" size="large" v-if="globalStats">
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px">历史连接总数:</span>
            <span style="font-weight: bold">{{
              globalStats.total_connect_count
            }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px">累计总上传:</span>
            <span :style="{ fontWeight: 'bold', color: themeVars.infoColor }">{{
              formatSize(globalStats.total_egress_bytes)
            }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px">累计总下载:</span>
            <span
              :style="{ fontWeight: 'bold', color: themeVars.successColor }"
              >{{ formatSize(globalStats.total_ingress_bytes) }}</span
            >
          </n-flex>

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
        </n-flex>
        <div v-else style="height: 34px"></div>
      </n-flex>
    </n-card>

    <!-- 历史模式专用工具栏 -->
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

      <!-- 自定义时间段选择器 -->
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
        style="width: 130px"
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
    <ConnectChartDrawer
      v-model:show="showChart"
      :conn="showChartKey"
      :title="showChartTitle"
      type="history"
    />
  </n-flex>
</template>
