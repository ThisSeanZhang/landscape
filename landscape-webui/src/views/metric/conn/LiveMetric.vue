<script setup lang="ts">
import { computed, reactive, ref, onMounted } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute } from "vue-router";
import { get_connects_info } from "@/api/metric";
import { useMobileLayout } from "@/composables/useMobileLayout";
import { Filter } from "@vicons/carbon";
import { useMetricAutoRefresh } from "@/composables/useMetricAutoRefresh";
import { useAsyncState } from "@vueuse/core";
import { useFrontEndStore } from "@/stores/front_end_config";
import { createConnectionFilter } from "@/lib/metric/connectionFilter";
import type { ConnectRealtimeStatus } from "@landscape-router/types/api/schemas";
import { formatRate, formatPackets } from "@/lib/util";
import { useThemeVars } from "naive-ui";
import ConnectList from "@/components/metric/connect/ConnectList.vue";
import FlowSelect from "@/components/flow/FlowSelect.vue";
import ConnectViewSwitcher from "@/components/metric/connect/ConnectViewSwitcher.vue";

const {
  state: connections,
  isLoading,
  isReady,
  execute: refresh,
} = useAsyncState(get_connects_info, [], { resetOnExecute: false });
useMetricAutoRefresh(refresh, isLoading);

const frontEndStore = useFrontEndStore();
const themeVars = useThemeVars();
const route = useRoute();
const { t } = useI18n();

// Live filter state
const liveFilter = reactive(createConnectionFilter());
const mobile = useMobileLayout();
const filtersOpen = ref(false);
const filterCount = computed(
  () =>
    Object.values(liveFilter).filter((value) => value !== null && value !== "")
      .length,
);
const showFilters = computed(() => !mobile.value || filtersOpen.value);

// Protocol options
const protocolOptions = computed(() => [
  { label: t("metric.connect.all_types"), value: null },
  { label: "TCP", value: 6 },
  { label: "UDP", value: 17 },
  { label: "ICMP", value: 1 },
  { label: "ICMPv6", value: 58 },
]);

// IP type options
const ipTypeOptions = computed(() => [
  { label: t("metric.connect.all_types"), value: null },
  { label: "IPv4", value: 0 },
  { label: "IPv6", value: 1 },
]);

// Direction options
const gressOptions = computed(() => [
  { label: t("metric.connect.all_types"), value: null },
  { label: t("metric.connect.filter.gress_egress"), value: 1 },
  { label: t("metric.connect.filter.gress_ingress"), value: 0 },
]);

// Sorting state
const sortKey = computed(() => frontEndStore.conn_sort_key);
const sortOrder = computed(() => frontEndStore.conn_sort_order);

const resetLiveFilter = () => {
  Object.assign(liveFilter, createConnectionFilter());
};

const handleSearchTuple = (conn: ConnectRealtimeStatus) => {
  liveFilter.src_ip = conn.src_ip;
  liveFilter.dst_ip = conn.dst_ip;
  liveFilter.port_start = conn.src_port;
  liveFilter.port_end = conn.dst_port;
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

// System-wide summary
const systemStats = computed(() => {
  const stats = {
    ingressBps: 0,
    egressBps: 0,
    ingressPps: 0,
    egressPps: 0,
    count: 0,
  };
  connections.value.forEach((item) => {
    stats.ingressBps += item.ingress_bps || 0;
    stats.egressBps += item.egress_bps || 0;
    stats.ingressPps += item.ingress_pps || 0;
    stats.egressPps += item.egress_pps || 0;
    stats.count++;
  });
  return stats;
});

// Calculate filtered and sorted connection metrics
const filteredConnectMetrics = computed(() => {
  const filtered = connections.value.filter((item) => {
    if (liveFilter.src_ip && !item.src_ip.includes(liveFilter.src_ip))
      return false;
    if (liveFilter.dst_ip && !item.dst_ip.includes(liveFilter.dst_ip))
      return false;
    if (
      liveFilter.port_start !== null &&
      item.src_port !== liveFilter.port_start
    )
      return false;
    if (liveFilter.port_end !== null && item.dst_port !== liveFilter.port_end)
      return false;
    if (liveFilter.l3_proto !== null && item.l3_proto !== liveFilter.l3_proto)
      return false;
    if (liveFilter.l4_proto !== null && item.l4_proto !== liveFilter.l4_proto)
      return false;
    if (liveFilter.flow_id !== null && item.flow_id !== liveFilter.flow_id)
      return false;
    if (liveFilter.gress !== null && item.gress !== liveFilter.gress)
      return false;
    if (liveFilter.ifindex !== null && item.ifindex !== liveFilter.ifindex)
      return false;
    return true;
  });

  return filtered.sort((a, b) => {
    let result = 0;
    if (sortKey.value === "time") {
      const timeA = a.last_report_time || a.create_time_ms || 0;
      const timeB = b.last_report_time || b.create_time_ms || 0;
      result = timeA - timeB;
    } else if (sortKey.value === "duration") {
      const durationA = Math.max(
        0,
        (a.last_report_time || a.create_time_ms) - a.create_time_ms,
      );
      const durationB = Math.max(
        0,
        (b.last_report_time || b.create_time_ms) - b.create_time_ms,
      );
      result = durationA - durationB;
    } else if (sortKey.value === "port") {
      result = (a.src_port || 0) - (b.src_port || 0);
    } else if (sortKey.value === "ingress") {
      result = (a.ingress_bps || 0) - (b.ingress_bps || 0);
    } else if (sortKey.value === "egress") {
      result = (a.egress_bps || 0) - (b.egress_bps || 0);
    }
    return sortOrder.value === "asc" ? result : -result;
  });
});

// Filtered data summary
const totalStats = computed(() => {
  const stats = {
    ingressBps: 0,
    egressBps: 0,
    ingressPps: 0,
    egressPps: 0,
    count: 0,
  };
  filteredConnectMetrics.value.forEach((item) => {
    stats.ingressBps += item.ingress_bps || 0;
    stats.egressBps += item.egress_bps || 0;
    stats.ingressPps += item.ingress_pps || 0;
    stats.egressPps += item.egress_pps || 0;
    stats.count++;
  });
  return stats;
});

onMounted(() => {
  // Initialize filters from route query
  const srcIp = queryString(route.query.src_ip);
  const dstIp = queryString(route.query.dst_ip);
  const portStart = queryNumber(route.query.port_start);
  const portEnd = queryNumber(route.query.port_end);
  const flowId = queryNumber(route.query.flow_id);
  const ifindex = queryNumber(route.query.ifindex);

  if (srcIp) liveFilter.src_ip = srcIp;
  if (dstIp) liveFilter.dst_ip = dstIp;
  if (portStart !== null) liveFilter.port_start = portStart;
  if (portEnd !== null) liveFilter.port_end = portEnd;
  if (flowId !== null) liveFilter.flow_id = flowId;
  if (ifindex !== null) liveFilter.ifindex = ifindex;
});
</script>

<template>
  <n-flex vertical :wrap="false" class="live-page">
    <!-- System-wide active connection stats -->
    <n-card
      size="small"
      :bordered="false"
      style="margin-bottom: 12px; background-color: #f9f9f910"
    >
      <n-flex align="center" justify="space-between">
        <ConnectViewSwitcher />

        <n-flex align="center" size="large" class="system-totals">
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ $t("metric.connect.stats.total_active_conns") }}:</span
            >
            <span style="font-weight: bold">{{ systemStats.count }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ $t("metric.connect.stats.total_egress") }}:</span
            >
            <span :style="{ fontWeight: 'bold', color: themeVars.infoColor }">{{
              formatRate(systemStats.egressBps)
            }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ $t("metric.connect.stats.total_ingress") }}:</span
            >
            <span
              :style="{ fontWeight: 'bold', color: themeVars.successColor }"
              >{{ formatRate(systemStats.ingressBps) }}</span
            >
          </n-flex>
        </n-flex>
      </n-flex>
    </n-card>

    <n-flex v-if="mobile" align="center" size="small">
      <n-button
        secondary
        :type="filterCount ? 'primary' : 'default'"
        :aria-expanded="filtersOpen"
        aria-controls="live-filters"
        @click="filtersOpen = !filtersOpen"
      >
        <template #icon><n-icon :component="Filter" /></template>
        {{ t("common.filters")
        }}<template v-if="filterCount"> ({{ filterCount }})</template>
      </n-button>
      <n-button secondary :loading="isLoading" @click="refresh()">{{
        t("metric.connect.stats.refresh_sample")
      }}</n-button>
      <n-text v-if="filterCount" depth="3"
        >{{ t("metric.connect.stats.filter_total") }} ·
        {{ totalStats.count }}</n-text
      >
    </n-flex>
    <div v-show="showFilters" id="live-filters" class="live-filters">
      <n-input
        v-model:value="liveFilter.src_ip"
        :placeholder="$t('metric.connect.filter.src_ip')"
        clearable
        style="width: 170px"
      />
      <n-input
        v-model:value="liveFilter.dst_ip"
        :placeholder="$t('metric.connect.filter.dst_ip')"
        clearable
        style="width: 170px"
      />
      <n-input-group style="width: 220px">
        <n-input-number
          v-model:value="liveFilter.port_start"
          :placeholder="$t('metric.connect.filter.port_start')"
          :show-button="false"
          clearable
        />
        <n-input-group-label>=></n-input-group-label>
        <n-input-number
          v-model:value="liveFilter.port_end"
          :placeholder="$t('metric.connect.filter.port_end')"
          :show-button="false"
          clearable
        />
      </n-input-group>
      <n-select
        v-model:value="liveFilter.l4_proto"
        :placeholder="$t('metric.connect.filter.proto')"
        :options="protocolOptions"
        clearable
        style="width: 130px"
      />
      <n-select
        v-model:value="liveFilter.l3_proto"
        :placeholder="$t('metric.connect.filter.l3_proto')"
        :options="ipTypeOptions"
        clearable
        style="width: 110px"
      />
      <n-select
        v-model:value="liveFilter.gress"
        :placeholder="$t('metric.connect.filter.gress')"
        :options="gressOptions"
        clearable
        style="width: 110px"
      />
      <FlowSelect v-model="liveFilter.flow_id" width="120px" />

      <n-button-group>
        <n-button
          v-if="!mobile"
          @click="refresh()"
          :loading="isLoading"
          type="primary"
          >{{ $t("metric.connect.stats.refresh_sample") }}</n-button
        >
        <n-button @click="resetLiveFilter">{{
          $t("metric.connect.reset")
        }}</n-button>
      </n-button-group>
    </div>

    <n-grid
      v-if="showFilters"
      x-gap="8"
      y-gap="8"
      cols="2 480:3 820:5"
      style="margin-bottom: 12px"
    >
      <n-gi>
        <n-card
          size="small"
          :bordered="false"
          style="background-color: #f9f9f910; height: 100%"
        >
          <n-statistic
            :label="$t('metric.connect.stats.filter_total')"
            :value="totalStats.count"
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
              {{ formatRate(totalStats.egressBps) }}
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
              {{ formatRate(totalStats.ingressBps) }}
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
              {{ formatPackets(totalStats.ingressPps) }}
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
          <n-statistic :label="$t('metric.connect.stats.filter_egress_pkts')">
            <span style="color: #888">
              {{ formatPackets(totalStats.egressPps) }}
            </span>
          </n-statistic>
        </n-card>
      </n-gi>
    </n-grid>

    <ConnectList
      mode="live"
      :items="filteredConnectMetrics"
      :show-empty="mobile && isReady && filteredConnectMetrics.length === 0"
      v-model:sort-key="frontEndStore.conn_sort_key"
      v-model:sort-order="frontEndStore.conn_sort_order"
      @filter="handleSearchTuple"
    />
  </n-flex>
</template>

<style scoped>
.live-filters {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 12px;
  margin-bottom: 12px;
}
.live-page {
  flex: 1;
  min-width: 0;
  overflow: hidden;
}
@media (max-width: 768px) {
  .live-page {
    overflow-y: auto;
  }
  .live-page > * {
    flex-shrink: 0;
  }
  .live-page :deep(.connection-list) {
    min-height: 180px;
  }
  .system-totals {
    display: grid !important;
    width: 100%;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 8px !important;
  }
  .system-totals > .n-flex {
    flex-direction: column !important;
    align-items: flex-start !important;
    gap: 2px !important;
  }
  .system-totals > .n-divider {
    display: none;
  }
  .live-filters {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .live-filters > * {
    width: 100% !important;
    min-width: 0;
  }
  .live-filters > .n-input-group {
    grid-column: span 2;
  }
}
</style>
