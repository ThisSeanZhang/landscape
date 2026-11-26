<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import type { IpRealtimeStat } from "@landscape-router/types/api/schemas";
import { useRoute } from "vue-router";
import {
  get_connects_info,
  get_src_ip_stats,
  get_dst_ip_stats,
} from "@/api/metric";
import { useMetricAutoRefresh } from "@/composables/useMetricAutoRefresh";
import { useAsyncState } from "@vueuse/core";
import { formatRate } from "@/lib/util";
import { useThemeVars } from "naive-ui";
import IpStatsList from "@/components/metric/connect/live/IpStatsList.vue";
import ConnectViewSwitcher from "@/components/metric/connect/ConnectViewSwitcher.vue";
import FlowSelect from "@/components/flow/FlowSelect.vue";

const { direction } = defineProps<{ direction: "src" | "dst" }>();

const {
  state: sample,
  isLoading,
  execute: refresh,
} = useAsyncState(
  async () => {
    const [connections, ipStats] = await Promise.all([
      get_connects_info(),
      direction === "src" ? get_src_ip_stats() : get_dst_ip_stats(),
    ]);
    return { connections, ipStats };
  },
  { connections: [], ipStats: [] },
  { resetOnExecute: false },
);
useMetricAutoRefresh(refresh, isLoading);

const themeVars = useThemeVars();
const route = useRoute();

const ipFilter = ref("");
const flowFilter = ref<number | null>(null);

const stats = computed(() => {
  // 如果没有任何过滤，优先使用后端提供的预聚合数据 (性能更好)
  if (!ipFilter.value && flowFilter.value === null) {
    return sample.value.ipStats;
  }

  // 如果有过滤（特别是 Flow 过滤），我们需要从原始连接数据中进行实时聚合
  const connections = sample.value.connections;
  const aggregatedMap = new Map<string, IpRealtimeStat & { flow_id: number }>();

  connections.forEach((conn) => {
    const ip = direction === "src" ? conn.src_ip : conn.dst_ip;
    if (
      ipFilter.value &&
      !ip.toLowerCase().includes(ipFilter.value.toLowerCase())
    )
      return;
    if (flowFilter.value !== null && conn.flow_id !== flowFilter.value) return;

    // 以 (IP, FlowID) 为键进行聚合，保持与历史记录一致
    const key = `${ip}_${conn.flow_id}`;
    let item = aggregatedMap.get(key);
    if (!item) {
      item = {
        ip,
        flow_id: conn.flow_id,
        stats: {
          active_conns: 0,
          ingress_bps: 0,
          egress_bps: 0,
          ingress_pps: 0,
          egress_pps: 0,
        },
      };
      aggregatedMap.set(key, item);
    }

    item.stats.active_conns += 1;
    item.stats.ingress_bps += conn.ingress_bps || 0;
    item.stats.egress_bps += conn.egress_bps || 0;
    item.stats.ingress_pps += conn.ingress_pps || 0;
    item.stats.egress_pps += conn.egress_pps || 0;
  });

  return Array.from(aggregatedMap.values());
});

// 系统全局汇总
const systemStats = computed(() => {
  const stats = {
    ingressBps: 0,
    egressBps: 0,
    ingressPps: 0,
    egressPps: 0,
    count: 0,
  };
  sample.value.connections.forEach((item) => {
    stats.ingressBps += item.ingress_bps || 0;
    stats.egressBps += item.egress_bps || 0;
    stats.ingressPps += item.ingress_pps || 0;
    stats.egressPps += item.egress_pps || 0;
    stats.count++;
  });
  return stats;
});

onMounted(() => {
  if (route.query.ip) ipFilter.value = route.query.ip as string;
  if (route.query.flow_id)
    flowFilter.value = parseInt(route.query.flow_id as string);
});
</script>

<template>
  <n-flex vertical style="flex: 1; overflow: hidden">
    <!-- 系统全局活跃连接统计 -->
    <n-card
      size="small"
      :bordered="false"
      style="margin-bottom: 12px; background-color: #f9f9f910"
    >
      <n-flex align="center" justify="space-between">
        <ConnectViewSwitcher />

        <n-flex align="center" size="large">
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

    <!-- 过滤器工具栏 -->
    <n-flex
      align="center"
      :wrap="true"
      style="margin-bottom: 12px"
      size="small"
    >
      <n-input
        v-model:value="ipFilter"
        :placeholder="$t(`metric.connect.filter.search_${direction}`)"
        clearable
        style="width: 200px"
      />
      <FlowSelect v-model="flowFilter" width="150px" />
      <n-button @click="refresh()" :loading="isLoading">{{
        $t("metric.connect.stats.refresh_sample")
      }}</n-button>
    </n-flex>

    <IpStatsList
      :stats="stats"
      :title="$t(`metric.connect.stats.live_${direction}`)"
      :show-geo-lookup="direction === 'dst'"
      :ip-label="$t(`metric.connect.col.${direction}_ip`)"
      @search:ip="(ip) => (ipFilter = ip)"
    />
  </n-flex>
</template>
