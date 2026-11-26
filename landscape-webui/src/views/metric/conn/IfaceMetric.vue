<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";
import { ArrowDown, ArrowUp } from "@vicons/carbon";
import { useIfaceNodeStore } from "@/stores/iface_node";
import { get_iface_stats } from "@/api/metric";
import { useMetricAutoRefresh } from "@/composables/useMetricAutoRefresh";
import { useAsyncState } from "@vueuse/core";
import ConnectViewSwitcher from "@/components/metric/connect/ConnectViewSwitcher.vue";
import { formatPackets, formatRate } from "@/lib/util";

const { t } = useI18n();
const themeVars = useThemeVars();
const {
  state: ifaceStats,
  isLoading,
  execute: refresh,
} = useAsyncState(get_iface_stats, [], { resetOnExecute: false });
useMetricAutoRefresh(refresh, isLoading);

const ifaceNodeStore = useIfaceNodeStore();

const ifaceRows = computed(() =>
  [...ifaceStats.value].sort(
    (a, b) =>
      (b.stats.egress_bps || 0) +
      (b.stats.ingress_bps || 0) -
      ((a.stats.egress_bps || 0) + (a.stats.ingress_bps || 0)),
  ),
);

const totalStats = computed(() => {
  const stats = {
    ingressBps: 0,
    egressBps: 0,
    ingressPps: 0,
    egressPps: 0,
    activeConns: 0,
  };
  ifaceRows.value.forEach((item) => {
    stats.ingressBps += item.stats.ingress_bps || 0;
    stats.egressBps += item.stats.egress_bps || 0;
    stats.ingressPps += item.stats.ingress_pps || 0;
    stats.egressPps += item.stats.egress_pps || 0;
    stats.activeConns += item.stats.active_conns || 0;
  });
  return stats;
});

function ifaceName(ifindex: number) {
  return ifaceNodeStore.FIND_DEV_BY_IFINDEX(ifindex)?.name ?? `#${ifindex}`;
}

onMounted(async () => {
  await ifaceNodeStore.UPDATE_INFO();
});
</script>

<template>
  <n-flex vertical style="flex: 1; overflow: hidden">
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
              >{{ t("metric.connect.stats.total_active_ifaces") }}:</span
            >
            <span style="font-weight: bold">{{ ifaceRows.length }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ t("metric.connect.stats.total_active_conns") }}:</span
            >
            <span style="font-weight: bold">{{ totalStats.activeConns }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ t("metric.connect.stats.total_egress") }}:</span
            >
            <span :style="{ fontWeight: 'bold', color: themeVars.infoColor }">{{
              formatRate(totalStats.egressBps)
            }}</span>
          </n-flex>
          <n-divider vertical />
          <n-flex align="center" size="small">
            <span style="color: #888; font-size: 13px"
              >{{ t("metric.connect.stats.total_ingress") }}:</span
            >
            <span
              :style="{ fontWeight: 'bold', color: themeVars.successColor }"
              >{{ formatRate(totalStats.ingressBps) }}</span
            >
          </n-flex>
        </n-flex>
      </n-flex>
    </n-card>

    <n-flex align="center" justify="space-between" style="margin-bottom: 12px">
      <n-h3 style="margin: 0">{{ t("metric.connect.stats.live_iface") }}</n-h3>
      <n-button @click="refresh()" :loading="isLoading" type="primary">
        {{ t("metric.connect.stats.refresh_sample") }}
      </n-button>
    </n-flex>

    <n-grid :cols="1" :x-gap="12" :y-gap="12">
      <n-gi v-for="item in ifaceRows" :key="item.ifindex">
        <n-card
          size="small"
          :bordered="false"
          style="background-color: #f9f9f910"
        >
          <n-flex align="center" justify="space-between">
            <n-flex vertical size="small">
              <n-flex align="center" size="small">
                <span style="font-size: 18px; font-weight: 700">{{
                  ifaceName(item.ifindex)
                }}</span>
                <n-tag size="small" :bordered="false">
                  {{ t("metric.connect.col.ifindex") }} {{ item.ifindex }}
                </n-tag>
              </n-flex>
              <span style="color: #888">
                {{ t("metric.connect.col.active_conns") }}:
                {{ item.stats.active_conns }}
              </span>
            </n-flex>

            <n-flex align="center" size="large">
              <n-flex
                align="center"
                :wrap="false"
                size="small"
                style="width: 150px"
              >
                <n-icon :color="themeVars.infoColor" size="22">
                  <ArrowUp />
                </n-icon>
                <n-flex vertical :size="[-4, 0]">
                  <span style="font-size: 15px; font-weight: 700">{{
                    formatRate(item.stats.egress_bps)
                  }}</span>
                  <span style="font-size: 11px; color: #888">{{
                    formatPackets(item.stats.egress_pps)
                  }}</span>
                </n-flex>
              </n-flex>

              <n-flex
                align="center"
                :wrap="false"
                size="small"
                style="width: 150px"
              >
                <n-icon :color="themeVars.successColor" size="22">
                  <ArrowDown />
                </n-icon>
                <n-flex vertical :size="[-4, 0]">
                  <span style="font-size: 15px; font-weight: 700">{{
                    formatRate(item.stats.ingress_bps)
                  }}</span>
                  <span style="font-size: 11px; color: #888">{{
                    formatPackets(item.stats.ingress_pps)
                  }}</span>
                </n-flex>
              </n-flex>
            </n-flex>
          </n-flex>
        </n-card>
      </n-gi>
    </n-grid>
  </n-flex>
</template>
