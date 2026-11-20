<script setup lang="ts">
import { ref, onMounted, watch } from "vue";
import { dnsLatencyStats } from "@/components/metric/dns/latencyStats";
import { useI18n } from "vue-i18n";
import {
  useThemeVars,
  NGrid,
  NStatistic,
  NText,
  NNumberAnimation,
  NIcon,
  NTooltip,
} from "naive-ui";
import { Refresh, HelpCircleOutline } from "@vicons/ionicons5";

import type { DnsLightweightSummaryResponse } from "@landscape-router/types/api/schemas";
import { get_dns_lightweight_summary } from "@/api/metric/dns";
import DnsRuleDrawer from "@/components/dns/DnsRuleDrawer.vue";
import WanIpRuleDrawer from "@/components/flow/wan/WanIpRuleDrawer.vue";
const themeVars = useThemeVars();
const { t } = useI18n();

const props = defineProps<{
  startTime?: number;
}>();

const summary = ref<DnsLightweightSummaryResponse | null>(null);
const loading = ref(true);

const show_rule_drawer = ref(false);
const show_ip_rule = ref(false);

let requestId = 0;
const loadSummary = async () => {
  const id = ++requestId;
  loading.value = true;
  try {
    const result = await get_dns_lightweight_summary({
      start_time: props.startTime ?? 0,
      end_time: 0,
    });
    if (requestId === id) summary.value = result;
  } catch (e) {
    console.error(e);
  } finally {
    if (requestId === id) loading.value = false;
  }
};

watch(() => props.startTime, loadSummary);

onMounted(() => {
  loadSummary();
});

const calculatePercentFromValues = (
  hit: number | undefined,
  total: number | undefined,
) => {
  if (hit === undefined || total === undefined || total === 0) return null;
  return Number(((hit / total) * 100).toFixed(1));
};

const calculatePercent = (count: number) => {
  if (!summary.value || summary.value.total_queries === 0) return 0;
  return Number(((count / summary.value.total_queries) * 100).toFixed(1));
};

defineExpose({ refresh: loadSummary });
</script>

<template>
  <n-card
    :loading="loading"
    class="dns-status-card"
    content-style="display: flex; flex-direction: column; height: 100%; padding-top: 26px;"
  >
    <template #header>
      <n-flex align="center" :size="4">
        <span>DNS</span>
        <n-text depth="3" style="font-size: 10px">{{
          t("metric.dns.dash.recent_5m")
        }}</n-text>
      </n-flex>
    </template>

    <template #header-extra>
      <n-flex :size="6" align="center">
        <n-tooltip trigger="hover">
          <template #trigger>
            <n-button
              size="tiny"
              secondary
              circle
              :loading="loading"
              @click="loadSummary"
            >
              <template #icon>
                <n-icon><Refresh /></n-icon>
              </template>
            </n-button>
          </template>
          {{ t("metric.dns.dash.refresh") || "Refresh" }}
        </n-tooltip>
        <n-button size="tiny" secondary @click="show_rule_drawer = true">
          {{ t("metric.dns.dash.rules") }}
        </n-button>
        <n-button size="tiny" secondary @click="show_ip_rule = true">
          {{ t("metric.dns.dash.ip_rules") }}
        </n-button>
      </n-flex>
    </template>

    <!-- DNS Metrics Content -->
    <n-flex vertical :size="16">
      <n-grid :cols="3" :x-gap="12">
        <!-- Total Queries -->
        <n-gi>
          <n-statistic :label="t('metric.dns.dash.total_queries')">
            <n-tooltip trigger="hover">
              <template #trigger>
                <span
                  ><n-number-animation
                    :from="0"
                    :to="summary?.total_queries || 0"
                /></span>
              </template>
              NX: {{ summary?.nxdomain_count || 0 }} / Err:
              {{ summary?.error_count || 0 }}
            </n-tooltip>
          </n-statistic>
        </n-gi>

        <!-- Cache Hit Rate -->
        <n-gi>
          <n-statistic>
            <template #label>
              <n-flex align="center" :size="4">
                {{ t("metric.dns.dash.cache_hit_rate") }}
                <n-tooltip trigger="hover" :width="240">
                  <template #trigger>
                    <n-icon size="14" depth="3" style="cursor: help">
                      <HelpCircleOutline />
                    </n-icon>
                  </template>
                  {{ t("metric.dns.dash.cache_hit_tip") }}
                </n-tooltip>
              </n-flex>
            </template>
            <template
              #suffix
              v-if="
                calculatePercentFromValues(
                  summary?.cache_hit_count,
                  summary?.total_effective_queries,
                ) !== null
              "
              >%</template
            >
            <n-tooltip
              v-if="
                calculatePercentFromValues(
                  summary?.cache_hit_count,
                  summary?.total_effective_queries,
                ) !== null
              "
              trigger="hover"
              :disabled="!summary?.total_v4 && !summary?.total_v6"
            >
              <template #trigger>
                <span>
                  <n-number-animation
                    :from="0"
                    :to="
                      calculatePercentFromValues(
                        summary?.cache_hit_count,
                        summary?.total_effective_queries,
                      ) || 0
                    "
                    :precision="1"
                  />
                </span>
              </template>
              v4:
              {{
                calculatePercentFromValues(
                  summary?.hit_count_v4,
                  summary?.total_v4,
                ) ?? "-"
              }}% / v6:
              {{
                calculatePercentFromValues(
                  summary?.hit_count_v6,
                  summary?.total_v6,
                ) ?? "-"
              }}%
            </n-tooltip>
            <n-text v-else depth="3" class="no-data-text">{{
              t("metric.dns.dash.no_data")
            }}</n-text>
          </n-statistic>
        </n-gi>

        <!-- Block Rate -->
        <n-gi>
          <n-statistic :label="t('metric.dns.dash.block_rate')">
            <template #suffix>%</template>
            <n-number-animation
              :from="0"
              :to="calculatePercent(summary?.block_count || 0)"
              :precision="1"
            />
          </n-statistic>
        </n-gi>
      </n-grid>

      <n-divider style="margin: 0" />

      <!-- Latency Section -->
      <n-flex vertical :size="8">
        <n-flex align="center" :size="4">
          <n-text depth="3" style="font-size: 11px">
            {{ t("metric.dns.dash.query_latency") }} (ms)
          </n-text>
          <n-tooltip trigger="hover" :width="280">
            <template #trigger>
              <n-icon size="13" depth="3" style="cursor: help">
                <HelpCircleOutline />
              </n-icon>
            </template>
            {{ t("metric.dns.dash.latency_tip") }}
          </n-tooltip>
        </n-flex>
        <n-flex justify="space-between">
          <n-flex
            vertical
            align="center"
            :size="2"
            v-for="stat in dnsLatencyStats"
            :key="stat.field"
          >
            <n-text
              depth="3"
              style="font-size: 10px; text-transform: uppercase"
              >{{ t(stat.label) }}</n-text
            >
            <n-text
              strong
              style="font-size: 14px"
              :style="{ color: themeVars[stat.color] }"
            >
              <n-number-animation
                :from="0"
                :to="summary?.[stat.field] ?? 0"
                :precision="1"
              />
            </n-text>
          </n-flex>
        </n-flex>
      </n-flex>
    </n-flex>

    <DnsRuleDrawer v-model:show="show_rule_drawer" />
    <WanIpRuleDrawer v-model:show="show_ip_rule" />
  </n-card>
</template>

<style scoped>
.no-data-text {
  font-size: 11px;
}
</style>
