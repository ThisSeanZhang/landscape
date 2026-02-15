<script setup lang="ts">
import { ref, onMounted, computed, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  useThemeVars,
  NGrid,
  NGridItem,
  NStatistic,
  NProgress,
  NText,
  NNumberAnimation,
  NIcon,
  NTooltip,
} from "naive-ui";
import { Refresh } from "@vicons/ionicons5";

import {
  get_dns_lightweight_summary,
  DnsLightweightSummaryResponse,
} from "@/api/metric/dns";
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

const loadSummary = async () => {
  loading.value = true;
  try {
    const now = Date.now();
    const startTime = props.startTime || now - 5 * 60 * 1000;
    summary.value = await get_dns_lightweight_summary({
      start_time: startTime,
      end_time: now,
    });
  } catch (e) {
    console.error(e);
  } finally {
    loading.value = false;
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

const latencyStats = computed(() => [
  {
    label: t("metric.dns.dash.avg"),
    value: summary.value?.avg_duration_ms,
    color: themeVars.value.successColor,
  },
  {
    label: t("metric.dns.dash.p50"),
    value: summary.value?.p50_duration_ms,
    color: themeVars.value.infoColor,
  },
  {
    label: t("metric.dns.dash.p95"),
    value: summary.value?.p95_duration_ms,
    color: themeVars.value.warningColor,
  },
  {
    label: t("metric.dns.dash.p99"),
    value: summary.value?.p99_duration_ms,
    color: themeVars.value.errorColor,
  },
  {
    label: t("metric.dns.dash.max"),
    value: summary.value?.max_duration_ms,
    color: themeVars.value.primaryColor,
  },
]);

defineExpose({ refresh: loadSummary });
</script>

<template>
  <n-card
    :loading="loading"
    class="dns-status-card"
    content-style="display: flex; flex-direction: column; height: 100%; padding-top: 6px;"
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
            <n-number-animation :from="0" :to="summary?.total_queries || 0" />
          </n-statistic>
          <n-flex :size="4" class="mini-breakdown">
            <n-text depth="3">NX: {{ summary?.nxdomain_count || 0 }}</n-text>
            <n-text depth="3">Err: {{ summary?.error_count || 0 }}</n-text>
          </n-flex>
        </n-gi>

        <!-- Cache Hit Rate -->
        <n-gi>
          <n-statistic :label="t('metric.dns.dash.cache_hit_rate')">
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
            <n-number-animation
              v-if="
                calculatePercentFromValues(
                  summary?.cache_hit_count,
                  summary?.total_effective_queries,
                ) !== null
              "
              :from="0"
              :to="
                calculatePercentFromValues(
                  summary?.cache_hit_count,
                  summary?.total_effective_queries,
                ) || 0
              "
              :precision="1"
            />
            <n-text v-else depth="3" class="no-data-text">{{
              t("metric.dns.dash.no_data")
            }}</n-text>
          </n-statistic>
          <n-flex
            :size="4"
            class="mini-breakdown"
            v-if="summary?.total_v4 || summary?.total_v6"
          >
            <n-text depth="3"
              >v4:
              {{
                calculatePercentFromValues(
                  summary?.hit_count_v4,
                  summary?.total_v4,
                ) ?? "-"
              }}%</n-text
            >
            <n-text depth="3"
              >v6:
              {{
                calculatePercentFromValues(
                  summary?.hit_count_v6,
                  summary?.total_v6,
                ) ?? "-"
              }}%</n-text
            >
          </n-flex>
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
          <n-progress
            type="line"
            :percentage="calculatePercent(summary?.block_count || 0)"
            :show-indicator="false"
            size="tiny"
            status="warning"
            style="width: 100%; margin-top: 4px"
          />
        </n-gi>
      </n-grid>

      <n-divider style="margin: 0" />

      <!-- Latency Section -->
      <n-flex vertical :size="8">
        <n-text depth="3" style="font-size: 11px"
          >{{ t("metric.dns.dash.query_latency") }} (ms)</n-text
        >
        <n-flex justify="space-between">
          <n-flex
            vertical
            align="center"
            :size="2"
            v-for="stat in latencyStats"
            :key="stat.label"
          >
            <n-text
              depth="3"
              style="font-size: 10px; text-transform: uppercase"
              >{{ stat.label }}</n-text
            >
            <n-text
              strong
              style="font-size: 14px"
              :style="{ color: stat.color }"
            >
              <n-number-animation
                :from="0"
                :to="stat.value || 0"
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
.mini-breakdown {
  margin-top: -2px;
}

.no-data-text {
  font-size: 11px;
}
</style>
