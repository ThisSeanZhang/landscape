<script setup lang="ts">
import { ref, onMounted, watch, computed } from "vue";
import { useI18n } from "vue-i18n";
import { useThemeVars, NScrollbar } from "naive-ui";
import { get_dns_summary, DnsSummaryResponse } from "@/api/metric/dns";
import { useFrontEndStore } from "@/stores/front_end_config";
import {
  NGrid,
  NGridItem,
  NCard,
  NStatistic,
  NProgress,
  NList,
  NListItem,
  NSpace,
  NText,
  NSkeleton,
  NEmpty,
  NNumberAnimation,
  NEllipsis,
  NFlex,
} from "naive-ui";
import { useMacBindingStore } from "@/stores/mac_binding";

const macBindingStore = useMacBindingStore();

const props = defineProps<{
  timeRange: [number, number] | null;
  flowId?: number | null;
}>();

const summary = ref<DnsSummaryResponse | null>(null);
const loading = ref(true);
const { t } = useI18n();
const themeVars = useThemeVars();
const frontEndStore = useFrontEndStore();

const loadSummary = async () => {
  loading.value = true;
  try {
    const now = Date.now();
    const startTime = props.timeRange?.[0] || now - 24 * 60 * 60 * 1000;
    const endTime = props.timeRange?.[1] || now;

    summary.value = await get_dns_summary({
      start_time: startTime,
      end_time: endTime,
      flow_id: props.flowId || undefined,
    });
  } catch (e) {
    console.error(e);
  } finally {
    loading.value = false;
  }
};

watch(() => [props.timeRange, props.flowId], loadSummary, { immediate: true });

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

const dashboardLists = computed(() => [
  {
    title: t("metric.dns.dash.most_queried_domains"),
    data: summary.value?.top_domains,
    type: "domain",
  },
  {
    title: t("metric.dns.dash.active_clients"),
    data: summary.value?.top_clients,
    type: "client",
  },
  {
    title: t("metric.dns.dash.latency_hotspots"),
    subtitle: t("metric.dns.dash.latency_subtitle"),
    data: summary.value?.slowest_domains,
    type: "latency",
  },
  {
    title: t("metric.dns.dash.top_blocked"),
    data: summary.value?.top_blocked,
    type: "blocked",
  },
]);

const formatDuration = (ms: number | undefined) => {
  if (ms === undefined) return "-";
  if (ms >= 1000) {
    return (ms / 1000).toFixed(2) + "s";
  }
  return ms.toFixed(1) + "ms";
};

defineExpose({ refresh: loadSummary });
</script>

<template>
  <div class="dns-dashboard">
    <!-- Top Stats Row -->
    <n-grid
      cols="5"
      :x-gap="12"
      :y-gap="12"
      item-responsive
      style="margin-bottom: 16px"
    >
      <!-- Total Queries with breakdown -->
      <n-grid-item span="0:5 640:1">
        <n-card size="small" :bordered="false" class="metric-card">
          <div class="metric-content">
            <n-statistic :label="t('metric.dns.dash.total_queries')">
              <n-number-animation :from="0" :to="summary?.total_queries || 0" />
            </n-statistic>
            <div class="hit-breakdown">
              <div class="breakdown-item">
                <span class="label">{{ t("metric.dns.dash.nxdomain") }}:</span>
                <span class="val">{{ summary?.nxdomain_count || 0 }}</span>
              </div>
              <div class="breakdown-item">
                <span class="label">{{ t("metric.dns.dash.filter") }}:</span>
                <span class="val">{{ summary?.filter_count || 0 }}</span>
              </div>
              <div class="breakdown-item">
                <span class="label">{{ t("metric.dns.dash.errors") }}:</span>
                <span
                  class="val"
                  :class="{ error: (summary?.error_count || 0) > 0 }"
                  >{{ summary?.error_count || 0 }}</span
                >
              </div>
            </div>
          </div>
        </n-card>
      </n-grid-item>

      <!-- Cache Hit Rate (with breakdown) -->
      <n-grid-item span="0:5 640:1">
        <n-card size="small" :bordered="false" class="metric-card">
          <div class="metric-content">
            <n-statistic :label="t('metric.dns.dash.cache_hit_rate')">
              <template
                #suffix
                v-if="
                  calculatePercentFromValues(
                    summary?.cache_hit_count,
                    summary?.total_effective_queries,
                  ) !== null
                "
                ><span class="suffix">%</span></template
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
              <n-text v-else depth="3" style="font-size: 14px">{{
                t("metric.dns.dash.no_data")
              }}</n-text>
            </n-statistic>
            <div class="hit-breakdown">
              <div class="breakdown-item">
                <span class="label">{{ t("metric.dns.dash.v4") }}:</span>
                <span
                  class="val"
                  v-if="
                    calculatePercentFromValues(
                      summary?.hit_count_v4,
                      summary?.total_v4,
                    ) !== null
                  "
                >
                  {{
                    calculatePercentFromValues(
                      summary?.hit_count_v4,
                      summary?.total_v4,
                    )
                  }}%
                </span>
                <span class="val none" v-else>-</span>
              </div>
              <div class="breakdown-item">
                <span class="label">{{ t("metric.dns.dash.v6") }}:</span>
                <span
                  class="val"
                  v-if="
                    calculatePercentFromValues(
                      summary?.hit_count_v6,
                      summary?.total_v6,
                    ) !== null
                  "
                >
                  {{
                    calculatePercentFromValues(
                      summary?.hit_count_v6,
                      summary?.total_v6,
                    )
                  }}%
                </span>
                <span class="val none" v-else>-</span>
              </div>
              <div class="breakdown-item">
                <span class="label">{{ t("metric.dns.dash.other") }}:</span>
                <span
                  class="val"
                  v-if="
                    calculatePercentFromValues(
                      summary?.hit_count_other,
                      summary?.total_other,
                    ) !== null
                  "
                >
                  {{
                    calculatePercentFromValues(
                      summary?.hit_count_other,
                      summary?.total_other,
                    )
                  }}%
                </span>
                <span class="val none" v-else>-</span>
              </div>
            </div>
          </div>
        </n-card>
      </n-grid-item>

      <!-- Block Rate -->
      <n-grid-item span="0:5 640:1">
        <n-card size="small" :bordered="false" class="metric-card">
          <div class="metric-content">
            <n-statistic :label="t('metric.dns.dash.block_rate')">
              <template #suffix><span class="suffix">%</span></template>
              <n-number-animation
                :from="0"
                :to="calculatePercent(summary?.block_count || 0)"
                :precision="1"
              />
            </n-statistic>
            <div class="metric-progress-container">
              <n-progress
                type="line"
                :percentage="calculatePercent(summary?.block_count || 0)"
                :show-indicator="false"
                size="tiny"
                status="warning"
              />
            </div>
          </div>
        </n-card>
      </n-grid-item>

      <!-- Latency Breakdown Card -->
      <n-grid-item span="0:5 640:2">
        <n-card size="small" :bordered="false" class="metric-card latency-card">
          <div class="latency-header">
            <span class="latency-title">{{
              t("metric.dns.dash.query_latency")
            }}</span>
            <span class="latency-unit">{{
              t("metric.dns.dash.milliseconds")
            }}</span>
          </div>
          <div class="latency-grid">
            <div
              class="latency-stat"
              v-for="stat in latencyStats"
              :key="stat.label"
            >
              <div class="latency-label">{{ stat.label }}</div>
              <div class="latency-value" :style="{ color: stat.color }">
                <n-number-animation
                  :from="0"
                  :to="stat.value || 0"
                  :precision="1"
                />
              </div>
            </div>
          </div>
        </n-card>
      </n-grid-item>
    </n-grid>

    <!-- Main Lists Grid -->
    <n-grid cols="4" :x-gap="16" :y-gap="16" item-responsive>
      <n-grid-item
        v-for="list in dashboardLists"
        :key="list.title"
        span="0:4 640:1"
      >
        <n-card size="small" class="list-card">
          <template #header>
            <n-flex justify="space-between" align="baseline">
              <span class="card-title">{{ list.title }}</span>
              <span v-if="list.subtitle" class="card-subtitle">{{
                list.subtitle
              }}</span>
            </n-flex>
          </template>
          <div class="card-content-wrapper">
            <n-skeleton v-if="loading" text :repeat="12" />
            <div class="empty-wrapper" v-else-if="!list.data?.length">
              <n-empty
                :description="t('metric.dns.dash.no_data')"
                size="small"
              />
            </div>
            <n-scrollbar v-else style="max-height: 520px" trigger="hover">
              <div class="scrollbar-content">
                <n-list hoverable size="small" :show-divider="false">
                  <n-list-item v-for="item in list.data" :key="item.name">
                    <n-flex vertical :wrap="false" style="width: 100%">
                      <!-- Header row with domain and value -->
                      <n-flex
                        justify="space-between"
                        align="center"
                        :wrap="false"
                      >
                        <n-ellipsis
                          tooltip
                          :class="[
                            'domain-text',
                            list.type === 'blocked' ? 'danger' : '',
                          ]"
                          style="flex: 1; min-width: 0"
                        >
                          {{
                            list.type === "client"
                              ? macBindingStore.GET_NAME_WITH_FALLBACK(
                                  item.name,
                                )
                              : item.name
                          }}
                        </n-ellipsis>
                        <n-text
                          v-if="list.type === 'latency'"
                          type="warning"
                          class="latency-text"
                        >
                          {{ formatDuration(item.value) }}
                        </n-text>
                        <n-text v-else depth="3" class="count-text">{{
                          item.count
                        }}</n-text>
                      </n-flex>

                      <!-- Progress bars for domain and client -->
                      <n-progress
                        v-if="list.type === 'domain' || list.type === 'client'"
                        type="line"
                        :percentage="calculatePercent(item.count)"
                        :show-indicator="false"
                        size="tiny"
                        :status="list.type === 'client' ? 'info' : 'default'"
                        class="item-progress"
                      />

                      <!-- Meta text for latency items -->
                      <n-text
                        v-if="list.type === 'latency'"
                        depth="3"
                        class="item-meta"
                      >
                        {{
                          t("metric.dns.dash.from_samples", {
                            count: item.count,
                          })
                        }}
                      </n-text>
                    </n-flex>
                  </n-list-item>
                </n-list>
              </div>
            </n-scrollbar>
          </div>
        </n-card>
      </n-grid-item>
    </n-grid>
  </div>
</template>

<style scoped>
.dns-dashboard {
  width: 100%;
}

.metric-card {
  background: rgba(128, 128, 128, 0.06);
  border-radius: 8px;
  height: 100%;
}

.metric-content {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  height: 100%;
}

.metric-progress-container {
  height: 4px; /* Fixed height for progress slot */
  margin-top: 10px;
}

.hit-breakdown {
  display: flex;
  justify-content: space-between;
  margin-top: 8px;
  background: rgba(128, 128, 128, 0.05);
  padding: 2px 6px;
  border-radius: 4px;
}

.breakdown-item {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.breakdown-item .label {
  font-size: 10px;
  color: #888;
  line-height: 1;
}

.breakdown-item .val {
  font-size: 11px;
  font-weight: 600;
  color: #2080f0;
}

.breakdown-item .val.none {
  color: #666;
  font-weight: 400;
}

.breakdown-item .val.error {
  color: #e88080;
  font-weight: 700;
}

.suffix {
  font-size: 14px;
  margin-left: 4px;
  color: #888;
}

.list-card {
  height: 600px; /* Unified fixed height to ensure all cards align even if empty */
  display: flex;
  flex-direction: column;
}

:deep(.list-card.n-card > .n-card__content) {
  flex: 1;
  display: flex;
  flex-direction: column;
  padding: 0 0 12px 0 !important; /* Zero horizontal padding, managed by inner wrapper */
}

:deep(.list-card.n-card > .n-card-header) {
  padding: 12px 16px !important;
}

.card-content-wrapper {
  padding: 10px 0 10px 16px;
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
}

.empty-wrapper {
  padding: 0 16px 0 0;
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
}

.scrollbar-content {
  padding-right: 16px;
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
}

.domain-text {
  font-size: 13px;
  font-weight: 600;
}

.domain-text.danger {
  color: #e88080;
}

.count-text {
  font-size: 12px;
  font-family: monospace;
  background: rgba(128, 128, 128, 0.1);
  padding: 1px 6px;
  border-radius: 4px;
}

.item-meta {
  font-size: 11px;
  margin-top: -2px;
}

.item-progress {
  margin-top: 4px;
}

:deep(.n-statistic .n-statistic-label) {
  font-size: 12px;
  color: #888;
  margin-bottom: 4px;
}

:deep(.n-statistic .n-statistic-value__content) {
  font-weight: 700;
  font-size: 1.8rem;
}

:deep(.n-list-item) {
  padding: 10px 0 !important;
}

:deep(.n-list-item__main) {
  width: 100%;
  min-width: 0;
  overflow: hidden;
}

:deep(.n-card-header__title) {
  font-size: 15px !important;
  font-weight: 600 !important;
}

.card-title {
  font-size: 15px;
  font-weight: 600;
  line-height: 1.2;
}

.card-subtitle {
  font-size: 11px;
  color: #888;
  font-weight: 400;
  font-style: italic;
}

/* Latency Card Styles */
.latency-card {
  background: rgba(128, 128, 128, 0.06);
}

.latency-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.latency-title {
  font-size: 12px;
  color: #888;
  font-weight: 500;
}

.latency-unit {
  font-size: 10px;
  color: #999;
  font-style: italic;
}

.latency-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 8px;
}

.latency-stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 6px 4px;
  background: rgba(128, 128, 128, 0.05);
  border-radius: 6px;
}

.latency-label {
  font-size: 10px;
  color: #888;
  margin-bottom: 4px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.latency-value {
  font-size: 16px;
  font-weight: 700;
  line-height: 1;
}
</style>
