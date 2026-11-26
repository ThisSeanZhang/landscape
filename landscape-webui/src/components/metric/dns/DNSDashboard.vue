<script setup lang="ts">
import { ref, watch, computed } from "vue";
import { useIntervalFn } from "@vueuse/core";
import MetricLineChart from "@/components/metric/connect/MetricLineChart.vue";
import { dnsLatencyStats } from "@/components/metric/dns/latencyStats";
import { useI18n } from "vue-i18n";
import { useThemeVars } from "naive-ui";
import type {
  DnsLiveDashboard,
  DnsMinutePoint,
  DnsSummaryResponse,
} from "@landscape-router/types/api/schemas";
import { get_dns_summary, getDnsLiveDashboard } from "@/api/metric/dns";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";

const enrolledDeviceStore = useEnrolledDeviceStore();

const props = defineProps<{
  live?: boolean;
  timeRange?: [number, number] | null;
  flowId?: number | null;
}>();

const summary = ref<DnsSummaryResponse | null>(null);
const loading = ref(true);
const { t } = useI18n();
const themeVars = useThemeVars();

const failed = ref(false);
const liveData = ref<DnsLiveDashboard | null>(null);
let requestId = 0;
const loadSummary = async () => {
  const id = ++requestId;
  loading.value = true;
  try {
    const flow_id = props.flowId ?? undefined;
    if (props.live) {
      const data = await getDnsLiveDashboard({ flow_id }, { silent: true });
      if (id === requestId) {
        liveData.value = data;
        summary.value = data.summary;
      }
    } else {
      const now = Date.now();
      const data = await get_dns_summary(
        {
          start_time: props.timeRange?.[0] ?? now - 10 * 60 * 1000,
          end_time: props.timeRange?.[1] ?? now,
          flow_id,
        },
        { silent: true },
      );
      if (id === requestId) summary.value = data;
    }
    if (id === requestId) failed.value = false;
  } catch (error) {
    if (id === requestId) failed.value = true;
    console.error(error);
  } finally {
    if (id === requestId) loading.value = false;
  }
};

watch(
  () => [props.timeRange, props.flowId],
  () => {
    liveData.value = null;
    summary.value = null;
    loadSummary();
  },
  { immediate: true },
);
useIntervalFn(
  () => {
    if (!loading.value) loadSummary();
  },
  5000,
  { immediate: props.live === true },
);

const trend = computed(() => {
  const series = (
    key: keyof Omit<DnsMinutePoint, "start_ms">,
    name: string,
  ) => ({
    name: t(name),
    data: (liveData.value?.minutes ?? []).map(
      (p) => [p.start_ms, p[key]] as [number, number],
    ),
  });
  return [
    series("queries", "metric.dns.dash.total_queries"),
    series("hits", "metric.dns.status_hit"),
    series("blocks", "metric.dns.status_block"),
    series("errors", "metric.dns.dash.errors"),
  ];
});

const latencySamples = computed(
  () =>
    liveData.value?.latency.reduce((total, band) => total + band.count, 0) ?? 0,
);
const statuses = computed(() => {
  const data = liveData.value;
  if (!data) return [];
  const s = data.summary;
  const upstream = latencySamples.value;
  return [
    ["normal", upstream - s.nxdomain_count],
    ["hit", s.cache_hit_count],
    ["local", s.total_effective_queries - s.cache_hit_count - upstream],
    ["nxdomain", s.nxdomain_count],
    ["block", s.block_count],
    ["filter", s.filter_count],
    ["error", s.error_count],
  ] as const;
});
const latencyBands = computed(() => {
  let lower = 0;
  return (liveData.value?.latency ?? []).map(({ upper_ms, count }) => {
    const label =
      upper_ms == null
        ? `> ${lower} ms`
        : `${lower === 0 ? 0 : lower + 1}–${upper_ms} ms`;
    lower = upper_ms ?? lower;
    return { label, count };
  });
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

function percent(hit?: number, total?: number) {
  const ratio = calculatePercentFromValues(hit, total);
  return ratio === null ? "—" : `${ratio}%`;
}

const cacheRates = computed(() => {
  const s = summary.value;
  return [
    [t("metric.dns.dash.v4"), percent(s?.hit_count_v4, s?.total_v4)],
    [t("metric.dns.dash.v6"), percent(s?.hit_count_v6, s?.total_v6)],
    [t("metric.dns.dash.other"), percent(s?.hit_count_other, s?.total_other)],
  ];
});
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

const formatDuration = (ms: number | null | undefined) => {
  if (ms == null) return "-";
  if (ms >= 1000) {
    return (ms / 1000).toFixed(2) + "s";
  }
  return ms.toFixed(1) + "ms";
};

defineExpose({ refresh: loadSummary, failed });
</script>

<template>
  <div class="dns-dashboard">
    <section class="summary-strip">
      <div class="summary-stat stat-queries">
        <span class="stat-label">{{ t("metric.dns.dash.total_queries") }}</span>
        <strong class="stat-value">{{
          summary?.total_queries.toLocaleString() ?? "—"
        }}</strong>
        <div class="details">
          <span
            >{{ t("metric.dns.dash.nxdomain") }}
            <b>{{ summary?.nxdomain_count ?? "—" }}</b></span
          >
          <span
            >{{ t("metric.dns.dash.filter") }}
            <b>{{ summary?.filter_count ?? "—" }}</b></span
          >
          <span
            >{{ t("metric.dns.dash.errors") }}
            <b>{{ summary?.error_count ?? "—" }}</b></span
          >
        </div>
      </div>
      <div class="summary-stat stat-cache">
        <span class="stat-label">{{
          t("metric.dns.dash.cache_hit_rate")
        }}</span>
        <strong class="stat-value">{{
          percent(summary?.cache_hit_count, summary?.total_effective_queries)
        }}</strong>
        <div class="details">
          <span v-for="[label, value] in cacheRates" :key="label"
            >{{ label }} <b>{{ value }}</b></span
          >
        </div>
      </div>
      <div class="summary-stat stat-blocks">
        <span class="stat-label">{{ t("metric.dns.dash.block_rate") }}</span>
        <strong class="stat-value">{{
          summary ? calculatePercent(summary.block_count) + "%" : "—"
        }}</strong>
        <div class="details">
          <span
            >{{ t("metric.dns.status_block") }}
            <b>{{ summary?.block_count ?? "—" }}</b></span
          >
        </div>
      </div>
      <div class="summary-stat stat-latency">
        <span class="stat-label"
          >{{ t("metric.dns.dash.query_latency") }} (ms)</span
        >
        <div class="latency-stats">
          <div v-for="stat in dnsLatencyStats" :key="stat.field">
            <strong :style="{ color: themeVars[stat.color] }">{{
              summary?.[stat.field]?.toFixed(1) ?? "—"
            }}</strong>
            <span>{{ t(stat.label) }}</span>
          </div>
        </div>
      </div>
    </section>

    <div v-if="live" class="analytics-grid">
      <section class="panel trend-panel">
        <h3>{{ t("metric.dns.dash.minute_trend") }}</h3>
        <MetricLineChart
          v-if="liveData"
          compact
          class="trend-chart"
          :series="trend"
          :x-axis-title="t('common.time')"
          :y-axis-title="t('metric.dns.dash.queries')"
          :value-formatter="String"
        />
        <n-skeleton v-else height="232px" />
      </section>
      <section class="panel">
        <h3>{{ t("metric.dns.dash.status_distribution") }}</h3>
        <div
          v-for="[status, count] in statuses"
          :key="status"
          class="distribution-row"
        >
          <span>{{ t("metric.dns.status_" + status) }}</span>
          <n-progress
            type="line"
            :percentage="calculatePercent(count)"
            :show-indicator="false"
            :height="5"
            :color="
              status === 'block'
                ? themeVars.warningColor
                : status === 'error'
                  ? themeVars.errorColor
                  : themeVars.primaryColor
            "
          />
          <b>{{ count.toLocaleString() }}</b>
        </div>
      </section>
      <section class="panel">
        <h3>{{ t("metric.dns.dash.latency_distribution") }}</h3>
        <div
          v-for="band in latencyBands"
          :key="band.label"
          class="distribution-row"
        >
          <span>{{ band.label }}</span>
          <n-progress
            type="line"
            :percentage="(band.count * 100) / (latencySamples || 1)"
            :show-indicator="false"
            :height="5"
            :color="themeVars.infoColor"
          />
          <b>{{ band.count.toLocaleString() }}</b>
        </div>
      </section>
    </div>

    <div class="ranking-grid">
      <section
        v-for="list in dashboardLists"
        :key="list.type"
        class="panel ranking-panel"
      >
        <header>
          <h3>{{ list.title }}</h3>
          <span v-if="list.subtitle" class="list-subtitle">{{
            list.subtitle
          }}</span>
        </header>
        <n-skeleton v-if="loading && !summary" text :repeat="5" />
        <n-empty
          v-else-if="!list.data?.length"
          size="small"
          :description="t('metric.dns.dash.no_data')"
        />
        <ol v-else>
          <li v-for="item in list.data" :key="item.name">
            <div class="rank-line">
              <n-ellipsis>{{
                list.type === "client"
                  ? enrolledDeviceStore.GET_NAME_WITH_FALLBACK(item.name)
                  : item.name
              }}</n-ellipsis>
              <span v-if="list.type === 'latency'" class="sample-count">{{
                t("metric.dns.dash.from_samples", { count: item.count })
              }}</span>
              <b>{{
                list.type === "latency"
                  ? formatDuration(item.value)
                  : item.count.toLocaleString()
              }}</b>
            </div>
            <n-progress
              v-if="list.type === 'domain' || list.type === 'client'"
              type="line"
              :percentage="calculatePercent(item.count)"
              :height="2"
              :show-indicator="false"
              :color="
                list.type === 'client'
                  ? themeVars.infoColor
                  : themeVars.primaryColor
              "
            />
          </li>
        </ol>
      </section>
    </div>
    <n-text v-if="live" depth="3" class="ranking-note">{{
      t("metric.dns.dash.ranking_note")
    }}</n-text>
  </div>
</template>

<style scoped>
.dns-dashboard {
  container-type: inline-size;
  width: 100%;
  color: v-bind("themeVars.textColor2");
  font-variant-numeric: tabular-nums;
}
.summary-stat,
.panel {
  background: v-bind("themeVars.cardColor");
  border: 1px solid v-bind("themeVars.dividerColor");
  border-radius: 8px;
}
.summary-strip,
.analytics-grid,
.ranking-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.summary-stat {
  min-width: 0;
  padding: 16px 18px;
  background: color-mix(
    in srgb,
    var(--accent) 7%,
    v-bind("themeVars.cardColor")
  );
  border-color: color-mix(
    in srgb,
    var(--accent) 16%,
    v-bind("themeVars.dividerColor")
  );
}
.stat-queries {
  --accent: v-bind("themeVars.successColor");
}
.stat-cache {
  --accent: v-bind("themeVars.infoColor");
}
.stat-blocks {
  --accent: v-bind("themeVars.warningColor");
}
.stat-latency {
  --accent: #a489df;
}
.stat-label,
.list-subtitle,
.sample-count,
.details,
.latency-stats span {
  color: v-bind("themeVars.textColor3");
  font-size: 12px;
}
.stat-value {
  color: color-mix(in srgb, var(--accent) 64%, v-bind("themeVars.textColor1"));
  display: block;
  margin: 4px 0;
  font-size: 30px;
  line-height: 1.25;
  font-weight: 600;
}
.details {
  display: flex;
  gap: 3px 14px;
  flex-wrap: wrap;
}
.details b {
  font-weight: 500;
  color: v-bind("themeVars.textColor2");
}
.latency-stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 5px;
  margin-top: 6px;
}
.latency-stats strong {
  display: block;
  font-size: clamp(15px, 1.45cqi, 24px);
  font-weight: 550;
  line-height: 1.55;
}
.analytics-grid,
.ranking-grid {
  margin-top: 12px;
}
.trend-panel {
  grid-column: span 2;
}
.panel {
  padding: 16px 18px;
  min-width: 0;
}
.panel h3 {
  margin: 0;
  color: v-bind("themeVars.textColor1");
  font-size: 15px;
  font-weight: 600;
  line-height: 1.5;
}
.analytics-grid h3 {
  margin-bottom: 14px;
}
.trend-chart {
  height: 232px;
}
.distribution-row {
  display: grid;
  grid-template-columns: minmax(76px, auto) minmax(24px, 1fr) auto;
  align-items: center;
  gap: 10px;
  min-height: 31px;
  font-size: 13px;
}
.distribution-row b {
  min-width: 3.4em;
  text-align: end;
  font-weight: 500;
}
.ranking-panel header {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 4px 8px;
  padding-bottom: 10px;
  border-bottom: 1px solid v-bind("themeVars.dividerColor");
}
.ranking-panel ol {
  list-style: none;
  margin: 0;
  padding: 0;
}
.ranking-panel li {
  min-height: 38px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 3px;
}
.rank-line {
  display: flex;
  align-items: baseline;
  gap: 8px;
  font-size: 13px;
}
.rank-line > :first-child {
  min-width: 0;
  flex: 1;
}
.rank-line b {
  white-space: nowrap;
  font-weight: 550;
}
.ranking-panel :deep(.n-empty) {
  padding: 28px 0;
}
.ranking-note {
  display: block;
  padding: 8px 2px;
  font-size: 12px;
}
@container (max-width: 1100px) {
  .summary-strip,
  .ranking-grid,
  .analytics-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .trend-panel {
    grid-column: 1 / -1;
  }
}
@container (max-width: 600px) {
  .analytics-grid,
  .ranking-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .summary-stat {
    padding: 12px;
  }
  .summary-stat:last-child,
  .summary-stat:nth-child(3) {
    grid-column: 1 / -1;
  }
  .stat-value {
    color: color-mix(
      in srgb,
      var(--accent) 64%,
      v-bind("themeVars.textColor1")
    );
    font-size: 24px;
  }
}
</style>
