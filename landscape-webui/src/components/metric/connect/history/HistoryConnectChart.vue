<script setup lang="ts">
import { ref, onMounted, watch, computed } from "vue";
import { get_connect_metric_info } from "@/api/metric";
import type {
  ConnectKey,
  ConnectMetricPoint,
  MetricResolution,
} from "@landscape-router/types/api/schemas";
import MetricLineChart from "../MetricLineChart.vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();

interface Props {
  conn: ConnectKey;
  createTimeMs?: number;
  lastReportTime?: number;
}

const props = defineProps<Props>();
const chartData = ref<ConnectMetricPoint[]>([]);
const loading = ref(false);

// 自动选择合适的初始分辨率
const resolution = ref<MetricResolution>(
  (() => {
    const now = Date.now();
    const startTime =
      props.createTimeMs || Number(props.conn.create_time) / 1000000;
    const ageMs = now - startTime;

    if (ageMs < 5 * 60 * 1000) return "second"; // 5分钟内看秒级
    if (ageMs < 24 * 3600 * 1000) return "minute"; // 1天内看分钟级
    if (ageMs < 7 * 24 * 3600 * 1000) return "hour"; // 7天内看小时级
    return "day"; // 其余看天级
  })(),
);

const resolutionOptions = computed(() => [
  { label: t("metric.connect.chart.second_level"), value: "second" },
  { label: t("metric.connect.chart.minute_level"), value: "minute" },
  { label: t("metric.connect.chart.hour_level"), value: "hour" },
  { label: t("metric.connect.chart.day_level"), value: "day" },
]);

async function fetchData() {
  loading.value = true;
  try {
    chartData.value = await get_connect_metric_info(
      props.conn,
      resolution.value,
    );
  } finally {
    loading.value = false;
  }
}

// 数据降采样
function downsampleData(data: number[], maxPoints: number = 100) {
  if (data.length <= maxPoints) return { data, indices: data.map((_, i) => i) };
  const step = Math.ceil(data.length / maxPoints);
  const sampledIndices: number[] = [];
  for (let i = 0; i < data.length; i += step) sampledIndices.push(i);
  if (sampledIndices[sampledIndices.length - 1] !== data.length - 1)
    sampledIndices.push(data.length - 1);
  return { indices: sampledIndices };
}

const sampledIndices = computed(
  () => downsampleData(chartData.value.map((m) => m.ingress_bytes)).indices,
);

const bytesSeries = computed(() => [
  {
    name: t("metric.connect.chart.ingress_total"),
    data: sampledIndices.value.map(
      (i) =>
        [chartData.value[i].report_time, chartData.value[i].ingress_bytes] as [
          number,
          number,
        ],
    ),
  },
  {
    name: t("metric.connect.chart.egress_total"),
    data: sampledIndices.value.map(
      (i) =>
        [chartData.value[i].report_time, chartData.value[i].egress_bytes] as [
          number,
          number,
        ],
    ),
  },
]);

const packetsSeries = computed(() => [
  {
    name: t("metric.connect.chart.ingress_packets_total"),
    data: sampledIndices.value.map(
      (i) =>
        [
          chartData.value[i].report_time,
          chartData.value[i].ingress_packets,
        ] as [number, number],
    ),
  },
  {
    name: t("metric.connect.chart.egress_packets_total"),
    data: sampledIndices.value.map(
      (i) =>
        [chartData.value[i].report_time, chartData.value[i].egress_packets] as [
          number,
          number,
        ],
    ),
  },
]);

function formatVolume(val: number): string {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  if (!Number.isFinite(val) || val <= 0) return `0 ${units[0]}`;
  const i = Math.min(
    Math.max(Math.floor(Math.log(val) / Math.log(1024)), 0),
    units.length - 1,
  );
  return `${(val / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

const formatPackets = (value: number) => `${Math.round(value)} pkt`;

watch(resolution, fetchData);
onMounted(fetchData);
</script>

<template>
  <n-flex vertical>
    <n-flex justify="end">
      <n-radio-group v-model:value="resolution" size="small">
        <n-radio-button
          v-for="opt in resolutionOptions"
          :key="opt.value"
          :value="opt.value"
        >
          {{ opt.label }}
        </n-radio-button>
      </n-radio-group>
    </n-flex>
    <n-spin :show="loading">
      <MetricLineChart
        :series="bytesSeries"
        :x-axis-title="t('metric.connect.filter.time')"
        :y-axis-title="t('metric.connect.chart.bytes_axis_total')"
        :value-formatter="formatVolume"
      />
      <MetricLineChart
        :series="packetsSeries"
        :x-axis-title="t('metric.connect.filter.time')"
        :y-axis-title="t('metric.connect.chart.packets_axis_total')"
        :value-formatter="formatPackets"
      />
    </n-spin>
  </n-flex>
</template>
