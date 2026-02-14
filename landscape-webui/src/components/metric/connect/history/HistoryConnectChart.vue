<script setup lang="ts">
import { ref, onMounted, watch, computed } from "vue";
import { get_connect_metric_info } from "@/api/metric";
import {
  ConnectKey,
  ConnectMetricPoint,
  MetricResolution,
} from "landscape-types/common/metric/connect";
import { ApexOptions } from "apexcharts";
import VueApexCharts from "vue3-apexcharts";
import { useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";

const themeVars = useThemeVars();
const { t } = useI18n();

interface Props {
  conn: ConnectKey;
}

const props = defineProps<Props>();
const chartData = ref<ConnectMetricPoint[]>([]);
const resolution = ref<MetricResolution>("second");
const loading = ref(false);

const resolutionOptions = [
  { label: "秒级 (5分钟保留)", value: "second" },
  { label: "分钟级 (1天保留)", value: "minute" },
  { label: "小时级 (7天保留)", value: "hour" },
  { label: "天级 (30天保留)", value: "day" },
];

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

const categories = computed(() =>
  sampledIndices.value.map((idx) => {
    const m = chartData.value[idx];
    const d = new Date(m.report_time);
    const span =
      (chartData.value[chartData.value.length - 1]?.report_time || 0) -
      (chartData.value[0]?.report_time || 0);
    if (span > 2 * 24 * 3600 * 1000) {
      return (
        d.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" }) +
        " " +
        d.toLocaleTimeString("zh-CN", {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        })
      );
    }
    return d.toLocaleTimeString("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  }),
);

const bytesSeries = computed(() => [
  {
    name: t("metric.connect.chart.ingress_total"),
    data: sampledIndices.value.map((i) => chartData.value[i].ingress_bytes),
  },
  {
    name: t("metric.connect.chart.egress_total"),
    data: sampledIndices.value.map((i) => chartData.value[i].egress_bytes),
  },
]);

const packetsSeries = computed(() => [
  {
    name: t("metric.connect.chart.ingress_packets_total"),
    data: sampledIndices.value.map((i) => chartData.value[i].ingress_packets),
  },
  {
    name: t("metric.connect.chart.egress_packets_total"),
    data: sampledIndices.value.map((i) => chartData.value[i].egress_packets),
  },
]);

const baseOptions = computed<ApexOptions>(() => ({
  chart: {
    id: "history-network-traffic",
    background: "transparent",
    toolbar: { show: true },
    animate: false,
    zoom: { enabled: true, type: "x" },
  },
  theme: { mode: "dark" },
  colors: [themeVars.value.successColor, themeVars.value.infoColor],
  stroke: { curve: "smooth", width: 2 },
  xaxis: {
    categories: categories.value,
    tickAmount: 10,
    title: { text: t("metric.connect.filter.time") },
  },
  legend: { position: "top" },
}));

function formatVolume(val: number): string {
  if (val === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(val) / Math.log(1024));
  return `${(val / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

const bytesOptions = computed<ApexOptions>(() => ({
  ...baseOptions.value,
  yaxis: {
    title: { text: t("metric.connect.chart.bytes_axis_total") },
    labels: { formatter: formatVolume },
  },
}));

const packetsOptions = computed<ApexOptions>(() => ({
  ...baseOptions.value,
  yaxis: {
    title: { text: t("metric.connect.chart.packets_axis_total") },
    labels: { formatter: (v: number) => `${Math.round(v)} pkt` },
  },
}));

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
      <VueApexCharts
        type="line"
        height="300"
        :options="bytesOptions"
        :series="bytesSeries"
      />
      <VueApexCharts
        type="line"
        height="300"
        :options="packetsOptions"
        :series="packetsSeries"
      />
    </n-spin>
  </n-flex>
</template>
