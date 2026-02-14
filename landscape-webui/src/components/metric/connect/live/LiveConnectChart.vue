<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from "vue";
import { get_connect_metric_info } from "@/api/metric";
import {
  ConnectKey,
  ConnectMetricPoint,
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
const interval = ref<any>(null);

async function fetchData() {
  chartData.value = await get_connect_metric_info(props.conn);
}

// 数据降采样
function downsampleData(
  data: number[],
  maxPoints: number = 100,
): { data: number[]; indices: number[] } {
  if (data.length <= maxPoints) {
    return { data, indices: data.map((_, i) => i) };
  }
  const step = Math.ceil(data.length / maxPoints);
  const sampledData: number[] = [];
  const sampledIndices: number[] = [];
  for (let i = 0; i < data.length; i += step) {
    sampledData.push(data[i]);
    sampledIndices.push(i);
  }
  if (sampledIndices[sampledIndices.length - 1] !== data.length - 1) {
    sampledData.push(data[data.length - 1]);
    sampledIndices.push(data.length - 1);
  }
  return { data: sampledData, indices: sampledIndices };
}

const sampledIndices = computed(() => {
  const ingressData = chartData.value.map((m) => m.ingress_bytes);
  return downsampleData(ingressData).indices;
});

const categories = computed(() =>
  sampledIndices.value.map((idx) => {
    const m = chartData.value[idx];
    const d = new Date(m.report_time);
    return d.toLocaleTimeString("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  }),
);

// 计算速率 (Speed/Rate)
function calculateRates(values: number[], timestamps: number[]): number[] {
  if (values.length === 0) return [];
  const rates = [0];
  for (let i = 1; i < values.length; i++) {
    const dt = (timestamps[i] - timestamps[i - 1]) / 1000;
    rates.push(dt > 0 ? Math.max(0, (values[i] - values[i - 1]) / dt) : 0);
  }
  return rates;
}

const bytesSeries = computed(() => {
  const ingress = chartData.value.map((m) => m.ingress_bytes);
  const egress = chartData.value.map((m) => m.egress_bytes);
  const ts = chartData.value.map((m) => m.report_time);
  const rI = calculateRates(ingress, ts);
  const rE = calculateRates(egress, ts);
  return [
    {
      name: t("metric.connect.chart.ingress_rate"),
      data: sampledIndices.value.map((i) => rI[i]),
    },
    {
      name: t("metric.connect.chart.egress_rate"),
      data: sampledIndices.value.map((i) => rE[i]),
    },
  ];
});

const packetsSeries = computed(() => {
  const ingress = chartData.value.map((m) => m.ingress_packets);
  const egress = chartData.value.map((m) => m.egress_packets);
  const ts = chartData.value.map((m) => m.report_time);
  const rI = calculateRates(ingress, ts);
  const rE = calculateRates(egress, ts);
  return [
    {
      name: t("metric.connect.chart.ingress_packets_rate"),
      data: sampledIndices.value.map((i) => rI[i]),
    },
    {
      name: t("metric.connect.chart.egress_packets_rate"),
      data: sampledIndices.value.map((i) => rE[i]),
    },
  ];
});

const baseOptions = computed<ApexOptions>(() => ({
  chart: {
    id: "live-network-traffic",
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

function formatVolumeRate(value: number): string {
  if (value === 0) return "0 B/s";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  const i = Math.floor(Math.log(value) / Math.log(1024));
  return `${(value / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

const bytesOptions = computed<ApexOptions>(() => ({
  ...baseOptions.value,
  yaxis: {
    title: { text: t("metric.connect.chart.bytes_axis_rate") },
    labels: { formatter: formatVolumeRate },
  },
}));

const packetsOptions = computed<ApexOptions>(() => ({
  ...baseOptions.value,
  yaxis: {
    title: { text: t("metric.connect.chart.packets_axis_rate") },
    labels: { formatter: (v: number) => `${Math.round(v)} pps` },
  },
}));

onMounted(() => {
  fetchData();
  interval.value = setInterval(fetchData, 5000);
});

onUnmounted(() => {
  if (interval.value) clearInterval(interval.value);
});
</script>

<template>
  <n-flex vertical>
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
  </n-flex>
</template>
