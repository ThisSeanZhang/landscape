<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from "vue";
import { get_connect_metric_info } from "@/api/metric";
import type {
  ConnectKey,
  ConnectMetricPoint,
} from "@landscape-router/types/api/schemas";
import MetricLineChart from "../MetricLineChart.vue";
import { useI18n } from "vue-i18n";

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
      data: sampledIndices.value.map(
        (i) => [chartData.value[i].report_time, rI[i]] as [number, number],
      ),
    },
    {
      name: t("metric.connect.chart.egress_rate"),
      data: sampledIndices.value.map(
        (i) => [chartData.value[i].report_time, rE[i]] as [number, number],
      ),
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
      data: sampledIndices.value.map(
        (i) => [chartData.value[i].report_time, rI[i]] as [number, number],
      ),
    },
    {
      name: t("metric.connect.chart.egress_packets_rate"),
      data: sampledIndices.value.map(
        (i) => [chartData.value[i].report_time, rE[i]] as [number, number],
      ),
    },
  ];
});

function formatVolumeRate(value: number): string {
  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s", "PB/s"];
  if (!Number.isFinite(value) || value <= 0) return `0 ${units[0]}`;
  const i = Math.min(
    Math.max(Math.floor(Math.log(value) / Math.log(1024)), 0),
    units.length - 1,
  );
  return `${(value / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

const formatPacketRate = (value: number) => `${Math.round(value)} pps`;

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
    <MetricLineChart
      :series="bytesSeries"
      :x-axis-title="t('metric.connect.filter.time')"
      :y-axis-title="t('metric.connect.chart.bytes_axis_rate')"
      :value-formatter="formatVolumeRate"
    />
    <MetricLineChart
      :series="packetsSeries"
      :x-axis-title="t('metric.connect.filter.time')"
      :y-axis-title="t('metric.connect.chart.packets_axis_rate')"
      :value-formatter="formatPacketRate"
    />
  </n-flex>
</template>
