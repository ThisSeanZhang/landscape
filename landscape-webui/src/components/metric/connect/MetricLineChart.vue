<script setup lang="ts">
import { computed } from "vue";
import { useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";
import VChart from "vue-echarts";
import { use, type ComposeOption } from "echarts/core";
import { LineChart, type LineSeriesOption } from "echarts/charts";
import { CanvasRenderer } from "echarts/renderers";
import {
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  ToolboxComponent,
  TooltipComponent,
  type DataZoomComponentOption,
  type GridComponentOption,
  type LegendComponentOption,
  type ToolboxComponentOption,
  type TooltipComponentOption,
} from "echarts/components";

use([
  CanvasRenderer,
  LineChart,
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  ToolboxComponent,
  TooltipComponent,
]);

type ECOption = ComposeOption<
  | LineSeriesOption
  | DataZoomComponentOption
  | GridComponentOption
  | LegendComponentOption
  | ToolboxComponentOption
  | TooltipComponentOption
>;

type MetricPoint = [timestamp: number, value: number];

interface MetricSeries {
  name: string;
  data: MetricPoint[];
}

interface Props {
  series: MetricSeries[];
  xAxisTitle: string;
  yAxisTitle: string;
  valueFormatter: (value: number) => string;
}

const props = defineProps<Props>();
const themeVars = useThemeVars();
const { t, locale } = useI18n();

const updateOptions = { replaceMerge: ["series"] };

const timeSpan = computed(() => {
  const timestamps = props.series.flatMap((series) =>
    series.data.map(([timestamp]) => timestamp),
  );
  if (timestamps.length < 2) return 0;
  return Math.max(...timestamps) - Math.min(...timestamps);
});

const timeFormatter = computed(
  () =>
    new Intl.DateTimeFormat(
      locale.value || "zh-CN",
      timeSpan.value > 2 * 24 * 3600 * 1000
        ? {
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            hour12: false,
          }
        : {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
          },
    ),
);

const option = computed<ECOption>(() => ({
  animation: false,
  color: [themeVars.value.successColor, themeVars.value.infoColor],
  textStyle: {
    color: themeVars.value.textColor2,
  },
  grid: {
    top: 52,
    right: 24,
    bottom: 32,
    left: 16,
    outerBoundsMode: "same",
    outerBoundsContain: "all",
  },
  legend: {
    type: "scroll",
    top: 8,
    left: 16,
    right: 112,
    textStyle: {
      color: themeVars.value.textColor2,
    },
  },
  tooltip: {
    trigger: "axis",
    backgroundColor: themeVars.value.popoverColor,
    borderColor: themeVars.value.borderColor,
    textStyle: {
      color: themeVars.value.textColor1,
    },
    valueFormatter: (value) => props.valueFormatter(Number(value)),
  },
  toolbox: {
    top: 4,
    right: 16,
    itemSize: 16,
    itemGap: 10,
    iconStyle: {
      borderColor: themeVars.value.textColor3,
    },
    emphasis: {
      iconStyle: {
        borderColor: themeVars.value.primaryColor,
      },
    },
    feature: {
      dataZoom: {
        yAxisIndex: "none",
        title: {
          zoom: t("metric.connect.chart.zoom"),
          back: t("metric.connect.chart.zoom_back"),
        },
      },
      restore: {
        title: t("metric.connect.chart.reset_zoom"),
      },
    },
  },
  dataZoom: [
    {
      type: "inside",
      xAxisIndex: 0,
      filterMode: "none",
    },
  ],
  xAxis: {
    type: "time",
    name: props.xAxisTitle,
    nameLocation: "middle",
    nameGap: 26,
    nameTextStyle: {
      color: themeVars.value.textColor2,
    },
    axisLabel: {
      color: themeVars.value.textColor3,
      hideOverlap: true,
      formatter: (value: number) => timeFormatter.value.format(value),
    },
    axisLine: {
      lineStyle: {
        color: themeVars.value.borderColor,
      },
    },
    axisTick: {
      lineStyle: {
        color: themeVars.value.borderColor,
      },
    },
    splitLine: {
      show: false,
    },
  },
  yAxis: {
    type: "value",
    name: props.yAxisTitle,
    nameLocation: "middle",
    nameGap: 54,
    nameTextStyle: {
      color: themeVars.value.textColor2,
    },
    axisLabel: {
      color: themeVars.value.textColor3,
      formatter: (value: number) => props.valueFormatter(value),
    },
    splitLine: {
      lineStyle: {
        color: themeVars.value.dividerColor,
      },
    },
  },
  series: props.series.map((series) => ({
    ...series,
    type: "line",
    smooth: true,
    showSymbol: false,
    lineStyle: {
      width: 2,
    },
    emphasis: {
      focus: "series",
    },
  })),
}));
</script>

<template>
  <VChart
    class="metric-line-chart"
    :option="option"
    :update-options="updateOptions"
    autoresize
  />
</template>

<style scoped>
.metric-line-chart {
  width: 100%;
  height: 300px;
}
</style>
