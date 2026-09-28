<script setup lang="ts">
import { computed, ref } from "vue";
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
  hiddenByDefault?: string[];
  dashedNames?: string[];
  height?: string;
}

const props = withDefaults(defineProps<Props>(), {
  hiddenByDefault: () => [],
  dashedNames: () => [],
  height: "320px",
});

const PALETTE = [
  "#5470c6",
  "#91cc75",
  "#fac858",
  "#ee6666",
  "#73c0de",
  "#3ba272",
  "#fc8452",
  "#9a60b4",
  "#ea7ccc",
  "#48b8d0",
  "#e97f7f",
  "#b6a2de",
];

const themeVars = useThemeVars();
const { t, locale } = useI18n();

const updateOptions = { replaceMerge: ["series"] };

const userSelected = ref<Record<string, boolean> | null>(null);

const onLegendSelectChanged = (params: {
  selected: Record<string, boolean>;
}) => {
  userSelected.value = params.selected;
};

const legendSelected = computed<Record<string, boolean>>(() => {
  if (userSelected.value) return userSelected.value;
  const map: Record<string, boolean> = {};
  for (const series of props.series) {
    map[series.name] = !props.hiddenByDefault.includes(series.name);
  }
  return map;
});

const timeSpan = computed(() => {
  let min = Infinity;
  let max = -Infinity;
  for (const series of props.series) {
    for (const [timestamp] of series.data) {
      if (timestamp < min) min = timestamp;
      if (timestamp > max) max = timestamp;
    }
  }
  return min === Infinity || max === -Infinity ? 0 : max - min;
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
  color: PALETTE,
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
    selected: legendSelected.value,
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
          zoom: t("metric.mem.chart.zoom"),
          back: t("metric.mem.chart.zoom_back"),
        },
      },
      restore: {
        title: t("metric.mem.chart.reset_zoom"),
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
    type: "line" as const,
    smooth: true,
    showSymbol: false,
    lineStyle: {
      width: 2,
      type: props.dashedNames.includes(series.name)
        ? ("dashed" as const)
        : ("solid" as const),
    },
    emphasis: {
      focus: "series" as const,
    },
  })),
}));
</script>

<template>
  <VChart
    class="metric-line-chart"
    :style="{ height: props.height, minHeight: 0 }"
    :option="option"
    :update-options="updateOptions"
    autoresize
    @legendselectchanged="onLegendSelectChanged"
  />
</template>

<style scoped>
.metric-line-chart {
  width: 100%;
}
</style>
