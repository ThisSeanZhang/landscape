<script setup lang="ts">
import { useMetricStore } from "@/stores/status_metric";
import { useFrontEndStore } from "@/stores/front_end_config";
import { ConnectKey } from "landscape-types/common/metric/connect";
import { computed, watch } from "vue";
import LiveConnectChart from "./live/LiveConnectChart.vue";
import HistoryConnectChart from "./history/HistoryConnectChart.vue";

const metricStore = useMetricStore();
const frontEndStore = useFrontEndStore();

interface Props {
  conn: ConnectKey | null;
  title?: string;
  type?: "live" | "history";
  createTimeMs?: number;
  lastReportTime?: number;
}

const props = withDefaults(defineProps<Props>(), {
  title: "",
  type: "live",
});

const show = defineModel("show");

const title = computed(() => {
  return frontEndStore.MASK_INFO(props.title);
});

// 当抽屉打开时，如果是实时模式，关闭全局指标轮询以减少压力（可选）
watch(show, (val) => {
  if (props.type === "live") {
    metricStore.SET_ENABLE("live", !val);
  }
});
</script>

<template>
  <n-drawer v-model:show="show" width="80%" placement="right">
    <n-drawer-content closable :title="title">
      <template v-if="conn">
        <LiveConnectChart
          v-if="type === 'live'"
          :conn="conn"
          :create-time-ms="createTimeMs"
          :last-report-time="lastReportTime"
        />
        <HistoryConnectChart
          v-else-if="type === 'history'"
          :conn="conn"
          :create-time-ms="createTimeMs"
          :last-report-time="lastReportTime"
        />
      </template>
    </n-drawer-content>
  </n-drawer>
</template>
