<script setup lang="ts">
import { ref, onMounted } from "vue";
import { get_metric_config } from "@/api/sys/config";
import ConnectViewSwitcher from "@/components/metric/connect/ConnectViewSwitcher.vue";
import HistoryMetric from "./HistoryMetric.vue";
import HistoryIpMetric from "./HistoryIpMetric.vue";

defineProps<{ direction?: "src" | "dst" }>();
const state = ref<"loading" | "ready" | "disabled" | "memory" | "error">(
  "loading",
);
async function load() {
  state.value = "loading";
  try {
    const { connect } = await get_metric_config();
    state.value =
      connect.enabled === false
        ? "disabled"
        : connect.store.backend === "memory"
          ? "memory"
          : "ready";
  } catch {
    state.value = "error";
  }
}
onMounted(load);
</script>

<template>
  <template v-if="state === 'ready'">
    <HistoryIpMetric v-if="direction" :direction="direction" />
    <HistoryMetric v-else />
  </template>
  <n-flex v-else vertical style="flex: 1">
    <ConnectViewSwitcher />
    <n-spin v-if="state === 'loading'" />
    <n-empty v-else :description="$t('metric.connect.history_state.' + state)">
      <template #extra>
        <n-button v-if="state === 'error'" @click="load">{{
          $t("metric.connect.history_state.retry")
        }}</n-button>
        <RouterLink
          v-else
          :to="{ name: 'routes.config', hash: '#connect-metric-config' }"
        >
          {{ $t("metric.connect.history_state.settings") }}
        </RouterLink>
      </template>
    </n-empty>
  </n-flex>
</template>
