<script setup lang="ts">
import { ConnectKey } from "@/rust_bindings/common/metric/connect";
import { ref } from "vue";

interface Props {
  connect_metrics: ConnectKey[];
}

const props = defineProps<Props>();

const show_chart = ref(false);

const show_chart_key = ref<ConnectKey | null>(null);
async function show_chart_drawer(key: ConnectKey) {
  show_chart_key.value = key;
  show_chart.value = true;
}
</script>

<template>
  <div>
    <n-grid x-gap="12" y-gap="12" cols="2 400:2 600:5">
      <n-grid-item v-for="conn of connect_metrics" :key="JSON.stringify(conn)">
        <ConnectCardInfo @show:key="show_chart_drawer" :conn="conn" />
      </n-grid-item>
    </n-grid>

    <ConnectChartDrawer
      v-model:show="show_chart"
      :conn="show_chart_key"
    ></ConnectChartDrawer>
  </div>
</template>
