<script setup lang="ts">
import { computed } from "vue";
import { useRoute, useRouter } from "vue-router";

const route = useRoute();
const router = useRouter();

const viewMode = computed({
  get: () => {
    const lastPart = route.path.split("/").pop();
    return lastPart || "live";
  },
  set: (val) => {
    router.push({ path: `/metrics/conn/${val}`, query: { ...route.query } });
  },
});
</script>

<template>
  <n-flex align="center" :wrap="false">
    <n-tabs
      v-model:value="viewMode"
      type="segment"
      size="small"
      style="min-width: 700px"
    >
      <n-tab name="live">{{ $t("metric.connect.switcher.live") }}</n-tab>
      <n-tab name="iface">{{ $t("metric.connect.switcher.iface") }}</n-tab>
      <n-tab name="src">{{ $t("metric.connect.switcher.src") }}</n-tab>
      <n-tab name="dst">{{ $t("metric.connect.switcher.dst") }}</n-tab>
      <n-tab name="history">{{ $t("metric.connect.switcher.history") }}</n-tab>
      <n-tab name="history-src">{{
        $t("metric.connect.switcher.history_src")
      }}</n-tab>
      <n-tab name="history-dst">{{
        $t("metric.connect.switcher.history_dst")
      }}</n-tab>
    </n-tabs>

    <n-tag
      v-if="['live', 'iface', 'src', 'dst'].includes(viewMode)"
      :bordered="false"
      type="info"
      size="small"
      round
    >
      <template #icon>
        <div class="pulse-dot"></div>
      </template>
      {{ $t("metric.connect.stats.five_sec_sample") }}
    </n-tag>
  </n-flex>
</template>

<style scoped>
.pulse-dot {
  width: 8px;
  height: 8px;
  background-color: #00d2ff;
  border-radius: 50%;
  box-shadow: 0 0 0 0 rgba(0, 210, 255, 0.7);
  animation: pulse 1.5s infinite;
  margin-right: 4px;
}

@keyframes pulse {
  0% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(0, 210, 255, 0.7);
  }
  70% {
    transform: scale(1);
    box-shadow: 0 0 0 6px rgba(0, 210, 255, 0);
  }
  100% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(0, 210, 255, 0);
  }
}
</style>
