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
  </n-flex>
</template>
