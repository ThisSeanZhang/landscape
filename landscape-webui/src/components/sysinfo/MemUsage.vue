<script setup lang="ts">
import { useI18n } from "vue-i18n";
import { computed } from "vue";
import SourceProgress from "@/components/SouceProgress.vue";

import { useSysInfo } from "@/stores/systeminfo";

let sysinfo = useSysInfo();
const { t } = useI18n({ useScope: "global" });

const percentage = computed(() => {
  // console.log(sysinfo.mem.used_mem / sysinfo.mem.total_mem);
  return (
    sysinfo.router_status.mem.used_mem / sysinfo.router_status.mem.total_mem
  );
});

const swap_percentage = computed(() => {
  // console.log(sysinfo.mem.used_mem / sysinfo.mem.total_mem);
  if (sysinfo.router_status.mem.total_swap === 0) {
    return 0;
  }
  return (
    sysinfo.router_status.mem.used_swap / sysinfo.router_status.mem.total_swap
  );
});

const men = computed(() => {
  return {
    total_mem: (
      sysinfo.router_status.mem.total_mem /
      1024 /
      1024 /
      1024
    ).toFixed(2),
    used_mem: (sysinfo.router_status.mem.used_mem / 1024 / 1024 / 1024).toFixed(
      2
    ),
  };
});

const swap = computed(() => {
  return {
    total_swap: (
      sysinfo.router_status.mem.total_swap /
      1024 /
      1024 /
      1024
    ).toFixed(2),
    used_swap: (
      sysinfo.router_status.mem.used_swap /
      1024 /
      1024 /
      1024
    ).toFixed(2),
  };
});
</script>
<template>
  <n-card title="内存" content-style="display: flex">
    <!-- {{ sysinfo.router_status.mem }} -->
    <n-flex style="flex: 1" vertical justify="space-between">
      <n-flex vertical justify="space-between">
        <n-flex justify="space-between">
          <n-flex>{{ t("mem") }}: {{ men.total_mem }} GB</n-flex>
          <n-flex>{{ t("used") }}: {{ men.used_mem }} GB</n-flex>
        </n-flex>

        <n-flex justify="space-between">
          <n-flex>{{ t("swap") }}: {{ swap.total_swap }} GB</n-flex>
          <n-flex>{{ t("used") }}: {{ swap.used_swap }} GB</n-flex>
        </n-flex>
      </n-flex>

      <n-flex justify="space-around" align="center">
        <SourceProgress
          :label="t('memory_usage')"
          :value="percentage"
        ></SourceProgress>
        <SourceProgress
          :label="t('swap_usage')"
          :warn="false"
          :value="swap_percentage"
        ></SourceProgress>
      </n-flex>
    </n-flex>
  </n-card>
</template>
