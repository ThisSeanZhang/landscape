<script setup lang="ts">
import { computed, ref } from "vue";
import SourceProgress from "@/components/SouceProgress.vue";

import { useSysInfo } from "@/stores/systeminfo";

let sysinfo = useSysInfo();

const percentage = computed(() => {
  // console.log(sysinfo.mem.used_mem / sysinfo.mem.total_mem);
  return (
    sysinfo.router_status.mem.used_mem / sysinfo.router_status.mem.total_mem
  );
});

const swap_percentage = computed(() => {
  // console.log(sysinfo.mem.used_mem / sysinfo.mem.total_mem);
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
          <n-flex>内存: {{ men.total_mem }} GB</n-flex>
          <n-flex>已用: {{ men.used_mem }} GB</n-flex>
        </n-flex>

        <n-flex justify="space-between">
          <n-flex>交换: {{ swap.total_swap }} GB</n-flex>
          <n-flex>已用: {{ swap.used_swap }} GB</n-flex>
        </n-flex>
      </n-flex>

      <n-flex justify="space-around" align="center">
        <SourceProgress :value="percentage"></SourceProgress>
        <SourceProgress :warn="false" :value="swap_percentage"></SourceProgress>
      </n-flex>
    </n-flex>
  </n-card>
</template>
