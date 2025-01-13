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
          <n-flex>swap: {{ swap.total_swap }} GB</n-flex>
          <n-flex>已用: {{ swap.used_swap }} GB</n-flex>
        </n-flex>
      </n-flex>

      <n-flex justify="center" align="center" style="flex: 1">
        <SourceProgress :value="percentage"></SourceProgress>
      </n-flex>
    </n-flex>
  </n-card>
</template>
