<script setup lang="ts">
import { computed, ref } from "vue";
import { ExhibitType } from "@/lib/sys";

import SourceProgress from "@/components/SouceProgress.vue";
import { useSysInfo } from "@/stores/systeminfo";

let sysinfo = useSysInfo();

const brand = computed(() => {
  let cpu = sysinfo.router_status.cpus[0];
  if (cpu) {
    return `${cpu.brand} @ ${(cpu.frequency / 1000).toFixed(2)} `;
  }
  return "N/A";
});

const load_avg = computed(() => {
  return sysinfo.router_status.load_avg;
});
</script>
<template>
  <!-- {{ sysinfo.router_status.cpus[0] }} -->
  <n-card content-style="display: flex; max-height: 240px;">
    <template #header> CPU </template>
    <n-flex style="flex: 1" vertical justify="space-between">
      <n-flex vertical justify="space-between">
        <n-flex justify="space-between">
          <n-flex>总 CPU 使用率:</n-flex>
          <n-flex>
            {{ sysinfo.router_status.global_cpu_info.toFixed(1) }} %
          </n-flex>
        </n-flex>

        <n-flex justify="space-between">
          <n-flex>平均负载:</n-flex>
          <n-flex>
            {{ `${load_avg.one} / ${load_avg.five} / ${load_avg.fifteen}` }}
          </n-flex>
        </n-flex>
      </n-flex>

      <n-flex style="flex: 1; overflow: hidden">
        <n-scrollbar>
          <n-popover
            :index="each_cpu.name"
            v-for="each_cpu of sysinfo.router_status.cpus"
            trigger="hover"
          >
            <template #trigger>
              <SourceProgress
                :exhibit_type="ExhibitType.Line"
                :value="each_cpu.usage / 100"
              >
              </SourceProgress>
            </template>
            <span
              >{{ each_cpu.name }}: {{ each_cpu.brand }} @
              {{ each_cpu.frequency }}</span
            >
          </n-popover>
        </n-scrollbar>
      </n-flex>
    </n-flex>
    <!-- {{ sysinfo.cpus }} -->
  </n-card>
</template>
