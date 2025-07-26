<script setup lang="ts">
import { computed } from "vue";
import { ExhibitType } from "@/lib/sys";

import SourceProgress from "@/components/SouceProgress.vue";
import { useSysInfo } from "@/stores/systeminfo";
import { useI18n } from "vue-i18n";

const { t } = useI18n({ useScope: "global" });

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

// 计算网格列数，根据CPU数量动态调整
const gridCols = computed(() => {
  const cpuCount = sysinfo.router_status.cpus.length;
  if (cpuCount <= 4) return 1;
  if (cpuCount <= 8) return 2;
  if (cpuCount <= 16) return 3;
  if (cpuCount <= 32) return 4;
  // 对于超过32个CPU的核心，每行显示最多6个
  return Math.min(6, Math.ceil(cpuCount / Math.ceil(cpuCount / 6)));
});

// 判断是否使用滚动条显示（CPU数量较少时）
const useScrollbar = computed(() => {
  return sysinfo.router_status.cpus.length <= 4;
});
</script>
<template>
  <!-- {{ sysinfo.router_status.cpus[0] }} -->
  <n-card content-style="display: flex; max-height: 240px;">
    <template #header> CPU </template>
    <n-flex style="flex: 1" vertical justify="space-between">
      <n-flex vertical justify="space-between">
        <n-flex justify="space-between">
          <n-flex>{{ t("total_cpu_usage") }}</n-flex>
          <n-flex>
            {{ sysinfo.router_status.global_cpu_info.toFixed(1) }} %
          </n-flex>
        </n-flex>

        <n-flex justify="space-between">
          <n-flex>{{ t("average_load") }}</n-flex>
          <n-flex>
            {{ `${load_avg.one} / ${load_avg.five} / ${load_avg.fifteen}` }}
          </n-flex>
        </n-flex>
      </n-flex>

      <n-flex
        v-if="useScrollbar"
        style="overflow: hidden"
      >
        <n-scrollbar>
          <n-flex>
            <n-popover
              v-for="each_cpu of sysinfo.router_status.cpus"
              :key="each_cpu.name"
              trigger="hover"
            >
              <template #trigger>
                <SourceProgress
                  :exhibit_type="ExhibitType.Line"
                  :value="each_cpu.usage / 100"
                />
              </template>
              <span
                >{{ each_cpu.name }}: {{ each_cpu.brand }} @
                {{ each_cpu.frequency }}</span
              >
            </n-popover>
          </n-flex>
        </n-scrollbar>
      </n-flex>

      <!-- 使用网格布局显示多个CPU核心，根据CPU数量动态调整列数 -->
      <n-grid
        v-else
        :cols="gridCols"
        :x-gap="12"
        :y-gap="12"
      >
        <n-gi
          v-for="each_cpu of sysinfo.router_status.cpus"
          :key="each_cpu.name"
        >
          <n-popover trigger="hover">
            <template #trigger>
              <SourceProgress
                :exhibit_type="ExhibitType.Line"
                :value="each_cpu.usage / 100"
              />
            </template>
            <span
              >{{ each_cpu.name }}: {{ each_cpu.brand }} @
              {{ each_cpu.frequency }}</span
            >
          </n-popover>
        </n-gi>
      </n-grid>
    </n-flex>
    <!-- {{ sysinfo.cpus }} -->
  </n-card>
</template>
