<script setup lang="ts">
import { useI18n } from "vue-i18n";
import { computed } from "vue";
import { useThemeVars } from "naive-ui";
import { useSysInfo } from "@/stores/systeminfo";

const sysinfo = useSysInfo();
const { t } = useI18n({ useScope: "global" });
const themeVars = useThemeVars();

// Format bytes to GB with 2 decimal places
const formatGB = (bytes: number) => (bytes / 1024 / 1024 / 1024).toFixed(2);

// Memory data
const memData = computed(() => {
  const mem = sysinfo.router_status.mem;
  return {
    total: formatGB(mem.total_mem),
    used: formatGB(mem.used_mem),
    percentage: mem.total_mem > 0 ? (mem.used_mem / mem.total_mem) * 100 : 0,
  };
});

// Swap data
const swapData = computed(() => {
  const mem = sysinfo.router_status.mem;
  return {
    total: formatGB(mem.total_swap),
    used: formatGB(mem.used_swap),
    percentage: mem.total_swap > 0 ? (mem.used_swap / mem.total_swap) * 100 : 0,
    enabled: mem.total_swap > 0,
  };
});

// Get color based on usage percentage
const getUsageColor = (percentage: number) => {
  if (percentage >= 90) return themeVars.value.errorColor;
  if (percentage >= 70) return themeVars.value.warningColor;
  return themeVars.value.successColor;
};
</script>

<template>
  <n-card content-style="display: flex; flex-direction: column; height: 100%;">
    <!-- Header -->
    <template #header>
      <n-flex align="center" justify="space-between">
        <span>{{ t("mem") }}</span>
        <n-tag size="small" :bordered="false">
          {{ memData.total }} GB
        </n-tag>
      </n-flex>
    </template>

    <!-- Memory Section -->
    <div class="mem-section">
      <n-flex justify="space-between" align="center" style="margin-bottom: 8px;">
        <n-text depth="3" style="font-size: 13px;">{{ t("memory_usage") }}</n-text>
        <n-text :style="{ color: getUsageColor(memData.percentage), fontWeight: 600 }">
          {{ memData.percentage.toFixed(1) }}%
        </n-text>
      </n-flex>
      
      <!-- Memory Bar -->
      <div class="usage-bar-container">
        <div
          class="usage-bar-fill"
          :style="{
            width: `${memData.percentage}%`,
            backgroundColor: getUsageColor(memData.percentage),
          }"
        ></div>
      </div>
      
      <n-flex justify="space-between" style="margin-top: 6px;">
        <n-text depth="3" style="font-size: 12px;">
          {{ t("used") }}: {{ memData.used }} GB
        </n-text>
        <n-text depth="3" style="font-size: 12px;">
          {{ t("total") }}: {{ memData.total }} GB
        </n-text>
      </n-flex>
    </div>

    <n-divider style="margin: 16px 0" />

    <!-- Swap Section -->
    <div class="mem-section">
      <n-flex justify="space-between" align="center" style="margin-bottom: 8px;">
        <n-flex align="center" :size="8">
          <n-text depth="3" style="font-size: 13px;">{{ t("swap_usage") }}</n-text>
          <n-tag v-if="!swapData.enabled" size="tiny" :bordered="false" type="default">
            Disabled
          </n-tag>
        </n-flex>
        <n-text 
          v-if="swapData.enabled"
          :style="{ color: getUsageColor(swapData.percentage), fontWeight: 600 }"
        >
          {{ swapData.percentage.toFixed(1) }}%
        </n-text>
        <n-text v-else depth="3">--</n-text>
      </n-flex>
      
      <!-- Swap Bar -->
      <div class="usage-bar-container" :class="{ disabled: !swapData.enabled }">
        <div
          v-if="swapData.enabled"
          class="usage-bar-fill"
          :style="{
            width: `${swapData.percentage}%`,
            backgroundColor: getUsageColor(swapData.percentage),
          }"
        ></div>
      </div>
      
      <n-flex justify="space-between" style="margin-top: 6px;">
        <n-text depth="3" style="font-size: 12px;">
          {{ t("used") }}: {{ swapData.enabled ? swapData.used + ' GB' : '--' }}
        </n-text>
        <n-text depth="3" style="font-size: 12px;">
          {{ t("total") }}: {{ swapData.enabled ? swapData.total + ' GB' : '--' }}
        </n-text>
      </n-flex>
    </div>
  </n-card>
</template>

<style scoped>
.mem-section {
  padding: 4px 0;
}

.usage-bar-container {
  height: 12px;
  background-color: rgba(128, 128, 128, 0.1);
  border-radius: 6px;
  overflow: hidden;
  position: relative;
}

.usage-bar-container.disabled {
  opacity: 0.5;
}

.usage-bar-fill {
  height: 100%;
  border-radius: 6px;
  transition: width 0.3s ease, background-color 0.3s ease;
  min-width: 4px;
}

/* Dark mode support */
:global(.n-config-provider--dark) .usage-bar-container {
  background-color: rgba(255, 255, 255, 0.08);
}
</style>
