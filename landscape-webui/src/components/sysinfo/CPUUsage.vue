<script setup lang="ts">
import { computed } from "vue";
import { useThemeVars } from "naive-ui";
import { useSysInfo } from "@/stores/systeminfo";
import { useI18n } from "vue-i18n";

const { t } = useI18n({ useScope: "global" });
const themeVars = useThemeVars();
const sysinfo = useSysInfo();

const cpus = computed(() => sysinfo.router_status.cpus);

const cpuCount = computed(() => cpus.value.length);

const cpuModel = computed(() => {
  const cpu = cpus.value[0];
  return cpu ? cpu.brand : "";
});

const load_avg = computed(() => sysinfo.router_status.load_avg);

const globalUsage = computed(() => sysinfo.router_status.global_cpu_info);

// Helper to get color based on usage percentage (0-100)
const getUsageColor = (usage: number) => {
  if (usage >= 80) return themeVars.value.errorColor;
  if (usage >= 50) return themeVars.value.warningColor;
  return themeVars.value.successColor;
};

// Dynamic sizing based on CPU count
const layoutMode = computed(() => {
  const count = cpuCount.value;
  if (count <= 4) return "large"; // Show labels, big bars
  if (count <= 8) return "medium"; // Medium bars, no labels
  if (count <= 16) return "small"; // Small bars
  return "compact"; // Tiny heatmap cells for 16+
});

// Box dimensions (numbers for grid calculation)
const boxDimensions = computed(() => {
  switch (layoutMode.value) {
    case "large":
      return { width: 56, height: 72, gap: 12 };
    case "medium":
      return { width: 40, height: 56, gap: 8 };
    case "small":
      return { width: 28, height: 40, gap: 6 };
    case "compact":
    default:
      return { width: 20, height: 28, gap: 4 };
  }
});

// Grid CSS styles - auto-fill columns that align properly
const gridStyle = computed(() => {
  const { width, gap } = boxDimensions.value;
  return {
    display: "grid",
    gridTemplateColumns: `repeat(auto-fill, ${width}px)`,
    gap: `${gap}px`,
    justifyContent: "center", // Center the grid items
  };
});

// Format CPU index for display
const getCpuIndex = (name: string, index: number) => {
  // Try to extract number from name like "CPU 0", "cpu1", etc.
  const match = name.match(/\d+/);
  return match ? match[0] : String(index);
};
</script>

<template>
  <n-card content-style="display: flex; flex-direction: column; height: 100%;">
    <!-- Header -->
    <template #header>
      <n-flex align="center" justify="space-between">
        <span>CPU</span>
        <n-tag size="small" :bordered="false">
          {{ cpuCount }} Cores
        </n-tag>
      </n-flex>
    </template>

    <!-- CPU Model -->
    <n-text v-if="cpuModel" depth="3" style="font-size: 12px; margin-bottom: 12px; display: block;">
      <n-ellipsis :tooltip="{ width: 300 }">{{ cpuModel }}</n-ellipsis>
    </n-text>

    <!-- Global Stats -->
    <n-grid :cols="2" :x-gap="12" style="margin-bottom: 12px;">
      <n-gi>
        <n-statistic :label="t('total_cpu_usage')">
          <template #default>
            <n-text :style="{ color: getUsageColor(globalUsage) }">
              {{ globalUsage.toFixed(1) }}%
            </n-text>
          </template>
        </n-statistic>
      </n-gi>
      <n-gi>
        <n-statistic :label="t('average_load')">
          <template #default>
            <span style="font-size: 0.85em">
              {{ load_avg.one }} / {{ load_avg.five }} / {{ load_avg.fifteen }}
            </span>
          </template>
        </n-statistic>
      </n-gi>
    </n-grid>

    <n-divider style="margin: 0 0 12px 0" />

    <!-- CPU Cores Visualization -->
    <div class="cpu-cores-wrapper">
      <n-scrollbar style="max-height: 100%;">
        <!-- Extra padding wrapper to prevent hover clipping -->
        <div class="cpu-cores-inner">
          <div :style="gridStyle">
            <n-tooltip
              v-for="(cpu, index) in cpus"
              :key="cpu.name"
              trigger="hover"
              placement="top"
            >
              <template #trigger>
                <div
                  class="cpu-core-box"
                  :class="[`mode-${layoutMode}`]"
                  :style="{
                    width: `${boxDimensions.width}px`,
                    height: `${boxDimensions.height}px`,
                  }"
                >
                  <!-- Fill bar -->
                  <div
                    class="cpu-core-fill"
                    :style="{
                      height: `${cpu.usage}%`,
                      backgroundColor: getUsageColor(cpu.usage),
                    }"
                  ></div>
                  <!-- Label overlay (only for large/medium modes) -->
                  <div v-if="layoutMode === 'large' || layoutMode === 'medium'" class="cpu-core-label">
                    <span class="cpu-index">{{ getCpuIndex(cpu.name, index) }}</span>
                    <span v-if="layoutMode === 'large'" class="cpu-usage">{{ Math.round(cpu.usage) }}%</span>
                  </div>
                </div>
              </template>
              <!-- Tooltip Content -->
              <div style="text-align: center;">
                <div style="font-weight: 600; margin-bottom: 4px;">{{ cpu.name }}</div>
                <div style="font-size: 1.1em;">{{ cpu.usage.toFixed(1) }}%</div>
                <div style="font-size: 0.85em; opacity: 0.7; margin-top: 2px;">
                  {{ cpu.frequency }} MHz
                </div>
              </div>
            </n-tooltip>
          </div>
        </div>
      </n-scrollbar>
    </div>
  </n-card>
</template>

<style scoped>
.cpu-cores-wrapper {
  flex: 1;
  min-height: 80px;
  max-height: 220px;
  overflow: hidden;
}

.cpu-cores-inner {
  /* Padding to prevent hover effects from being clipped */
  padding: 4px 4px 8px 4px;
}

.cpu-core-box {
  background-color: rgba(128, 128, 128, 0.08);
  border: 1px solid rgba(128, 128, 128, 0.15);
  border-radius: 4px;
  position: relative;
  display: flex;
  align-items: flex-end;
  overflow: hidden;
  cursor: pointer;
  transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
}

.cpu-core-box:hover {
  transform: translateY(-3px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  border-color: rgba(128, 128, 128, 0.3);
  z-index: 10;
}

.cpu-core-fill {
  width: 100%;
  transition: height 0.3s ease, background-color 0.3s ease;
  min-height: 2px;
  border-radius: 0 0 3px 3px;
}

.cpu-core-label {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  pointer-events: none;
  z-index: 1;
}

.cpu-index {
  font-weight: 600;
  opacity: 0.7;
  font-size: inherit;
  line-height: 1.2;
  text-shadow: 0 1px 2px rgba(255, 255, 255, 0.8);
}

.cpu-usage {
  font-size: 0.85em;
  opacity: 0.6;
  line-height: 1.2;
  text-shadow: 0 1px 2px rgba(255, 255, 255, 0.8);
}

/* Mode-specific adjustments */
.mode-large {
  border-radius: 6px;
}

.mode-large .cpu-core-fill {
  border-radius: 0 0 5px 5px;
}

.mode-large .cpu-index {
  font-size: 13px;
}

.mode-medium .cpu-index {
  font-size: 11px;
}

.mode-small {
  border-radius: 3px;
}

.mode-small .cpu-core-fill {
  border-radius: 0 0 2px 2px;
}

.mode-compact {
  border-radius: 2px;
}

.mode-compact .cpu-core-fill {
  border-radius: 0 0 1px 1px;
}

/* Dark mode support */
:global(.n-config-provider--dark) .cpu-core-box {
  background-color: rgba(255, 255, 255, 0.04);
  border-color: rgba(255, 255, 255, 0.1);
}

:global(.n-config-provider--dark) .cpu-core-box:hover {
  border-color: rgba(255, 255, 255, 0.2);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

:global(.n-config-provider--dark) .cpu-index,
:global(.n-config-provider--dark) .cpu-usage {
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
}
</style>
