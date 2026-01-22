<script setup lang="ts">
import { get_sysinfo } from "@/api/sys";
import { SysInfo } from "@/lib/sys";
import { onMounted, ref, computed } from "vue";
import { useThemeVars } from "naive-ui";

const themeVars = useThemeVars();

const sysinfo = ref<SysInfo>({
  host_name: undefined,
  system_name: undefined,
  kernel_version: undefined,
  os_version: undefined,
  landscape_version: undefined,
  cpu_arch: undefined,
  start_at: 0,
});

const now = ref<number>(new Date().getTime());

setInterval(() => {
  now.value = new Date().getTime();
}, 1000);

onMounted(async () => {
  sysinfo.value = await get_sysinfo();
});

const ui_version = __APP_VERSION__;

const isVersionMismatch = computed(() => {
  if (!sysinfo.value.landscape_version || !ui_version) {
    return false;
  }
  return sysinfo.value.landscape_version !== ui_version;
});

// Calculate uptime in a readable format
const uptime = computed(() => {
  if (!sysinfo.value.start_at) return "";
  const seconds = Math.floor((now.value - sysinfo.value.start_at * 1000) / 1000);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  
  if (days > 0) {
    return `${days}d ${hours}h ${minutes}m`;
  } else if (hours > 0) {
    return `${hours}h ${minutes}m`;
  } else {
    return `${minutes}m`;
  }
});
</script>

<template>
  <n-card content-style="display: flex; flex-direction: column; height: 100%;">
    <!-- Header -->
    <template #header>
      <n-flex align="center" justify="space-between">
        <span>系统</span>
        <n-tag v-if="sysinfo.cpu_arch" size="small" :bordered="false">
          {{ sysinfo.cpu_arch }}
        </n-tag>
      </n-flex>
    </template>

    <!-- Main Info Grid -->
    <div class="info-grid">
      <!-- Hostname - Featured -->
      <div class="info-item featured">
        <n-text depth="3" class="info-label">主机名称</n-text>
        <n-text class="info-value large">
          {{ sysinfo.host_name || '--' }}
        </n-text>
      </div>

      <!-- OS Info -->
      <div class="info-item">
        <n-text depth="3" class="info-label">系统</n-text>
        <n-text class="info-value">
          {{ sysinfo.system_name || '--' }}
        </n-text>
      </div>

      <!-- Kernel -->
      <div class="info-item">
        <n-text depth="3" class="info-label">内核</n-text>
        <n-ellipsis class="info-value" :tooltip="{ width: 300 }">
          {{ sysinfo.kernel_version || '--' }}
        </n-ellipsis>
      </div>

      <!-- Uptime -->
      <div class="info-item">
        <n-text depth="3" class="info-label">运行时间</n-text>
        <n-flex align="center" :size="6">
          <n-text class="info-value uptime">{{ uptime || '--' }}</n-text>
          <n-tooltip trigger="hover" placement="top">
            <template #trigger>
              <n-icon size="14" style="opacity: 0.5; cursor: help;">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>
                </svg>
              </n-icon>
            </template>
            <n-flex vertical :size="2">
              <span>启动于:</span>
              <n-time :time="sysinfo.start_at" format="yyyy-MM-dd HH:mm:ss" unix />
            </n-flex>
          </n-tooltip>
        </n-flex>
      </div>
    </div>

    <n-divider style="margin: 12px 0" />

    <!-- Version Info -->
    <div class="version-section">
      <n-flex justify="space-between" align="center">
        <n-text depth="3" style="font-size: 12px;">Landscape Router</n-text>
        <n-tooltip v-if="isVersionMismatch" trigger="hover" placement="top">
          <template #trigger>
            <n-tag size="small" type="error" :bordered="false">
              {{ sysinfo.landscape_version }}
              <n-icon size="12" style="margin-left: 4px;">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>
                </svg>
              </n-icon>
            </n-tag>
          </template>
          <div>
            <div style="font-weight: 600; margin-bottom: 4px;">版本不匹配!</div>
            <div>后端: {{ sysinfo.landscape_version }}</div>
            <div>前端: {{ ui_version }}</div>
            <div style="margin-top: 8px; opacity: 0.8; font-size: 12px;">
              请检查前端静态文件或清理浏览器缓存
            </div>
          </div>
        </n-tooltip>
        <n-tag v-else size="small" type="success" :bordered="false">
          {{ sysinfo.landscape_version || '--' }}
        </n-tag>
      </n-flex>
    </div>
  </n-card>
</template>

<style scoped>
.info-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-item.featured {
  grid-column: 1 / -1;
}

.info-label {
  font-size: 12px;
  line-height: 1.2;
}

.info-value {
  font-size: 14px;
  font-weight: 500;
  line-height: 1.4;
  word-break: break-all;
}

.info-value.large {
  font-size: 18px;
  font-weight: 600;
}

.info-value.uptime {
  font-family: monospace;
  font-size: 14px;
}

.version-section {
  padding: 4px 0;
}
</style>
