<script setup lang="ts">
import type { LandscapeSystemInfo } from "@landscape-router/types/api/schemas";
import { get_sysinfo } from "@/api/sys";

import { onMounted, onUnmounted, ref, computed } from "vue";
import { useThemeVars } from "naive-ui";
import { useI18n } from "vue-i18n";
import { InformationFilled, Router, WarningAltFilled } from "@vicons/carbon";

import { usePreferenceStore } from "@/stores/preference";
defineProps<{ compact?: boolean }>();
const { t } = useI18n({ useScope: "global" });
const themeVars = useThemeVars();
const prefStore = usePreferenceStore();

const sysinfo = ref<LandscapeSystemInfo>({
  host_name: undefined,
  system_name: undefined,
  kernel_version: undefined,
  os_version: undefined,
  landscape_version: "",
  cpu_arch: "",
  start_at: 0,
});

const now = ref<number>(new Date().getTime());

const uptimeTimer = setInterval(() => {
  now.value = new Date().getTime();
}, 1000);
onUnmounted(() => clearInterval(uptimeTimer));

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
  const seconds = Math.floor(
    (now.value - sysinfo.value.start_at * 1000) / 1000,
  );
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
  <div v-if="compact" class="host-summary">
    <span class="host-icon"><n-icon :component="Router" /></span>
    <div class="host-identity">
      <strong>{{ sysinfo.host_name || t("sysinfo.system") }}</strong>
      <small v-if="uptime">{{ t("sysinfo.uptime") }} · {{ uptime }}</small>
    </div>
    <slot name="details" />
  </div>
  <n-card
    v-else
    content-style="display: flex; flex-direction: column; height: 100%;"
  >
    <!-- Header -->
    <template #header>
      <n-flex align="center" justify="space-between">
        <span>{{ t("sysinfo.system") }}</span>
        <n-tag v-if="sysinfo.cpu_arch" size="small" :bordered="false">
          {{ sysinfo.cpu_arch }}
        </n-tag>
      </n-flex>
    </template>

    <!-- Main Info Section -->
    <n-flex vertical :size="12">
      <!-- Hostname - Featured -->
      <n-flex vertical :size="4">
        <n-text depth="3" class="info-label">{{
          t("sysinfo.hostname")
        }}</n-text>
        <n-text class="info-value large">
          {{ sysinfo.host_name || "--" }}
        </n-text>
      </n-flex>

      <!-- OS and Kernel Info Row -->
      <n-flex :size="12">
        <!-- OS Info -->
        <n-flex vertical :size="4" style="flex: 1; min-width: 0">
          <n-text depth="3" class="info-label">{{
            t("sysinfo.system")
          }}</n-text>
          <n-text class="info-value">
            {{ sysinfo.system_name || "--" }}
          </n-text>
        </n-flex>

        <!-- Kernel -->
        <n-flex vertical :size="4" style="flex: 1; min-width: 0">
          <n-text depth="3" class="info-label">{{
            t("sysinfo.kernel")
          }}</n-text>
          <n-ellipsis class="info-value" :tooltip="{ width: 300 }">
            {{ sysinfo.kernel_version || "--" }}
          </n-ellipsis>
        </n-flex>
      </n-flex>
    </n-flex>

    <n-divider style="margin: 12px 0" />

    <!-- Version and Runtime Info -->
    <n-flex vertical :size="8">
      <!-- Landscape Router Version -->
      <n-flex justify="space-between" align="center">
        <n-text depth="3" style="font-size: 12px">{{
          t("sysinfo.landscape_router")
        }}</n-text>
        <n-tooltip v-if="isVersionMismatch" trigger="hover" placement="top">
          <template #trigger>
            <n-tag size="small" type="error" :bordered="false">
              {{ sysinfo.landscape_version }}
              <n-icon size="12" style="margin-left: 4px">
                <WarningAltFilled></WarningAltFilled>
              </n-icon>
            </n-tag>
          </template>
          <div>
            <div style="font-weight: 600; margin-bottom: 4px">
              {{ t("sysinfo.version_mismatch") }}
            </div>
            <div>
              {{ t("sysinfo.backend") }}: {{ sysinfo.landscape_version }}
            </div>
            <div>{{ t("sysinfo.frontend") }}: {{ ui_version }}</div>
            <div style="margin-top: 8px; opacity: 0.8; font-size: 12px">
              {{ t("sysinfo.check_browser_cache") }}
            </div>
          </div>
        </n-tooltip>
        <n-tag v-else size="small" type="success" :bordered="false">
          {{ sysinfo.landscape_version || "--" }}
        </n-tag>
      </n-flex>

      <!-- Uptime -->
      <n-flex justify="space-between" align="center">
        <n-text depth="3" style="font-size: 12px">{{
          t("sysinfo.uptime")
        }}</n-text>
        <n-flex align="center" :size="6">
          <n-text class="info-value uptime">{{ uptime || "--" }}</n-text>
          <n-tooltip trigger="hover" placement="top">
            <template #trigger>
              <n-icon size="14" style="opacity: 0.5; cursor: help">
                <InformationFilled></InformationFilled>
              </n-icon>
            </template>
            <n-flex vertical :size="2">
              <span>{{ t("sysinfo.started_at") }}:</span>
              <n-time
                :time="sysinfo.start_at"
                format="yyyy-MM-dd HH:mm:ss"
                unix
                :time-zone="prefStore.timezone"
              />
            </n-flex>
          </n-tooltip>
        </n-flex>
      </n-flex>
    </n-flex>
  </n-card>
</template>

<style scoped>
.host-summary {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 14px;
  border-bottom: 1px solid v-bind("themeVars.dividerColor");
}
.host-icon {
  display: grid;
  place-items: center;
  flex-shrink: 0;
  width: 42px;
  height: 42px;
  border-radius: 11px;
  color: v-bind("themeVars.primaryColor");
  background: color-mix(in srgb, currentColor 12%, transparent);
  font-size: 25px;
}
.host-identity {
  display: grid;
  gap: 1px;
  flex: 1;
  min-width: 0;
}
.host-identity strong {
  font-size: 20px;
  line-height: 1.3;
  overflow-wrap: anywhere;
}
.host-identity small {
  font-size: 12px;
  color: v-bind("themeVars.textColor2");
}

@media (max-width: 380px) {
  .host-summary {
    gap: 8px;
    padding: 12px 10px;
  }
  .host-icon {
    width: 34px;
    height: 34px;
    font-size: 21px;
  }
  .host-identity strong {
    font-size: 18px;
  }
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
  font-family: var(--font-mono);
  font-size: 14px;
}
</style>
