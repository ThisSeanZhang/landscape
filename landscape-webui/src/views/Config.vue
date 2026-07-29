<script setup lang="ts">
import { onMounted, ref } from "vue";
import { usePreferenceStore } from "@/stores/preference";
import { useMetricConfigStore } from "@/stores/metric_config";
import { useDnsConfigStore } from "@/stores/dns_config";
import { useLanHostnameConfigStore } from "@/stores/lan_hostname_config";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";

import UIConfigCard from "@/views/config_parts/UIConfigCard.vue";
import DNSConfigCard from "@/views/config_parts/DNSConfigCard.vue";
import LanHostnameConfigCard from "@/views/config_parts/LanHostnameConfigCard.vue";
import MetricConfigCard from "@/views/config_parts/MetricConfigCard.vue";
import BackupConfigCard from "@/views/config_parts/BackupConfigCard.vue";
import PasswordConfigCard from "@/views/config_parts/PasswordConfigCard.vue";

const { t } = useI18n();
const prefStore = usePreferenceStore();
const metricStore = useMetricConfigStore();
const dnsStore = useDnsConfigStore();
const lanHostnameStore = useLanHostnameConfigStore();
const message = useMessage();
const loading = ref(false);

const scrollTarget = () => document.querySelector(".main-body");

onMounted(async () => {
  loading.value = true;
  try {
    await Promise.all([
      prefStore.loadPreferenceForEdit(),
      metricStore.loadMetricConfig(),
      dnsStore.loadDnsConfig(),
      lanHostnameStore.loadLanHostnameConfig(),
    ]);
  } catch (e) {
    message.error(t("config.load_failed"));
    console.error(e);
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="config-container">
    <div class="main-content">
      <n-space vertical size="large">
        <UIConfigCard />
        <DNSConfigCard />
        <LanHostnameConfigCard />
        <MetricConfigCard />
        <PasswordConfigCard />
        <BackupConfigCard />
        <div style="height: 400px"></div>
      </n-space>
    </div>

    <!-- 侧边目录容器 -->
    <div class="side-nav hidden-mobile">
      <n-anchor
        affix
        :top="70"
        :offset-top="70"
        :bound="24"
        :ignore-gap="true"
        listen-to=".main-body"
        style="width: 200px"
      >
        <n-card
          :title="t('config.directory')"
          size="small"
          :segmented="{ content: true }"
          class="anchor-card"
        >
          <n-anchor-link :title="t('config.ui_title')" href="#ui-config" />
          <n-anchor-link :title="t('config.dns_title')" href="#dns-config" />
          <n-anchor-link
            :title="t('config.lan_hostname_title')"
            href="#lan-hostname-config"
          />
          <n-anchor-link
            :title="t('config.metric_title')"
            href="#metric-config"
          />
          <n-anchor-link
            :title="t('config.password_title')"
            href="#password-config"
          />
          <n-anchor-link
            :title="t('config.backup_title')"
            href="#backup-config"
          />
        </n-card>
      </n-anchor>
    </div>
  </div>
</template>

<style scoped>
.config-container {
  padding: 24px;
  width: 100%;
  display: flex;
  flex-direction: row;
  align-items: flex-start;
  gap: 48px;
}

.main-content {
  flex: 1;
  min-width: 0; /* 防止内容撑破 flex 容器 */
}

.side-nav {
  width: 200px;
  flex-shrink: 0;
}

.anchor-card {
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
  border-radius: 8px;
}

/* 响应式：在窄屏下隐藏目录，主内容自动占满 */
@media (max-width: 992px) {
  .hidden-mobile {
    display: none;
  }
  .config-container {
    gap: 0;
  }
}

:deep(.n-anchor-link) {
  font-size: 14px;
}
</style>
