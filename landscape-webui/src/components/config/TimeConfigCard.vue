<script setup lang="ts">
import { computed } from "vue";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
import { useTimeConfigStore } from "@/stores/time_config";

const store = useTimeConfigStore();
const message = useMessage();
const { t } = useI18n();
const options = computed(() => [
  { label: t("config.default_disabled"), value: "default" },
  { label: t("config.option_enabled"), value: "enabled" },
  { label: t("config.option_disabled"), value: "disabled" },
]);
async function save() {
  try {
    await store.saveTimeConfig();
    message.success(t("config.save_success"));
  } catch (e: any) {
    message.error(
      e.response?.status === 409
        ? t("config.conflict")
        : t("config.save_failed") + ": " + e.message,
    );
  }
}
</script>

<template>
  <n-card :title="t('config.time_title')" segmented id="time-config">
    <template #header-extra>
      <n-button
        type="primary"
        :disabled="!store.loaded || store.saving"
        :loading="store.saving"
        @click="save"
      >
        {{ t("config.save_time") }}
      </n-button>
    </template>
    <n-form
      label-placement="left"
      label-width="160"
      :disabled="!store.loaded || store.saving"
    >
      <n-form-item :label="t('config.time_enabled')">
        <n-select v-model:value="store.enabled" :options="options" />
      </n-form-item>
      <n-form-item :label="t('config.time_servers')">
        <n-input
          v-model:value="store.servers"
          type="textarea"
          placeholder="ntp.aliyun.com:123&#10;time.cloudflare.com:123&#10;pool.ntp.org:123"
        />
        <template #feedback>{{ t("config.time_servers_desc") }}</template>
      </n-form-item>
      <n-form-item :label="t('config.time_interval')">
        <n-input-number
          v-model:value="store.syncIntervalSecs"
          :min="0"
          :max="Number.MAX_SAFE_INTEGER"
          :precision="0"
          placeholder="3600"
        />
        <template #feedback>{{ t("config.empty_uses_default") }}</template>
      </n-form-item>
      <n-form-item :label="t('config.time_timeout')">
        <n-input-number
          v-model:value="store.timeoutSecs"
          :min="0"
          :max="Number.MAX_SAFE_INTEGER"
          :precision="0"
          placeholder="3"
        />
        <template #feedback>{{ t("config.empty_uses_default") }}</template>
      </n-form-item>
      <n-form-item :label="t('config.time_threshold')">
        <n-input-number
          v-model:value="store.stepThresholdMs"
          :min="0"
          :max="Number.MAX_SAFE_INTEGER"
          :precision="0"
          placeholder="500"
        />
        <template #feedback>{{ t("config.empty_uses_default") }}</template>
      </n-form-item>
      <n-form-item :label="t('config.time_samples')">
        <n-input-number
          v-model:value="store.samplesPerServer"
          :min="1"
          :max="255"
          :precision="0"
          placeholder="3"
        />
        <template #feedback>{{ t("config.empty_uses_default") }}</template>
      </n-form-item>
    </n-form>
  </n-card>
</template>
