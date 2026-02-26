<script setup lang="ts">
import { usePreferenceStore } from "@/stores/preference";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";

const prefStore = usePreferenceStore();
const message = useMessage();
const { t } = useI18n();

const languageOptions = [
  { label: "简体中文", value: "zh" },
  { label: "English", value: "en" },
];

const themeOptions = [
  { label: "深色模式", value: "dark" },
  { label: "浅色模式", value: "light" },
];

const timezoneOptions = (Intl as any)
  .supportedValuesOf("timeZone")
  .map((tz: string) => ({
    label: tz,
    value: tz,
  }));

async function handleSave() {
  try {
    await prefStore.savePreference();
    message.success(t("config.save_success"));
  } catch (e: any) {
    if (e.response?.status === 409) {
      message.error(t("config.conflict"));
    } else {
      message.error(t("config.save_failed") + ": " + e.message);
    }
  }
}
</script>

<template>
  <n-card :title="t('config.ui_title')" segmented id="ui-config">
    <template #header-extra>
      <n-button type="primary" @click="handleSave">
        {{ t("config.save_ui") }}
      </n-button>
    </template>

    <n-form label-placement="left" label-width="120">
      <n-form-item :label="t('config.language')">
        <n-select
          v-model:value="prefStore.language"
          :options="languageOptions"
          style="max-width: 300px"
        />
      </n-form-item>
      <n-form-item :label="t('config.theme')">
        <n-select
          v-model:value="prefStore.theme"
          :options="themeOptions"
          disabled
          :placeholder="t('config.theme_placeholder')"
          style="max-width: 300px"
        />
      </n-form-item>
      <n-form-item :label="t('config.timezone')">
        <n-select
          v-model:value="prefStore.timezone"
          filterable
          :options="timezoneOptions"
          :placeholder="t('config.timezone_placeholder')"
          style="max-width: 400px"
        />
      </n-form-item>
    </n-form>
  </n-card>
</template>
