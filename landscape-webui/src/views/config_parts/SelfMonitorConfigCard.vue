<script setup lang="ts">
import { useMetricConfigStore } from "@/stores/metric_config";
import { useCapabilityStore } from "@/stores/capability";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
import { onMounted } from "vue";

const block = useMetricConfigStore().selfMonitor;
const capabilities = useCapabilityStore();
const { t } = useI18n();
const message = useMessage();
onMounted(async () => {
  try {
    await block.load();
  } catch {
    message.error(t("config.load_failed"));
  }
});
async function save() {
  try {
    await block.save();
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
  <n-card
    :title="t('config.self_monitor_title')"
    segmented
    id="self-monitor-config"
  >
    <template #header-extra
      ><n-button
        type="primary"
        :disabled="block.hash === null"
        :loading="block.saving"
        @click="save"
        >{{ t("config.save_ui") }}</n-button
      ></template
    >
    <n-form
      :model="block.config"
      :disabled="block.hash === null || block.saving"
      label-placement="left"
    >
      <n-form-item :label="t('config.self_monitor_sampling')"
        ><n-switch
          :value="block.config.enabled ?? true"
          @update:value="block.config.enabled = $event"
      /></n-form-item>
      <template v-if="capabilities.HAS('metric_persistent')">
        <n-form-item :label="t('config.self_monitor_history')"
          ><n-switch
            :value="block.config.history_enabled ?? true"
            @update:value="block.config.history_enabled = $event"
        /></n-form-item>
        <n-form-item :label="t('config.self_monitor_retention')"
          ><n-input-number
            :value="block.config.retention_days"
            :min="1"
            :precision="0"
            placeholder="30"
            @update:value="block.config.retention_days = $event ?? undefined"
        /></n-form-item>
      </template>
    </n-form>
  </n-card>
</template>
