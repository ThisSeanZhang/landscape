<script setup lang="ts">
import { useI18n } from "vue-i18n";
import { usePreferenceStore } from "@/stores/preference";

defineProps<{ failed: boolean; updatedAt?: number }>();
defineEmits<{ retry: [] }>();
const { t } = useI18n();
const preferences = usePreferenceStore();
</script>

<template>
  <n-flex v-if="failed" align="center" size="small">
    <n-text type="warning" role="status">{{
      t("common.sample_failed")
    }}</n-text>
    <n-button size="small" secondary @click="$emit('retry')">{{
      t("common.retry")
    }}</n-button>
    <n-text v-if="updatedAt !== undefined" depth="3">
      {{ t("common.updated_at") }}
      <n-time
        :time="updatedAt"
        format="HH:mm:ss"
        :time-zone="preferences.timezone"
      />
    </n-text>
  </n-flex>
  <n-text v-else-if="updatedAt === undefined" role="status" depth="3">{{
    t("common.sample_pending")
  }}</n-text>
</template>
