<script setup lang="ts">
import { useMetricConfigStore } from "@/stores/metric_config";
import { useMessage } from "naive-ui";
import { computed } from "vue";
import { useI18n } from "vue-i18n";

const metricStore = useMetricConfigStore();
const message = useMessage();
const { t } = useI18n();
const modeOptions = computed(() => [
  { label: t("config.metric_mode_off"), value: "off" },
  { label: t("config.metric_mode_memory"), value: "memory" },
  { label: t("config.metric_mode_persistent"), value: "persistent" },
  { label: t("config.metric_mode_duckdb"), value: "duckdb" },
]);

async function handleSaveMetric() {
  try {
    await metricStore.saveMetricConfig();
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
  <n-card :title="t('config.metric_title')" segmented id="metric-config">
    <template #header-extra>
      <n-button type="primary" @click="handleSaveMetric">
        {{ t("config.save_metric") }}
      </n-button>
    </template>
    <n-form label-placement="left" label-width="120">
      <n-form-item :label="t('config.metric_mode')">
        <n-select
          v-model:value="metricStore.mode"
          :options="modeOptions"
          style="width: 240px"
        />
        <template #feedback>
          {{ t("config.metric_mode_desc") }}
        </template>
      </n-form-item>

      <n-divider title-placement="left">
        {{ t("config.conn_retention_mins") }}
      </n-divider>
      <n-grid x-gap="12" :cols="2">
        <n-gi>
          <n-form-item :label="t('config.connect_second_window_mins')">
            <n-input-number
              v-model:value="metricStore.connectSecondWindowMinutes"
              :min="1"
              :max="60"
              placeholder="5"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.connect_second_window_mins_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.conn_retention_minute_days')">
            <n-input-number
              v-model:value="metricStore.connect1mRetentionDays"
              :min="1"
              :max="365"
              placeholder="1"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.conn_retention_minute_days_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.conn_retention_hour_days')">
            <n-input-number
              v-model:value="metricStore.connect1hRetentionDays"
              :min="1"
              :max="365"
              placeholder="7"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.conn_retention_hour_days_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.conn_retention_day_days')">
            <n-input-number
              v-model:value="metricStore.connect1dRetentionDays"
              :min="1"
              :max="3650"
              placeholder="30"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.conn_retention_day_days_desc") }}
            </template>
          </n-form-item>
        </n-gi>
      </n-grid>

      <n-divider title-placement="left">
        {{ t("config.dns_retention_days") }}
      </n-divider>
      <n-form-item :label="t('config.dns_retention_days')">
        <n-input-number
          v-model:value="metricStore.dnsRetentionDays"
          :min="1"
          :max="365"
          placeholder="7"
          style="width: 200px"
        />
        <template #feedback>
          {{ t("config.dns_retention_days_desc") }}
        </template>
      </n-form-item>

      <n-divider title-placement="left">
        {{ t("config.performance_settings") }}
      </n-divider>
      <n-grid x-gap="12" :cols="2">
        <n-gi>
          <n-form-item :label="t('config.write_flush_interval')">
            <n-input-number
              v-model:value="metricStore.writeFlushIntervalSecs"
              :min="1"
              :max="3600"
              placeholder="30"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.write_flush_interval_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.write_batch_size')">
            <n-input-number
              v-model:value="metricStore.writeBatchSize"
              :min="100"
              :max="50000"
              placeholder="20000"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.write_batch_size_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.db_max_memory')">
            <n-input-number
              v-model:value="metricStore.dbMaxMemoryMb"
              :min="32"
              :max="8192"
              placeholder="256"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.db_max_memory_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.db_max_threads')">
            <n-input-number
              v-model:value="metricStore.dbMaxThreads"
              :min="1"
              :max="64"
              placeholder="4"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.db_max_threads_desc") }}
            </template>
          </n-form-item>
        </n-gi>
      </n-grid>

      <n-divider title-placement="left">
        {{ t("config.maintenance_settings") }}
      </n-divider>
      <n-grid x-gap="12" :cols="2">
        <n-gi>
          <n-form-item :label="t('config.cleanup_interval')">
            <n-input-number
              v-model:value="metricStore.cleanupIntervalSecs"
              :min="60"
              :max="86400"
              placeholder="300"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.cleanup_interval_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.cleanup_budget')">
            <n-input-number
              v-model:value="metricStore.cleanupTimeBudgetMs"
              :min="100"
              :max="60000"
              placeholder="2000"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.cleanup_budget_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.cleanup_slice_window')">
            <n-input-number
              v-model:value="metricStore.cleanupSliceWindowSecs"
              :min="10"
              :max="3600"
              placeholder="300"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.cleanup_slice_window_desc") }}
            </template>
          </n-form-item>
        </n-gi>
      </n-grid>
    </n-form>
  </n-card>
</template>
