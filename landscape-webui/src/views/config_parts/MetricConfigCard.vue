<script setup lang="ts">
import { useMetricConfigStore } from "@/stores/metric_config";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";

const metricStore = useMetricConfigStore();
const message = useMessage();
const { t } = useI18n();

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
      <n-divider title-placement="left">
        {{ t("config.conn_retention_mins") }}
      </n-divider>
      <n-grid x-gap="12" :cols="2">
        <n-gi>
          <n-form-item :label="t('config.conn_retention_mins')">
            <n-input-number
              v-model:value="metricStore.connRetentionMins"
              :min="1"
              :max="1440"
              placeholder="5"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.conn_retention_mins_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.conn_retention_minute_days')">
            <n-input-number
              v-model:value="metricStore.connRetentionMinuteDays"
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
              v-model:value="metricStore.connRetentionHourDays"
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
              v-model:value="metricStore.connRetentionDayDays"
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
      <n-form-item :label="t('config.flush_interval')">
        <n-input-number
          v-model:value="metricStore.flushIntervalSecs"
          :min="1"
          :max="3600"
          placeholder="5"
          style="width: 200px"
        />
        <template #feedback> {{ t("config.flush_interval_desc") }} </template>
      </n-form-item>
      <n-form-item :label="t('config.batch_size')">
        <n-input-number
          v-model:value="metricStore.batchSize"
          :min="100"
          :max="10000"
          placeholder="2000"
          style="width: 200px"
        />
        <template #feedback> {{ t("config.batch_size_desc") }} </template>
      </n-form-item>
      <n-form-item :label="t('config.max_memory')">
        <n-input-number
          v-model:value="metricStore.maxMemory"
          :min="32"
          :max="4096"
          placeholder="128"
          style="width: 200px"
        />
        <template #feedback> {{ t("config.max_memory_desc") }} </template>
      </n-form-item>
      <n-form-item :label="t('config.max_threads')">
        <n-input-number
          v-model:value="metricStore.maxThreads"
          :min="1"
          :max="16"
          placeholder="4"
          style="width: 200px"
        />
        <template #feedback> {{ t("config.max_threads_desc") }} </template>
      </n-form-item>
    </n-form>
  </n-card>
</template>
