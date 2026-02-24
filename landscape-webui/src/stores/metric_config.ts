import { defineStore } from "pinia";
import { ref } from "vue";
import type { LandscapeMetricConfig } from "@landscape-router/types/api/schemas";
import { get_metric_config_edit, update_metric_config } from "@/api/sys/config";

export const useMetricConfigStore = defineStore("metric_config", () => {
  const connRetentionMins = ref<number | undefined>(undefined);
  const connRetentionMinuteDays = ref<number | undefined>(undefined);
  const connRetentionHourDays = ref<number | undefined>(undefined);
  const connRetentionDayDays = ref<number | undefined>(undefined);
  const dnsRetentionDays = ref<number | undefined>(undefined);
  const batchSize = ref<number | undefined>(undefined);
  const flushIntervalSecs = ref<number | undefined>(undefined);
  const maxMemory = ref<number | undefined>(undefined);
  const maxThreads = ref<number | undefined>(undefined);
  const expectedHash = ref<string>("");

  async function loadMetricConfig() {
    const { metric, hash } = await get_metric_config_edit();
    connRetentionMins.value = metric.conn_retention_mins ?? undefined;
    connRetentionMinuteDays.value =
      metric.conn_retention_minute_days ?? undefined;
    connRetentionHourDays.value = metric.conn_retention_hour_days ?? undefined;
    connRetentionDayDays.value = metric.conn_retention_day_days ?? undefined;
    dnsRetentionDays.value = metric.dns_retention_days ?? undefined;
    batchSize.value = metric.batch_size ?? undefined;
    flushIntervalSecs.value = metric.flush_interval_secs ?? undefined;
    maxMemory.value = metric.max_memory ?? undefined;
    maxThreads.value = metric.max_threads ?? undefined;
    expectedHash.value = hash;
  }

  async function saveMetricConfig() {
    const new_metric: LandscapeMetricConfig = {
      conn_retention_mins: connRetentionMins.value,
      conn_retention_minute_days: connRetentionMinuteDays.value,
      conn_retention_hour_days: connRetentionHourDays.value,
      conn_retention_day_days: connRetentionDayDays.value,
      dns_retention_days: dnsRetentionDays.value,
      batch_size: batchSize.value,
      flush_interval_secs: flushIntervalSecs.value,
      max_memory: maxMemory.value,
      max_threads: maxThreads.value,
    };
    await update_metric_config({
      new_metric,
      expected_hash: expectedHash.value,
    });

    // Refresh hash after save
    const { hash } = await get_metric_config_edit();
    expectedHash.value = hash;
  }

  return {
    connRetentionMins,
    connRetentionMinuteDays,
    connRetentionHourDays,
    connRetentionDayDays,
    dnsRetentionDays,
    batchSize,
    flushIntervalSecs,
    maxMemory,
    maxThreads,
    expectedHash,
    loadMetricConfig,
    saveMetricConfig,
  };
});
