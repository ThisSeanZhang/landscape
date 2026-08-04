import { defineStore } from "pinia";
import { ref } from "vue";
import type { LandscapeMetricConfig } from "@landscape-router/types/api/schemas";
import { get_metric_config_edit, update_metric_config } from "@/api/sys/config";

type MetricMode = "off" | "memory" | "duckdb";

export const useMetricConfigStore = defineStore("metric_config", () => {
  const mode = ref<MetricMode>("duckdb");
  const connectSecondWindowMinutes = ref<number | undefined>(undefined);
  const connect1mRetentionDays = ref<number | undefined>(undefined);
  const connect1hRetentionDays = ref<number | undefined>(undefined);
  const connect1dRetentionDays = ref<number | undefined>(undefined);
  const connectSummaryRetentionDays = ref<number | undefined>(undefined);
  const connectSummaryMaxRows = ref<number | undefined>(undefined);
  const dnsRetentionDays = ref<number | undefined>(undefined);
  const writeBatchSize = ref<number | undefined>(undefined);
  const writeFlushIntervalSecs = ref<number | undefined>(undefined);
  const dbMaxMemoryMb = ref<number | undefined>(undefined);
  const dbMaxThreads = ref<number | undefined>(undefined);
  const cleanupIntervalSecs = ref<number | undefined>(undefined);
  const cleanupTimeBudgetMs = ref<number | undefined>(undefined);
  const cleanupSliceWindowSecs = ref<number | undefined>(undefined);
  const expectedHash = ref<string>("");

  async function loadMetricConfig() {
    const { metric, hash } = await get_metric_config_edit();
    mode.value = (metric.mode as MetricMode | undefined) ?? "duckdb";
    connectSecondWindowMinutes.value =
      metric.connect_second_window_minutes ?? undefined;
    connect1mRetentionDays.value =
      metric.connect_1m_retention_days ?? undefined;
    connect1hRetentionDays.value =
      metric.connect_1h_retention_days ?? undefined;
    connect1dRetentionDays.value =
      metric.connect_1d_retention_days ?? undefined;
    connectSummaryRetentionDays.value =
      metric.connect_summary_retention_days ?? undefined;
    connectSummaryMaxRows.value = metric.connect_summary_max_rows ?? undefined;
    dnsRetentionDays.value = metric.dns_retention_days ?? undefined;
    writeBatchSize.value = metric.write_batch_size ?? undefined;
    writeFlushIntervalSecs.value =
      metric.write_flush_interval_secs ?? undefined;
    dbMaxMemoryMb.value = metric.db_max_memory_mb ?? undefined;
    dbMaxThreads.value = metric.db_max_threads ?? undefined;
    cleanupIntervalSecs.value = metric.cleanup_interval_secs ?? undefined;
    cleanupTimeBudgetMs.value = metric.cleanup_time_budget_ms ?? undefined;
    cleanupSliceWindowSecs.value =
      metric.cleanup_slice_window_secs ?? undefined;
    expectedHash.value = hash;
  }

  async function saveMetricConfig() {
    const new_metric: LandscapeMetricConfig = {
      mode: mode.value,
      connect_second_window_minutes: connectSecondWindowMinutes.value,
      connect_1m_retention_days: connect1mRetentionDays.value,
      connect_1h_retention_days: connect1hRetentionDays.value,
      connect_1d_retention_days: connect1dRetentionDays.value,
      connect_summary_retention_days: connectSummaryRetentionDays.value,
      connect_summary_max_rows: connectSummaryMaxRows.value,
      dns_retention_days: dnsRetentionDays.value,
      write_batch_size: writeBatchSize.value,
      write_flush_interval_secs: writeFlushIntervalSecs.value,
      db_max_memory_mb: dbMaxMemoryMb.value,
      db_max_threads: dbMaxThreads.value,
      cleanup_interval_secs: cleanupIntervalSecs.value,
      cleanup_time_budget_ms: cleanupTimeBudgetMs.value,
      cleanup_slice_window_secs: cleanupSliceWindowSecs.value,
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
    mode,
    connectSecondWindowMinutes,
    connect1mRetentionDays,
    connect1hRetentionDays,
    connect1dRetentionDays,
    connectSummaryRetentionDays,
    connectSummaryMaxRows,
    dnsRetentionDays,
    writeBatchSize,
    writeFlushIntervalSecs,
    dbMaxMemoryMb,
    dbMaxThreads,
    cleanupIntervalSecs,
    cleanupTimeBudgetMs,
    cleanupSliceWindowSecs,
    expectedHash,
    loadMetricConfig,
    saveMetricConfig,
  };
});
