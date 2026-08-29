import { defineStore } from "pinia";
import { ref } from "vue";
import type {
  LandscapeMetricConfig,
  MetricMode,
} from "@landscape-router/types/api/schemas";
import { get_metric_config_edit, update_metric_config } from "@/api/sys/config";

export const useMetricConfigStore = defineStore("metric_config", () => {
  const mode = ref<MetricMode>("persistent");
  const connectSecondWindowMinutes = ref<number | undefined>(undefined);
  const connect1mRetentionDays = ref<number | undefined>(undefined);
  const connect1hRetentionDays = ref<number | undefined>(undefined);
  const connect1dRetentionDays = ref<number | undefined>(undefined);
  const connectSummaryRetentionDays = ref<number | undefined>(undefined);
  const connectSummaryMaxRows = ref<number | undefined>(undefined);
  const connectDbMaxMb = ref<number | undefined>(undefined);
  const dnsRetentionDays = ref<number | undefined>(undefined);
  const dns1mRetentionDays = ref<number | undefined>(undefined);
  const dnsDbMaxMb = ref<number | undefined>(undefined);
  const writeBatchSize = ref<number | undefined>(undefined);
  const writeFlushIntervalSecs = ref<number | undefined>(undefined);
  const cleanupIntervalSecs = ref<number | undefined>(undefined);
  const cleanupTimeBudgetSecs = ref<number | undefined>(undefined);
  const cleanupSliceWindowSecs = ref<number | undefined>(undefined);
  const expectedHash = ref<string>("");

  async function loadMetricConfig() {
    const { metric, hash } = await get_metric_config_edit();
    mode.value =
      metric.mode === "duckdb" ? "persistent" : (metric.mode ?? "persistent");
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
    connectDbMaxMb.value = metric.connect_db_max_mb ?? undefined;
    dnsRetentionDays.value = metric.dns_retention_days ?? undefined;
    dns1mRetentionDays.value = metric.dns_1m_retention_days ?? undefined;
    dnsDbMaxMb.value = metric.dns_db_max_mb ?? undefined;
    writeBatchSize.value = metric.write_batch_size ?? undefined;
    writeFlushIntervalSecs.value =
      metric.write_flush_interval_secs ?? undefined;
    cleanupIntervalSecs.value = metric.cleanup_interval_secs ?? undefined;
    cleanupTimeBudgetSecs.value = metric.cleanup_time_budget_secs ?? undefined;
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
      connect_db_max_mb: connectDbMaxMb.value,
      dns_retention_days: dnsRetentionDays.value,
      dns_1m_retention_days: dns1mRetentionDays.value,
      dns_db_max_mb: dnsDbMaxMb.value,
      write_batch_size: writeBatchSize.value,
      write_flush_interval_secs: writeFlushIntervalSecs.value,
      cleanup_interval_secs: cleanupIntervalSecs.value,
      cleanup_time_budget_secs: cleanupTimeBudgetSecs.value,
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
    connectDbMaxMb,
    dnsRetentionDays,
    dns1mRetentionDays,
    dnsDbMaxMb,
    writeBatchSize,
    writeFlushIntervalSecs,
    cleanupIntervalSecs,
    cleanupTimeBudgetSecs,
    cleanupSliceWindowSecs,
    expectedHash,
    loadMetricConfig,
    saveMetricConfig,
  };
});
