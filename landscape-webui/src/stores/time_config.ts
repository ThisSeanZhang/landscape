import { defineStore } from "pinia";
import { ref } from "vue";
import type { LandscapeTimeConfig } from "@landscape-router/types/api/schemas";
import { get_time_config_edit, update_time_config } from "@/api/sys/config";

export const useTimeConfigStore = defineStore("time_config", () => {
  const enabled = ref<"default" | "enabled" | "disabled">("default");
  const servers = ref("");
  const syncIntervalSecs = ref<number | null>(null);
  const timeoutSecs = ref<number | null>(null);
  const stepThresholdMs = ref<number | null>(null);
  const samplesPerServer = ref<number | null>(null);
  const expectedHash = ref("");
  const loaded = ref(false);
  const saving = ref(false);

  async function loadTimeConfig() {
    loaded.value = false;
    const { time, hash } = await get_time_config_edit();
    enabled.value =
      time.enabled === undefined
        ? "default"
        : time.enabled
          ? "enabled"
          : "disabled";
    servers.value = time.servers?.join("\n") ?? "";
    syncIntervalSecs.value = time.sync_interval_secs ?? null;
    timeoutSecs.value = time.timeout_secs ?? null;
    stepThresholdMs.value = time.step_threshold_ms ?? null;
    samplesPerServer.value = time.samples_per_server ?? null;
    expectedHash.value = hash;
    loaded.value = true;
  }

  async function saveTimeConfig() {
    if (!loaded.value || saving.value) return;
    saving.value = true;
    try {
      const serverList = servers.value
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      const new_time: LandscapeTimeConfig = {
        enabled:
          enabled.value === "default" ? undefined : enabled.value === "enabled",
        servers: serverList.length ? serverList : undefined,
        sync_interval_secs: syncIntervalSecs.value ?? undefined,
        timeout_secs: timeoutSecs.value ?? undefined,
        step_threshold_ms: stepThresholdMs.value ?? undefined,
        samples_per_server: samplesPerServer.value ?? undefined,
      };
      await update_time_config({ new_time, expected_hash: expectedHash.value });
      await loadTimeConfig();
    } finally {
      saving.value = false;
    }
  }

  return {
    enabled,
    servers,
    syncIntervalSecs,
    timeoutSecs,
    stepThresholdMs,
    samplesPerServer,
    expectedHash,
    loaded,
    saving,
    loadTimeConfig,
    saveTimeConfig,
  };
});
