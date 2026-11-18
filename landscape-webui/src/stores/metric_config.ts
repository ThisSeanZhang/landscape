import { defineStore } from "pinia";
import { reactive, ref, type Ref } from "vue";
import type {
  ConnectMetricConfig,
  DnsMetricConfig,
  LandscapeSelfMonitorConfig,
} from "@landscape-router/types/api/schemas";
import {
  getConnectMetricConfig,
  updateConnectMetricConfig,
  getDnsMetricConfig,
  updateDnsMetricConfig,
  getSelfMonitorConfig,
  updateSelfMonitorConfig,
} from "@/api/sys/config";

function configSection<T extends object>(
  initial: T,
  get: () => Promise<{ config: T; hash: string }>,
  update: (payload: { config: T; expected_hash: string }) => Promise<unknown>,
) {
  const config = ref(initial) as Ref<T>;
  const hash = ref<string | null>(null);
  const saving = ref(false);
  async function load() {
    hash.value = null;
    const response = await get();
    config.value = response.config;
    hash.value = response.hash;
  }
  async function save() {
    if (hash.value === null || saving.value) return;
    saving.value = true;
    try {
      await update({ config: config.value, expected_hash: hash.value });
      await load();
    } finally {
      saving.value = false;
    }
  }
  return reactive({ config, hash, saving, load, save });
}

export const useMetricConfigStore = defineStore("metric_config", () => ({
  connect: configSection<ConnectMetricConfig>(
    { store: {} },
    getConnectMetricConfig,
    updateConnectMetricConfig,
  ),
  dns: configSection<DnsMetricConfig>(
    { store: {} },
    getDnsMetricConfig,
    updateDnsMetricConfig,
  ),
  selfMonitor: configSection<LandscapeSelfMonitorConfig>(
    {},
    getSelfMonitorConfig,
    updateSelfMonitorConfig,
  ),
}));
