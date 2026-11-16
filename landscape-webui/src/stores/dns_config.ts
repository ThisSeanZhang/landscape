import { defineStore } from "pinia";
import { ref } from "vue";
import type { LandscapeDnsConfig } from "@landscape-router/types/api/schemas";
import { get_dns_config_edit, update_dns_config } from "@/api/sys/config";

export const useDnsConfigStore = defineStore("dns_config", () => {
  const cacheCapacity = ref<number | undefined>(undefined);
  const cacheTtl = ref<number | undefined>(undefined);
  const cacheNegativeTtl = ref<number | undefined>(undefined);
  const dohListenPort = ref<number | null>(null);
  const dohHttpEndpoint = ref("");
  const tcpEnabled = ref<"default" | "enabled" | "disabled">("default");
  const loaded = ref(false);
  const saving = ref(false);
  const expectedHash = ref<string>("");

  async function loadDnsConfig() {
    loaded.value = false;
    const { dns, hash } = await get_dns_config_edit();
    cacheCapacity.value = dns.cache_capacity ?? undefined;
    cacheTtl.value = dns.cache_ttl ?? undefined;
    cacheNegativeTtl.value = dns.negative_cache_ttl ?? undefined;
    dohListenPort.value = dns.doh_listen_port ?? null;
    dohHttpEndpoint.value = dns.doh_http_endpoint ?? "";
    tcpEnabled.value =
      dns.tcp_enabled === undefined
        ? "default"
        : dns.tcp_enabled
          ? "enabled"
          : "disabled";
    expectedHash.value = hash;
    loaded.value = true;
  }

  async function saveDnsConfig() {
    if (!loaded.value || saving.value) return;
    saving.value = true;
    try {
      const new_dns: LandscapeDnsConfig = {
        cache_capacity: cacheCapacity.value ?? undefined,
        cache_ttl: cacheTtl.value ?? undefined,
        negative_cache_ttl: cacheNegativeTtl.value ?? undefined,
        doh_listen_port: dohListenPort.value ?? undefined,
        doh_http_endpoint: dohHttpEndpoint.value.trim() || undefined,
        tcp_enabled:
          tcpEnabled.value === "default"
            ? undefined
            : tcpEnabled.value === "enabled",
      };
      await update_dns_config({ new_dns, expected_hash: expectedHash.value });
      await loadDnsConfig();
    } finally {
      saving.value = false;
    }
  }

  return {
    cacheCapacity,
    cacheTtl,
    cacheNegativeTtl,
    dohListenPort,
    dohHttpEndpoint,
    tcpEnabled,
    loaded,
    saving,
    expectedHash,
    loadDnsConfig,
    saveDnsConfig,
  };
});
