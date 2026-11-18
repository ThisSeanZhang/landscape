import { defineStore } from "pinia";
import { reactive } from "vue";
import {
  getDnsCacheConfig,
  updateDnsCacheConfig,
  getDohConfig,
  updateDohConfig,
} from "@/api/sys/config";

export const useDnsConfigStore = defineStore("dns_config", () => {
  const cache = reactive({
    capacity: null as number | null,
    ttl: null as number | null,
    negativeTtl: null as number | null,
    hash: null as string | null,
    saving: false,
  });
  const doh = reactive({
    listenPort: null as number | null,
    httpEndpoint: "",
    hash: null as string | null,
    saving: false,
  });

  async function loadCache() {
    cache.hash = null;
    const response = await getDnsCacheConfig();
    cache.capacity = response.cache.capacity ?? null;
    cache.ttl = response.cache.ttl ?? null;
    cache.negativeTtl = response.cache.negative_ttl ?? null;
    cache.hash = response.hash;
  }

  async function saveCache() {
    if (cache.hash === null || cache.saving) return;
    cache.saving = true;
    try {
      await updateDnsCacheConfig({
        new_cache: {
          capacity: cache.capacity ?? undefined,
          ttl: cache.ttl ?? undefined,
          negative_ttl: cache.negativeTtl ?? undefined,
        },
        expected_hash: cache.hash,
      });
      await loadCache();
    } finally {
      cache.saving = false;
    }
  }

  async function loadDoh() {
    doh.hash = null;
    const response = await getDohConfig();
    doh.listenPort = response.doh.listen_port ?? null;
    doh.httpEndpoint = response.doh.http_endpoint ?? "";
    doh.hash = response.hash;
  }

  async function saveDoh() {
    if (doh.hash === null || doh.saving) return;
    doh.saving = true;
    try {
      await updateDohConfig({
        new_doh: {
          listen_port: doh.listenPort ?? undefined,
          http_endpoint: doh.httpEndpoint.trim() || undefined,
        },
        expected_hash: doh.hash,
      });
      await loadDoh();
    } finally {
      doh.saving = false;
    }
  }

  return { cache, doh, loadCache, loadDoh, saveCache, saveDoh };
});
