import { defineStore } from "pinia";
import { ref } from "vue";
import type { LandscapeLanHostnameConfig } from "@landscape-router/types/api/schemas";
import {
  get_lan_hostname_config_edit,
  update_lan_hostname_config,
} from "@/api/sys/config";

export const useLanHostnameConfigStore = defineStore(
  "lan_hostname_config",
  () => {
    const enabled = ref(true);
    const lanSuffix = ref<string | undefined>(undefined);
    const expectedHash = ref<string>("");

    async function loadLanHostnameConfig() {
      const { lan_hostname, hash } = await get_lan_hostname_config_edit();
      enabled.value = lan_hostname.enable ?? true;
      lanSuffix.value = lan_hostname.lan_suffix ?? undefined;
      expectedHash.value = hash;
    }

    async function saveLanHostnameConfig() {
      const new_lan_hostname: LandscapeLanHostnameConfig = {
        enable: enabled.value,
        lan_suffix: lanSuffix.value?.trim() || undefined,
      };
      await update_lan_hostname_config({
        new_lan_hostname,
        expected_hash: expectedHash.value,
      });

      await loadLanHostnameConfig();
    }

    return {
      enabled,
      lanSuffix,
      expectedHash,
      loadLanHostnameConfig,
      saveLanHostnameConfig,
    };
  },
);
