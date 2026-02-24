import { defineStore } from "pinia";
import { ref, watch } from "vue";
import type { LandscapeUIConfig } from "@landscape-router/types/api/schemas";
import {
  get_ui_config,
  get_ui_config_edit,
  update_ui_config,
} from "@/api/sys/config";
import i18n from "@/i18n";

export const usePreferenceStore = defineStore("preference", () => {
  const language = ref<string | undefined>(undefined);
  const timezone = ref<string | undefined>(undefined);
  const theme = ref<string | undefined>(undefined);
  const expectedHash = ref<string>("");

  async function loadPreference() {
    try {
      const config = await get_ui_config();
      language.value = config.language || "zh-CN";
      timezone.value = config.timezone || "Asia/Shanghai";
      theme.value = config.theme || "dark";

      applyPreference();
    } catch (error) {
      console.error("Failed to load generic UI config", error);
    }
  }

  async function loadPreferenceForEdit() {
    const { ui, hash } = await get_ui_config_edit();
    language.value = ui.language || "zh-CN";
    timezone.value = ui.timezone || "Asia/Shanghai";
    theme.value = ui.theme || "dark";
    expectedHash.value = hash;
  }

  function applyPreference() {
    if (language.value) {
      i18n.global.locale.value = language.value as any;
    }
  }

  async function savePreference() {
    const new_ui: LandscapeUIConfig = {
      language: language.value === "zh-CN" ? undefined : language.value,
      timezone: timezone.value === "Asia/Shanghai" ? undefined : timezone.value,
      theme: theme.value === "dark" ? undefined : theme.value,
    };
    await update_ui_config({
      new_ui,
      expected_hash: expectedHash.value,
    });

    // Refresh hash
    const { hash } = await get_ui_config_edit();
    expectedHash.value = hash;
  }

  // Watchers for immediate effect if needed
  watch(language, (newLang) => {
    if (newLang) {
      i18n.global.locale.value = newLang as any;
    }
  });

  return {
    language,
    timezone,
    theme,
    expectedHash,
    loadPreference,
    loadPreferenceForEdit,
    savePreference,
  };
});
