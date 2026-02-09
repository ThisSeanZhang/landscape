import { defineStore } from "pinia";
import { ref, computed } from "vue";
import { IpMacBinding } from "landscape-types/common/mac_binding";
import { get_mac_bindings } from "@/api/mac_binding";
import { mask_string } from "@/lib/common";
import { useFrontEndStore } from "./front_end_config";

export const useMacBindingStore = defineStore("mac_binding", () => {
  const frontEndStore = useFrontEndStore();
  const bindings = ref<IpMacBinding[]>([]);
  const loading = ref(false);

  // 建立 MAC 地址索引 Map
  const macMap = computed(() => {
    const map = new Map<string, IpMacBinding>();
    bindings.value.forEach((b) => {
      map.set(b.mac.toLowerCase(), b);
    });
    return map;
  });

  // 建立 IP 地址索引 Map
  const ipMap = computed(() => {
    const map = new Map<string, IpMacBinding>();
    bindings.value.forEach((b) => {
      if (b.ipv4) map.set(b.ipv4, b);
      if (b.ipv6) map.set(b.ipv6.toLowerCase(), b);
    });
    return map;
  });

  async function UPDATE_INFO() {
    loading.value = true;
    try {
      const data = await get_mac_bindings();
      bindings.value = data;
    } catch (error) {
      console.error("Failed to fetch mac bindings:", error);
    } finally {
      loading.value = false;
    }
  }

  /**
   * 获取名称显示，支持自定义 fallback（如 DHCP 主机名）
   * @param key IP 或 MAC
   * @param fallback 当无绑定记录时返回的备选值，默认为 key
   */
  function GET_NAME_WITH_FALLBACK(
    key: string | undefined | null,
    fallback?: string | null,
  ): string {
    const isPrivacyMode = frontEndStore.presentation_mode;
    const finalFallback = fallback ?? key ?? "";

    if (!key) return isPrivacyMode ? mask_string(finalFallback) : finalFallback;

    const lowerKey = key.toLowerCase();
    const binding = macMap.value.get(lowerKey) || ipMap.value.get(lowerKey);

    if (isPrivacyMode) {
      if (binding && binding.fake_name) return binding.fake_name;
      return mask_string(finalFallback);
    }

    return binding ? binding.name : finalFallback;
  }

  /**
   * 获取显示文本 (IP/MAC 专用，无绑定则显示原始值的脱敏)
   */
  function GET_DISPLAY_NAME(key: string | undefined | null): string {
    const isPrivacyMode = frontEndStore.presentation_mode;
    if (!key) return "";

    const lowerKey = key.toLowerCase();
    const binding = macMap.value.get(lowerKey) || ipMap.value.get(lowerKey);

    if (isPrivacyMode) {
      if (binding && binding.fake_name) return binding.fake_name;
      return mask_string(key);
    }

    return binding ? binding.name : key;
  }

  /**
   * 获取绑定的 ID (用于快速跳转编辑)
   */
  function GET_BINDING_ID(key: string | undefined | null): string | null {
    if (!key) return null;
    const lowerKey = key.toLowerCase();
    const binding = macMap.value.get(lowerKey) || ipMap.value.get(lowerKey);
    return binding ? (binding.id ?? null) : null;
  }

  return {
    bindings,
    loading,
    UPDATE_INFO,
    GET_DISPLAY_NAME,
    GET_NAME_WITH_FALLBACK,
    GET_BINDING_ID,
  };
});
