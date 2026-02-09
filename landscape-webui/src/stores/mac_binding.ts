import { defineStore } from "pinia";
import { ref, computed } from "vue";
import { IpMacBinding } from "landscape-types/common/mac_binding";
import { get_mac_bindings } from "@/api/mac_binding";
import { mask_string } from "@/lib/common";

export const useMacBindingStore = defineStore("mac_binding", () => {
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
   * 获取显示文本
   * @param key IP 地址、MAC 地址或主机名
   * @param isPrivacyMode 是否开启隐私模式
   * @returns 匹配到的名称或原始值的脱敏显示
   */
  function GET_DISPLAY_NAME(
    key: string | undefined | null,
    isPrivacyMode: boolean,
  ): string {
    if (!key) return "";

    const lowerKey = key.toLowerCase();
    const binding = macMap.value.get(lowerKey) || ipMap.value.get(lowerKey);

    if (isPrivacyMode) {
      // 隐私模式：如果有 fake_name 则使用，否则一律对原始值（IP/MAC）进行脱敏显示
      if (binding && binding.fake_name) {
        return binding.fake_name;
      }
      return mask_string(key);
    }

    // 正常模式：优先显示绑定名称，无绑定显示原始值
    return binding ? binding.name : key;
  }

  return {
    bindings,
    loading,
    UPDATE_INFO,
    GET_DISPLAY_NAME,
  };
});
