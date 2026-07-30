import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type { EnrolledDevice } from "@landscape-router/types/api/schemas";
import { get_enrolled_devices } from "@/api/enrolled_device";
import { is_ipv4, is_mac, mask_string } from "@/lib/common";
import { useFrontEndStore } from "./front_end_config";

function normalizeMac(mac: string): string {
  return mac.trim().toLowerCase().replace(/-/g, ":");
}

function expandIpv6(value: string): string | null {
  const normalized = value.trim().toLowerCase().split("%")[0];
  if (!normalized || !normalized.includes(":")) return null;
  if (!/^[0-9a-f:]+$/.test(normalized)) return null;

  const segments = normalized.split("::");
  if (segments.length > 2) return null;

  const hasCompression = segments.length === 2;
  const head = segments[0] ? segments[0].split(":").filter(Boolean) : [];
  const tail =
    hasCompression && segments[1] ? segments[1].split(":").filter(Boolean) : [];

  const isValidHextet = (part: string) => /^[0-9a-f]{1,4}$/.test(part);
  if (!head.every(isValidHextet) || !tail.every(isValidHextet)) {
    return null;
  }

  const missingCount = 8 - head.length - tail.length;
  if (hasCompression) {
    if (missingCount < 1) return null;
  } else if (missingCount !== 0) {
    return null;
  }

  const full = hasCompression
    ? [...head, ...Array.from({ length: missingCount }, () => "0"), ...tail]
    : head;

  if (full.length !== 8) return null;
  return full.map((part) => part.padStart(4, "0")).join(":");
}

function macToLinkLocalIpv6(mac: string): string | null {
  if (!is_mac(mac)) return null;

  const bytes = normalizeMac(mac)
    .split(":")
    .map((part) => Number.parseInt(part, 16));

  if (bytes.length !== 6 || bytes.some(Number.isNaN)) return null;

  bytes[0] ^= 0x02;

  const interfaceId = [
    (bytes[0] << 8) | bytes[1],
    (bytes[2] << 8) | 0xff,
    (0xfe << 8) | bytes[3],
    (bytes[4] << 8) | bytes[5],
  ]
    .map((part) => part.toString(16))
    .join(":");

  return expandIpv6(`fe80::${interfaceId}`);
}

function normalizeLookupKey(key: string): string {
  const trimmed = key.trim();
  if (!trimmed) return "";

  if (is_mac(trimmed)) {
    return normalizeMac(trimmed);
  }

  const lowerKey = trimmed.toLowerCase();
  if (lowerKey.startsWith("::ffff:")) {
    const mappedIpv4 = lowerKey.slice(7);
    if (is_ipv4(mappedIpv4)) {
      return mappedIpv4;
    }
  }

  return expandIpv6(trimmed) ?? lowerKey;
}

export const useEnrolledDeviceStore = defineStore("enrolled_device", () => {
  const frontEndStore = useFrontEndStore();
  const bindings = ref<EnrolledDevice[]>([]);
  const loading = ref(false);
  let updatePromise: Promise<void> | null = null;

  // 建立 MAC 地址索引 Map
  const macMap = computed(() => {
    const map = new Map<string, EnrolledDevice>();
    bindings.value.forEach((b) => {
      if (b.mac) {
        map.set(normalizeMac(b.mac), b);
      }
    });
    return map;
  });

  // 建立 IP 地址索引 Map
  const ipMap = computed(() => {
    const map = new Map<string, EnrolledDevice>();
    bindings.value.forEach((b) => {
      if (b.ipv4) map.set(b.ipv4, b);
      if (b.ipv6) {
        map.set(b.ipv6.toLowerCase(), b);
        const normalizedIpv6 = expandIpv6(b.ipv6);
        if (normalizedIpv6) {
          map.set(normalizedIpv6, b);
        }
      }

      // 某些 DNS 指标只会暴露 fe80::/64 地址，这里补一条由 MAC 推导的别名匹配。
      if (b.mac) {
        const linkLocalIpv6 = macToLinkLocalIpv6(b.mac);
        if (linkLocalIpv6) {
          map.set(linkLocalIpv6, b);
        }
      }
    });
    return map;
  });

  function lookupBinding(
    key: string | undefined | null,
  ): EnrolledDevice | undefined {
    if (!key) return undefined;
    const normalizedKey = normalizeLookupKey(key);
    if (!normalizedKey) return undefined;

    return macMap.value.get(normalizedKey) || ipMap.value.get(normalizedKey);
  }

  function UPDATE_INFO(): Promise<void> {
    if (updatePromise) return updatePromise;

    loading.value = true;
    updatePromise = (async () => {
      try {
        const data = await get_enrolled_devices();
        bindings.value = data;
      } catch (error) {
        console.error("Failed to fetch enrolled devices:", error);
      } finally {
        loading.value = false;
        updatePromise = null;
      }
    })();

    return updatePromise;
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

    const binding = lookupBinding(key);

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

    const binding = lookupBinding(key);

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
    const binding = lookupBinding(key);
    return binding ? (binding.id ?? null) : null;
  }

  function GET_BINDING(
    key: string | undefined | null,
  ): EnrolledDevice | undefined {
    return lookupBinding(key);
  }

  function GET_DISPLAY_NAME_BY_ID(id: string | undefined | null): string {
    const isPrivacyMode = frontEndStore.presentation_mode;
    if (!id) return "";

    const binding = bindings.value.find((device) => device.id === id);
    if (!binding) return isPrivacyMode ? mask_string(id) : id;
    if (isPrivacyMode) return binding.fake_name || mask_string(binding.name);
    return binding.name;
  }

  return {
    bindings,
    loading,
    UPDATE_INFO,
    GET_BINDING,
    GET_DISPLAY_NAME,
    GET_DISPLAY_NAME_BY_ID,
    GET_NAME_WITH_FALLBACK,
    GET_BINDING_ID,
  };
});
