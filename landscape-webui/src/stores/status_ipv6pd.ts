import { get_all_ipv6pd_status } from "@/api/service_ipv6pd";
import { ServiceStatus } from "@/lib/services";
import { defineStore } from "pinia";
import { computed, ComputedRef, ref } from "vue";

export const useIPv6PDStore = defineStore("status_ipv6pd", () => {
  const status = ref<Map<string, ServiceStatus>>(
    new Map<string, ServiceStatus>(),
  );

  async function UPDATE_INFO() {
    // WAN link 迁移:旧 per-service status 端点已下线,失败时保留旧值,
    // 避免拖垮全局轮询循环。
    const result = await get_all_ipv6pd_status().catch(() => undefined);
    if (result !== undefined) {
      status.value = result;
    }
  }

  function GET_STATUS_BY_IFACE_NAME(
    name: string,
  ): ComputedRef<ServiceStatus | undefined> {
    return computed(() => status.value.get(name));
  }

  return {
    UPDATE_INFO,
    GET_STATUS_BY_IFACE_NAME,
  };
});
