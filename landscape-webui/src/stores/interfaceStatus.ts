import type { ServiceStatus } from "@landscape-router/types/api/schemas";
import { defineStore } from "pinia";
import { computed, ref } from "vue";

export function defineInterfaceStatusStore<Id extends string>(
  id: Id,
  fetchStatus: () => Promise<Map<string, ServiceStatus>>,
) {
  return defineStore(id, () => {
    const status = ref(new Map<string, ServiceStatus>());

    async function UPDATE_INFO() {
      status.value = await fetchStatus();
    }

    function GET_STATUS_BY_IFACE_NAME(name: string) {
      return computed(() => status.value.get(name));
    }

    return { UPDATE_INFO, GET_STATUS_BY_IFACE_NAME };
  });
}
