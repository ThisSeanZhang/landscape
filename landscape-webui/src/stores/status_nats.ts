import { get_all_nat_status } from "@/api/service_nat";
import { ServiceStatus } from "@/lib/services";
import { defineStore } from "pinia";
import { computed, ComputedRef, ref } from "vue";

export const useNATConfigStore = defineStore("status_nat", () => {
  const status = ref<Map<string, ServiceStatus>>(
    new Map<string, ServiceStatus>()
  );

  async function UPDATE_INFO() {
    status.value = await get_all_nat_status();
  }

  function GET_STATUS_BY_IFACE_NAME(
    name: string
  ): ComputedRef<ServiceStatus | undefined> {
    return computed(() => status.value.get(name));
  }

  return {
    UPDATE_INFO,
    GET_STATUS_BY_IFACE_NAME,
  };
});

// const natConfigStore = useNATConfigStore();