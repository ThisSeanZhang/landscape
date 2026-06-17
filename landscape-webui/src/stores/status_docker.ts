import { get_docker_container_summarys, get_docker_status } from "@/api/docker";
import { ServiceStatus, ServiceStatusType } from "@/lib/services";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useDockerStore = defineStore("docker_status", () => {
  const docker_status = ref<ServiceStatus>({ t: ServiceStatusType.Stop });

  const container_summarys = ref<any[]>([]);

  const page_active = ref(false);

  async function UPDATE_INFO() {
    if (!page_active.value) return;
    try {
      docker_status.value = await get_docker_status();
      container_summarys.value = await get_docker_container_summarys();
    } catch {
      // Docker may be unavailable
    }
  }

  function SET_ACTIVE(active: boolean) {
    page_active.value = active;
  }

  return {
    docker_status,
    container_summarys,
    UPDATE_INFO,
    SET_ACTIVE,
  };
});
