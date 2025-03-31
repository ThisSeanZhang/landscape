import { get_docker_container_summarys, get_docker_status } from "@/api/docker";
import { ServiceStatus } from "@/lib/services";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useDockerStore = defineStore("docker_status", () => {
  const docker_status = ref<ServiceStatus>(new ServiceStatus());

  const container_summarys = ref<any[]>([]);

  async function UPDATE_INFO() {
    docker_status.value = await get_docker_status();
    container_summarys.value = await get_docker_container_summarys();
  }

  return {
    docker_status,
    container_summarys,
    UPDATE_INFO,
  };
});
