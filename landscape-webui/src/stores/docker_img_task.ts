import { get_current_tasks } from "@/api/docker";
import type {
  ImgPullEvent,
  PullImgTask,
} from "@landscape-router/types/api/schemas";
import { defineStore } from "pinia";
import { ref } from "vue";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";

export const useDockerImgTask = defineStore("docker-img_task", () => {
  const socket = ref<WebSocket | undefined>(undefined);

  const tasks = ref<PullImgTask[]>([]);

  const page_active = ref(false);

  function CONNECT() {
    if (!page_active.value) return;
    if (socket.value && socket.value.readyState === WebSocket.OPEN) {
      socket.value.send(JSON.stringify({ type: "ping" }));
      return;
    }

    const token = localStorage.getItem(LANDSCAPE_TOKEN_KEY);
    socket.value = new WebSocket(
      `wss://${window.location.hostname}:${window.location.port}/api/ws/docker/tasks?token=${token}`,
    );
    socket.value.addEventListener("open", function (event) {
      socket.value?.send("Hello Server!");
    });

    socket.value.addEventListener("message", function (event) {
      console.log("Message from server ", event.data);
      let data = JSON.parse(event.data) as ImgPullEvent;
      for (const task of tasks.value) {
        if (task.id == data.task_id) {
          task.layer_current_info[data.id] = data;
        }
      }
    });
  }

  async function INIT() {
    tasks.value = await get_current_tasks();
  }

  function DISCONNECT() {
    if (socket.value) {
      socket.value.close();
    }
  }

  function SET_ACTIVE(active: boolean) {
    page_active.value = active;
  }

  return {
    tasks,
    INIT,
    CONNECT,
    DISCONNECT,
    SET_ACTIVE,
  };
});

export default useDockerImgTask;
