import { defineStore } from "pinia";
import { ref } from "vue";
import { getFlowWanStatus } from "@landscape-router/types/api/route/route";
import type { FlowWanStatus } from "@landscape-router/types/api/schemas";

export const useFailoverStore = defineStore("failover-status", () => {
  const statuses = ref<FlowWanStatus[]>([]);
  const unavailable = ref(false);
  let users = 0;
  let timer: ReturnType<typeof setInterval> | undefined;
  let pending = false;
  async function refresh() {
    if (pending) return;
    pending = true;
    try {
      statuses.value = await getFlowWanStatus({ silent: true });
      unavailable.value = false;
    } catch {
      unavailable.value = true;
    } finally {
      pending = false;
    }
  }
  function subscribe() {
    users++;
    if (users === 1) {
      void refresh();
      timer = setInterval(refresh, 3000);
    }
  }
  function unsubscribe() {
    users = Math.max(0, users - 1);
    if (!users && timer) {
      clearInterval(timer);
      timer = undefined;
    }
  }
  return { statuses, unavailable, refresh, subscribe, unsubscribe };
});
