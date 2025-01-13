import { defineStore } from "pinia";
import { computed, ref, watch } from "vue";

import { useSysInfo } from "./systeminfo";
import { useIfaceNodeStore } from "./iface_node";
import { useIpConfigStore } from "./status_ipconfig";
import { useNATConfigStore } from "@/stores/status_nats";
import { useMarkConfigStore } from "./status_mark";
import { useDockerStore } from "./status_docker";
import { useDnsStore } from "./status_dns";

export const useFetchIntervalStore = defineStore("fetch_interval", () => {
  const sysinfo = useSysInfo();
  const ifaceNodeStore = useIfaceNodeStore();
  const ipConfigStore = useIpConfigStore();
  const natConfigStore = useNATConfigStore();
  const markConfigStore = useMarkConfigStore();
  const dockerStore = useDockerStore();
  const dnsStore = useDnsStore();

  const interval_function = async () => {
    if (start_count_down_callback.value !== undefined) {
      start_count_down_callback.value();
    }
    try {
      await sysinfo.UPDATE_INFO();
      await dockerStore.UPDATE_INFO();
      await dnsStore.UPDATE_INFO();
      await ifaceNodeStore.UPDATE_INFO();
      await ipConfigStore.UPDATE_INFO();
      await natConfigStore.UPDATE_INFO();
      await markConfigStore.UPDATE_INFO();
    } catch (error) {
      // console.log("1111");
      enable_interval.value = false;
      if (interval_timer != undefined) {
        clean_interval();
      }
      if (error instanceof Error) {
        error_message.value = error.message;
      } else {
        error_message.value = `An unknown error occurred: ${error}`;
      }
    }
  };

  const error_message = ref<string | undefined>(undefined);
  const enable_interval = ref<boolean>(true);
  const interval_time = ref<number>(3000);
  const interval_timer = ref<any>(undefined);

  const start_count_down_callback = ref<any>();

  // set_interval();
  function set_interval() {
    interval_function();
    interval_timer.value = setInterval(interval_function, interval_time.value);
  }

  function clean_interval() {
    clearInterval(interval_timer.value);
    interval_timer.value = undefined;
  }

  watch(enable_interval, (new_value, _) => {
    if (new_value) {
      set_interval();
    } else {
      clean_interval();
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      if (interval_timer.value != undefined) {
        clean_interval();
      }
    } else {
      if (enable_interval.value) {
        set_interval();
      }
    }
  });

  function IMMEDIATELY_EXECUTE() {
    clean_interval();
    set_interval();
    enable_interval.value = true;
  }

  async function SETTING_CALLBACK(call_back: any) {
    start_count_down_callback.value = call_back;
  }
  return {
    enable_interval,
    interval_time,
    error_message,
    IMMEDIATELY_EXECUTE,
    SETTING_CALLBACK,
  };
});
