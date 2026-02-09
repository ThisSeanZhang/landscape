import { mask_string } from "@/lib/common";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useFrontEndStore = defineStore(
  "front_end",
  () => {
    const presentation_mode = ref(false);
    const username = ref<string>("");

    async function INSERT_USERNAME(name: string) {
      username.value = name;
    }

    function MASK_INFO(value: string | undefined | null): string {
      if (value) {
        return presentation_mode.value ? mask_string(value) : value;
      } else {
        return "";
      }
    }

    function MASK_PORT(
      value: string | number | undefined | null,
    ): string | number | undefined | null {
      if (value) {
        return presentation_mode.value ? "****" : value;
      } else {
        return value;
      }
    }

    const conn_sort_key = ref<"time" | "port" | "ingress" | "egress">("time");
    const conn_sort_order = ref<"asc" | "desc">("desc");

    const history_conn_sort_key = ref<
      "time" | "port" | "ingress" | "egress" | "duration"
    >("time");
    const history_conn_sort_order = ref<"asc" | "desc">("desc");

    return {
      presentation_mode,
      username,
      INSERT_USERNAME,
      MASK_INFO,
      MASK_PORT,
      conn_sort_key,
      conn_sort_order,
      history_conn_sort_key,
      history_conn_sort_order,
    };
  },
  {
    persist: {
      key: "front_end",
      storage: localStorage,
    },
  },
);
