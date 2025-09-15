import { mask_string } from "@/lib/common";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useFrontEndStore = defineStore(
  "front_end",
  () => {
    const presentation_mode = ref(false);

    function MASK_INFO(
      value: string | undefined | null
    ): string | undefined | null {
      if (value) {
        return presentation_mode.value ? mask_string(value) : value;
      } else {
        return value;
      }
    }
    return {
      presentation_mode,
      MASK_INFO,
    };
  },
  {
    persist: {
      key: "front_end",
      storage: localStorage,
    },
  }
);
