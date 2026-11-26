import { get_lan_devices } from "@/api/lan_device";
import type { LanDeviceView } from "@landscape-router/types/api/schemas";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useLanDeviceStore = defineStore("lan_device", () => {
  const devices = ref<LanDeviceView[]>([]);

  async function UPDATE_INFO() {
    devices.value = await get_lan_devices();
  }

  function GET_DEVICE_BY_MAC(mac?: string): LanDeviceView | undefined {
    if (!mac) return undefined;
    return devices.value.find((device) => device.mac === mac);
  }

  return {
    devices,
    UPDATE_INFO,
    GET_DEVICE_BY_MAC,
  };
});
