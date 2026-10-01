import { get_lan_devices } from "@/api/lan_device";
import type { LanDeviceView } from "@/api/lan_device";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useLanDeviceStore = defineStore("lan_device", () => {
  const devices = ref<LanDeviceView[]>([]);

  async function UPDATE_INFO() {
    devices.value = await get_lan_devices();
  }

  function GET_DEVICE_BY_MAC(mac?: string): LanDeviceView | undefined {
    if (!mac) return undefined;
    // MacAddr is typed as string[] in the ORVAL schema but serialized as a string at runtime
    return devices.value.find((device) => device.mac === (mac as never));
  }

  return {
    devices,
    UPDATE_INFO,
    GET_DEVICE_BY_MAC,
  };
});
