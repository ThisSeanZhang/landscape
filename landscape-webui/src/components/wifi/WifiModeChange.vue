<script setup lang="ts">
import { computed, ref } from "vue";
import { WifiMode } from "@/lib/dev";
import { ServiceExhibitSwitch } from "@/lib/services";
import { change_wifi_mode } from "@/api/network";
import { SpatialAudioOutlined } from "@vicons/material";
import { Wifi } from "@vicons/carbon";
import { stop_and_del_iface_wifi } from "@/api/service_wifi";

// const showModal = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const props = defineProps<{
  iface_name: string;
  wifi_info?: WifiMode;
  show_switch: ServiceExhibitSwitch;
}>();

async function change_mode() {
  let change_mode = WifiMode.Undefined;

  if (props.show_switch.wifi) {
    change_mode = WifiMode.Client;
  } else {
    change_mode = WifiMode.AP;
  }
  await stop_and_del_iface_wifi(props.iface_name);
  await change_wifi_mode(props.iface_name, change_mode);
  emit("refresh");
}
</script>

<template>
  <n-popconfirm
    v-if="show_switch.wifi || show_switch.station"
    @positive-click="change_mode()"
  >
    <template #trigger>
      <n-button text :focusable="false" style="font-size: 16px" @click="">
        <n-icon>
          <Wifi v-if="show_switch.wifi"></Wifi>
          <SpatialAudioOutlined v-else></SpatialAudioOutlined>
        </n-icon>
      </n-button>
    </template>
    确定切换模式吗
  </n-popconfirm>
</template>
