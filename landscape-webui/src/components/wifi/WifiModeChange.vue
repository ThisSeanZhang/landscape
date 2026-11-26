<script setup lang="ts">
import { WifiMode } from "@landscape-router/types/api/schemas";

import { ServiceExhibitSwitch } from "@/lib/network/services";
import { change_wifi_mode } from "@/api/network";
import { SpatialAudioOutlined } from "@vicons/material";
import { Wifi } from "@vicons/carbon";
import { stop_and_del_iface_wifi } from "@/api/services/wifi";
import { useI18n } from "vue-i18n";

const { t } = useI18n();

// const showModal = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const props = defineProps<{
  iface_name: string;
  wifi_info?: WifiMode;
  show_switch: ServiceExhibitSwitch;
}>();

async function change_mode() {
  const mode = props.show_switch.wifi ? WifiMode.client : WifiMode.ap;
  await stop_and_del_iface_wifi(props.iface_name);
  await change_wifi_mode(props.iface_name, mode);
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
    {{ t("wifi.change_mode_confirm") }}
  </n-popconfirm>
</template>
