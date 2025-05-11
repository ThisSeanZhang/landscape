<script setup lang="ts">
import { ZoneType } from "@/lib/service_ipconfig";
import { Wifi } from "@vicons/carbon";

import StatusBtn from "@/components/status_btn/StatusBtn.vue";
import { useWifiConfigStore } from "@/stores/status_wifi";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

const wifiConfigStore = useWifiConfigStore();

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const status = wifiConfigStore.GET_STATUS_BY_IFACE_NAME(iface_info.iface_name);

const emit = defineEmits(["click"]);
</script>

<template>
  <StatusBtn :status="status" @click="emit('click')">
    <template #btn-icon>
      <n-icon>
        <Wifi />
      </n-icon>
    </template>
  </StatusBtn>
</template>
