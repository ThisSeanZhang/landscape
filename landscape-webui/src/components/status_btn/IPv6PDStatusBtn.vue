<script setup lang="ts">
import { ZoneType } from "@/lib/service_ipconfig";
import { BareMetalServer02 } from "@vicons/carbon";

import StatusBtn from "@/components/status_btn/StatusBtn.vue";
import { useIPv6PDStore } from "@/stores/status_ipv6pd";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

const ipv6PDStore = useIPv6PDStore();

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const status = ipv6PDStore.GET_STATUS_BY_IFACE_NAME(iface_info.iface_name);

const emit = defineEmits(["click"]);
</script>

<template>
  <StatusBtn :status="status" @click="emit('click')">
    <template #btn-icon>
      <BareMetalServer02></BareMetalServer02>
    </template>
  </StatusBtn>
</template>
