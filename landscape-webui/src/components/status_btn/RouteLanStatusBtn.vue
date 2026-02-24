<script setup lang="ts">
import { Router } from "@vicons/carbon";

import StatusBtn from "@/components/status_btn/StatusBtn.vue";
import { IfaceZoneType } from "landscape-types/api/schemas";
import { useRouteLanConfigStore } from "@/stores/status_route_lan";

const routeLanConfigStore = useRouteLanConfigStore();

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const status = routeLanConfigStore.GET_STATUS_BY_IFACE_NAME(
  iface_info.iface_name,
);

const emit = defineEmits(["click"]);
</script>

<template>
  <StatusBtn :status="status" @click="emit('click')">
    <template #btn-icon>
      <n-icon>
        <Router />
      </n-icon>
    </template>
  </StatusBtn>
</template>
