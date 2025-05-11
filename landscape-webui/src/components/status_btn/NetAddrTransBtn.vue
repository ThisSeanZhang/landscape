<script setup lang="ts">
import { ZoneType } from "@/lib/service_ipconfig";
import { ImportExportRound } from "@vicons/material";

import StatusBtn from "@/components/status_btn/StatusBtn.vue";
import { useNATConfigStore } from "@/stores/status_nats";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

const natConfigStore = useNATConfigStore();

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const status = natConfigStore.GET_STATUS_BY_IFACE_NAME(iface_info.iface_name);

const emit = defineEmits(["click"]);
</script>

<template>
  <StatusBtn
    v-if="iface_info.zone === ZoneType.Wan"
    :status="status"
    @click="emit('click')"
  >
    <template #btn-icon>
      <n-icon>
        <ImportExportRound />
      </n-icon>
    </template>
  </StatusBtn>
</template>
