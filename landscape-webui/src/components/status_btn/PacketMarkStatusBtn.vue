<script setup lang="ts">
import { ZoneType } from "@/lib/service_ipconfig";
import { Bookmark } from "@vicons/carbon";

import StatusBtn from "@/components/status_btn/StatusBtn.vue";
import { useMarkConfigStore } from "@/stores/status_mark";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

const markConfigStore = useMarkConfigStore();

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const status = markConfigStore.GET_STATUS_BY_IFACE_NAME(iface_info.iface_name);

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
        <Bookmark />
      </n-icon>
    </template>
  </StatusBtn>
</template>
