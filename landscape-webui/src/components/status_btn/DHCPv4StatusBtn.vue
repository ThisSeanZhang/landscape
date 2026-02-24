<script setup lang="ts">
import { H, NetworkEnterprise } from "@vicons/carbon";

import StatusBtn from "@/components/status_btn/StatusBtn.vue";
import { useDHCPv4ConfigStore } from "@/stores/status_dhcp_v4";
import { computed, h, ref } from "vue";
import { ServiceStatusType } from "@/lib/services";
import { IfaceZoneType } from "landscape-types/api/schemas";

const dhcpv4ConfigStore = useDHCPv4ConfigStore();

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const status = dhcpv4ConfigStore.GET_STATUS_BY_IFACE_NAME(
  iface_info.iface_name,
);
const emit = defineEmits(["click"]);
</script>

<template>
  <StatusBtn :status="status" @click="emit('click')">
    <template #btn-icon>
      <n-icon>
        <NetworkEnterprise />
      </n-icon>
    </template>
  </StatusBtn>
</template>
