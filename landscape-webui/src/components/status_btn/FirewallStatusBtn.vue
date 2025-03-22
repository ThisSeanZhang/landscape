<script setup lang="ts">
import { ZoneType } from "@/lib/service_ipconfig";
import { Wall } from "@vicons/tabler";

import StatusBtn from "@/components/status_btn/StatusBtn.vue";
import { useFirewallConfigStore } from "@/stores/status_firewall";

const firewallConfigStore = useFirewallConfigStore();

const iface_info = defineProps<{
  iface_name: string;
  zone: ZoneType;
}>();

const status = firewallConfigStore.GET_STATUS_BY_IFACE_NAME(
  iface_info.iface_name
);

const emit = defineEmits(["click"]);
</script>

<template>
  <StatusBtn :status="status" @click="emit('click')">
    <template #btn-icon>
      <n-icon>
        <Wall />
      </n-icon>
    </template>
  </StatusBtn>
</template>
