<script setup lang="ts">
import { ZoneType } from "@/lib/service_ipconfig";
import { H, NetworkEnterprise } from "@vicons/carbon";

import StatusBtn from "@/components/status_btn/StatusBtn.vue";
import { useDHCPv4ConfigStore } from "@/stores/status_dhcp_v4";
import { NCountdown } from "naive-ui";
import { computed, h } from "vue";
import { DHCPv4OfferInfoShow, conver_to_show } from "@/lib/dhcp_v4";
import { ServiceStatusType } from "@/lib/services";

const dhcpv4ConfigStore = useDHCPv4ConfigStore();

const iface_info = defineProps<{
  iface_name: string;
  zone: ZoneType;
}>();

const status = dhcpv4ConfigStore.GET_STATUS_BY_IFACE_NAME(
  iface_info.iface_name
);
const emit = defineEmits(["click"]);
const columns = [
  {
    title: "Mac 地址",
    key: "mac",
  },
  {
    title: "分配 IP",
    key: "ip",
  },
  {
    title: "分配租期时间 (s)",
    key: "time_left",
    // render(row: DHCPv4OfferInfoShow) {
    //   return h(NCountdown, {
    //     duration: row.time_left * 1000,
    //   });
    // },
  },
];

const disable_popover = computed(() => {
  return status.value?.status.t === ServiceStatusType.Running ? false : true;
});
</script>

<template>
  <StatusBtn
    :status="status?.status"
    :disable_popover="disable_popover"
    @click="emit('click')"
  >
    <template #btn-icon>
      <n-icon>
        <NetworkEnterprise />
      </n-icon>
    </template>

    <template #popover-panel>
      <!-- {{ status?.data }} -->
      <n-data-table
        :columns="columns"
        :data="conver_to_show(status?.data)"
        :bordered="false"
      />
    </template>
  </StatusBtn>
</template>
