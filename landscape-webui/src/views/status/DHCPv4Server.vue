<script lang="ts" setup>
import {
  get_all_iface_arp_scan_info,
  get_dhcp_v4_assigned_ips,
} from "@/api/service_dhcp_v4";
import type { ArpScanInfo, DHCPv4OfferInfo } from "@/api/service_dhcp_v4";
import { info } from "console";
import { computed, onMounted, ref } from "vue";

onMounted(async () => {
  await get_info();
});

const loading = ref(false);
const infos = ref<{ label: string; value: DHCPv4OfferInfo | null }[]>([]);
const arp_infos = ref<Map<string, ArpScanInfo[]>>(new Map());
async function get_arp_info() {
  arp_infos.value = await get_all_iface_arp_scan_info();
}

async function get_info() {
  try {
    loading.value = true;
    let req_data = await get_dhcp_v4_assigned_ips();
    const result = [];
    for (const [label, value] of req_data) {
      result.push({
        label,
        value,
      });
    }
    result.sort((a, b) => a.label.localeCompare(b.label));
    infos.value = result;
  } finally {
    loading.value = false;
  }
  await get_arp_info();
}
</script>

<template>
  <n-flex vertical style="flex: 1">
    <n-flex>
      <n-button :loading="loading" @click="get_info">刷新</n-button>
    </n-flex>
    <!-- {{ infos }} -->
    <n-flex v-if="infos.length > 0">
      <AssignedIpTable
        @refresh="get_info"
        v-for="(data, index) in infos"
        :key="index"
        :iface_name="data.label"
        :info="data.value"
        :arp_info="arp_infos.get(data.label)"
      ></AssignedIpTable>
    </n-flex>
    <n-empty style="flex: 1" v-else></n-empty
  ></n-flex>

  <!-- {{ infos }} -->
</template>
