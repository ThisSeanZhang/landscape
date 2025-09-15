<script lang="ts" setup>
import { get_dhcp_v4_assigned_ips } from "@/api/service_dhcp_v4";
import { DHCPv4OfferInfo } from "@/rust_bindings/common/dhcp_v4_server";
import { info } from "console";
import { computed, onMounted, ref } from "vue";

onMounted(async () => {
  await get_info();
});

const loading = ref(false);
const infos = ref<{ label: string; value: DHCPv4OfferInfo | null }[]>([]);
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
      ></AssignedIpTable>
    </n-flex>
    <n-empty style="flex: 1" v-else></n-empty
  ></n-flex>

  <!-- {{ infos }} -->
</template>
