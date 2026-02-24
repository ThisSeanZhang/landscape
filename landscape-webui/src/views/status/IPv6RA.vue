<script lang="ts" setup>
import { get_icmpra_assigned_ips } from "@/api/service_icmpv6ra";
import type { IPv6NAInfo } from "@/api/service_icmpv6ra";
import { computed, onMounted, ref } from "vue";

onMounted(async () => {
  await get_info();
});

const loading = ref(false);
const infos = ref<{ label: string; value: IPv6NAInfo | null }[]>([]);
async function get_info() {
  try {
    loading.value = true;
    let req_data = await get_icmpra_assigned_ips();
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
    <n-alert type="info">
      目前列表不会自动刷新， 30s 不活跃的 IP 将会被标记为
      <n-tag :bordered="false" type="warning">STALE</n-tag>
    </n-alert>
    <n-flex>
      <n-button :loading="loading" @click="get_info">刷新</n-button>
    </n-flex>
    <n-flex v-if="infos.length > 0">
      <ICMPRaShowItem
        v-for="(data, index) in infos"
        :key="index"
        :config="data.value"
        :iface_name="data.label"
      />
    </n-flex>
    <n-empty style="flex: 1" v-else></n-empty>
  </n-flex>

  <!-- {{ infos }} -->
</template>
