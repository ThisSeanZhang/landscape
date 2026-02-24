<script lang="ts" setup>
import { get_current_ip_prefix_info } from "@/api/service_ipv6pd";
import type { LDIAPrefix } from "@/api/service_ipv6pd";
import { computed, onMounted, ref } from "vue";

onMounted(async () => {
  await get_info();
});

const loading = ref(false);
const infos = ref<{ label: string; value: LDIAPrefix | null }[]>([]);
async function get_info() {
  try {
    loading.value = true;
    let req_data = await get_current_ip_prefix_info();
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
    <n-flex v-if="infos.length > 0">
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3 1600:3">
        <n-grid-item v-for="(data, index) in infos" :key="index">
          <IAPrefixInfoCard :config="data.value" :iface_name="data.label" />
        </n-grid-item>
      </n-grid>
    </n-flex>
    <n-empty style="flex: 1" v-else></n-empty
  ></n-flex>

  <!-- {{ infos }} -->
</template>
