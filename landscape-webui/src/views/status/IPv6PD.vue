<script lang="ts" setup>
import { get_all_ipv6pd_prefix_status } from "@/api/service_ipv6pd";
import type { IPV6PDPrefixStatus } from "@/api/service_ipv6pd";
import { link_label } from "@/lib/wan_link";
import { useWanLinkStore } from "@/stores/wan_link";
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
const { t } = useI18n();
const wanLinkStore = useWanLinkStore();

onMounted(async () => {
  await get_info();
});

const loading = ref(false);
const infos = ref<{ label: string; value: IPV6PDPrefixStatus }[]>([]);
async function get_info() {
  try {
    loading.value = true;
    // The backend keys prefix statuses by the wan link uuid; resolve the
    // user-visible link label for display, falling back to the raw id.
    await wanLinkStore.UPDATE_INFO();
    let req_data = await get_all_ipv6pd_prefix_status();
    const result = [];
    for (const [key, value] of req_data) {
      result.push({
        label: link_label(wanLinkStore.links, key) || key,
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
      <n-button :loading="loading" @click="get_info">{{
        t("common.refresh")
      }}</n-button>
    </n-flex>
    <n-flex v-if="infos.length > 0">
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3 1600:3">
        <n-grid-item v-for="(data, index) in infos" :key="index">
          <IAPrefixInfoCard
            :prefix_status="data.value"
            :iface_name="data.label"
          />
        </n-grid-item>
      </n-grid>
    </n-flex>
    <n-empty style="flex: 1" v-else></n-empty
  ></n-flex>

  <!-- {{ infos }} -->
</template>
