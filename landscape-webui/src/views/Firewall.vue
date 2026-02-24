<script setup lang="ts">
import { get_firewall_blacklists } from "@/api/firewall_blacklist";
import FirewallBlacklistEditModal from "@/components/firewall/FirewallBlacklistEditModal.vue";
import FirewallBlacklistCard from "@/components/firewall/FirewallBlacklistCard.vue";
import type { FirewallBlacklistConfig } from "landscape-types/api/schemas";
import { onMounted, ref } from "vue";

const configs = ref<FirewallBlacklistConfig[]>([]);
const show_create_modal = ref(false);

async function read_configs() {
  configs.value = await get_firewall_blacklists();
}

onMounted(async () => {
  await read_configs();
});
</script>
<template>
  <n-flex vertical style="flex: 1; padding: 10px">
    <n-flex align="center">
      <n-button @click="show_create_modal = true"> 创建 </n-button>
      <n-text depth="3">
        当前配置为 IP 黑名单, 命中规则的 IP 将被阻止访问. ICMP 默认不放行.
      </n-text>
    </n-flex>

    <n-divider />

    <n-grid
      v-if="configs.length > 0"
      x-gap="12"
      y-gap="10"
      cols="1 600:2 900:3 1200:4 1600:5"
    >
      <n-grid-item
        v-for="config in configs"
        :key="config.id"
        style="display: flex"
      >
        <FirewallBlacklistCard :rule="config" @refresh="read_configs()" />
      </n-grid-item>
    </n-grid>

    <n-empty v-else description="暂无黑名单规则" style="margin-top: 100px" />

    <FirewallBlacklistEditModal
      v-model:show="show_create_modal"
      :id="null"
      @refresh="read_configs()"
    />
  </n-flex>
</template>
