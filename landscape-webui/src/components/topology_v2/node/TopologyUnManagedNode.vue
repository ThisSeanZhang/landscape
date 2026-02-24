<script setup lang="ts">
import { manage_iface } from "@/api/iface";
import type { NetworkIfaceConfig } from "landscape-types/api/schemas";

const props = defineProps<{
  node: NetworkIfaceConfig;
}>();

async function manage_this_dev() {
  await manage_iface(props.node.name);
}
</script>

<template>
  <n-card
    size="small"
    :title="node.name"
    style="min-width: 220px; max-width: 230px"
  >
    <template #header-extra>
      <n-button @click="manage_this_dev" size="small" secondary strong>
        小
      </n-button>
    </template>
  </n-card>
</template>
