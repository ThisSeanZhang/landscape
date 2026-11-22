<script setup lang="ts">
import type { NetDev } from "@/lib/network/dev";
import TopologyDetailPanel from "./TopologyDetailPanel.vue";

defineProps<{ node?: NetDev }>();
const emit = defineEmits<{ close: [] }>();
</script>
<template>
  <n-drawer
    style="border-radius: 16px 16px 0 0; overflow: hidden"
    placement="bottom"
    height="80%"
    :show="!!node"
    @update:show="!$event && emit('close')"
  >
    <n-drawer-content
      body-content-style="padding: 0; height: 100%; box-sizing: border-box;"
    >
      <TopologyDetailPanel
        v-if="node"
        :key="node.name"
        :node="node"
        in-drawer
        @close="emit('close')"
      />
    </n-drawer-content>
  </n-drawer>
</template>
