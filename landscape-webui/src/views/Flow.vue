<script setup lang="ts">
import { onMounted, ref } from "vue";
import type { FlowConfig } from "@landscape-router/types/api/schemas";
import { getFlowRules } from "@landscape-router/types/api/flow-rules/flow-rules";
import FlowEditModal from "@/components/flow/FlowEditModal.vue";

const flows = ref<FlowConfig[]>([]);

const show_edit = ref(false);
onMounted(async () => {
  await refresh();
});

async function refresh() {
  flows.value = await getFlowRules();
}
</script>
<template>
  <n-layout :native-scrollbar="false" content-style="padding: 10px;">
    <n-grid x-gap="12" y-gap="10" cols="1 600:1 900:2 1200:3 1600:4">
      <n-grid-item style="display: flex">
        <DefaultFlowConfigCard @create-flow="show_edit = true" />
      </n-grid-item>
      <n-grid-item
        v-for="flow in flows"
        :key="flow.flow_id"
        style="display: flex"
      >
        <FlowConfigCard @refresh="refresh" :config="flow"></FlowConfigCard>
      </n-grid-item>
    </n-grid>
    <FlowEditModal @refresh="refresh" v-model:show="show_edit" />
  </n-layout>
</template>
