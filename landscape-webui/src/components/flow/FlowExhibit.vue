<script lang="ts" setup>
import { getFlowRuleByFlowId } from "@landscape-router/types/api/flow-rules/flow-rules";
import type { FlowConfig } from "@landscape-router/types/api/schemas";
import { onMounted, ref, watch, watchEffect } from "vue";
import { Docker, NetworkWired } from "@vicons/fa";
import { useFrontEndStore } from "@/stores/front_end_config";

const frontEndStore = useFrontEndStore();
type Props = {
  flow_id: number;
};

const props = defineProps<Props>();

onMounted(async () => {
  await refresh();
});

watch(
  () => props.flow_id,
  async () => {
    await refresh();
  },
);

const config = ref<FlowConfig>();
async function refresh() {
  config.value = await getFlowRuleByFlowId(props.flow_id);
}
</script>
<template>
  <n-popover v-if="config" trigger="hover">
    <template #trigger>
      <n-flex align="center">
        {{
          config.remark ? frontEndStore.MASK_INFO(config.remark) : "`未命名`"
        }}
        的
        <n-tag
          size="small"
          v-for="each in config.flow_targets"
          :bordered="false"
        >
          {{
            each.t === "netns"
              ? frontEndStore.MASK_INFO(each.container_name)
              : frontEndStore.MASK_INFO(each.name)
          }}
          <template #icon>
            <n-icon :component="each.t === 'netns' ? Docker : NetworkWired" />
          </template>
        </n-tag>
      </n-flex>
    </template>
    <FlowConfigCard :show_action="false" :config="config"></FlowConfigCard>
    <!-- <span>{{ config }}</span> -->
  </n-popover>
  <n-flex v-else> 使用 FlowID: {{ flow_id }} 查询不到 Flow 信息</n-flex>
</template>
