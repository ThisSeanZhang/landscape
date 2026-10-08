<script lang="ts" setup>
import { getFlowRuleByFlowId } from "@landscape-router/types/api/flow-rules/flow-rules";
import type { ApiFlowConfig as FlowConfig } from "@landscape-router/types/api/schemas";
import { onMounted, ref, watch, watchEffect } from "vue";
import { Docker, NetworkWired } from "@vicons/fa";
import { get_all_wan_links } from "@/api/service_wan_link";
import { link_label } from "@/lib/wan_link";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useI18n } from "vue-i18n";

const frontEndStore = useFrontEndStore();
const { t } = useI18n();
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
const wan_links = ref<Awaited<ReturnType<typeof get_all_wan_links>>>([]);
async function refresh() {
  [config.value, wan_links.value] = await Promise.all([
    getFlowRuleByFlowId(props.flow_id),
    get_all_wan_links(),
  ]);
}

function target_label(target: FlowConfig["flow_targets"][number]["target"]) {
  return target.t === "netns"
    ? target.container_name
    : link_label(wan_links.value, target.link_id) || t("common.deleted_link");
}
</script>
<template>
  <n-popover v-if="config" trigger="hover">
    <template #trigger>
      <n-flex align="center">
        {{
          config.remark
            ? frontEndStore.MASK_INFO(config.remark)
            : t("common.unnamed")
        }}
        <n-tag
          size="small"
          v-for="each in config.flow_targets"
          :bordered="false"
        >
          {{ frontEndStore.MASK_INFO(target_label(each.target)) }}
          <span v-if="(each.weight ?? 1) !== 1"> ×{{ each.weight ?? 1 }}</span>
          <template #icon>
            <n-icon
              :component="each.target.t === 'netns' ? Docker : NetworkWired"
            />
          </template>
        </n-tag>
      </n-flex>
    </template>
    <FlowConfigCard :show_action="false" :config="config"></FlowConfigCard>
    <!-- <span>{{ config }}</span> -->
  </n-popover>
  <n-flex v-else> {{ t("flow.exhibit.flow_not_found", { flow_id }) }}</n-flex>
</template>
