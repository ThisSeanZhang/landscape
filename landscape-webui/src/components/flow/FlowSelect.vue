<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import { useI18n } from "vue-i18n";
import { getFlowRules } from "@landscape-router/types/api/flow-rules/flow-rules";

const { t } = useI18n();

interface Props {
  placeholder?: string;
  disabled?: boolean;
  clearable?: boolean;
  filterable?: boolean;
  includeAll?: boolean; // 是否包含"全部"选项
  width?: string;
}

const props = withDefaults(defineProps<Props>(), {
  placeholder: undefined,
  disabled: false,
  clearable: true,
  filterable: true,
  includeAll: true,
  width: "150px",
});

const flowId = defineModel<number | null>();

const flowRules = ref<Awaited<ReturnType<typeof getFlowRules>>>([]);
const loading = ref(false);

const flowOptions = computed(() => [
  ...(props.includeAll ? [{ label: t("flow.select.all"), value: null }] : []),
  { label: `0 - ${t("flow.default_card.title")}`, value: 0 },
  ...flowRules.value
    .filter((rule) => rule.flow_id !== 0)
    .map(({ flow_id, remark }) => ({
      value: flow_id,
      label: remark ? `${flow_id} - ${remark}` : `Flow ${flow_id}`,
    })),
]);

async function loadFlowRules() {
  loading.value = true;
  try {
    flowRules.value = await getFlowRules();
  } catch (error) {
    console.error(t("flow.select.get_list_failed"), error);
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  loadFlowRules();
});

// 暴露刷新方法，供外部调用
defineExpose({
  refresh: loadFlowRules,
});
</script>

<template>
  <n-select
    v-model:value="flowId"
    :placeholder="placeholder ?? t('flow.select.select_flow')"
    :options="flowOptions"
    :disabled="disabled || loading"
    :filterable="filterable"
    :clearable="clearable"
    :loading="loading"
    :style="{ width }"
  />
</template>
