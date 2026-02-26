<script setup lang="ts">
import { FlowMarkType } from "@/lib/default_value";
import type { FlowMark } from "@landscape-router/types/api/schemas";
import { computed } from "vue";
import FlowSelect from "./FlowSelect.vue";
import { useI18n } from "vue-i18n";

const mark = defineModel<FlowMark>("mark", { required: true });
const { t } = useI18n();

const mark_type_option = [
  {
    label: t("flow.mark_edit.option_current_flow"),
    value: FlowMarkType.KeepGoing,
  },
  {
    label: t("flow.mark_edit.option_default_flow"),
    value: FlowMarkType.Direct,
  },
  {
    label: t("flow.mark_edit.option_block"),
    value: FlowMarkType.Drop,
  },
  {
    label: t("flow.mark_edit.option_redirect"),
    value: FlowMarkType.Redirect,
  },
];

const show_other_function = computed(() => {
  return (
    mark.value.action.t == FlowMarkType.KeepGoing ||
    mark.value.action.t == FlowMarkType.Direct
  );
});

function mark_action_update(value: FlowMarkType) {
  switch (value) {
    case FlowMarkType.KeepGoing:
    case FlowMarkType.Direct: {
      mark.value.flow_id = 0;
      break;
    }
    case FlowMarkType.Drop: {
      mark.value.flow_id = 0;
      mark.value.allow_reuse_port = false;
      break;
    }
    case FlowMarkType.Redirect: {
      mark.value.allow_reuse_port = false;
      break;
    }
  }
}
</script>

<template>
  <n-flex align="center" style="flex: 1" v-if="show_other_function">
    <n-select
      style="width: 50%"
      v-model:value="mark.action.t"
      @update:value="mark_action_update"
      :options="mark_type_option"
      :placeholder="t('flow.mark_edit.select_match_type')"
    />

    <n-flex align="center">
      <span>&nbsp;{{ t("flow.mark_edit.nat1_label") }}</span>
      <n-switch v-model:value="mark.allow_reuse_port" :round="false" />
    </n-flex>
  </n-flex>
  <n-input-group v-else-if="mark.action.t === FlowMarkType.Redirect">
    <n-select
      style="width: 50%"
      v-model:value="mark.action.t"
      @update:value="mark_action_update"
      :options="mark_type_option"
      :placeholder="t('flow.mark_edit.select_match_type')"
    />
    <FlowSelect
      v-model="mark.flow_id"
      :include-all="false"
      :placeholder="t('flow.mark_edit.flow_id_placeholder')"
      width="50%"
    />
  </n-input-group>
  <n-select
    v-else
    style="width: 50%"
    v-model:value="mark.action.t"
    @update:value="mark_action_update"
    :options="mark_type_option"
    :placeholder="t('flow.mark_edit.select_match_type')"
  />
</template>
