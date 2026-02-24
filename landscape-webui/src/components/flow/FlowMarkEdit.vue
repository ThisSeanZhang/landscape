<script setup lang="ts">
import { FlowMarkType } from "@/lib/default_value";
import type { FlowMark } from "landscape-types/api/schemas";
import { computed } from "vue";
import FlowSelect from "./FlowSelect.vue";

const mark = defineModel<FlowMark>("mark", { required: true });

const mark_type_option = [
  {
    label: "当前流的出口",
    value: FlowMarkType.KeepGoing,
  },
  {
    label: "默认流的出口",
    value: FlowMarkType.Direct,
  },
  {
    label: "禁止连接",
    value: FlowMarkType.Drop,
  },
  {
    label: "使用指定流出口",
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
      placeholder="选择匹配方式"
    />

    <n-flex align="center">
      <span>&nbsp;全锥型 (NAT1)</span>
      <n-switch v-model:value="mark.allow_reuse_port" :round="false" />
    </n-flex>
  </n-flex>
  <n-input-group v-else-if="mark.action.t === FlowMarkType.Redirect">
    <n-select
      style="width: 50%"
      v-model:value="mark.action.t"
      @update:value="mark_action_update"
      :options="mark_type_option"
      placeholder="选择匹配方式"
    />
    <FlowSelect
      v-model="mark.flow_id"
      :include-all="false"
      placeholder="指定流的 ID"
      width="50%"
    />
  </n-input-group>
  <n-select
    v-else
    style="width: 50%"
    v-model:value="mark.action.t"
    @update:value="mark_action_update"
    :options="mark_type_option"
    placeholder="选择匹配方式"
  />
</template>
