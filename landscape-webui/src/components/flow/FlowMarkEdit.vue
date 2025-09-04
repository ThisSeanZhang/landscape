<script setup lang="ts">
import { get_flow_rules } from "@/api/flow";
import { FlowMarkType } from "@/lib/default_value";
import { FlowMark } from "@/rust_bindings/flow";
import { computed, onMounted, ref } from "vue";

const mark = defineModel<FlowMark>("mark", { required: true });

const mark_type_option = [
  {
    label: "无动作",
    value: FlowMarkType.KeepGoing,
  },
  {
    label: "忽略 Flow 设置",
    value: FlowMarkType.Direct,
  },
  {
    label: "禁止连接",
    value: FlowMarkType.Drop,
  },
  {
    label: "重定向至流",
    value: FlowMarkType.Redirect,
  },
  // {
  //   label: "允许端口共享",
  //   value: FlowMarkType.AllowReusePort,
  // },
];

onMounted(async () => {
  await search_flows();
});

const flow_rules = ref<any[]>([]);
const flow_options = computed(() => {
  return flow_rules.value.map((e) => ({
    value: e.flow_id,
    label: e.remark ? `${e.flow_id} - ${e.remark}` : e.flow_id,
  }));
});
const flow_search_loading = ref(false);
async function search_flows() {
  flow_rules.value = await get_flow_rules();
}

const show_other_function = computed(() => {
  return (
    mark.value.action.t == FlowMarkType.KeepGoing ||
    mark.value.action.t == FlowMarkType.Direct
  );
});

function mark_action_update(value: FlowMarkType) {
  // console.log(value);
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
    <n-select
      style="width: 50%"
      v-model:value="mark.flow_id"
      filterable
      placeholder="重定向的流 ID"
      :options="flow_options"
      :loading="flow_search_loading"
      clearable
      remote
      @search="search_flows"
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
