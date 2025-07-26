<script setup lang="ts">
import { get_flow_rules } from "@/api/flow";
import { FlowDnsMarkType } from "@/lib/default_value";
import { FlowDnsMark } from "@/rust_bindings/flow";
import { computed, onMounted, ref } from "vue";

const mark = defineModel<FlowDnsMark>("mark", { required: true });

const mark_type_option = [
  {
    label: "无动作",
    value: FlowDnsMarkType.KeepGoing,
  },
  {
    label: "忽略 Flow 设置",
    value: FlowDnsMarkType.Direct,
  },
  {
    label: "禁止连接",
    value: FlowDnsMarkType.Drop,
  },
  {
    label: "重定向至流",
    value: FlowDnsMarkType.Redirect,
  },
  // {
  //   label: "允许端口共享",
  //   value: FlowDnsMarkType.AllowReusePort,
  // },
];

onMounted(async () => {
  await search_flows();
});

const flow_rules = ref<any[]>([]);
const search_key = ref("");

const flow_options = computed(() => {
  // 先按照flow_id排序
  let filteredFlowRules = flow_rules.value;
  if (search_key.value) {
    // 根据搜索关键词过滤规则
    const keyword = search_key.value.toLowerCase();
    filteredFlowRules = flow_rules.value.filter(
      (e) => 
        e.flow_id.toString().includes(keyword) || 
        (e.remark && e.remark.toLowerCase().includes(keyword))
    );
  }
  
  const sortedFlowRules = [...filteredFlowRules].sort((a, b) => a.flow_id - b.flow_id);
  return sortedFlowRules.map((e) => ({
    value: e.flow_id,
    label: e.remark ? `${e.flow_id} - ${e.remark}` : e.flow_id,
  }));
});

const flow_search_loading = ref(false);
async function search_flows(query: string = "") {
  search_key.value = query;
  if (!query) {
    flow_search_loading.value = true;
    try {
      flow_rules.value = await get_flow_rules();
    } finally {
      flow_search_loading.value = false;
    }
  }
}
</script>

<template>
  <n-input-group>
    <n-select
      style="width: 50%"
      v-model:value="mark.t"
      :options="mark_type_option"
      placeholder="选择匹配方式"
    />
    <n-select
      style="width: 50%"
      v-if="mark.t === FlowDnsMarkType.Redirect"
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
</template>
