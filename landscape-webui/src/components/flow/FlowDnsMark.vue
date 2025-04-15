<script setup lang="ts">
import { FlowDnsMarkType } from "@/lib/default_value";
import { FlowDnsMark } from "@/rust_bindings/flow";

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
  {
    label: "允许端口共享",
    value: FlowDnsMarkType.AllowReusePort,
  },
];
</script>

<template>
  <n-input-group>
    <n-select
      style="width: 38%"
      v-model:value="mark.t"
      :options="mark_type_option"
      placeholder="选择匹配方式"
    />
    <n-input-number
      :show-button="false"
      v-if="mark.t === FlowDnsMarkType.Redirect"
      placeholder="重定向的流 ID"
      v-model:value="mark.flow_id"
      type="text"
    />
  </n-input-group>
</template>
