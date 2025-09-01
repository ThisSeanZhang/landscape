<script lang="ts" setup>
import { FlowMark } from "@/rust_bindings/flow";

type Props = {
  mark: FlowMark;
  flow_id: number;
};

defineProps<Props>();

enum FlowMarkActionCode {
  KEEP_GOING = "keep_going",
  DIRECT = "direct",
  DROP = "drop",
  REDIRECT = "redirect",
}
</script>
<template>
  <n-flex>
    <n-tag
      :bordered="false"
      v-if="mark.action.t == FlowMarkActionCode.KEEP_GOING"
    >
      {{
        flow_id === 0 ? `将使用默认出口发出` : `将使用 flow: ${flow_id} 的出口`
      }}
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.DIRECT"
    >
      将使用默认出口发出
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.DROP"
      type="error"
    >
      将丢弃相关数据包
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.REDIRECT"
      type="warning"
    >
      将使用 flow: {{ mark.flow_id }} 的出口
    </n-tag>

    <n-tag v-if="mark.allow_reuse_port" :bordered="false" type="success">
      NAT1
    </n-tag>
    <!-- <n-tag v-else :bordered="false"> NAT4 </n-tag> -->
  </n-flex>
</template>
