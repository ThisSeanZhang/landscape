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
      {{ flow_id === 0 ? `默认路由出口发出` : `Flow ID ${flow_id} 的出口` }}
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.DIRECT"
    >
      默认路由出口发出
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.DROP"
      type="error"
    >
      丢弃
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.REDIRECT"
      type="warning"
    >
      <FlowExhibit :flow_id="mark.flow_id"></FlowExhibit>
    </n-tag>

    <n-tag v-if="mark.allow_reuse_port" :bordered="false" type="success">
      NAT1
    </n-tag>
    <!-- <n-tag v-else :bordered="false"> NAT4 </n-tag> -->
  </n-flex>
</template>
