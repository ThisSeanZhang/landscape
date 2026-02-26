<script lang="ts" setup>
import type { FlowMark } from "@landscape-router/types/api/schemas";
import { useI18n } from "vue-i18n";

type Props = {
  mark: FlowMark;
  flow_id: number;
};

defineProps<Props>();
const { t } = useI18n();

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
        flow_id === 0
          ? t("flow.mark_exhibit.current_flow_egress")
          : t("flow.mark_exhibit.flow_id_egress", { flow_id })
      }}
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.DIRECT"
    >
      {{ t("flow.mark_exhibit.default_flow_egress") }}
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.DROP"
      type="error"
    >
      {{ t("flow.mark_exhibit.drop") }}
    </n-tag>
    <n-tag
      :bordered="false"
      v-else-if="mark.action.t == FlowMarkActionCode.REDIRECT"
      type="warning"
    >
      <FlowExhibit :flow_id="mark.flow_id"></FlowExhibit>
    </n-tag>

    <n-tag v-if="mark.allow_reuse_port" :bordered="false" type="success">
      {{ t("flow.mark_exhibit.nat1") }}
    </n-tag>
    <!-- <n-tag v-else :bordered="false"> NAT4 </n-tag> -->
  </n-flex>
</template>
