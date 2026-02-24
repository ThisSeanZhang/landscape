<script setup lang="ts">
import type { FlowEntryRule } from "landscape-types/api/schemas";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";

interface Prop {
  rule: FlowEntryRule;
}

const enrolledDeviceStore = useEnrolledDeviceStore();
defineProps<Prop>();
</script>

<template>
  <n-tag :bordered="false" v-if="rule.mode.t === 'mac'">
    {{ enrolledDeviceStore.GET_NAME_WITH_FALLBACK(rule.mode.mac_addr) }}
  </n-tag>
  <n-tag :bordered="false" v-else>
    {{
      enrolledDeviceStore.GET_NAME_WITH_FALLBACK(
        rule.mode.ip,
        `${rule.mode.ip}/${rule.mode.prefix_len}`,
      )
    }}
  </n-tag>
</template>
