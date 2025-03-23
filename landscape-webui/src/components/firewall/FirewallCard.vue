<script setup lang="ts">
import { ref } from "vue";
import FirewallRuleDrawer from "@/components/firewall/FirewallRuleDrawer.vue";

const show_rule_drawer = ref(false);
</script>
<template>
  <n-card title="防火墙" content-style="display: flex;">
    <template #header-extra>
      <n-button
        :focusable="false"
        size="small"
        @click="show_rule_drawer = true"
      >
        规则配置
      </n-button>
    </template>
    <n-flex justify="center" align="center" style="flex: 1">
      <n-empty description="TODO"> </n-empty>
    </n-flex>
    <FirewallRuleDrawer v-model:show="show_rule_drawer" />
  </n-card>
</template>
