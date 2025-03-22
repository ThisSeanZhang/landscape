<script setup lang="ts">
import { ref } from "vue";
import FirewallRuleDrawer from "@/components/firewall/FirewallRuleDrawer.vue";

const show_rule_drawer = ref(false);
</script>
<template>
  <n-card title="防火墙">
    <template #header-extra>
      <n-button
        :focusable="false"
        size="small"
        @click="show_rule_drawer = true"
      >
        规则配置
      </n-button>
    </template>
    <FirewallRuleDrawer v-model:show="show_rule_drawer" />
  </n-card>
</template>
