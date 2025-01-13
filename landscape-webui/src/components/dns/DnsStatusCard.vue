<script setup lang="ts">
import { computed, onMounted, ref } from "vue";

import { DotMark } from "@vicons/carbon";
import { useThemeVars } from "naive-ui";

import {
  get_dns_rule,
  get_dns_status,
  start_dns_service,
  stop_dns_service,
} from "@/api/dns_service";
import DnsRuleDrawer from "@/components/dns/DnsRuleDrawer.vue";
import { useDnsStore } from "@/stores/status_dns";
import { ServiceStatusType } from "@/lib/services";

const dnsStore = useDnsStore();
const themeVars = ref(useThemeVars());

const show_rule_drawer = ref(false);

async function start_dns() {
  await start_dns_service(53);
}

async function stop_dns() {
  await stop_dns_service();
}
</script>
<template>
  <n-card content-style="display: flex;">
    <template #header>
      <n-icon :color="dnsStore.dns_status.get_color(themeVars)" size="16">
        <DotMark />
      </n-icon>
      DNS
    </template>
    <template #header-extra>
      <n-flex>
        <n-button @click="show_rule_drawer = true">域名解析规则</n-button>
        <n-button @click="start_dns" v-if="dnsStore.is_down"> 开启 </n-button>
        <n-button v-else @click="stop_dns">关闭</n-button>
      </n-flex>
    </template>
    <n-flex justify="center" align="center" style="flex: 1">
      <n-empty description="TODO"> </n-empty>
    </n-flex>
    <!-- {{ dnsStore.dns_status }} -->
    <!-- <template #footer> #footer </template>
    <template #action> #action </template> -->
    <DnsRuleDrawer v-model:show="show_rule_drawer" />
  </n-card>
</template>
