<script setup lang="ts">
import { ref } from "vue";

import { DotMark } from "@vicons/carbon";
import { useThemeVars } from "naive-ui";

import { start_dns_service, stop_dns_service } from "@/api/dns_service";
import DnsRuleDrawer from "@/components/dns/DnsRuleDrawer.vue";
import { useDnsStore } from "@/stores/status_dns";

const dnsStore = useDnsStore();
const themeVars = ref(useThemeVars());

const show_rule_drawer = ref(false);
const show_ip_rule = ref(false);

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
      <!-- <n-icon :color="dnsStore.dns_status.get_color(themeVars)" size="16">
        <DotMark />
      </n-icon> -->
      DNS
    </template>
    <template #header-extra>
      <n-flex>
        <n-button
          :focusable="false"
          size="small"
          @click="show_rule_drawer = true"
        >
          默认域名规则
        </n-button>
        <n-button :focusable="false" size="small" @click="show_ip_rule = true">
          默认 IP 规则
        </n-button>
        <!-- <n-button
          :focusable="false"
          size="small"
          @click="start_dns"
          v-if="dnsStore.is_down"
        >
          开启
        </n-button>
        <n-popconfirm v-else @positive-click="stop_dns">
          <template #trigger>
            <n-button :focusable="false" size="small" @click="">
              关闭
            </n-button>
          </template>
          确定停止吗
        </n-popconfirm> -->
      </n-flex>
    </template>
    <n-flex justify="center" align="center" style="flex: 1">
      <n-empty description="TODO"> </n-empty>
    </n-flex>
    <!-- {{ dnsStore.dns_status }} -->
    <!-- <template #footer> #footer </template>
    <template #action> #action </template> -->
    <DnsRuleDrawer v-model:show="show_rule_drawer" />
    <WanIpRuleDrawer v-model:show="show_ip_rule" />
  </n-card>
</template>
