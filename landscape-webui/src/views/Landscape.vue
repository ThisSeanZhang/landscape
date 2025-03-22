<script setup lang="ts">
import { useI18n } from "vue-i18n";

import PacketDump from "@/components/PacketDump.vue";
import CPUUsage from "@/components/sysinfo/CPUUsage.vue";
import MemUsage from "@/components/sysinfo/MemUsage.vue";
import DnsStatusCard from "@/components/dns/DnsStatusCard.vue";
import DockerStatusCard from "@/components/docker/DockerStatusCard.vue";
import DockerAllContainer from "@/components/docker/DockerAllContainer.vue";
import FirewallCard from "@/components/firewall/FirewallCard.vue";
import SystemInfo from "@/components/sysinfo/SystemInfo.vue";
import IntervalFetch from "@/components/head/IntervalFetch.vue";
import LanguageSetting from "@/components/head/LanguageSetting.vue";

import CopyRight from "@/components/CopyRight.vue";
import NetFlow from "@/components/flow/NetFlow.vue";

import { ref } from "vue";
import MarkRuleCard from "@/components/mark/MarkRuleCard.vue";

const show_dump = ref(false);

const { t } = useI18n({ useScope: "global" });
</script>

<template>
  <n-layout position="absolute" style="">
    <n-layout-header style="height: 24px; padding: 0 10px; display: flex">
      <n-flex style="flex: 1" justify="space-between" align="center">
        <n-flex>Landscape</n-flex>
        <n-flex>
          <LanguageSetting />
          <IntervalFetch />
        </n-flex>
      </n-flex>
    </n-layout-header>
    <!-- <n-layout has-sider>
    <n-layout-sider content-style="padding: 24px;">
      海淀桥
    </n-layout-sider>
    <n-layout-content content-style="padding: 24px;">
      平山道
    </n-layout-content>
  </n-layout> -->
    <n-layout-content
      :native-scrollbar="false"
      position="absolute"
      style="top: 24px; bottom: 24px"
      content-class="main-body"
      content-style="padding: 10px;"
    >
      <n-flex vertical>
        <n-grid x-gap="12" y-gap="12" cols="1 600:2 1200:4 1900:6">
          <n-gi :span="1">
            <SystemInfo></SystemInfo>
          </n-gi>
          <n-gi style="display: flex; height: 320px" :span="1">
            <CPUUsage></CPUUsage>
          </n-gi>
          <n-gi style="display: flex; height: 320px" :span="1">
            <MemUsage></MemUsage>
          </n-gi>
          <n-gi style="display: flex; height: 320px" :span="1">
            <DnsStatusCard></DnsStatusCard>
          </n-gi>
          <n-gi style="display: flex; height: 320px" :span="1">
            <DockerStatusCard></DockerStatusCard>
          </n-gi>
          <n-gi style="display: flex; height: 320px" :span="1">
            <MarkRuleCard></MarkRuleCard>
          </n-gi>
          <n-gi style="display: flex; height: 320px" :span="1">
            <FirewallCard></FirewallCard>
          </n-gi>
          <!-- <n-gi style="display: flex; height: 320px" :span="1">
            <FireWallStatusCard></FireWallStatusCard>
          </n-gi> -->
        </n-grid>
        <n-divider style="margin: 16px 0" title-placement="left">
          {{ t("docker_divider") }}
        </n-divider>
        <DockerAllContainer></DockerAllContainer>
        <n-divider style="margin: 16px 0" title-placement="left">
          {{ t("topology_divider") }}
        </n-divider>
        <NetFlow></NetFlow>
      </n-flex>

      <!-- <n-button @click="show_dump = true">Show DUMP</n-button> -->

      <PacketDump v-model="show_dump"></PacketDump>
    </n-layout-content>
    <n-layout-footer
      position="absolute"
      style="height: 24px"
      content-style="dispaly: flex; height: 24px"
    >
      <n-flex style="height: 24px" align="center">
        <CopyRight :icon="true"></CopyRight>
      </n-flex>
    </n-layout-footer>
  </n-layout>
</template>
