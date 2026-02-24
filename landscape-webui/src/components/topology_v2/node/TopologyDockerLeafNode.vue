<script setup lang="ts">
import { Handle, Position, useNodesData } from "@vue-flow/core";
import { useThemeVars } from "naive-ui";

import IPConfigStatusBtn from "@/components/status_btn/IPConfigStatusBtn.vue";
import IPv6PDStatusBtn from "@/components/status_btn/IPv6PDStatusBtn.vue";
import ICMPv6RAStatusBtn from "@/components/status_btn/ICMPv6RAStatusBtn.vue";
import WifiStatusBtn from "@/components/status_btn/WifiStatusBtn.vue";
import NetAddrTransBtn from "@/components/status_btn/NetAddrTransBtn.vue";
import DHCPv4StatusBtn from "@/components/status_btn/DHCPv4StatusBtn.vue";

import IpConfigModal from "@/components/ipconfig/IpConfigModal.vue";
import NATEditModal from "@/components/nat/NATEditModal.vue";
import FirewallServiceEditModal from "@/components/firewall/FirewallServiceEditModal.vue";
import IPv6PDEditModal from "@/components/ipv6pd/IPv6PDEditModal.vue";
import WifiServiceEditModal from "@/components/wifi/WifiServiceEditModal.vue";
import DHCPv4ServiceEditModal from "@/components/dhcp_v4/DHCPv4ServiceEditModal.vue";

import IfaceChangeZone from "@/components/iface/IfaceChangeZone.vue";
import { AreaCustom, Power, Link, DotMark } from "@vicons/carbon";
import { PlugDisconnected20Regular } from "@vicons/fluent";
import { computed, ref } from "vue";

import { DevStateType, NetDev } from "@/lib/dev";
import { useIfaceNodeStore } from "@/stores/iface_node";
import { add_controller, change_iface_status } from "@/api/network";
import { ServiceExhibitSwitch } from "@/lib/services";
import type { NetworkIfaceConfig } from "@landscape-router/types/api/schemas";

const props = defineProps<{
  node: NetworkIfaceConfig;
}>();
</script>

<template>
  <n-card size="small" style="min-width: 220px; max-width: 230px">
    <template #header>
      <n-flex style="gap: 3px" inline align="center">
        <n-icon size="16">
          <DotMark />
        </n-icon>
        {{ node.name }}
      </n-flex>
    </template>
  </n-card>

  <Handle v-if="true" type="target" :position="Position.Left" />
</template>

<style scoped>
.undefined {
  color: whitesmoke;
}

.wan {
  color: rgb(255, 99, 71);
}

.lan {
  color: rgb(0, 102, 204);
}
</style>
