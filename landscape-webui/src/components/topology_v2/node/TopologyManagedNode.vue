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
import { TopologyServiceExhibitSwitch } from "@/lib/services";
import {
  LandscapeInterface,
  LandscapeWifiInterface,
} from "landscape-types/iface";
import { NetworkIfaceConfig } from "landscape-types/common/iface";
import { ZoneType } from "@/lib/service_ipconfig";

const props = defineProps<{
  config: NetworkIfaceConfig;
  status: LandscapeInterface;
  wifi_info: LandscapeWifiInterface | null;
  // node: NetDev;
}>();

const themeVars = ref(useThemeVars());
const ifaceNodeStore = useIfaceNodeStore();
// const connections = useHandleConnections({
//   type: 'target',
// })

// const nodesData = useNodesData(() => connections.value[0]?.source)
const iface_dhcp_v4_service_edit_show = ref(false);
const iface_wifi_edit_show = ref(false);
const iface_firewall_edit_show = ref(false);
const iface_icmpv6ra_edit_show = ref(false);
const iface_ipv6pd_edit_show = ref(false);
const iface_nat_edit_show = ref(false);
const iface_service_edit_show = ref(false);
const show_zone_change = ref(false);
const show_pppd_drawer = ref(false);
function handleUpdateShow(show: boolean) {
  if (show) {
  }
}

async function refresh() {
  await ifaceNodeStore.UPDATE_INFO();
}

async function change_dev_status() {
  // if (props.node === undefined) {
  //   return;
  // }
  if (props.status.dev_status.t == DevStateType.Up) {
    await change_iface_status(props.config.name, false);
  } else {
    await change_iface_status(props.config.name, true);
  }
  await refresh();
}

async function remove_controller() {
  await add_controller({
    link_name: props.status.iface_name as string,
    link_ifindex: props.status.index as number,
    master_name: undefined,
    master_ifindex: undefined,
  });
  await refresh();
}

const show_switch = computed(() => {
  return new TopologyServiceExhibitSwitch(
    props.config,
    props.status,
    props.wifi_info
  );
});

function has_target_hook() {
  if (props.config.zone_type == ZoneType.Wan) {
    return false;
  } else if (props.config.zone_type == ZoneType.Lan) {
    return false;
  } else if (props.config.zone_type == ZoneType.Undefined) {
    return true;
  }
  return false;
}

// right Handle
function has_source_hook() {
  if (props.config.zone_type == ZoneType.Wan) {
    return false;
  } else if (props.status.dev_kind == "bridge") {
    return true;
  } else if (props.config.zone_type == ZoneType.Lan) {
    return true;
  } else if (props.config.zone_type == ZoneType.Undefined) {
    return false;
  }
  return false;
}
</script>

<template>
  <!-- {{ has_source_hook() }} -->
  <!-- {{ show_switch }} -->
  <!-- <NodeToolbar
    style="display: flex; gap: 0.5rem; align-items: center"
    :is-visible="undefined"
    :position="Position.Top"
  >
    <button>Action1</button>
    <button>Action2</button>
    <button>Action3</button>
  </NodeToolbar> -->
  <n-flex vertical>
    <n-popover
      trigger="hover"
      :show-arrow="false"
      @update:show="handleUpdateShow"
      style="padding: 0; background: transparent;"
    >
      <template #trigger>
        <n-card size="small" style="min-width: 220px; max-width: 230px">
          <template #header>
            <n-flex style="gap: 3px" inline align="center">
              <n-icon
                v-if="show_switch.carrier"
                :color="status.carrier ? themeVars.successColor : ''"
                size="16"
              >
                <DotMark />
              </n-icon>
              {{ config.name }}
            </n-flex>
          </template>
          <template #header-extra>
            <n-flex>
              <n-popconfirm
                v-if="show_switch.enable_in_boot"
                @positive-click="change_dev_status"
              >
                <template #trigger>
                  <n-button
                    text
                    :type="
                      status.dev_status.t === DevStateType.Up
                        ? 'info'
                        : 'default'
                    "
                    :focusable="false"
                    style="font-size: 16px"
                  >
                    <n-icon>
                      <Power></Power>
                    </n-icon>
                  </n-button>
                </template>
                确定
                {{ status.dev_status.t === DevStateType.Up ? "关闭" : "开启" }}
                网卡吗
              </n-popconfirm>
              <n-button
                v-if="show_switch.zone_type"
                :class="config.zone_type"
                text
                :focusable="false"
                style="font-size: 16px"
                @click="show_zone_change = true"
              >
                <n-icon>
                  <AreaCustom></AreaCustom>
                </n-icon>
              </n-button>

              <n-button
                v-if="show_switch.pppd"
                text
                :focusable="false"
                style="font-size: 16px"
                @click="show_pppd_drawer = true"
              >
                <n-icon>
                  <Link></Link>
                </n-icon>
              </n-button>

              <WifiModeChange
                :iface_name="config.name"
                :show_switch="show_switch"
                @refresh="refresh"
              />
            </n-flex>
          </template>
        </n-card>
      </template>
      
      <n-card size="small" style="min-width: 260px; max-width: 300px; border: none;">
          <n-flex align="center" justify="space-between" style="margin-bottom: 12px;">
             <span style="font-weight: 600">设备详情</span>
             <n-tag
                size="small"
                :bordered="false"
                :type="status.dev_status.t === DevStateType.Up ? 'success' : 'error'"
              >
                {{ status.dev_status.t }}
              </n-tag>
          </n-flex>

          <!-- Mac Addresses -->
          <n-grid :cols="1" :y-gap="4" style="margin-bottom: 12px">
             <n-gi>
                <n-text depth="3" style="font-size: 12px">MAC: {{ status.mac ?? "N/A" }}</n-text>
             </n-gi>
             <n-gi>
                <n-text depth="3" style="font-size: 12px">Perm MAC: {{ status.perm_mac ?? "N/A" }}</n-text>
             </n-gi>
          </n-grid>

          <n-divider style="margin: 0 0 12px 0" />

          <!-- Details Grid -->
          <n-grid :cols="2" :x-gap="12" :y-gap="8" style="margin-bottom: 12px">
            <n-gi>
              <n-statistic label="类型" style="zoom: 0.9">
                <template #default>
                  <n-tag size="small" :bordered="false" type="info">
                    {{ status.dev_type ?? "N/A" }}
                  </n-tag>
                </template>
              </n-statistic>
            </n-gi>
            <n-gi>
              <n-statistic label="Kind" style="zoom: 0.9">
                <template #default>
                  <n-tag size="small" :bordered="false">
                    {{ status.dev_kind ?? "N/A" }}
                  </n-tag>
                </template>
              </n-statistic>
            </n-gi>
          </n-grid>

           <!-- Controller Info if present -->
          <div v-if="config.controller_name || status.controller_id">
             <n-text depth="3" style="font-size: 12px; display: block; margin-bottom: 4px">上层设备</n-text>
             <n-flex align="center" justify="space-between" style="background: rgba(128,128,128,0.1); padding: 4px 8px; border-radius: 4px;">
                <n-text>
                  {{ status.controller_id ?? "N/A" }}
                  <span v-if="config.controller_name" style="opacity: 0.7">({{ config.controller_name }})</span>
                </n-text>
                 <n-button
                    tertiary
                    type="error"
                    size="tiny"
                    :focusable="false"
                    @click="remove_controller"
                  >
                    <template #icon>
                      <n-icon><PlugDisconnected20Regular /></n-icon>
                    </template>
                  </n-button>
             </n-flex>
          </div>
      </n-card>
    </n-popover>

    <n-flex style="min-width: 240px; max-width: 240px">
      <!-- IP 配置 按钮 -->
      <IPConfigStatusBtn
        v-if="show_switch.ip_config"
        @click="iface_service_edit_show = true"
        :iface_name="config.name"
        :zone="config.zone_type"
      />
      <!-- DHCPv4 按钮 -->
      <DHCPv4StatusBtn
        v-if="show_switch.dhcp_v4"
        @click="iface_dhcp_v4_service_edit_show = true"
        :iface_name="config.name"
        :zone="config.zone_type"
      />
      <FirewallStatusBtn
        v-if="show_switch.nat_config"
        @click="iface_firewall_edit_show = true"
        :iface_name="config.name"
        :zone="config.zone_type"
      />
      <!-- NAT 配置 按钮 -->
      <NetAddrTransBtn
        v-if="show_switch.nat_config"
        @click="iface_nat_edit_show = true"
        :iface_name="config.name"
        :zone="config.zone_type"
      />
      <!-- IPV6PD 配置按钮 -->
      <IPv6PDStatusBtn
        v-if="show_switch.ipv6pd"
        @click="iface_ipv6pd_edit_show = true"
        :iface_name="config.name"
        :zone="config.zone_type"
      />
      <!-- ICMPv6 RA -->
      <ICMPv6RAStatusBtn
        v-if="show_switch.icmpv6ra"
        @click="iface_icmpv6ra_edit_show = true"
        :iface_name="config.name"
        :zone="config.zone_type"
      />

      <!-- Wifi -->
      <WifiStatusBtn
        v-if="show_switch.wifi"
        @click="iface_wifi_edit_show = true"
        :iface_name="config.name"
        :zone="config.zone_type"
      />
    </n-flex>
  </n-flex>

  <Handle v-if="has_target_hook()" type="target" :position="Position.Left" />
  <Handle v-if="has_source_hook()" type="source" :position="Position.Right" />

  <IpConfigModal
    v-model:show="iface_service_edit_show"
    :zone="config.zone_type"
    :iface_name="config.name"
    @refresh="refresh"
  />
  <DHCPv4ServiceEditModal
    v-model:show="iface_dhcp_v4_service_edit_show"
    :zone="config.zone_type"
    :iface_name="config.name"
    @refresh="refresh"
  />
  <NATEditModal
    v-model:show="iface_nat_edit_show"
    :zone="config.zone_type"
    :iface_name="config.name"
    @refresh="refresh"
  />
  <IfaceChangeZone
    v-model:show="show_zone_change"
    :zone="config.zone_type"
    :iface_name="config.name"
    @refresh="refresh"
  />

  <PPPDServiceListDrawer
    v-model:show="show_pppd_drawer"
    :attach_iface_name="config.name"
    @refresh="refresh"
  />
  <IPv6PDEditModal
    v-model:show="iface_ipv6pd_edit_show"
    :zone="config.zone_type"
    :iface_name="config.name"
    :mac="status.mac"
    @refresh="refresh"
  />
  <ICMPRaEditModal
    v-model:show="iface_icmpv6ra_edit_show"
    :zone="config.zone_type"
    :iface_name="config.name"
    :mac="status.mac"
    @refresh="refresh"
  />
  <FirewallServiceEditModal
    v-model:show="iface_firewall_edit_show"
    :zone="config.zone_type"
    :iface_name="config.name"
    :mac="status.mac"
    @refresh="refresh"
  />
  <WifiServiceEditModal
    v-model:show="iface_wifi_edit_show"
    :zone="config.zone_type"
    :iface_name="config.name"
    :mac="status.mac"
    @refresh="refresh"
  />
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
