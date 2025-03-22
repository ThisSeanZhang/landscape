<script setup lang="ts">
import { Handle, Position, useNodesData } from "@vue-flow/core";
import { useThemeVars } from "naive-ui";

import IpConfigModal from "@/components/ipconfig/IpConfigModal.vue";
import NATEditModal from "@/components/nat/NATEditModal.vue";
import MarkEditModal from "@/components/mark/MarkEditModal.vue";

import IfaceChangeZone from "../iface/IfaceChangeZone.vue";
import IPConfigStatusBtn from "@/components/status_btn/IPConfigStatusBtn.vue";
import NetAddrTransBtn from "@/components/status_btn/NetAddrTransBtn.vue";
import PacketMarkStatusBtn from "@/components/status_btn/PacketMarkStatusBtn.vue";
import { AreaCustom, Power, Link, DotMark } from "@vicons/carbon";
import { PlugDisconnected20Regular } from "@vicons/fluent";
import { Ethernet } from "@vicons/fa";
import { computed, ref } from "vue";

import { DevStateType } from "@/lib/dev";
import { useIfaceNodeStore } from "@/stores/iface_node";
import { add_controller, change_iface_status } from "@/api/network";
import { ZoneType } from "@/lib/service_ipconfig";
import { ServiceExhibitSwitch } from "@/lib/services";
import IPv6PDStatusBtn from "../status_btn/IPv6PDStatusBtn.vue";
import ICMPv6RAStatusBtn from "../status_btn/ICMPv6RAStatusBtn.vue";

import FirewallServiceEditModal from "@/components/firewall/FirewallServiceEditModal.vue";
import IPv6PDEditModal from "../ipv6pd/IPv6PDEditModal.vue";

// import { NodeToolbar } from "@vue-flow/node-toolbar";

const props = defineProps(["node"]);

const themeVars = ref(useThemeVars());
const ifaceNodeStore = useIfaceNodeStore();
// const connections = useHandleConnections({
//   type: 'target',
// })

// const nodesData = useNodesData(() => connections.value[0]?.source)

const iface_firewall_edit_show = ref(false);
const iface_icmpv6ra_edit_show = ref(false);
const iface_ipv6pd_edit_show = ref(false);
const iface_mark_edit_show = ref(false);
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
  if (props.node === undefined) {
    return;
  }
  if (props.node.dev_status.t == DevStateType.Up) {
    await change_iface_status(props.node.name, false);
  } else {
    await change_iface_status(props.node.name, true);
  }
  await refresh();
}

async function remove_controller() {
  await add_controller({
    link_name: props.node.name as string,
    link_ifindex: props.node.index as number,
    master_name: undefined,
    master_ifindex: undefined,
  });
  await refresh();
}

const show_switch = computed(() => {
  return new ServiceExhibitSwitch(props.node);
});

// const card_style = computed(() => {
//   if (props.node.zone_type == ZoneType.Wan) {
//     return "min-width: 330px";
//   } else if (props.node.zone_type == ZoneType.Lan) {
//     return "min-width: 220px";
//   } else {
//     return "min-width: 200px";
//   }
// });
</script>

<template>
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
  <!-- {{ node }} -->
  <n-flex vertical>
    <n-popover
      trigger="hover"
      :show-arrow="false"
      @update:show="handleUpdateShow"
    >
      <template #trigger>
        <n-card size="small" style="min-width: 220px; max-width: 230px">
          <template #header>
            <n-flex style="gap: 3px" inline align="center">
              <n-icon
                v-if="show_switch.carrier"
                :color="node.carrier ? themeVars.successColor : ''"
                size="16"
              >
                <DotMark />
              </n-icon>
              {{ node.name }}
            </n-flex>
          </template>
          <template #header-extra>
            <n-flex>
              <!-- <n-button
                v-if="show_switch.carrier"
                text
                :type="node.carrier ? 'info' : 'default'"
                :focusable="false"
                style="font-size: 16px"
              >
                <n-icon>
                  <Ethernet></Ethernet>
                </n-icon>
              </n-button> -->
              <n-popconfirm
                v-if="show_switch.enable_in_boot"
                @positive-click="change_dev_status"
              >
                <template #trigger>
                  <n-button
                    text
                    :type="
                      node.dev_status.t === DevStateType.Up ? 'info' : 'default'
                    "
                    :focusable="false"
                    style="font-size: 16px"
                  >
                    <n-icon>
                      <Power></Power>
                    </n-icon>
                  </n-button>
                </template>
                确定{{
                  node.dev_status.t === DevStateType.Up ? "关闭" : "开启"
                }}网卡吗
              </n-popconfirm>
              <n-button
                v-if="show_switch.zone_type"
                :class="node.zone_type"
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
            </n-flex>
          </template>
        </n-card>
      </template>
      <n-descriptions label-placement="left" :column="2">
        <n-descriptions-item label="mac地址">
          {{ node.mac ?? "N/A" }}
        </n-descriptions-item>
        <n-descriptions-item label="物理mca">
          {{ node.perm_mac ?? "N/A" }}
        </n-descriptions-item>
        <n-descriptions-item label="网路类型">
          {{ node.dev_type ?? "N/A" }}/{{ node.dev_kind ?? "N/A" }}
        </n-descriptions-item>
        <n-descriptions-item label="状态">
          {{ node.dev_status ?? "N/A" }}
        </n-descriptions-item>
        <n-descriptions-item label="上层控制设备(配置)">
          {{ node.controller_id == undefined ? "N/A" : node.controller_id }}
          ({{
            node.controller_name == undefined ? "N/A" : node.controller_name
          }})
          <n-button
            v-if="node.controller_name || node.controller_id"
            tertiary
            size="tiny"
            :focusable="false"
            @click="remove_controller"
            >断开连接
            <template #icon>
              <n-icon>
                <PlugDisconnected20Regular></PlugDisconnected20Regular>
              </n-icon>
            </template>
          </n-button>
        </n-descriptions-item>
      </n-descriptions>
      <!-- <n-divider /> -->
    </n-popover>

    <n-flex
      v-if="node.controller_id == undefined"
      style="min-width: 230px; max-width: 230px"
    >
      <!-- IP 配置 按钮 -->
      <IPConfigStatusBtn
        v-if="show_switch.ip_config"
        @click="iface_service_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />
      <FirewallStatusBtn
        v-if="show_switch.nat_config"
        @click="iface_firewall_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />
      <!-- NAT 配置 按钮 -->
      <NetAddrTransBtn
        v-if="show_switch.nat_config"
        @click="iface_nat_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />
      <!-- 标记服务配置按钮 -->
      <PacketMarkStatusBtn
        v-if="show_switch.mark_config"
        @click="iface_mark_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />
      <!-- IPV6PD 配置按钮 -->
      <IPv6PDStatusBtn
        v-if="show_switch.ipv6pd"
        @click="iface_ipv6pd_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />
      <!-- ICMPv6 RA -->
      <ICMPv6RAStatusBtn
        v-if="show_switch.icmpv6ra"
        @click="iface_icmpv6ra_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />
    </n-flex>
  </n-flex>

  <Handle
    v-if="node.has_target_hook()"
    type="target"
    :position="Position.Left"
  />
  <Handle
    v-if="node.has_source_hook()"
    type="source"
    :position="Position.Right"
  />

  <IpConfigModal
    v-model:show="iface_service_edit_show"
    :zone="node.zone_type"
    :iface_name="node.name"
    @refresh="refresh"
  />
  <NATEditModal
    v-model:show="iface_nat_edit_show"
    :zone="node.zone_type"
    :iface_name="node.name"
    @refresh="refresh"
  />
  <IfaceChangeZone
    v-model:show="show_zone_change"
    :zone="node.zone_type"
    :iface_name="node.name"
    @refresh="refresh"
  />

  <MarkEditModal
    v-model:show="iface_mark_edit_show"
    :zone="node.zone_type"
    :iface_name="node.name"
    @refresh="refresh"
  />

  <PPPDServiceListDrawer
    v-model:show="show_pppd_drawer"
    :attach_iface_name="node.name"
    @refresh="refresh"
  />
  <IPv6PDEditModal
    v-model:show="iface_ipv6pd_edit_show"
    :zone="node.zone_type"
    :iface_name="node.name"
    :mac="node.mac"
    @refresh="refresh"
  />
  <IcmpRAEditModal
    v-model:show="iface_icmpv6ra_edit_show"
    :zone="node.zone_type"
    :iface_name="node.name"
    :mac="node.mac"
    @refresh="refresh"
  />
  <FirewallServiceEditModal
    v-model:show="iface_firewall_edit_show"
    :zone="node.zone_type"
    :iface_name="node.name"
    :mac="node.mac"
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
