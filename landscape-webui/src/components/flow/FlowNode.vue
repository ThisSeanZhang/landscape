<script setup lang="ts">
import {
  Handle,
  Position,
  useHandleConnections,
  useNodesData,
} from "@vue-flow/core";
import IpConfigModal from "@/components/ipconfig/IpConfigModal.vue";
import NATEditModal from "@/components/nat/NATEditModal.vue";
import MarkEditModal from "@/components/mark/MarkEditModal.vue";

import IfaceChangeZone from "../iface/IfaceChangeZone.vue";
import IPConfigStatusBtn from "@/components/status_btn/IPConfigStatusBtn.vue";
import NetAddrTransBtn from "@/components/status_btn/NetAddrTransBtn.vue";
import PacketMarkStatusBtn from "@/components/status_btn/PacketMarkStatusBtn.vue";
import { AreaCustom, Power } from "@vicons/carbon";
import { PlugDisconnected20Regular } from "@vicons/fluent";
import { Ethernet } from "@vicons/fa";
import { ref } from "vue";

import { DevStateType } from "@/lib/dev";
import { useIfaceNodeStore } from "@/stores/iface_node";
import { add_controller, change_iface_status } from "@/api/network";
import { ZoneType } from "@/lib/service_ipconfig";

// import { NodeToolbar } from "@vue-flow/node-toolbar";

const props = defineProps(["node"]);

const ifaceNodeStore = useIfaceNodeStore();
// const connections = useHandleConnections({
//   type: 'target',
// })

// const nodesData = useNodesData(() => connections.value[0]?.source)

const iface_mark_edit_show = ref(false);
const iface_nat_edit_show = ref(false);
const iface_service_edit_show = ref(false);
const show_zone_change = ref(false);
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
</script>

<template>
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
        <n-card
          size="small"
          :class="node.zone_type"
          :title="node.name"
          style="min-width: 200px"
        >
          <template #header-extra>
            <!-- {{ node.zone_type }} -->
            <!-- <n-button size="small" @click="iface_edit_show = true"> IP </n-button> -->
            <!-- <n-button size="small" @click="iface_service_edit_show = true">
            服务配置
          </n-button> -->
            <n-flex>
              <n-button
                text
                :type="node.carrier ? 'info' : 'default'"
                :focusable="false"
                style="font-size: 16px"
              >
                <n-icon>
                  <Ethernet></Ethernet>
                </n-icon>
              </n-button>
              <n-button
                text
                :type="
                  node.dev_status.t === DevStateType.Up ? 'info' : 'default'
                "
                :focusable="false"
                style="font-size: 16px"
                @click="change_dev_status()"
              >
                <n-icon>
                  <Power></Power>
                </n-icon>
              </n-button>
              <n-button
                text
                :focusable="false"
                style="font-size: 16px"
                @click="show_zone_change = true"
              >
                <n-icon>
                  <AreaCustom></AreaCustom>
                </n-icon>
              </n-button>
            </n-flex>
          </template>
        </n-card>
      </template>
      <n-descriptions label-placement="left" :column="2">
        <n-descriptions-item label="mac地址">
          {{ node.mac }}
        </n-descriptions-item>
        <n-descriptions-item label="物理mca">
          {{ node.perm_mac == undefined ? "N/A" : node.perm_mac }}
        </n-descriptions-item>
        <n-descriptions-item label="网路类型">
          {{ node.dev_type }}/{{ node.dev_kind }}
        </n-descriptions-item>
        <n-descriptions-item label="状态">
          {{ node.dev_status }}
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

    <n-flex v-if="node.controller_id == undefined">
      <IPConfigStatusBtn
        @click="iface_service_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />
      <NetAddrTransBtn
        @click="iface_nat_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />

      <PacketMarkStatusBtn
        @click="iface_mark_edit_show = true"
        :iface_name="node.name"
        :zone="node.zone_type"
      />
    </n-flex>
  </n-flex>

  <Handle
    v-if="node.zone_type === ZoneType.Undefined"
    type="target"
    :position="Position.Left"
  />
  <Handle
    v-if="node.zone_type !== ZoneType.Wan"
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
</template>

<style scoped>
.undefined {
  background-color: whitesmoke;
}

.wan {
  background-color: rgba(249, 184, 45, 0.66);
}

.lan {
  background-color: rgba(78, 197, 197, 0.66);
}
</style>
