<script setup lang="ts">
import { VueFlow, useVueFlow } from "@vue-flow/core";
import { MiniMap } from "@vue-flow/minimap";
import InteractionControls from "@/components/flow/InteractionControls.vue";
import FlowHeaderExtra from "@/components/flow_v2/FlowHeaderExtra.vue";
import TopologyNetNode from "@/components/flow_v2/TopologyNetNode.vue";
import TopologyDockerNode from "@/components/flow_v2/TopologyDockerNode.vue";
import { add_controller } from "@/api/network";

import { useMessage, SelectOption } from "naive-ui";

import { onMounted, ref } from "vue";
import { WLANTypeTag } from "@/lib/dev";
import { useTopologyStore } from "@/stores/topology";

const naive_message = useMessage();

let ifaceNodeStore = useTopologyStore();
const { zoomOnScroll, fitView, onConnect, id } = useVueFlow();

zoomOnScroll.value = false;

onMounted(async () => {
  await ifaceNodeStore.UPDATE_INFO();
  fitView({ padding: 0.23 });
});

onConnect(async (params: any) => {
  // source 相当于 master_ifindex
  const is_source_bridge = ifaceNodeStore.FIND_BRIDGE_BY_IFNAME(params.source);
  const is_target_bridge = ifaceNodeStore.FIND_BRIDGE_BY_IFNAME(params.target);
  if (is_source_bridge && is_target_bridge) {
    naive_message.warning("还没做好 Bridge 环路检测");
  } else if (is_target_bridge) {
    naive_message.warning("只能从 Bridge 的右边开始连");
  } else if (!is_source_bridge && !is_target_bridge) {
    naive_message.warning(
      "连接的双方, 必须要有一个是 Bridge, 且只能从 Bridge 的右边开始连"
    );
  }

  let dev = ifaceNodeStore.FIND_DEV_BY_IFNAME(params.target);
  if (dev?.wifi_info !== undefined) {
    if (dev.wifi_info.wifi_type.t !== WLANTypeTag.Ap) {
      naive_message.warning(
        "当前无线网卡为客户端模式, 需要转为 AP 模式才能加入桥接网络"
      );
    }
  }
  let master_dev = ifaceNodeStore.FIND_DEV_BY_IFNAME(params.source);
  if (dev) {
    if (dev.controller_id || dev.controller_name) {
      naive_message.error("此设备已有上级设备了");
    }
    let result = await add_controller({
      link_name: dev.name,
      link_ifindex: parseInt(params.target),
      master_ifindex: parseInt(params.source),
      master_name: master_dev?.name,
    });
    if (result) {
      await ifaceNodeStore.UPDATE_INFO();
    }
    // 检查 target 是否有
    console.log(params);
  } else {
    naive_message.error("找不到设备");
  }
});
const controlelr_config = ref<any>({});

async function create_connection() {
  let result = await add_controller(controlelr_config.value);
  controlelr_config.value = {};
  if (result) {
    await ifaceNodeStore.UPDATE_INFO();
  }
}
// onConnect((connection) => {
//   console.log(connection);
// });
function handleMasterUpdate(value: string, option: SelectOption) {
  controlelr_config.value.master_ifindex = option.ifindex;
}
function handleIfaceUpdate(value: string, option: SelectOption) {
  controlelr_config.value.link_ifindex = option.ifindex;
}
</script>

<template>
  <!-- {{ ifaceNodeStore.topo_nodes }}
  {{ ifaceNodeStore.topo_edges }} -->
  <VueFlow
    :nodes="ifaceNodeStore.topo_nodes"
    :edges="ifaceNodeStore.topo_edges"
    fit-view-on-init
    style="min-height: 600px; min-width: 100%"
  >
    <!-- bind your custom node type to a component by using slots, slot names are always `node-<type>` -->
    <!-- <template #node-special="specialNodeProps">
        <SpecialNode v-bind="specialNodeProps" />
      </template> -->

    <!-- bind your custom edge type to a component by using slots, slot names are always `edge-<type>` -->
    <!-- <template #edge-special="specialEdgeProps">
      <SpecialEdge v-bind="specialEdgeProps" />
    </template> -->
    <!-- <MiniMap pannable zoomable /> -->
    <template #node-netflow="{ data }">
      <!-- {{ nodeProps }} -->
      <TopologyNetNode :node="data.dev" />
    </template>
    <template #node-docker="{ data }">
      <!-- {{ nodeProps }} -->
      <TopologyDockerNode :node="data.dev" />
    </template>

    <!-- <InteractionControls /> -->

    <FlowHeaderExtra />
  </VueFlow>
</template>

<style>
/* import the necessary styles for Vue Flow to work */
@import "@vue-flow/core/dist/style.css";

/* import the default theme, this is optional but generally recommended */
@import "@vue-flow/core/dist/theme-default.css";

/* import default minimap styles */
@import "@vue-flow/minimap/dist/style.css";
/* @import '@vue-flow/controls/dist/style.css'; */
</style>
