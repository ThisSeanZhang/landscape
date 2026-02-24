<script setup lang="ts">
import { VueFlow, useVueFlow } from "@vue-flow/core";
import { MiniMap } from "@vue-flow/minimap";
import InteractionControls from "@/components/topology_v2/InteractionControls.vue";
import TopologyHeaderExtra from "@/components/topology_v2/TopologyHeaderExtra.vue";
import TopologyManagedNode from "@/components/topology_v2/node/TopologyManagedNode.vue";
import TopologyDockerNode from "@/components/topology_v2/node/TopologyDockerNode.vue";
import { add_controller } from "@/api/network";

import { useMessage, SelectOption } from "naive-ui";

import { onMounted, ref } from "vue";
import { WLANTypeTag } from "@/lib/dev";
import { useTopologyStore } from "@/stores/topology";

const naive_message = useMessage();

let ifaceNodeStore = useTopologyStore();
const { zoomOnScroll, fitView, onConnect, onNodeDragStop, id } = useVueFlow();

zoomOnScroll.value = false;

// 监听节点拖拽结束，保存位置
onNodeDragStop((event) => {
  const { node } = event;
  ifaceNodeStore.save_node_position(node.id, node.position, true);
});

onMounted(async () => {
  await ifaceNodeStore.UPDATE_INFO();
  fitView({ padding: 0.3 });
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
      "连接的双方, 必须要有一个是 Bridge, 且只能从 Bridge 的右边开始连",
    );
  }

  let dev = ifaceNodeStore.FIND_DEV_BY_IFNAME(params.target);
  if (dev?.wifi_info !== undefined) {
    if (dev.wifi_info.wifi_type.t !== WLANTypeTag.Ap) {
      naive_message.warning(
        "当前无线网卡为客户端模式, 需要转为 AP 模式才能加入桥接网络",
      );
    }
  }
  let master_dev = ifaceNodeStore.FIND_DEV_BY_IFNAME(params.source);
  if (dev) {
    if (dev.controller_id || dev.controller_name) {
      naive_message.error("此设备已有上级设备了");
    }
    await add_controller({
      link_name: dev.name,
      link_ifindex: parseInt(params.target),
      master_ifindex: parseInt(params.source),
      master_name: master_dev?.name ?? null,
    });
    await ifaceNodeStore.UPDATE_INFO();
    // 检查 target 是否有
    console.log(params);
  } else {
    naive_message.error("找不到设备");
  }
});
const controlelr_config = ref<any>({});

async function create_connection() {
  await add_controller(controlelr_config.value);
  controlelr_config.value = {};
  await ifaceNodeStore.UPDATE_INFO();
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
    <template #node-managed="{ data }">
      <!-- {{ data }} -->
      <TopologyManagedNode
        v-if="data.dev.status !== null && data.dev.status !== undefined"
        :config="data.dev.config"
        :status="data.dev.status"
        :wifi_info="data.dev.wifi_info"
      />
      <TopologyManagedButDevMissNode v-else :config="data.dev.config" />
    </template>
    <template #node-unmanaged="{ data }">
      <TopologyUnManagedNode
        v-model:out_data="data.out_data"
        :node="data.dev.status"
      />
    </template>
    <template #node-unmanaged-docker="{ data }">
      <!-- {{ data }} -->
      <!-- <TopologyNetNode :node="data.dev" /> -->
      <TopologyDockerNode :node="data.dev.status" />
    </template>
    <template #node-docker-leaf="{ data }">
      <!-- {{ nodeProps }} -->
      <TopologyDockerLeafNode :node="data.dev.status" />
    </template>

    <!-- <InteractionControls /> -->

    <TopologyHeaderExtra />
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
