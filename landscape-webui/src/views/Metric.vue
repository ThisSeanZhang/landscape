<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from "vue";
import { useMetricStore } from "@/stores/status_metric";
import { ConnectFilter } from "@/lib/metric.rs";

const metricStore = useMetricStore();

// 添加防抖和加载状态
const loading = ref(false);
let updateInfoTimeout: number | null = null;

onMounted(async () => {
  metricStore.SET_ENABLE(true);
  await updateInfoWithDebounce();
});

onUnmounted(() => {
  metricStore.SET_ENABLE(false);
  if (updateInfoTimeout) {
    clearTimeout(updateInfoTimeout);
  }
});

// 防抖更新信息
async function updateInfoWithDebounce() {
  if (updateInfoTimeout) {
    clearTimeout(updateInfoTimeout);
  }
  
  loading.value = true;
  // 延迟100ms执行更新，避免频繁请求
  updateInfoTimeout = window.setTimeout(async () => {
    await metricStore.UPDATE_INFO();
    loading.value = false;
  }, 100);
}

// 初始化过滤器
const filter = ref(new ConnectFilter());

// 协议类型选项
const protocolOptions = [
  { label: "全部", value: undefined },
  { label: "TCP", value: 6 },
  { label: "UDP", value: 17 },
  { label: "ICMP", value: 1 },
];

// IP 类型选项
const ipTypeOptions = [
  { label: "全部", value: undefined },
  { label: "IPv4", value: 0 },
  { label: "IPv6", value: 1 },
];

// 计算过滤后的连接指标
const filteredConnectMetrics = computed(() => {
  if (!metricStore.firewall_info) return [];

  return metricStore.firewall_info.filter((item) => {
    const key = item;

    // 源IP过滤 (支持部分匹配)
    if (filter.value.src_ip && !key.src_ip.includes(filter.value.src_ip)) {
      return false;
    }

    // 目标IP过滤 (支持部分匹配)
    if (filter.value.dst_ip && !key.dst_ip.includes(filter.value.dst_ip)) {
      return false;
    }

    // 源端口精准匹配
    if (
      filter.value.port_start !== null &&
      key.src_port !== filter.value.port_start
    ) {
      return false;
    }

    // 目标端口精准匹配
    if (
      filter.value.port_end !== null &&
      key.dst_port !== filter.value.port_end
    ) {
      return false;
    }

    // L3协议过滤 (精确匹配)
    if (
      filter.value.l3_proto !== null &&
      key.l3_proto !== filter.value.l3_proto
    ) {
      return false;
    }

    // L4协议过滤 (精确匹配)
    if (
      filter.value.l4_proto !== null &&
      key.l4_proto !== filter.value.l4_proto
    ) {
      return false;
    }

    // Flow ID过滤 (精确匹配)
    if (filter.value.flow_id !== null && key.flow_id !== filter.value.flow_id) {
      return false;
    }

    return true;
  });
});

// 重置过滤器
const resetFilter = () => {
  filter.value = new ConnectFilter();
};

// 应用过滤器 (防抖)
const applyFilter = () => {
  updateInfoWithDebounce();
};
</script>

<template>
  <n-flex style="flex: 1; overflow: hidden; margin-bottom: 10px" vertical>
    <n-alert title="注意" type="warning">
      当前的指标是以 5s 为单位, 并且短链接不会生成图表. 当前为简单版本,
      后续还将修改
    </n-alert>
    <n-flex :wrap="false">
      <!-- 源 IP -->
      <n-input
        v-model:value="filter.src_ip"
        placeholder="源IP"
        clearable
        style="width: 180px"
      />

      <!-- 目标 IP -->
      <n-input
        v-model:value="filter.dst_ip"
        placeholder="目标IP"
        clearable
        style="width: 180px"
      />

      <n-input-group style="width: 240px">
        <n-input-number
          v-model:value="filter.port_start"
          placeholder="源端口"
          :show-button="false"
          :min="1"
          :max="65535"
          clearable
        />
        <n-input-group-label>=></n-input-group-label>
        <n-input-number
          v-model:value="filter.port_end"
          placeholder="目标端口"
          :show-button="false"
          :min="1"
          :max="65535"
          clearable
        />
      </n-input-group>

      <!-- L4 协议类型 -->
      <n-select
        v-model:value="filter.l4_proto"
        placeholder="传输协议"
        :options="protocolOptions"
        clearable
        style="width: 140px"
      />

      <!-- L3 协议类型 -->
      <n-select
        v-model:value="filter.l3_proto"
        placeholder="IP协议"
        :options="ipTypeOptions"
        clearable
        style="width: 120px"
      />
      <!-- flow id -->
      <n-input-number
        v-model:value="filter.flow_id"
        placeholder="Flow ID"
        :min="1"
        :max="255"
        clearable
        style="width: 120px"
      />

      <n-button @click="applyFilter" type="primary" :loading="loading">过滤</n-button>
      <n-button @click="resetFilter" :disabled="loading">重置</n-button>
    </n-flex>

    <n-spin :show="loading">
      <n-virtual-list 
        v-if="filteredConnectMetrics.length > 0" 
        :item-height="180" 
        :items="filteredConnectMetrics" 
        style="flex: 1"
        height="100%"
      >
        <template #default="{ item }">
          <ConnectList :connect_metrics="[item]" :key="item" />
        </template>
      </n-virtual-list>
      
      <n-empty 
        v-else
        description="没有连接数据"
        style="flex: 1; display: flex; align-items: center; justify-content: center;"
      />
    </n-spin>
  </n-flex>
</template>
