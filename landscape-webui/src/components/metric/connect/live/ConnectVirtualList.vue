<script setup lang="ts">
import { ref } from "vue";
import {
  ConnectKey,
  ConnectRealtimeStatus,
} from "landscape-types/common/metric/connect";
import { useFrontEndStore } from "@/stores/front_end_config";
import ConnectItemInfo from "./ConnectItemInfo.vue";
import ConnectChartDrawer from "../ConnectChartDrawer.vue";

const frontEndStore = useFrontEndStore();

interface Props {
  connect_metrics: ConnectRealtimeStatus[];
}
const props = defineProps<Props>();

const show_chart = ref(false);
const show_chart_key = ref<ConnectKey | null>(null);
const show_chart_title = ref("");
async function show_chart_drawer(conn: ConnectRealtimeStatus) {
  show_chart_key.value = conn.key;
  show_chart_title.value = `${frontEndStore.MASK_INFO(conn.src_ip)}:${frontEndStore.MASK_PORT(conn.src_port)} => ${frontEndStore.MASK_INFO(conn.dst_ip)}:${frontEndStore.MASK_PORT(conn.dst_port)}`;
  show_chart.value = true;
}
const emit = defineEmits(["search:tuple", "search:src", "search:dst"]);
</script>

<template>
  <n-virtual-list class="list" :item-size="40" :items="props.connect_metrics">
    <template #default="{ item, index }">
      <ConnectItemInfo
        @show:chart="show_chart_drawer"
        @search:tuple="emit('search:tuple', $event)"
        @search:src="emit('search:src', $event)"
        @search:dst="emit('search:dst', $event)"
        :conn="item"
        :index="index"
      />
    </template>
  </n-virtual-list>

  <ConnectChartDrawer
    v-model:show="show_chart"
    :conn="show_chart_key"
    :title="show_chart_title"
  />
</template>

<style scoped>
.list {
  height: 100%;
}
</style>
