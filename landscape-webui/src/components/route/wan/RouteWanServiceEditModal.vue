<script setup lang="ts">
import { ref } from "vue";

import { IfaceZoneType } from "landscape-types/api/schemas";
import type { RouteWanServiceConfig } from "landscape-types/api/schemas";
import { useRouteWanConfigStore } from "@/stores/status_route_wan";
import {
  get_route_wan_config,
  update_route_wans_config,
} from "@/api/route/wan";

let routeWanConfigStore = useRouteWanConfigStore();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const service_config = ref<RouteWanServiceConfig | null>(null);

async function on_modal_enter() {
  try {
    let config = await get_route_wan_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    service_config.value = {
      iface_name: iface_info.iface_name,
      enable: true,
      update_at: 0,
    };
  }
}

async function save_config() {
  if (service_config.value != null) {
    let config = await update_route_wans_config(service_config.value);
    await routeWanConfigStore.UPDATE_INFO();
    show_model.value = false;
  }
}
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show_model"
    @after-enter="on_modal_enter"
  >
    <n-card
      style="width: 600px"
      title="Wan 路由转发服务"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-form v-if="service_config !== null" :model="service_config">
        <n-form-item label="是否启用">
          <n-switch v-model:value="service_config.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item>
      </n-form>

      <template #footer>
        <n-flex justify="end">
          <n-button round type="primary" @click="save_config"> 更新 </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
