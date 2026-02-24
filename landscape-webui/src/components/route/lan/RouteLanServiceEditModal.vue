<script setup lang="ts">
import { ref } from "vue";

import type {
  RouteLanServiceConfig,
  StaticRouteConfig,
} from "landscape-types/api/schemas";
import {
  get_route_lan_config,
  update_route_lans_config,
} from "@/api/route/lan";
import { useRouteLanConfigStore } from "@/stores/status_route_lan";

const routeLanConfigStore = useRouteLanConfigStore();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
}>();

const service_config = ref<RouteLanServiceConfig | null>(null);

async function on_modal_enter() {
  try {
    let config = await get_route_lan_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    service_config.value = {
      iface_name: iface_info.iface_name,
      enable: true,
      update_at: 0,
      static_routes: null,
    };
  }
}

async function save_config() {
  if (service_config.value != null) {
    let config = await update_route_lans_config(service_config.value);
    await routeLanConfigStore.UPDATE_INFO();
    show_model.value = false;
  }
}

function onCreate(): StaticRouteConfig {
  return {
    next_hop: "",
    subnet: "",
    sub_prefix: 32,
  };
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
      title="Lan 路由转发服务"
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

        <n-form-item label="静态路由 (当前只能设置一个)">
          <n-dynamic-input
            item-style="padding-right: 15px"
            :max="1"
            v-model:value="service_config.static_routes"
            :on-create="onCreate"
          >
            <template #create-button-default> 增加可达子网 </template>
            <template #default="{ value, index }">
              <n-input-group>
                <n-input
                  placeholder="下一跳"
                  v-model:value="value.next_hop"
                  type="text"
                />
                <n-input
                  placeholder="子网范围"
                  v-model:value="value.subnet"
                  type="text"
                />
                <n-input-group-label>/</n-input-group-label>
                <n-input-number
                  :style="{ width: '200px' }"
                  placeholder=""
                  v-model:value="value.sub_prefix"
                  type="text"
                />
              </n-input-group>
            </template>
          </n-dynamic-input>
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
