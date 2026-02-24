<script setup lang="ts">
import { computed, ref } from "vue";
import { ZoneType, IfaceIpMode } from "@/lib/service_ipconfig";
import {
  get_iface_mss_clamp_config,
  update_mss_clamp_config,
} from "@/api/service/mss_clamp";
import { IfaceZoneType } from "landscape-types/common/iface";
import type { MSSClampServiceConfig } from "landscape-types/api/schemas";

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
}>();

const service_config = ref<MSSClampServiceConfig>({
  iface_name: iface_info.iface_name,
  enable: false,
  clamp_size: 1492,
  update_at: new Date().getTime(),
});

async function on_modal_enter() {
  try {
    let config = await get_iface_mss_clamp_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    service_config.value = {
      iface_name: iface_info.iface_name,
      enable: false,
      clamp_size: 1492,
      update_at: new Date().getTime(),
    };
  }
}

async function save_config() {
  let config = await update_mss_clamp_config(service_config.value);
  show_model.value = false;
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
      title="配置 TCP MSS 钳制"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-form :model="service_config">
        <n-grid :cols="5">
          <n-form-item-gi label="是否启用" :span="1">
            <n-switch v-model:value="service_config.enable">
              <template #checked> 启用 </template>
              <template #unchecked> 禁用 </template>
            </n-switch>
          </n-form-item-gi>
          <n-form-item-gi label="钳制值" :span="4">
            <n-input-number
              v-model:value="service_config.clamp_size"
              :show-button="false"
              style="flex: 1"
              min="0"
              max="65535"
              placeholder=""
            />
          </n-form-item-gi>
        </n-grid>
      </n-form>

      <template #footer>
        <n-flex justify="end">
          <n-button round type="primary" @click="save_config"> 更新 </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
