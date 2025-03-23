<script setup lang="ts">
import { computed, ref } from "vue";
import { ZoneType, IfaceIpMode } from "@/lib/service_ipconfig";
import { WifiServiceConfig } from "@/lib/wifi";
import { useWifiConfigStore } from "@/stores/status_wifi";
import { get_iface_wifi_config, update_wifi_config } from "@/api/service_wifi";

const wifiConfigStore = useWifiConfigStore();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: ZoneType;
}>();

const service_config = ref<WifiServiceConfig>(
  new WifiServiceConfig({
    iface_name: iface_info.iface_name,
  })
);

async function on_modal_enter() {
  try {
    let config = await get_iface_wifi_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    service_config.value = new WifiServiceConfig({
      iface_name: iface_info.iface_name,
    });
  }
}

async function save_config() {
  let config = await update_wifi_config(service_config.value);
  await wifiConfigStore.UPDATE_INFO();
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
      title="无线服务配置"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-form :model="service_config">
        <n-form-item label="是否启用">
          <n-switch v-model:value="service_config.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item>
        <n-form-item label="配置">
          <n-input
            v-model:value="service_config.config"
            type="textarea"
            rows="10"
            placeholder="hostapd 配置"
          />
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
