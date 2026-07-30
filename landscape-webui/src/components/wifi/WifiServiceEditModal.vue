<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import ConfigModal from "@/components/common/ConfigModal.vue";
import { WifiServiceConfig } from "@/lib/wifi";
import { useWifiConfigStore } from "@/stores/status_wifi";
import { get_iface_wifi_config, update_wifi_config } from "@/api/service_wifi";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";

const { t } = useI18n();
const wifiConfigStore = useWifiConfigStore();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const service_config = ref<WifiServiceConfig>(
  new WifiServiceConfig({
    iface_name: iface_info.iface_name,
  }),
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
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="service_config.enable"
    :title="t('wifi.title')"
    width="600px"
    @after-enter="on_modal_enter"
  >
    <n-form :model="service_config">
      <n-form-item :label="t('wifi.config')">
        <n-input
          v-model:value="service_config.config"
          type="textarea"
          rows="10"
          :placeholder="t('wifi.hostapd_config')"
        />
      </n-form-item>
    </n-form>

    <template #footer>
      <n-flex justify="end">
        <n-button round type="primary" @click="save_config">
          {{ t("common.update") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>
