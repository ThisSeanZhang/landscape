<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

import ConfigModal from "@/components/common/ConfigModal.vue";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import type { RouteWanServiceConfig } from "@landscape-router/types/api/schemas";
import { useRouteWanConfigStore } from "@/stores/status_route_wan";
import {
  get_route_wan_config,
  update_route_wans_config,
} from "@/api/route/wan";

const { t } = useI18n();
let routeWanConfigStore = useRouteWanConfigStore();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const service_config = ref<RouteWanServiceConfig | null>(null);

const service_enabled = computed({
  get() {
    return service_config.value?.enable ?? false;
  },
  set(value: boolean) {
    if (service_config.value) {
      service_config.value.enable = value;
    }
  },
});

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
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="service_enabled"
    :title="t('network.route_wan.title')"
    :switch-disabled="service_config === null"
    width="600px"
    @after-enter="on_modal_enter"
  >
    <template #footer>
      <n-flex justify="end">
        <n-button round type="primary" @click="save_config">
          {{ t("common.update") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>
