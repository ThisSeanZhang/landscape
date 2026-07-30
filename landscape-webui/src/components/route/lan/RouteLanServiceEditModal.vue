<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

import ConfigModal from "@/components/common/ConfigModal.vue";
import type {
  RouteLanServiceConfig,
  StaticRouteConfig,
} from "@landscape-router/types/api/schemas";
import {
  get_route_lan_config,
  update_route_lans_config,
} from "@/api/route/lan";
import { useRouteLanConfigStore } from "@/stores/status_route_lan";

const { t } = useI18n();
const routeLanConfigStore = useRouteLanConfigStore();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
}>();

const service_config = ref<RouteLanServiceConfig | null>(null);

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
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="service_enabled"
    :title="t('network.route_lan.title')"
    :switch-disabled="service_config === null"
    width="600px"
    @after-enter="on_modal_enter"
  >
    <n-form v-if="service_config !== null" :model="service_config">
      <n-form-item :label="t('network.route_lan.static_route_limit')">
        <n-dynamic-input
          item-style="padding-right: 15px"
          :max="1"
          v-model:value="service_config.static_routes"
          :on-create="onCreate"
        >
          <template #create-button-default>
            {{ t("network.route_lan.add_subnet") }}
          </template>
          <template #default="{ value, index }">
            <n-input-group>
              <n-input
                :placeholder="t('network.route_lan.next_hop')"
                v-model:value="value.next_hop"
                type="text"
              />
              <n-input
                :placeholder="t('network.route_lan.subnet_range')"
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
        <n-button round type="primary" @click="save_config">
          {{ t("common.update") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>
