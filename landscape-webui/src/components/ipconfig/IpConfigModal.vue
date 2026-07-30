<script setup lang="ts">
import {
  get_iface_server_config,
  update_iface_server_config,
} from "@/api/service_ipconfig";
import { IfaceIpServiceConfig, IfaceIpMode } from "@/lib/service_ipconfig";
import { computed, ref } from "vue";
import ConfigModal from "@/components/common/ConfigModal.vue";
import IpEdit from "../IpEdit.vue";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import { useI18n } from "vue-i18n";

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);
const { t } = useI18n();

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const iface_data = ref<IfaceIpServiceConfig>(
  new IfaceIpServiceConfig({ iface_name: iface_info.iface_name }),
);

const ip_config_options = computed(() => {
  let result = [
    {
      label: t("interface.mode_none"),
      value: IfaceIpMode.Nothing,
    },
    {
      label: t("interface.mode_static"),
      value: IfaceIpMode.Static,
    },
  ];
  if (iface_info.zone == IfaceZoneType.wan) {
    result.push({
      label: t("interface.mode_pppoe_native"),
      value: IfaceIpMode.PPPoE,
    });
    result.push({
      label: t("interface.mode_dhcp_client"),
      value: IfaceIpMode.DHCPClient,
    });
  }
  return result;
});

async function on_modal_enter() {
  try {
    let config = await get_iface_server_config(iface_info.iface_name);
    // console.log(config);
    // iface_service_type.value = config.t;
    iface_data.value = new IfaceIpServiceConfig(config);
  } catch (e) {
    iface_data.value = new IfaceIpServiceConfig({
      iface_name: iface_info.iface_name,
    });
  }
}

async function update_mode() {
  if (iface_data.value !== undefined) {
    try {
      if (
        iface_data.value.ip_model.t === IfaceIpMode.PPPoE &&
        iface_data.value.ip_model.ac_name === ""
      ) {
        iface_data.value.ip_model.ac_name = null;
      }
      let config = await update_iface_server_config(iface_data.value);
      emit("refresh");
      show_model.value = false;
    } catch (error) {}
  }
}

function select_ip_model(value: IfaceIpMode) {
  if (value === IfaceIpMode.Nothing) {
    iface_data.value.ip_model = { t: IfaceIpMode.Nothing };
  } else if (value === IfaceIpMode.Static) {
    iface_data.value.ip_model = {
      t: IfaceIpMode.Static,
      default_router_ip: "0.0.0.0",
      default_router: false,
      ipv4: "0.0.0.0",
      ipv4_mask: 24,
      ipv6: null,
    };
  } else if (value === IfaceIpMode.PPPoE) {
    iface_data.value.ip_model = {
      t: IfaceIpMode.PPPoE,
      default_router: false,
      username: "",
      password: "",
      mtu: 1492,
      ac_name: null,
    };
  } else if (value === IfaceIpMode.DHCPClient) {
    iface_data.value.ip_model = {
      t: IfaceIpMode.DHCPClient,
      default_router: false,
      hostname: null,
      custome_opts: [],
    };
  }
}
</script>

<template>
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="iface_data.enable"
    :title="t('interface.title')"
    width="600px"
    @after-enter="on_modal_enter"
  >
    <n-flex style="flex: 1" vertical v-if="iface_data.ip_model !== undefined">
      <n-flex style="flex: 1">
        <n-select
          :value="iface_data.ip_model.t"
          @update:value="select_ip_model"
          :options="ip_config_options"
        />
      </n-flex>

      <n-flex style="flex: 1">
        <n-flex
          style="flex: 1"
          v-if="iface_data.ip_model.t === IfaceIpMode.Static"
        >
          <n-form style="flex: 1" :model="iface_data.ip_model" :cols="5">
            <n-grid :cols="5">
              <n-form-item-gi :label="t('interface.static_ip')" :span="5">
                <IpEdit
                  v-model:ip="iface_data.ip_model.ipv4"
                  v-model:mask="iface_data.ip_model.ipv4_mask"
                ></IpEdit>
              </n-form-item-gi>
              <n-form-item-gi
                v-if="iface_info.zone == IfaceZoneType.wan"
                :label="t('interface.set_default_route')"
                :span="5"
              >
                <n-switch v-model:value="iface_data.ip_model.default_router">
                  <template #checked>
                    {{ t("interface.yes") }}
                  </template>
                  <template #unchecked>
                    {{ t("interface.no") }}
                  </template>
                </n-switch>
              </n-form-item-gi>
              <n-form-item-gi
                v-if="iface_info.zone == IfaceZoneType.wan"
                :label="t('interface.route_ip')"
                :span="5"
              >
                <IpEdit
                  v-model:ip="iface_data.ip_model.default_router_ip"
                ></IpEdit>
              </n-form-item-gi>
            </n-grid>
          </n-form>
        </n-flex>
        <n-flex
          vertical
          style="flex: 1"
          v-else-if="iface_data.ip_model.t === IfaceIpMode.PPPoE"
        >
          <n-form style="flex: 1" :model="iface_data.ip_model" :cols="5">
            <n-grid :cols="5">
              <n-form-item-gi :label="t('interface.username')" :span="5">
                <n-input
                  v-model:value="iface_data.ip_model.username"
                  placeholder=""
                />
              </n-form-item-gi>
              <n-form-item-gi :label="t('interface.password')" :span="5">
                <n-input
                  v-model:value="iface_data.ip_model.password"
                  type="password"
                  show-password-on="click"
                  placeholder=""
                />
              </n-form-item-gi>
              <n-form-item-gi
                :label="t('interface.set_default_route')"
                :span="5"
              >
                <n-switch v-model:value="iface_data.ip_model.default_router">
                  <template #checked>
                    {{ t("interface.yes") }}
                  </template>
                  <template #unchecked>
                    {{ t("interface.no") }}
                  </template>
                </n-switch>
              </n-form-item-gi>
              <n-form-item-gi :label="t('interface.mtu')" :span="5">
                <n-input-number
                  v-model:value="iface_data.ip_model.mtu"
                  :min="576"
                  :max="1492"
                  style="width: 100%"
                />
              </n-form-item-gi>
              <n-form-item-gi :span="5">
                <template #label>
                  <Notice>
                    {{ t("interface.ac_name") }}
                    <template #msg>
                      {{ t("interface.ac_name_tip") }}
                    </template>
                  </Notice>
                </template>
                <n-input
                  v-model:value="iface_data.ip_model.ac_name"
                  placeholder=""
                />
              </n-form-item-gi>
            </n-grid>
          </n-form>
        </n-flex>

        <n-flex
          vertical
          style="flex: 1"
          v-else-if="iface_data.ip_model.t === IfaceIpMode.DHCPClient"
        >
          <n-alert type="warning">
            {{ t("interface.dhcp_warn") }}
          </n-alert>
          <n-form style="flex: 1" :model="iface_data.ip_model" :cols="5">
            <n-grid :cols="5">
              <n-form-item-gi
                :label="t('interface.set_default_route')"
                :span="5"
              >
                <n-switch v-model:value="iface_data.ip_model.default_router">
                  <template #checked>
                    {{ t("interface.yes") }}
                  </template>
                  <template #unchecked>
                    {{ t("interface.no") }}
                  </template>
                </n-switch>
              </n-form-item-gi>
              <n-form-item-gi :label="t('interface.dhcp_hostname')" :span="5">
                <n-input v-model:value="iface_data.ip_model.hostname"></n-input>
              </n-form-item-gi>
            </n-grid>
          </n-form>
        </n-flex>
      </n-flex>
    </n-flex>

    <template #footer>
      <n-flex justify="end">
        <n-button round type="primary" @click="update_mode">
          {{ t("interface.update") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>
