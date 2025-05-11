<script setup lang="ts">
import {
  get_iface_server_config,
  update_iface_server_config,
} from "@/api/service_ipconfig";
import {
  IfaceIpServiceConfig,
  ZoneType,
  IfaceIpMode,
} from "@/lib/service_ipconfig";
import { computed, ref } from "vue";
import NewIpEdit from "../NewIpEdit.vue";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const iface_data = ref<IfaceIpServiceConfig>(
  new IfaceIpServiceConfig({ iface_name: iface_info.iface_name })
);

const ip_config_options = computed(() => {
  let result = [
    {
      label: "无",
      value: IfaceIpMode.Nothing,
    },
    {
      label: "静态IP",
      value: IfaceIpMode.Static,
    },
  ];
  if (iface_info.zone == ZoneType.Wan) {
    // result.push({
    //   label: "PPPoE",
    //   value: IfaceIpMode.PPPoE,
    // });
    result.push({
      label: "DHCP 客户端",
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
      ipv6: undefined,
    };
  } else if (value === IfaceIpMode.PPPoE) {
    iface_data.value.ip_model = {
      t: IfaceIpMode.PPPoE,
      default_router: false,
      username: "",
      password: "",
      mtu: 1492,
    };
  } else if (value === IfaceIpMode.DHCPClient) {
    iface_data.value.ip_model = {
      t: IfaceIpMode.DHCPClient,
      default_router: false,
      hostname: undefined,
    };
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
      title="网卡运行服务配置"
      :bordered="false"
      role="dialog"
      aria-modal="true"
    >
      <n-flex
        vertical
        style="width: 100%"
        v-if="iface_data.ip_model !== undefined"
      >
        <n-flex align="center" :wrap="false">
          <n-flex>
            <n-switch v-model:value="iface_data.enable">
              <template #checked> 启用 </template>
              <template #unchecked> 禁用 </template>
            </n-switch>
          </n-flex>
          <n-flex style="flex: 1">
            <n-select
              :value="iface_data.ip_model.t"
              @update:value="select_ip_model"
              :options="ip_config_options"
            />
          </n-flex>
        </n-flex>

        <n-flex>
          <n-flex v-if="iface_data.ip_model.t === IfaceIpMode.Static">
            <n-form style="flex: 1" :model="iface_data.ip_model" :cols="5">
              <n-grid :cols="5">
                <n-form-item-gi label="静态 IP" :span="5">
                  <NewIpEdit
                    v-model:ip="iface_data.ip_model.ipv4"
                    v-model:mask="iface_data.ip_model.ipv4_mask"
                  ></NewIpEdit>
                </n-form-item-gi>
                <n-form-item-gi
                  v-if="iface_info.zone == ZoneType.Wan"
                  label="是否设置默认路由"
                  :span="5"
                >
                  <n-switch v-model:value="iface_data.ip_model.default_router">
                    <template #checked> 是 </template>
                    <template #unchecked> 否 </template>
                  </n-switch>
                </n-form-item-gi>
                <n-form-item-gi
                  v-if="iface_info.zone == ZoneType.Wan"
                  label="路由 IP"
                  :span="5"
                >
                  <NewIpEdit
                    v-model:ip="iface_data.ip_model.default_router_ip"
                  ></NewIpEdit>
                </n-form-item-gi>
              </n-grid>
            </n-form>
          </n-flex>
          <n-flex v-else-if="iface_data.ip_model.t === IfaceIpMode.PPPoE">
            <n-input-group>
              <n-input-group-label>用户名</n-input-group-label>
              <n-input
                v-model:value="iface_data.ip_model.username"
                placeholder=""
              />
              <n-input-group-label>密码</n-input-group-label>
              <n-input
                v-model:value="iface_data.ip_model.password"
                placeholder=""
              />
            </n-input-group>
          </n-flex>

          <n-flex
            vertical
            style="flex: 1"
            v-else-if="iface_data.ip_model.t === IfaceIpMode.DHCPClient"
          >
            <n-alert type="warning">
              本端口如果有开启防火墙, 那么需要配置规则将 68 端口开放
            </n-alert>
            <n-form style="flex: 1" :model="iface_data.ip_model" :cols="5">
              <n-grid :cols="5">
                <n-form-item-gi label="是否设置默认路由" :span="5">
                  <n-switch v-model:value="iface_data.ip_model.default_router">
                    <template #checked> 是 </template>
                    <template #unchecked> 否 </template>
                  </n-switch>
                </n-form-item-gi>
                <n-form-item-gi label="DHCP 时填充的主机名称" :span="5">
                  <n-input
                    v-model:value="iface_data.ip_model.hostname"
                  ></n-input>
                </n-form-item-gi>
              </n-grid>
            </n-form>
          </n-flex>
        </n-flex>
      </n-flex>

      <template #footer>
        <n-flex justify="end">
          <n-button round type="primary" @click="update_mode"> 更新 </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
