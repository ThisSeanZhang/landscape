<script setup lang="ts">
import { computed, ref } from "vue";
import NewIpEdit from "../NewIpEdit.vue";
import { ZoneType } from "@/lib/service_ipconfig";
import {
  DHCPv4ServiceConfig,
  get_dhcp_range,
  MacBindingRecord,
} from "@/lib/dhcp_v4";
import { useDHCPv4ConfigStore } from "@/stores/status_dhcp_v4";
import {
  get_iface_dhcp_v4_config,
  update_dhcp_v4_config,
} from "@/api/service_dhcp_v4";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

const dhcpv4ConfigStore = useDHCPv4ConfigStore();

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const service_config = ref<DHCPv4ServiceConfig>(
  new DHCPv4ServiceConfig({
    iface_name: iface_info.iface_name,
  })
);

async function on_modal_enter() {
  try {
    let config = await get_iface_dhcp_v4_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    service_config.value = new DHCPv4ServiceConfig({
      iface_name: iface_info.iface_name,
    });
  }
}

async function save_config() {
  let config = await update_dhcp_v4_config(service_config.value);
  await dhcpv4ConfigStore.UPDATE_INFO();
  show_model.value = false;
}

const server_ip_addr = computed({
  get() {
    return service_config.value.config.server_ip_addr;
  },
  set(new_value) {
    service_config.value.config.server_ip_addr = new_value;
    const [start, end] = get_dhcp_range(
      `${service_config.value.config.server_ip_addr}/${service_config.value.config.network_mask}`
    );
    service_config.value.config.ip_range_start = start;
    service_config.value.config.ip_range_end = end;
  },
});

const network_mask = computed({
  get() {
    return service_config.value.config.network_mask;
  },
  set(new_value) {
    service_config.value.config.network_mask = new_value;
    const [start, end] = get_dhcp_range(
      `${service_config.value.config.server_ip_addr}/${service_config.value.config.network_mask}`
    );
    service_config.value.config.ip_range_start = start;
    service_config.value.config.ip_range_end = end;
  },
});

function onCreateBinding(): MacBindingRecord {
  return {
    mac: "",
    ip: "",
    expire_time: 300,
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
      title="DHCPv4 服务配置"
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

        <n-grid :cols="5">
          <n-form-item-gi label="DHCP 服务 IP" :span="5">
            <NewIpEdit
              v-model:ip="server_ip_addr"
              v-model:mask="network_mask"
              :mask_max="30"
            ></NewIpEdit>
          </n-form-item-gi>
          <n-form-item-gi label="分配 IP起始地址 (包含)" :span="5">
            <NewIpEdit
              v-model:ip="service_config.config.ip_range_start"
            ></NewIpEdit>
          </n-form-item-gi>
          <n-form-item-gi label="分配 IP结束地址 (不包含)" :span="5">
            <NewIpEdit
              v-model:ip="service_config.config.ip_range_end"
            ></NewIpEdit>
          </n-form-item-gi>
          <n-form-item-gi label="Mac IP 地址绑定" :span="5">
            <n-dynamic-input
              v-model:value="service_config.config.mac_binding_records"
              :on-create="onCreateBinding"
            >
              <template #create-button-default>
                新建 MAC 静态 IP 映射
              </template>
              <template #default="{ value }">
                <n-input-group>
                  <n-input
                    v-model:value="value.mac"
                    type="text"
                    placeholder="Mac"
                  />
                  <n-input
                    v-model:value="value.ip"
                    type="text"
                    placeholder="IPv4"
                  />
                  <n-input-number
                    v-model:value="value.expire_time"
                    style="width: 230px"
                    placeholder="过期时间"
                    :show-button="false"
                  />
                </n-input-group>
              </template>
            </n-dynamic-input>
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
