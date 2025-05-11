<script setup lang="ts">
import { ZoneType, IfaceIpMode } from "@/lib/service_ipconfig";
import { computed, ref } from "vue";
import Range from "@/components/PortRange.vue";
import { NatServiceConfig } from "@/lib/nat";
import {
  get_iface_nat_config,
  update_iface_nat_config,
} from "@/api/service_nat";
import { useNATConfigStore } from "@/stores/status_nats";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

let natConfigStore = useNATConfigStore();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const nat_service_config = ref<NatServiceConfig>(
  new NatServiceConfig({
    iface_name: iface_info.iface_name,
  })
);

async function on_modal_enter() {
  try {
    let config = await get_iface_nat_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    nat_service_config.value = config;
  } catch (e) {
    nat_service_config.value = new NatServiceConfig({
      iface_name: iface_info.iface_name,
    });
  }
}

async function save_config() {
  let config = await update_iface_nat_config(nat_service_config.value);
  await natConfigStore.UPDATE_INFO();
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
      title="网卡NAT配置"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-form :model="nat_service_config">
        <n-form-item label="是否启用">
          <n-switch v-model:value="nat_service_config.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item>
        <n-form-item label="TCP 端口范围">
          <Range v-model:range="nat_service_config.nat_config.tcp_range">
          </Range>
        </n-form-item>
        <n-form-item label="UDP 端口范围">
          <Range v-model:range="nat_service_config.nat_config.udp_range">
          </Range>
        </n-form-item>
        <n-form-item label="ICMP ID 范围">
          <Range v-model:range="nat_service_config.nat_config.icmp_in_range">
          </Range>
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
