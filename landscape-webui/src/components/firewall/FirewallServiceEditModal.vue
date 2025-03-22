<script setup lang="ts">
import { computed, ref } from "vue";
import { ZoneType, IfaceIpMode } from "@/lib/service_ipconfig";
import { FirewallServiceConfig } from "@/lib/firewall";
import { useFirewallConfigStore } from "@/stores/status_firewall";
import {
  get_iface_firewall_config,
  update_firewall_config,
} from "@/api/service_firewall";

const firewallConfigStore = useFirewallConfigStore();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: ZoneType;
}>();

const service_config = ref<FirewallServiceConfig>(
  new FirewallServiceConfig({
    iface_name: iface_info.iface_name,
  })
);

async function on_modal_enter() {
  try {
    let config = await get_iface_firewall_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    service_config.value = new FirewallServiceConfig({
      iface_name: iface_info.iface_name,
    });
  }
}

async function save_config() {
  let config = await update_firewall_config(service_config.value);
  await firewallConfigStore.UPDATE_INFO();
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
      title="防火墙服务配置"
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
      </n-form>

      <template #footer>
        <n-flex justify="end">
          <n-button round type="primary" @click="save_config"> 更新 </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
