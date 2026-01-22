<script setup lang="ts">
import { computed, ref } from "vue";
import { useMessage } from "naive-ui";
import { ZoneType, IfaceIpMode } from "@/lib/service_ipconfig";
import { IPV6PDConfig, IPV6PDServiceConfig } from "@/lib/ipv6pd";
import {
  get_iface_ipv6pd_config,
  update_ipv6pd_config,
} from "@/api/service_ipv6pd";
import { useIPv6PDStore } from "@/stores/status_ipv6pd";
import { generateValidMAC, formatMacAddress } from "@/lib/util";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

let ipv6PDStore = useIPv6PDStore();
const message = useMessage();

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  mac: string | null;
  zone: IfaceZoneType;
}>();

const service_config = ref<IPV6PDServiceConfig>(
  new IPV6PDServiceConfig({
    iface_name: iface_info.iface_name,
    config: new IPV6PDConfig({
      mac: iface_info.mac ?? generateValidMAC(),
    }),
  })
);

async function on_modal_enter() {
  try {
    let config = await get_iface_ipv6pd_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    new IPV6PDServiceConfig({
      iface_name: iface_info.iface_name,
      config: new IPV6PDConfig({
        mac: iface_info.mac ?? generateValidMAC(),
      }),
    });
  }
}

async function save_config() {
  if (
    service_config.value.config.mac === "" ||
    service_config.value.config.mac === undefined
  ) {
    message.warning("MAC 地址不能为空");
  } else {
    let config = await update_ipv6pd_config(service_config.value);
    await ipv6PDStore.UPDATE_INFO();
    show_model.value = false;
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
      title="IPv6-PD 客户端配置"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <!-- {{ service_config }} -->
      <n-form :model="service_config">
        <n-form-item label="是否启用">
          <n-switch v-model:value="service_config.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item>
        <n-form-item label="申请使用的 mac 地址 (PPP网卡上是生成虚拟的)">
          <n-input
            :value="service_config.config.mac"
            @update:value="
              (v: string) => (service_config.config.mac = formatMacAddress(v))
            "
          ></n-input>
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
