<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useMessage } from "naive-ui";
import { ZoneType } from "@/lib/service_ipconfig";
import { useIPv6PDStore } from "@/stores/status_ipv6pd";
import { IPV6RAServiceConfig } from "@/lib/icmpv6ra";
import {
  get_iface_icmpv6ra_config,
  update_icmpv6ra_config,
} from "@/api/service_icmpv6ra";

let ipv6PDStore = useIPv6PDStore();
const message = useMessage();

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  mac?: string;
  zone: ZoneType;
}>();

const service_config = ref<IPV6RAServiceConfig>(
  new IPV6RAServiceConfig({
    iface_name: iface_info.iface_name,
  })
);

async function on_modal_enter() {
  try {
    let config = await get_iface_icmpv6ra_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    new IPV6RAServiceConfig({
      iface_name: iface_info.iface_name,
    });
  }
}

async function save_config() {
  let config = await update_icmpv6ra_config(service_config.value);
  await ipv6PDStore.UPDATE_INFO();
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
      title="ICMPv6 RA 配置"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
      closable
      @close="show_model = false"
    >
      <!-- {{ service_config }} -->
      <n-form :model="service_config">
        <n-grid :x-gap="12" :y-gap="8" cols="4" item-responsive>
          <n-form-item-gi span="4 m:4 l:4" label="是否启用">
            <n-switch v-model:value="service_config.enable">
              <template #checked> 启用 </template>
              <template #unchecked> 禁用 </template>
            </n-switch>
          </n-form-item-gi>

          <n-form-item-gi
            span="4 m:4 l:4"
            label="所关联的网卡 (须对应网卡开启 DHCPv6-PD)"
          >
            <n-input
              style="flex: 1"
              v-model:value="service_config.config.depend_iface"
              clearable
            />
          </n-form-item-gi>

          <n-form-item-gi span="2 m:2 l:2" label="子网索引">
            <n-input-number
              style="flex: 1"
              v-model:value="service_config.config.subnet_index"
              clearable
            />
          </n-form-item-gi>
          <n-form-item-gi span="2 m:2 l:2" label="子网前缀长度">
            <n-input-number
              style="flex: 1"
              v-model:value="service_config.config.subnet_prefix"
              clearable
            />
          </n-form-item-gi>

          <n-form-item-gi span="2 m:2 l:2" label="IP 首选状态时间 (s)">
            <n-input-number
              style="flex: 1"
              v-model:value="service_config.config.ra_preferred_lifetime"
              clearable
            />
          </n-form-item-gi>
          <n-form-item-gi span="2 m:2 l:2" label="IP 有效状态时间 (s)">
            <n-input-number
              style="flex: 1"
              v-model:value="service_config.config.ra_valid_lifetime"
              clearable
            />
          </n-form-item-gi>

          <!-- flag 部分 -->
          <n-form-item-gi span="2 m:2" label="使用 DHCPv6 获取 IPv6 地址">
            <n-switch
              v-model:value="
                service_config.config.ra_flag.managed_address_config
              "
            />
          </n-form-item-gi>
          <n-form-item-gi span="2 m:2" label="使用 DHCPv6 获取 其他信息">
            <n-switch
              v-model:value="service_config.config.ra_flag.other_config"
            />
          </n-form-item-gi>
          <n-form-item-gi span="2 m:2" label="移动 IPv6 归属代理">
            <n-switch
              v-model:value="service_config.config.ra_flag.home_agent"
            />
          </n-form-item-gi>

          <n-form-item-gi span="2 m:2" label="邻居发现代理">
            <n-switch v-model:value="service_config.config.ra_flag.nd_proxy" />
          </n-form-item-gi>
          <n-form-item-gi span="4 m:4" label="默认路由优先级">
            <n-radio-group
              v-model:value="service_config.config.ra_flag.prf"
              name="ra_flag"
            >
              <n-radio-button :value="3" label="低" />
              <n-radio-button :value="0" label="中 (默认)" />
              <n-radio-button :value="1" label="高" />
            </n-radio-group>
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
