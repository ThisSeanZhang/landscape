<script setup lang="ts">
import { get_iface_cpu_balance, set_iface_cpu_balance } from "@/api/iface";
import { IfaceCpuSoftBalance } from "@/rust_bindings/common/iface";
import { ref } from "vue";

const show_model = defineModel<boolean>("show", { required: true });
const loading = ref(false);
const props = defineProps<{
  iface_name: string;
}>();

const balance_config = ref<IfaceCpuSoftBalance>({
  xps: "",
  rps: "",
});

async function get_current_config() {
  let data = await get_iface_cpu_balance(props.iface_name);
  if (data) {
    balance_config.value = data;
  }
}

async function save_config() {
  try {
    loading.value = true;
    show_model.value = false;
    if (balance_config.value.xps !== "" || balance_config.value.rps !== "") {
      await set_iface_cpu_balance(props.iface_name, balance_config.value);
    }
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show_model"
    @after-enter="get_current_config"
  >
    <n-card
      style="width: 600px"
      title="配置网卡软负载"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-flex vertical>
        <n-alert type="info">
          比如要将CPU 负载在 0 核心, 二进制是 1. 如果要负载在 1-2 核心, 二进制是
          11 设置值为 3. 如果要负载在 2-3 核心, 二进制是 110 设置为 6. 以此类推.
          重置设置为 0
        </n-alert>
        <n-form v-if="balance_config" :model="balance_config">
          <n-form-item label="发送核心负载">
            <n-input v-model:value="balance_config.xps"></n-input>
          </n-form-item>
          <n-form-item label="接收核心负载">
            <n-input v-model:value="balance_config.rps"></n-input>
          </n-form-item>
        </n-form>
      </n-flex>

      <template #footer>
        <n-flex v-if="balance_config" justify="end">
          <n-button
            :loading="loading"
            round
            type="primary"
            @click="save_config"
          >
            更新
          </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
