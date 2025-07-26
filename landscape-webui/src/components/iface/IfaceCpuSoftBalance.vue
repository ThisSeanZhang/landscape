<script setup lang="ts">
import { get_iface_cpu_balance, set_iface_cpu_balance } from "@/api/iface";
import { IfaceCpuSoftBalance } from "@/rust_bindings/common/iface";
import { ref, computed } from "vue";

const show_model = defineModel<boolean>("show", { required: true });
const loading = ref(false);
const props = defineProps<{
  iface_name: string;
}>();

const balance_config = ref<IfaceCpuSoftBalance>({
  xps: "",
  rps: "",
});

// 计算属性，用于处理十进制和二进制之间的转换
const binary_balance_config = computed({
  get: () => {
    return {
      xps: balance_config.value.xps ? parseInt(balance_config.value.xps, 10).toString(2) : "",
      rps: balance_config.value.rps ? parseInt(balance_config.value.rps, 10).toString(2) : ""
    };
  },
  set: (val) => {
    balance_config.value.xps = val.xps ? parseInt(val.xps, 2).toString(10) : "";
    balance_config.value.rps = val.rps ? parseInt(val.rps, 2).toString(10) : "";
  }
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
          输入二进制数字来配置CPU核心负载。例如：
          要将CPU负载在0核心，二进制是 1
          负载在0-1核心，二进制是 11
          负载在1-2核心，0核心不负载，二进制是 110
          负载在2-3核心，0-1核心不负载，二进制是 1100
          清除配置留空或输入 0
        </n-alert>
        <n-form v-if="balance_config" :model="binary_balance_config">
          <n-form-item label="发送核心负载 (二进制)">
            <n-input v-model:value="binary_balance_config.xps" placeholder="例如: 110"></n-input>
          </n-form-item>
          <n-form-item label="接收核心负载 (二进制)">
            <n-input v-model:value="binary_balance_config.rps" placeholder="例如: 110"></n-input>
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
