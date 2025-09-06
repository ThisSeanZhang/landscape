<script setup lang="ts">
import { create_bridge } from "@/api/network";
import { ref } from "vue";

const showModal = defineModel<boolean>("show", { required: true });

const loading = ref(false);
const bridge_name = ref<string>("");
async function add_bridge() {
  if (bridge_name.value !== "") {
    try {
      loading.value = true;
      await create_bridge(bridge_name.value);
      showModal.value = false;
      bridge_name.value = "";
    } finally {
      loading.value = false;
    }
  }
}
</script>

<template>
  <n-modal v-model:show="showModal">
    <n-card
      style="width: 600px; display: flex"
      title="创建桥接设备"
      :bordered="false"
      role="dialog"
      aria-modal="true"
    >
      <n-input-group>
        <n-input
          v-model:value="bridge_name"
          :style="{ width: '50%', flex: '1' }"
          placeholder="bridge name"
        />
        <n-button :loading="loading" type="primary" @click="add_bridge" ghost>
          add bridge
        </n-button>
      </n-input-group>
    </n-card>
  </n-modal>
</template>
