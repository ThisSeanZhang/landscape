<script setup lang="ts">
import { create_bridge } from "@/api/network";
import { ref } from "vue";
import { useI18n } from "vue-i18n";

const showModal = defineModel<boolean>("show", { required: true });
const { t } = useI18n();

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
      :title="t('common.create_bridge_device')"
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
          {{ t("common.add_bridge") }}
        </n-button>
      </n-input-group>
    </n-card>
  </n-modal>
</template>
