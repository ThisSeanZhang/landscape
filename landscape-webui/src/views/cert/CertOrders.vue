<script lang="ts" setup>
import { get_cert_orders } from "@/api/cert/order";
import type { CertOrderConfig } from "@landscape-router/types/api/schemas";
import { ref, onMounted } from "vue";
import { useI18n } from "vue-i18n";

const items = ref<CertOrderConfig[]>([]);
const { t } = useI18n();
const show_edit_modal = ref(false);

async function refresh() {
  items.value = await get_cert_orders();
}

onMounted(async () => {
  await refresh();
});
</script>

<template>
  <n-flex vertical style="flex: 1">
    <n-flex>
      <n-button @click="show_edit_modal = true">
        {{ t("common.create") }}
      </n-button>
    </n-flex>
    <n-flex v-if="items.length === 0" justify="center" style="padding: 40px">
      <n-empty :description="t('cert.no_orders')" />
    </n-flex>
    <n-flex v-else>
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3">
        <n-grid-item v-for="item in items" :key="item.id">
          <CertOrderCard @refresh="refresh()" :rule="item" />
        </n-grid-item>
      </n-grid>
    </n-flex>

    <CertOrderEditModal
      :rule_id="null"
      @refresh="refresh"
      v-model:show="show_edit_modal"
    />
  </n-flex>
</template>
