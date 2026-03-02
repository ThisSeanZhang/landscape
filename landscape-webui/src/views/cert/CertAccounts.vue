<script lang="ts" setup>
import { get_cert_accounts } from "@/api/cert/account";
import type { CertAccountConfig } from "@landscape-router/types/api/schemas";
import { ref, onMounted } from "vue";
import { useI18n } from "vue-i18n";

const items = ref<CertAccountConfig[]>([]);
const { t } = useI18n();
const show_edit_modal = ref(false);

async function refresh() {
  items.value = await get_cert_accounts();
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
      <n-empty :description="t('cert.no_accounts')" />
    </n-flex>
    <n-flex v-else>
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3">
        <n-grid-item v-for="item in items" :key="item.id">
          <CertAccountCard @refresh="refresh()" :rule="item" />
        </n-grid-item>
      </n-grid>
    </n-flex>

    <CertAccountEditModal
      :rule_id="null"
      @refresh="refresh"
      v-model:show="show_edit_modal"
    />
  </n-flex>
</template>
