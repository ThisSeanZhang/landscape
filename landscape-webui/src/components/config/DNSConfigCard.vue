<script setup lang="ts">
import { useDnsConfigStore } from "@/stores/dns_config";
import { ref } from "vue";
import type { FormInst, FormRules } from "naive-ui";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";

const dnsStore = useDnsConfigStore();
const message = useMessage();
const { t } = useI18n();

const formRef = ref<FormInst | null>(null);
const rules: FormRules = {
  listenPort: {
    validator: (_rule, value) =>
      value === 53 ? new Error(t("config.doh_port_reserved")) : true,
    trigger: ["blur", "change"],
  },
};

async function saveDoh() {
  try {
    await formRef.value?.validate();
  } catch {
    return;
  }
  await saveBlock(dnsStore.saveDoh);
}

async function saveBlock(save: () => Promise<void>) {
  try {
    await save();
    message.success(t("config.save_success"));
  } catch (e: any) {
    if (e.response?.status === 409) {
      message.error(t("config.conflict"));
    } else {
      message.error(t("config.save_failed") + ": " + e.message);
    }
  }
}
</script>

<template>
  <n-space vertical size="large">
    <n-card :title="t('config.dns_title')" segmented id="dns-config">
      <template #header-extra>
        <n-button
          type="primary"
          :disabled="dnsStore.cache.hash === null || dnsStore.cache.saving"
          :loading="dnsStore.cache.saving"
          @click="saveBlock(dnsStore.saveCache)"
        >
          {{ t("config.save_cache") }}
        </n-button>
      </template>
      <n-form
        :model="dnsStore.cache"
        :disabled="dnsStore.cache.hash === null || dnsStore.cache.saving"
        label-placement="left"
        label-width="120"
      >
        <n-form-item :label="t('config.cache_capacity')">
          <n-input-number
            v-model:value="dnsStore.cache.capacity"
            :precision="0"
            :min="1024"
            :max="1048576"
            placeholder="4096"
            style="width: 200px"
          />
          <template #feedback> {{ t("config.cache_capacity_desc") }} </template>
        </n-form-item>
        <n-form-item :label="t('config.cache_ttl')">
          <n-input-number
            v-model:value="dnsStore.cache.ttl"
            :precision="0"
            :min="60"
            :max="2592000"
            placeholder="86400"
            style="width: 200px"
          />
          <template #feedback> {{ t("config.cache_ttl_desc") }} </template>
        </n-form-item>
        <n-form-item :label="t('config.cache_negative_ttl')">
          <n-input-number
            v-model:value="dnsStore.cache.negativeTtl"
            :precision="0"
            :min="5"
            :max="3600"
            placeholder="120"
            style="width: 200px"
          />
          <template #feedback>
            {{ t("config.cache_negative_ttl_desc") }}
          </template>
        </n-form-item>
      </n-form>
      <n-text depth="3">{{ t("config.dns_transports") }}</n-text>
    </n-card>
    <n-card :title="t('config.doh_title')" segmented id="doh-config">
      <template #header-extra>
        <n-button
          type="primary"
          :disabled="dnsStore.doh.hash === null || dnsStore.doh.saving"
          :loading="dnsStore.doh.saving"
          @click="saveDoh"
        >
          {{ t("config.save_doh") }}
        </n-button>
      </template>
      <n-form
        ref="formRef"
        :model="dnsStore.doh"
        :rules="rules"
        :disabled="dnsStore.doh.hash === null || dnsStore.doh.saving"
        label-placement="left"
        label-width="120"
      >
        <n-form-item :label="t('config.doh_listen_port')" path="listenPort">
          <n-input-number
            v-model:value="dnsStore.doh.listenPort"
            :min="0"
            :max="65535"
            :precision="0"
            placeholder="6053"
          />
          <template #feedback>{{ t("config.doh_port_desc") }}</template>
        </n-form-item>
        <n-form-item :label="t('config.doh_http_endpoint')">
          <n-input
            v-model:value="dnsStore.doh.httpEndpoint"
            clearable
            placeholder="/dns-query"
          />
          <template #feedback>{{ t("config.empty_uses_default") }}</template>
        </n-form-item>
      </n-form>
      <n-text depth="3">{{ t("config.doh_dhcp_renewal") }}</n-text>
    </n-card>
  </n-space>
</template>
