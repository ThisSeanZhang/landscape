<script setup lang="ts">
import { useDnsConfigStore } from "@/stores/dns_config";
import { computed, ref } from "vue";
import type { FormInst, FormRules } from "naive-ui";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";

const dnsStore = useDnsConfigStore();
const message = useMessage();
const { t } = useI18n();

const formRef = ref<FormInst | null>(null);
const options = computed(() => [
  { label: t("config.default_enabled"), value: "default" },
  { label: t("config.option_enabled"), value: "enabled" },
  { label: t("config.option_disabled"), value: "disabled" },
]);
const rules: FormRules = {
  dohListenPort: {
    validator: (_rule, value) =>
      value === 53 ? new Error(t("config.doh_port_reserved")) : true,
    trigger: ["blur", "change"],
  },
};

async function handleSaveDns() {
  try {
    await formRef.value?.validate();
  } catch {
    return;
  }
  try {
    await dnsStore.saveDnsConfig();
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
  <n-card :title="t('config.dns_title')" segmented id="dns-config">
    <template #header-extra>
      <n-button
        type="primary"
        :disabled="!dnsStore.loaded || dnsStore.saving"
        :loading="dnsStore.saving"
        @click="handleSaveDns"
      >
        {{ t("config.save_dns") }}
      </n-button>
    </template>
    <n-form
      ref="formRef"
      :model="dnsStore"
      :rules="rules"
      :disabled="!dnsStore.loaded || dnsStore.saving"
      label-placement="left"
      label-width="120"
    >
      <n-form-item :label="t('config.cache_capacity')">
        <n-input-number
          v-model:value="dnsStore.cacheCapacity"
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
          v-model:value="dnsStore.cacheTtl"
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
          v-model:value="dnsStore.cacheNegativeTtl"
          :precision="0"
          :min="5"
          :max="3600"
          placeholder="60"
          style="width: 200px"
        />
        <template #feedback>
          {{ t("config.cache_negative_ttl_desc") }}
        </template>
      </n-form-item>
      <n-form-item :label="t('config.doh_listen_port')" path="dohListenPort">
        <n-input-number
          v-model:value="dnsStore.dohListenPort"
          :min="0"
          :max="65535"
          :precision="0"
          placeholder="6053"
        />
        <template #feedback>{{ t("config.doh_port_desc") }}</template>
      </n-form-item>
      <n-form-item :label="t('config.doh_http_endpoint')">
        <n-input
          v-model:value="dnsStore.dohHttpEndpoint"
          clearable
          placeholder="/dns-query"
        />
        <template #feedback>{{ t("config.empty_uses_default") }}</template>
      </n-form-item>
      <n-form-item :label="t('config.dns_tcp_enabled')">
        <n-select v-model:value="dnsStore.tcpEnabled" :options="options" />
      </n-form-item>
    </n-form>
  </n-card>
</template>
