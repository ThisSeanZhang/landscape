<script setup lang="ts">
import type { DhcpV4DnrOptionConfig } from "./types";
import { useI18n } from "vue-i18n";

const { t } = useI18n();

const model = defineModel<DhcpV4DnrOptionConfig>({ required: true });

const modeOptions = [
  { label: t("dhcp_v4.option_dnr.use_local"), value: "local" },
  { label: t("dhcp_v4.option_dnr.use_custom"), value: "custom" },
];

function updateMode(mode: "local" | "custom") {
  if (mode === "local") {
    model.value = { mode: "local" };
  } else {
    model.value = {
      mode: "custom",
      domains: [],
      ips: [],
      port: null,
      doh_path: null,
    };
  }
}
</script>

<template>
  <n-space vertical size="small">
    <n-select
      :value="model.mode"
      :options="modeOptions"
      style="max-width: 240px"
      @update:value="updateMode"
    />
    <n-alert v-if="model.mode === 'local'" type="info" :bordered="false">
      {{ t("dhcp_v4.option_dnr.local_alert") }}
    </n-alert>
    <template v-else>
      <n-alert type="info" :bordered="false">
        {{ t("dhcp_v4.option_dnr.custom_alert") }}
      </n-alert>
      <n-form-item :label="t('dhcp_v4.option_dnr.domain_label')">
        <n-dynamic-tags v-model:value="model.domains" />
      </n-form-item>
      <n-form-item :label="t('dhcp_v4.option_dnr.ipv4_label')">
        <n-dynamic-tags v-model:value="model.ips" />
      </n-form-item>
      <n-form-item :label="t('dhcp_v4.option_dnr.port_label')">
        <n-input-number
          v-model:value="model.port"
          :min="1"
          :max="65535"
          :placeholder="t('dhcp_v4.option_dnr.port_placeholder')"
          style="width: 100%"
        />
      </n-form-item>
      <n-form-item :label="t('dhcp_v4.option_dnr.path_label')">
        <n-input
          v-model:value="model.doh_path"
          :placeholder="t('dhcp_v4.option_dnr.path_placeholder')"
          style="width: 100%"
        />
      </n-form-item>
    </template>
  </n-space>
</template>
